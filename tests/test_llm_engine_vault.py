"""LLMEngine end-to-end against the live PracticeVault.

A scripted FakeProvider plays the audit brain: probe four check ids, request
a finding for each citing the REAL evidence ids the loop appended, then
finish_scan. The engine's debunk pass then deterministically verifies the
candidates. No litellm, no network beyond loopback.

Governance assertions: every ledger finding is evidence-valid (RULE-E1),
zero findings exist without evidence, verification came from replay evidence
(RULE-E2), and the hash chain verifies.
"""

import re
from typing import Any
from urllib.parse import urlencode

import pytest

from hunter.agent.debunk import debunk_pass
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.engine.base import EngineContext, TargetSpec
from hunter.engine.llm import LLMEngine
from hunter.kernel.findings import FindingStatus
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ClassifiedError, ToolCall, TurnResult
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server
from hunter.workflow.pipeline import run_scan

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
CANARY = "hun<x>ter<b>q9"


# -- FakeProvider (same contract as tests/test_agent_loop.py) ---------------------


class FakeProvider:
    name = "fake"

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append({"tier": tier, "messages": [dict(m) for m in messages], "tools": tools})
        index = len(self.calls) - 1
        if index >= len(self.script):
            raise AssertionError(f"FakeProvider script exhausted after {len(self.script)} turns")
        step = self.script[index]
        if callable(step):
            return step(messages=messages, tools=tools)
        return step

    def classify(self, exc: BaseException) -> ClassifiedError:
        return ClassifiedError(reason="unknown")


def turn(*calls: ToolCall) -> TurnResult:
    return TurnResult(
        text="",
        tool_calls=tuple(calls),
        finish_reason="tool_calls" if calls else "stop",
        input_tokens=25,
        output_tokens=12,
        cost_usd=0.002,
        model="fake-model",
        provider="fake",
    )


def evidence_ids_for(messages: list[dict[str, Any]], marker: str) -> list[str]:
    ids: list[str] = []
    for message in messages:
        if message.get("role") != "tool":
            continue
        content = str(message.get("content", ""))
        if marker not in content:
            continue
        ids.extend(re.findall(r"evidence_id: (EV-\d+)", content))
    return ids


# -- the scripted audit plan ------------------------------------------------------

FINDING_SPECS = {
    "missing-headers": {
        "marker": "missing-headers|GET|/|-",
        "args": {
            "title": "Missing security response headers",
            "severity": "info",
            "cwe": "CWE-693",
            "endpoint": "/",
            "method": "GET",
            "description": "Landing page sends no CSP, X-Frame-Options or X-Content-Type-Options.",
            "impact": "Clickjacking and MIME-sniffing mitigations are absent.",
            "severity_justification": "Defense-in-depth gap; no direct compromise on its own.",
            "counterevidence": "All responses checked; the headers are absent everywhere.",
            "confidence": "high",
        },
    },
    "reflected-xss": {
        "marker": "reflected-xss|GET|/search|q",
        "args": {
            "title": "Reflected XSS in search parameter",
            "severity": "high",
            "cwe": "CWE-79",
            "endpoint": "/search",
            "method": "GET",
            "param": "q",
            "payload_used": CANARY,
            "description": "The q parameter echoes the canary unescaped into the HTML body.",
            "impact": "Attacker-controlled script executes in victims' browsers.",
            "severity_justification": "Raw HTML reflection with no CSP; session theft is trivial.",
            "counterevidence": "Baseline /search does not reflect; encoding would kill the signal.",
            "confidence": "high",
        },
    },
    "sql-error": {
        "marker": "sql-error|POST|/login|username",
        "args": {
            "title": "SQL error disclosure on login",
            "severity": "medium",
            "cwe": "CWE-653",
            "endpoint": "/login",
            "method": "POST",
            "param": "username",
            "payload_used": "'",
            "description": "A quote in username returns a 500 leaking raw SQLite error text.",
            "impact": "Backend technology and query structure leak, easing targeted injection.",
            "severity_justification": "Information disclosure, not direct injection; medium by impact.",
            "counterevidence": "Benign username returns the normal 401 page.",
            "confidence": "high",
        },
    },
    "unauth-action": {
        "marker": "unauth-action|POST|/transfer|-",
        "args": {
            "title": "Funds transfer without authorization",
            "severity": "high",
            "cwe": "CWE-862",
            "endpoint": "/transfer",
            "method": "POST",
            "description": "POST /transfer completes with no session or role check at all.",
            "impact": "Anyone can move funds between arbitrary accounts.",
            "severity_justification": "Direct unauthorized state change on a money path.",
            "counterevidence": "No auth required on any tested variant of the request.",
            "confidence": "high",
        },
    },
}


def audit_script():
    """probe x4 -> create_finding_request x4 (citing real evidence ids) -> finish_scan."""
    script: list[Any] = [
        turn(ToolCall(id="c-p1", name="run_probe", arguments={"check_id": "missing-headers"})),
        turn(ToolCall(id="c-p2", name="run_probe", arguments={"check_id": "reflected-xss"})),
        turn(ToolCall(id="c-p3", name="run_probe", arguments={"check_id": "sql-error"})),
        turn(ToolCall(id="c-p4", name="run_probe", arguments={"check_id": "unauth-action"})),
    ]
    for step, check_id in enumerate(["missing-headers", "reflected-xss", "sql-error", "unauth-action"]):
        spec = FINDING_SPECS[check_id]

        def request_finding(messages, tools, _spec=spec, _check_id=check_id, _step=step):
            ids = evidence_ids_for(messages, _spec["marker"])
            assert ids, f"no evidence ids found for {_check_id}"
            return turn(
                ToolCall(
                    id=f"c-f{_step}",
                    name="create_finding_request",
                    arguments={"check_id": _check_id, "evidence_ids": ids, **_spec["args"]},
                )
            )

        script.append(request_finding)
    script.append(turn(ToolCall(id="c-end", name="finish_scan")))
    return script


# -- fixtures -------------------------------------------------------------------


@pytest.fixture()
def no_proxy(monkeypatch):
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


@pytest.fixture()
def vault(no_proxy):
    handle, _port = start_server()
    try:
        yield handle
    finally:
        handle.shutdown()


# -- end-to-end scan -------------------------------------------------------------


def test_llm_engine_full_scan_against_vault(vault, tmp_path, monkeypatch):
    provider = FakeProvider(audit_script())
    engine = LLMEngine(provider, tier="advanced")
    real_get_engine = __import__("hunter.tools.registry", fromlist=["get_engine"]).get_engine

    def scripted_get_engine(name, **kwargs):
        return engine if name == "llm" else real_get_engine(name, **kwargs)

    monkeypatch.setattr("hunter.workflow.pipeline.get_engine", scripted_get_engine)
    summary = run_scan(
        vault.url,
        engine_name="llm",
        scope=localhost_scope(),
        state_dir=tmp_path / "state",
    )

    assert summary.status == "completed"
    assert summary.stats["turns"] == 9  # 4 probes + 4 finding requests + finish_scan
    assert summary.stats["cost_usd"] == pytest.approx(9 * 0.002)

    findings = summary.findings
    assert len(findings) >= 4
    by_key = {f.key: f for f in findings}
    for check_id in FINDING_SPECS:
        marker = FINDING_SPECS[check_id]["marker"]
        assert marker in by_key, f"missing finding for {marker}; got {sorted(by_key)}"

    # zero findings without evidence (RULE-E1) and every id resolves
    ledger = Ledger(tmp_path / "state" / "ledger.db")
    try:
        rows = {row["id"]: row for row in ledger.evidence(summary.run_id)}
        for finding in findings:
            assert finding.evidence_ids, f"finding {finding.id} has no evidence"
            for eid in finding.evidence_ids:
                assert eid in rows
                assert rows[eid]["kind"] == "http_exchange"
        # verification came from debunk replay evidence (RULE-E2), not the model
        assert summary.verified == len(findings)
        assert summary.candidates == 0
        for finding in findings:
            assert finding.status is FindingStatus.VERIFIED
            replay_rows = [
                row for row in ledger.evidence(summary.run_id)
                if row["data"].get("replay") is True and row["data"].get("finding_id") == finding.id
            ]
            assert replay_rows, f"no replay evidence bound for {finding.id}"
        report = ledger.verify_chain(summary.run_id)
        assert report.ok, report.details
    finally:
        ledger.close()


def test_llm_engine_collect_returns_zero_candidates_by_design(vault, tmp_path, monkeypatch):
    """Agent findings are already in the ledger, so EngineResult.candidates
    is empty and the pipeline's collect phase adds nothing — documented."""
    provider = FakeProvider(audit_script())
    engine = LLMEngine(provider, tier="advanced")
    scope = localhost_scope()
    events: list[tuple[str, dict]] = []
    http = ScopedHttpClient(scope)
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run("R-E2E-1", vault.url, "llm", scope.name)
    try:
        ctx = EngineContext(
            http=http,
            emit=lambda kind, payload: events.append((kind, dict(payload))),
            config={},
            ledger=ledger,
            run_id="R-E2E-1",
        )
        result = engine.run(TargetSpec(url=vault.url, scope=scope), ctx)
        assert result.candidates == []
        assert result.stats["findings"] == 4
        assert result.stats["verified"] == 4
        assert result.stats["debunk_verified"] == 4
        assert any(kind == "engine_event" and payload.get("stage") == "agent_finished"
                   for kind, payload in events)
    finally:
        http.close()
        ledger.close()


# -- debunk pass -----------------------------------------------------------------


@pytest.fixture()
def tool_env(vault, tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    events: list[tuple[str, dict]] = []
    http = ScopedHttpClient(scope)
    ctx = ToolContext(
        run_id="R-DEBUNK-1",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url=vault.url,
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"tier": "advanced"},
    )
    registry = build_registry("advanced")
    try:
        yield DebunkEnv(ctx=ctx, ledger=ledger, registry=registry, vault=vault)
    finally:
        http.close()
        ledger.close()


class DebunkEnv:
    def __init__(self, ctx, ledger, registry, vault):
        self.ctx = ctx
        self.ledger = ledger
        self.registry = registry
        self.vault = vault

    def create_finding(self, check_id: str, endpoint: str, path: str, param: str | None = None,
                        payload_used: str | None = None, method: str = "GET"):
        """Create a candidate the honest way: real exchange, governance tool."""
        exchange = self.ctx.http.request(method, self.ctx.target_url + path)
        eid = self.ledger.add_evidence(
            self.ctx.run_id, "http_exchange", {**exchange.to_dict(), "check_id": check_id}
        )
        outcome = self.registry.dispatch(
            "create_finding_request",
            {
                "check_id": check_id,
                "title": f"Candidate for {check_id}",
                "severity": "medium",
                "cwe": "CWE-0",
                "endpoint": endpoint,
                "method": method,
                "param": param,
                "payload_used": payload_used,
                "description": "Test candidate.",
                "impact": "Test impact.",
                "severity_justification": "Test justification.",
                "counterevidence": "Test counterevidence.",
                "confidence": "medium",
                "evidence_ids": [eid],
            },
            self.ctx,
        )
        assert outcome.ok, outcome.result_for_model
        return self.ledger.findings(self.ctx.run_id)[-1]


def test_debunk_pass_verifies_reproducible_signal(tool_env):
    canary_path = f"/search?{urlencode({'q': CANARY})}"
    finding = tool_env.create_finding("reflected-xss", "/search", canary_path, param="q", payload_used=CANARY)
    assert finding.status is FindingStatus.CANDIDATE
    verdict = debunk_pass(finding, tool_env.ctx)
    assert verdict == "verified"
    updated = tool_env.ledger.get_finding(finding.id)
    assert updated.status is FindingStatus.VERIFIED
    rows = tool_env.ledger.evidence(tool_env.ctx.run_id)
    replay = [
        row
        for row in rows
        if row["data"].get("finding_id") == finding.id and row["data"].get("replay") is True
    ]
    assert len(replay) == 1
    assert updated.evidence_ids[-1] == replay[0]["id"]


def test_debunk_pass_rules_out_non_reproducing_signal(tool_env):
    finding = tool_env.create_finding("reflected-xss", "/nope", "/nope", param="q", payload_used=CANARY)
    verdict = debunk_pass(finding, tool_env.ctx)
    assert verdict == "ruled_out"
    updated = tool_env.ledger.get_finding(finding.id)
    assert updated.status is FindingStatus.RULED_OUT  # kept for the audit trail, never deleted
    coverage = tool_env.ctx.state["coverage"]
    assert coverage[-1]["outcome"] == "ruled_out" and coverage[-1]["risk_area"] == "reflected-xss"
    assert coverage[-1]["evidence_ids"], "ruled_out coverage row must cite its debunk exchange"


def test_debunk_pass_transport_error_leaves_candidate(tool_env):
    from dataclasses import replace

    canary_path = f"/search?{urlencode({'q': CANARY})}"
    finding = tool_env.create_finding("reflected-xss", "/search", canary_path, param="q", payload_used=CANARY)
    dead_ctx = replace(tool_env.ctx, target_url="http://127.0.0.1:9")  # nothing listens there
    verdict = debunk_pass(finding, dead_ctx)
    assert verdict == "needs_follow_up"
    assert tool_env.ledger.get_finding(finding.id).status is FindingStatus.CANDIDATE
    coverage = dead_ctx.state["coverage"]
    assert coverage[-1]["outcome"] == "needs_follow_up"


def test_debunk_pass_unknown_check_needs_follow_up(tool_env):
    finding = tool_env.create_finding("not-a-real-check", "/", "/")
    verdict = debunk_pass(finding, tool_env.ctx)
    assert verdict == "needs_follow_up"
    assert tool_env.ledger.get_finding(finding.id).status is FindingStatus.CANDIDATE


# -- engine contract --------------------------------------------------------------


def test_llm_engine_plan_declares_v02_phases(vault):
    engine = LLMEngine(FakeProvider([]), tier="advanced")
    plan = engine.plan(TargetSpec(url=vault.url, scope=localhost_scope()))
    assert plan.engine == "llm"
    assert plan.phases == ["brief", "audit", "finish"]
    assert plan.notes["tier"] == "advanced"


def test_llm_engine_run_requires_ledger(vault):
    provider = FakeProvider([turn(ToolCall(id="c1", name="finish_scan"))])
    engine = LLMEngine(provider)
    scope = localhost_scope()
    http = ScopedHttpClient(scope)
    events: list[tuple[str, dict]] = []
    try:
        ctx = EngineContext(http=http, emit=lambda kind, payload: events.append((kind, dict(payload))))
        with pytest.raises(Exception) as excinfo:
            engine.run(TargetSpec(url=vault.url, scope=scope), ctx)
        assert "engine.no_ledger" in str(getattr(excinfo.value, "code", ""))
    finally:
        http.close()


def test_llm_engine_replay_delegates_to_deterministic_recheck(vault):
    provider = FakeProvider([])
    engine = LLMEngine(provider)
    from hunter.engine.base import CandidateFinding
    from hunter.kernel.findings import Severity

    scope = localhost_scope()
    http = ScopedHttpClient(scope)
    events: list[tuple[str, dict]] = []
    try:
        ctx = EngineContext(http=http, emit=lambda kind, payload: events.append((kind, dict(payload))))
        target = TargetSpec(url=vault.url, scope=scope)
        good = CandidateFinding(
            key="reflected-xss|GET|/search|q",
            title="x",
            severity=Severity.HIGH,
            cwe="CWE-79",
            endpoint="/search",
            param="q",
            payload_used=CANARY,
        )
        assert engine.replay(target, ctx, good) is True
        bogus = CandidateFinding(
            key="no-such-check|GET|/|-", title="x", severity=Severity.LOW, cwe="CWE-0", endpoint="/"
        )
        assert engine.replay(target, ctx, bogus) is False
    finally:
        http.close()


def test_registry_llm_resolves_to_ships_dark_engine_without_provider():
    """Without litellm/B5's router, get_engine('llm') must still RESOLVE (the
    pipeline's failed-run contract depends on it) and degrade to the stub."""
    from hunter.tools.registry import get_engine

    engine = get_engine("llm")
    assert engine.name == "llm"
    if getattr(engine, "_provider", None) is None:
        # ships-dark degradation: run/replay refuse with the actionable message
        target = TargetSpec(url="http://127.0.0.1:1/", scope=localhost_scope())
        with pytest.raises(RuntimeError, match="LLMEngine lands in v0.2"):
            engine.replay(target, None, None)  # type: ignore[arg-type]
