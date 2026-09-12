"""Agent tool governance tests — the hostile-LLM suite.

These tests ARE the hostile model: every blocked outcome here is an attempt
to slip a claim past the gates (forged evidence ids, note-only "evidence",
out-of-scope endpoints, duplicate findings, invalid scales, non-passive
methods at basic tier). Valid paths run against the live PracticeVault with
the real Ledger, ScopedHttpClient and ScopeSet — no fakes in the governance
path.

Documented contract check (handler-level tier gating): every v0.2 tool
registers at min_tier="basic", so the schema list the model sees is
IDENTICAL for basic and advanced tiers; advanced content is refused INSIDE
http_request / run_probe with stable BLOCKED codes (tools_base T2 note).
"""

import json
from typing import Any
from urllib.parse import urlencode

import pytest

from hunter.agent.tools import PROBE_TIERS, build_registry
from hunter.agent.tools_base import ToolContext, ToolOutcome
from hunter.kernel.events import canonical_json, sha256_hex
from hunter.kernel.findings import FindingStatus
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")

CANARY = "hun<x>ter<b>q9"


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


@pytest.fixture()
def env(vault, tmp_path):
    """Real Ledger + real scope-gated client + registry, at basic tier."""
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    events: list[tuple[str, dict]] = []
    http = ScopedHttpClient(scope)
    ctx = ToolContext(
        run_id="R-TEST-0001",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url=vault.url,
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"tier": "basic"},
    )
    registry = build_registry("basic")
    try:
        yield SimpleEnv(ctx=ctx, registry=registry, ledger=ledger, vault=vault, events=events)
    finally:
        http.close()
        ledger.close()


class SimpleEnv:
    def __init__(self, ctx, registry, ledger, vault, events):
        self.ctx = ctx
        self.registry = registry
        self.ledger = ledger
        self.vault = vault
        self.events = events

    def call(self, name: str, args: dict[str, Any] | None = None) -> ToolOutcome:
        return self.registry.dispatch(name, args or {}, self.ctx)

    def add_exchange_evidence(self, method: str = "GET", path: str = "/", check_id: str = "missing-headers",
                              purpose: str = "") -> str:
        """Bind a REAL vault exchange as http_exchange evidence (the honest way)."""
        exchange = self.ctx.http.request(method, self.ctx.target_url + path)
        return self.ledger.add_evidence(
            self.ctx.run_id, "http_exchange", {**exchange.to_dict(), "check_id": check_id, "purpose": purpose}
        )

    def add_note_evidence(self, text: str = "trust me, it looked bad") -> str:
        return self.ledger.add_evidence(self.ctx.run_id, "note", {"text": text})

    def finding_args(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "check_id": "reflected-xss",
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
            "evidence_ids": [],
        }
        base.update(overrides)
        return base


# -- tier gating ----------------------------------------------------------------


def test_basic_tier_blocks_non_passive_http_methods(env):
    outcome = env.call("http_request", {"method": "POST", "url": env.ctx.target_url + "/transfer",
                                        "body": "from=a&to=b&amount=1"})
    assert outcome.ok is False and outcome.blocked is True
    assert outcome.code == "tier.passive_only"
    assert "passive-only" in outcome.result_for_model
    # the refused method never touched the wire and never became evidence
    assert env.ledger.evidence(env.ctx.run_id) == []


def test_basic_tier_allows_passive_methods_and_binds_evidence_declared(env):
    outcome = env.call("http_request", {"method": "GET", "url": env.ctx.target_url + "/"})
    assert outcome.ok is True
    assert outcome.evidence is not None
    assert outcome.evidence["kind"] == "http_exchange"
    assert outcome.evidence["data"]["status"] == 200
    # handlers DECLARE evidence; the LOOP persists it — ledger still empty here
    assert env.ledger.evidence(env.ctx.run_id) == []


def test_advanced_tier_allows_post(env):
    env.ctx.config["tier"] = "advanced"
    outcome = env.call("http_request", {"method": "POST", "url": env.ctx.target_url + "/login",
                                        "body": urlencode({"username": "'", "password": "x"}),
                                        "purpose": "sql error probe"})
    assert outcome.ok is True
    assert outcome.evidence["data"]["status"] == 500
    assert outcome.evidence["data"]["purpose"] == "sql error probe"
    assert "BLOCKED" not in outcome.result_for_model


def test_tier_gating_is_handler_level_schemas_identical(env):
    """Documented v0.2 contract: schema list identical across tiers; the
    advanced gate lives inside the handlers."""
    basic = env.registry.schemas_for_tier("basic")
    advanced = env.registry.schemas_for_tier("advanced")
    assert [t["function"]["name"] for t in basic] == [t["function"]["name"] for t in advanced]
    assert len(basic) == 15
    assert all(spec.min_tier == "basic" for spec in env.registry.specs_for_tier("advanced"))


def test_probe_tier_map_shape():
    assert PROBE_TIERS["reflected-xss"] == "advanced"
    assert PROBE_TIERS["sql-error"] == "advanced"
    assert PROBE_TIERS["unauth-action"] == "advanced"
    assert PROBE_TIERS["path-traversal"] == "advanced"
    assert PROBE_TIERS["auth-bypass"] == "advanced"
    assert PROBE_TIERS["form-injection"] == "advanced"
    assert PROBE_TIERS["missing-headers"] == "basic"
    assert PROBE_TIERS["dir-listing"] == "basic"
    assert len(PROBE_TIERS) == 12


# -- dispatch safety --------------------------------------------------------------


def test_unknown_tool_returns_tool_not_found(env):
    outcome = env.call("drop_all_tables", {})
    assert outcome.ok is False
    assert outcome.code == "tool.tool_not_found"
    assert "unknown tool" in outcome.result_for_model


# -- notes ------------------------------------------------------------------------


def test_notes_add_list_get_roundtrip(env):
    add = env.call("note_add", {"text": "login form posts urlencoded", "tags": ["recon"]})
    assert add.ok and "N-0001" in add.result_for_model
    listing = env.call("note_list", {})
    assert "login form posts urlencoded" in listing.result_for_model
    got = env.call("note_get", {"id": "N-0001"})
    assert got.ok and "N-0001" in got.result_for_model
    assert any(kind == "engine_event" and payload.get("tool") == "note_add" for kind, payload in env.events)


def test_note_get_requires_id_and_rejects_unknown(env):
    missing = env.call("note_get", {})
    assert missing.blocked and missing.code == "note.id_required"
    unknown = env.call("note_get", {"id": "N-9999"})
    assert unknown.ok is False and unknown.code == "note.not_found"


def test_note_add_requires_text(env):
    outcome = env.call("note_add", {"text": "   "})
    assert outcome.blocked and outcome.code == "note.text_required"


# -- coverage -----------------------------------------------------------------------


def test_coverage_ruled_out_without_evidence_blocked(env):
    outcome = env.call("coverage_record", {"surface": "/search", "risk_area": "xss", "outcome": "ruled_out"})
    assert outcome.blocked and outcome.code == "coverage.evidence_required"
    assert "closure" in outcome.result_for_model.lower() or "evidence_id" in outcome.result_for_model


def test_coverage_not_applicable_with_unresolvable_id_blocked(env):
    outcome = env.call(
        "coverage_record",
        {"surface": "/admin", "risk_area": "auth", "outcome": "not_applicable", "evidence_ids": ["EV-9999"]},
    )
    assert outcome.blocked and outcome.code == "coverage.evidence_required"


def test_coverage_ruled_out_with_real_evidence_ok(env):
    eid = env.add_exchange_evidence()
    outcome = env.call("coverage_record", {"surface": "/", "risk_area": "headers", "outcome": "ruled_out",
                                           "evidence_ids": [eid], "note": "headers present"})
    assert outcome.ok, outcome.result_for_model
    rows = env.ctx.state["coverage"]
    assert rows[0]["outcome"] == "ruled_out" and rows[0]["evidence_ids"] == [eid]


def test_coverage_duplicate_row_blocked_with_update_hint(env):
    eid = env.add_exchange_evidence()
    first = env.call(
        "coverage_record",
        {"surface": "/search", "risk_area": "xss", "outcome": "no_issue_found", "evidence_ids": [eid]},
    )
    assert first.ok, first.result_for_model
    second = env.call(
        "coverage_record", {"surface": "/search", "risk_area": "xss", "outcome": "no_issue_found"}
    )
    assert second.blocked and second.code == "coverage.duplicate_row"
    assert "update pattern" in second.result_for_model


def test_coverage_invalid_outcome_blocked(env):
    outcome = env.call("coverage_record", {"surface": "/x", "risk_area": "y", "outcome": "vibes"})
    assert outcome.blocked and outcome.code == "coverage.outcome_invalid"


def test_coverage_list_empty_and_populated(env):
    empty = env.call("coverage_list", {})
    assert empty.ok and "no coverage" in empty.result_for_model
    env.ctx.state.setdefault("coverage", []).append(
        {"surface": "/", "risk_area": "headers", "outcome": "reported", "note": "", "evidence_ids": []}
    )
    listing = env.call("coverage_list", {})
    assert "headers -> reported" in listing.result_for_model


# -- threat model -----------------------------------------------------------------


def test_threat_model_get_empty_then_amend_attributed(env):
    empty = env.call("threat_model_get", {})
    assert "no threat model" in empty.result_for_model
    base = env.call("threat_model_amend", {"text": "Single-user app; funds move without auth."})
    assert base.ok and "base" in base.result_for_model
    amend = env.call("threat_model_amend", {"text": "Plaintext role cookie is the auth boundary.",
                                            "note": "from /admin 403 vs 200 diff"})
    assert amend.ok and "amendment 1" in amend.result_for_model
    got = env.call("threat_model_get", {})
    assert "Single-user app" in got.result_for_model
    assert "amendment 1 by agent; from /admin 403 vs 200 diff" in got.result_for_model


def test_threat_model_amend_requires_text(env):
    outcome = env.call("threat_model_amend", {"text": ""})
    assert outcome.blocked and outcome.code == "threat.text_required"


# -- run_probe ---------------------------------------------------------------------


def test_run_probe_unknown_check_id_blocked(env):
    outcome = env.call("run_probe", {"check_id": "teleport"})
    assert outcome.blocked and outcome.code == "probe.unknown_check_id"


def test_run_probe_active_check_blocked_at_basic(env):
    outcome = env.call("run_probe", {"check_id": "reflected-xss"})
    assert outcome.blocked and outcome.code == "tier.capability_locked"
    assert "advanced" in outcome.result_for_model


def test_run_probe_passive_check_allowed_at_basic(env):
    outcome = env.call("run_probe", {"check_id": "missing-headers"})
    assert outcome.ok, outcome.result_for_model
    assert "missing-headers|GET|/|-" in outcome.result_for_model
    # handler returns evidence ARTIFACTS; ids are appended by the loop (not persisted here)
    assert isinstance(outcome.evidence, list) and outcome.evidence
    assert all(artifact["kind"] == "http_exchange" for artifact in outcome.evidence)
    assert all(artifact["data"]["check_id"] == "missing-headers" for artifact in outcome.evidence)


def test_run_probe_active_check_allowed_at_advanced(env):
    env.ctx.config["tier"] = "advanced"
    outcome = env.call("run_probe", {"check_id": "reflected-xss"})
    assert outcome.ok, outcome.result_for_model
    assert "reflected-xss|GET|/search|q" in outcome.result_for_model
    assert outcome.evidence and len(outcome.evidence) >= 2  # baseline + payload
    assert outcome.evidence[-1]["data"]["url"].endswith(f"/search?{urlencode({'q': CANARY})}")


# -- ledger reads --------------------------------------------------------------


def test_list_findings_empty_then_populated(env):
    empty = env.call("list_findings", {})
    assert "no findings" in empty.result_for_model
    eid = env.add_exchange_evidence(
        method="GET", path=f"/search?{urlencode({'q': CANARY})}", check_id="reflected-xss"
    )
    created = env.call("create_finding_request", env.finding_args(evidence_ids=[eid]))
    assert created.ok, created.result_for_model
    listing = env.call("list_findings", {})
    assert "reflected-xss|GET|/search|q" in listing.result_for_model
    assert "candidate" in listing.result_for_model


def test_ledger_search_bounded_output(env):
    for i in range(12):  # more matches than the hard cap of 10
        env.add_exchange_evidence(path=f"/search?{urlencode({'q': f'needle{i}'})}", check_id="reflected-xss")
    outcome = env.call("ledger_search", {"query": "needle", "limit": 99})
    assert outcome.ok
    lines = outcome.result_for_model.splitlines()
    assert len(lines) <= 10
    assert all(len(line) <= 200 for line in lines)
    no_args = env.call("ledger_search", {})
    assert no_args.blocked and no_args.code == "ledger.query_required"
    nothing = env.call("ledger_search", {"query": "zzz-not-there"})
    assert "no ledger rows match" in nothing.result_for_model


def test_ledger_search_finds_findings_too(env):
    eid = env.add_exchange_evidence(
        method="GET", path=f"/search?{urlencode({'q': CANARY})}", check_id="reflected-xss"
    )
    env.call("create_finding_request", env.finding_args(evidence_ids=[eid]))
    outcome = env.call("ledger_search", {"query": "search"})
    assert "reflected-xss|GET|/search|q" in outcome.result_for_model


# -- create_finding_request: the governance gauntlet ---------------------------


def test_r1_missing_prose_blocked(env):
    eid = env.add_exchange_evidence(
        method="GET", path=f"/search?{urlencode({'q': CANARY})}", check_id="reflected-xss"
    )
    outcome = env.call("create_finding_request", env.finding_args(evidence_ids=[eid], title="  "))
    assert outcome.blocked and outcome.code == "finding.r1_required_fields"
    assert "title" in outcome.result_for_model

    outcome2 = env.call("create_finding_request", env.finding_args(evidence_ids=[eid], counterevidence=""))
    assert outcome2.blocked and outcome2.code == "finding.r1_required_fields"
    assert "counterevidence" in outcome2.result_for_model


def test_r1_fabricated_finding_without_evidence_ids_blocked(env):
    """The classic hostile move: a well-written finding, zero evidence."""
    outcome = env.call("create_finding_request", env.finding_args(evidence_ids=[]))
    assert outcome.blocked and outcome.code == "finding.r2_evidence_missing"
    assert "never invent" in outcome.result_for_model.lower()


def test_r2_forged_evidence_id_blocked(env):
    outcome = env.call("create_finding_request", env.finding_args(evidence_ids=["EV-4242"]))
    assert outcome.blocked and outcome.code == "finding.r2_evidence_missing"
    assert "EV-4242" in outcome.result_for_model
    assert env.ledger.findings(env.ctx.run_id) == []


def test_r2_chain_integrity_check(env):
    """Tampered evidence (stored sha256 no longer matches data) is refused."""
    eid = env.add_exchange_evidence(
        method="GET", path=f"/search?{urlencode({'q': CANARY})}", check_id="reflected-xss"
    )

    class TamperedLedger:
        def __init__(self, real, row):
            self._real = real
            self._row = row

        def evidence(self, run_id=None):
            return [self._row]

        def findings(self, run_id=None):
            return self._real.findings(run_id)

    rows = env.ledger.evidence(env.ctx.run_id)
    assert rows and rows[0]["id"] == eid
    tampered = dict(rows[0])
    tampered["sha256"] = "0" * 64  # digest no longer matches the stored data
    original = env.ctx.ledger
    env.ctx.ledger = TamperedLedger(original, tampered)
    try:
        outcome = env.call("create_finding_request", env.finding_args(evidence_ids=[eid]))
    finally:
        env.ctx.ledger = original
    assert outcome.blocked and outcome.code == "finding.r2_chain_integrity"


def test_r3_note_only_evidence_blocked(env):
    note_id = env.add_note_evidence()
    outcome = env.call("create_finding_request", env.finding_args(evidence_ids=[note_id]))
    assert outcome.blocked and outcome.code == "finding.r3_evidence_kind"
    assert "http_exchange" in outcome.result_for_model and "note" in outcome.result_for_model
    assert env.ledger.findings(env.ctx.run_id) == []


def test_r4_out_of_scope_endpoint_blocked(env):
    eid = env.add_exchange_evidence()
    for endpoint in ("http://evil.example.com/admin", "//evil.example.com/admin", "ftp://x/y"):
        outcome = env.call("create_finding_request", env.finding_args(evidence_ids=[eid], endpoint=endpoint))
        assert outcome.blocked, endpoint
        assert outcome.code == "scope.target_out_of_scope", endpoint
    assert env.ledger.findings(env.ctx.run_id) == []


def test_r5_duplicate_key_blocked_with_existing_id(env):
    eid = env.add_exchange_evidence(
        method="GET", path=f"/search?{urlencode({'q': CANARY})}", check_id="reflected-xss"
    )
    first = env.call("create_finding_request", env.finding_args(evidence_ids=[eid]))
    assert first.ok and "F-0001" in first.result_for_model
    second = env.call("create_finding_request", env.finding_args(evidence_ids=[eid]))
    assert second.blocked and second.code == "finding.r5_duplicate"
    assert "F-0001" in second.result_for_model
    assert "immutable" in second.result_for_model


def test_r6_invalid_severity_and_confidence_blocked(env):
    eid = env.add_exchange_evidence()
    bad_sev = env.call("create_finding_request", env.finding_args(evidence_ids=[eid], severity="apocalyptic"))
    assert bad_sev.blocked and bad_sev.code == "finding.r6_severity_invalid"
    bad_conf = env.call("create_finding_request", env.finding_args(evidence_ids=[eid], confidence="certain"))
    assert bad_conf.blocked and bad_conf.code == "finding.r6_confidence_invalid"
    assert env.ledger.findings(env.ctx.run_id) == []


def test_valid_request_against_live_vault_creates_candidate(env):
    eid = env.add_exchange_evidence(
        method="GET", path=f"/search?{urlencode({'q': CANARY})}", check_id="reflected-xss"
    )
    outcome = env.call("create_finding_request", env.finding_args(evidence_ids=[eid]))
    assert outcome.ok, outcome.result_for_model
    assert "status candidate" in outcome.result_for_model
    findings = env.ledger.findings(env.ctx.run_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.evidence_ids == (eid,)
    assert finding.key == "reflected-xss|GET|/search|q"
    assert "Severity justification:" in finding.description
    assert "Counterevidence:" in finding.description
    assert "Confidence: high" in finding.description
    # the bound evidence really resolves and its digest is intact
    rows = {row["id"]: row for row in env.ledger.evidence(env.ctx.run_id)}
    row = rows[finding.evidence_ids[0]]
    assert row["kind"] == "http_exchange"
    assert sha256_hex(canonical_json(row["data"])) == row["sha256"]


def test_claim_gate_backstop_blocks_evidenceless_claim(env):
    """Even if a future handler bug skipped R2, the ledger refuses (RULE-E1)."""
    from hunter.kernel.claimgate import ClaimGateBlocked
    from hunter.kernel.findings import Finding, Severity

    claim = Finding(
        id="",
        run_id=env.ctx.run_id,
        key="x|GET|/|-",
        title="no evidence",
        severity=Severity.LOW,
        cwe="CWE-0",
        endpoint="/",
        evidence_ids=(),
    )
    with pytest.raises(ClaimGateBlocked):
        env.ledger.create_finding(claim)
    assert env.ledger.findings(env.ctx.run_id) == []


# -- lifecycle tools ------------------------------------------------------------


def test_finish_scan_warns_without_coverage(env):
    outcome = env.call("finish_scan", {})
    assert outcome.lifecycle_finish is True
    assert "No coverage was recorded for this scan" in outcome.result_for_model
    assert "findings: 0" in outcome.result_for_model


def test_finish_scan_reconciles_coverage_and_findings(env):
    eid = env.add_exchange_evidence()
    env.call("coverage_record", {"surface": "/", "risk_area": "headers", "outcome": "reported",
                                 "evidence_ids": [eid]})
    env.call("coverage_record", {"surface": "/api", "risk_area": "idor", "outcome": "needs_follow_up",
                                 "note": "needs a second account"})
    env.call("coverage_record", {"surface": "/search", "risk_area": "xss", "outcome": "reported",
                                 "evidence_ids": [eid]})
    outcome = env.call("finish_scan", {})
    assert outcome.lifecycle_finish is True
    assert "No coverage was recorded" not in outcome.result_for_model
    assert "needs_follow_up" in outcome.result_for_model
    assert "/api / idor" in outcome.result_for_model
    assert "findings: 0 (critical: 0, high: 0, medium: 0, low: 0, info: 0)" in outcome.result_for_model


def test_respond_to_user_sets_yield(env):
    outcome = env.call("respond_to_user", {"message": "Found 1 XSS; continuing with auth checks."})
    assert outcome.ok
    assert outcome.lifecycle_yield == "Found 1 XSS; continuing with auth checks."
    assert outcome.lifecycle_finish is False


def test_respond_to_user_requires_message(env):
    outcome = env.call("respond_to_user", {"message": ""})
    assert outcome.blocked and outcome.code == "respond.message_required"


# -- think + event discipline ------------------------------------------------------


def test_think_is_silent_and_side_effect_free(env):
    before_events = len(env.events)
    before_rows = len(env.ledger.events(env.ctx.run_id))
    outcome = env.call("think", {"thought": "maybe the cookie is the auth boundary"})
    assert outcome.ok and outcome.result_for_model == "noted."
    assert len(env.events) == before_events  # no emit
    assert len(env.ledger.events(env.ctx.run_id)) == before_rows  # nothing chained


def test_tools_emit_engine_event(env):
    env.call("note_add", {"text": "x"})
    env.call("coverage_list", {})
    env.call("list_findings", {})
    tool_events = [payload for kind, payload in env.events if kind == "engine_event" and "tool" in payload]
    assert {e["tool"] for e in tool_events} >= {"note_add", "coverage_list", "list_findings"}


def test_registry_rejects_unknown_tier():
    with pytest.raises(ValueError, match="unknown tier"):
        build_registry("godmode")


def test_tool_outcome_json_shape_documented():
    """Sanity on the contract the loop relies on: evidence artifacts are
    {"kind", "data"} dicts and blocked outcomes carry a stable code."""
    outcome = ToolOutcome(ok=False, blocked=True, code="x", result_for_model="m")
    assert json.dumps({"ok": outcome.ok, "code": outcome.code})


# -- phase machine hook (v0.3, additive) ---------------------------------------------


def test_phase_machine_follows_agent_tools(env):
    """First surface tool while recon is open drives recon -> classify ->
    hunting with source "agent"; finish_scan carries the phase line."""
    from hunter.phases import PhaseState

    ledger, run = env.ledger, env.ctx.run_id
    ledger.create_run(run, env.ctx.target_url, "llm", "localhost-only")
    ledger.append(
        run,
        "run_started",
        {"target": env.ctx.target_url, "engine": "llm", "scope": env.ctx.scope.summary()},
    )
    machine = PhaseState(ledger, run)
    env.ctx.config["phase_machine"] = machine
    machine.start("score")
    machine.close_current()
    machine.start("recon")

    env.add_exchange_evidence()  # a real surface fact: the recon gate can pass
    outcome = env.call("run_probe", {"check_id": "missing-headers"})
    assert outcome.ok
    assert machine.current == "hunting"

    events = ledger.events(run)
    recon_close = [
        e
        for e in events
        if e.kind_value() == "phase_ended"
        and e.payload.get("phase") == "recon"
        and isinstance(e.payload.get("gate"), dict)
    ]
    assert recon_close and recon_close[0].payload["gate"]["passed"] is True
    classifications = [e for e in events if e.kind_value() == "classification_recorded"]
    assert classifications and classifications[0].payload["source"] == "agent"
    assert any(
        e.kind_value() == "phase_started" and e.payload.get("phase") == "hunting" for e in events
    )

    finish = env.call("finish_scan", {})
    assert finish.lifecycle_finish is True
    assert "hunting" in finish.result_for_model  # the phase line is in the result
    finish_events = [
        payload
        for kind, payload in env.events
        if kind == "engine_event" and payload.get("tool") == "finish_scan"
    ]
    assert finish_events and finish_events[-1].get("phase") == "hunting"
