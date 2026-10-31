"""Tests for the adversarial challenger hook in debunk_pass."""

from urllib.parse import urlencode

import pytest

from hunter.agent.debunk import debunk_pass
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.findings import FindingStatus
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server


CANARY = "hun<x>ter<b>q9"


@pytest.fixture()
def no_proxy(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
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
def tool_env(vault, tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    events = []
    http = ScopedHttpClient(scope)
    ctx = ToolContext(
        run_id="R-DEBUNK-CHALLENGER",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url=vault.url,
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"tier": "advanced"},
    )
    registry = build_registry("advanced")
    try:
        yield ChallengerEnv(ctx=ctx, ledger=ledger, registry=registry, vault=vault)
    finally:
        http.close()
        ledger.close()


class ChallengerEnv:
    def __init__(self, ctx, ledger, registry, vault):
        self.ctx = ctx
        self.ledger = ledger
        self.registry = registry
        self.vault = vault

    def create_finding(self, check_id, endpoint, path, param=None, payload_used=None, method="GET"):
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
                "falsifier": "Test falsifier.",
                "confidence": "medium",
                "evidence_ids": [eid],
            },
            self.ctx,
        )
        assert outcome.ok, outcome.result_for_model
        return self.ledger.findings(self.ctx.run_id)[-1]


def test_debunk_challenger_provider_none_unchanged(tool_env):
    canary_path = f"/search?{urlencode({'q': CANARY})}"
    finding = tool_env.create_finding("reflected-xss", "/search", canary_path, param="q", payload_used=CANARY)

    calls = []

    def provider(finding=None, ctx=None):
        calls.append(True)
        return "should never be called"

    verdict = debunk_pass(finding, tool_env.ctx, provider=None)
    assert verdict == "verified"
    assert calls == []
    assert tool_env.ctx.state.get("challenger_notes", []) == []
    assert tool_env.ledger.get_finding(finding.id).status is FindingStatus.VERIFIED


def test_debunk_challenger_callable_invoked_and_recorded(tool_env):
    finding = tool_env.create_finding("reflected-xss", "/nope", "/nope", param="q", payload_used=CANARY)

    calls = []

    def challenger(finding, ctx):
        calls.append(finding.id)
        return "adversarial: likely a false positive"

    verdict = debunk_pass(finding, tool_env.ctx, provider=challenger)
    assert calls == [finding.id]
    assert verdict == "ruled_out"
    assert tool_env.ledger.get_finding(finding.id).status is FindingStatus.RULED_OUT

    notes = tool_env.ctx.state.get("notes", [])
    assert any("adversarial: likely a false positive" in n.get("text", "") for n in notes)
    assert tool_env.ctx.state.get("challenger_note") == "adversarial: likely a false positive"

    coverage = tool_env.ctx.state["coverage"]
    assert coverage[-1]["outcome"] == "ruled_out"
    assert "adversarial: likely a false positive" in coverage[-1]["note"]


def test_debunk_challenger_keyword_form(tool_env):
    finding = tool_env.create_finding("reflected-xss", "/nope", "/nope", param="q", payload_used=CANARY)

    calls = []

    def challenger(ctx):
        calls.append("called")
        return "challenger says no"

    verdict = debunk_pass(finding, tool_env.ctx, challenger=challenger)
    assert calls == ["called"]
    assert verdict == "ruled_out"
    assert "challenger says no" in tool_env.ctx.state.get("challenger_note", "")
