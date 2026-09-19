"""Royalty guards — Planner B safety invariants that MUST PASS TODAY (green).

These pin the non-negotiable governance the T1-T5 expansion must preserve:
no fabricated ids, R2 re-resolve+rehash, RULE-E1..E4 claim gates, fail-closed
scope (no redirects, no loopback aliases), shell cwd jail + minimal env +
ledgered runs, and fail-closed approval without a gate.

Unlike the T1-T5 files, this file is green on the current tree. If any test
here goes red, the expansion has broken a load-bearing invariant — stop.
"""

from __future__ import annotations

import os

import httpx
import pytest


def _ctx(transport=None, events=None, config=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    if events is None:
        events = []
    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=transport or _ok_transport())
    return ToolContext(
        run_id="R-ROYAL", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://127.0.0.1:9/", emit=lambda k, p: events.append((k, dict(p))),
        config={"tier": "basic", **(config or {})}, state={},
    ), events


def _ok_transport(text="ok", status=200, headers=None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers or {}, text=text)

    return httpx.MockTransport(handler)


# -- 1. handlers never fabricate ids; R2 re-resolve + rehash --------------------------------------

def test_royal_no_handler_fabricates_ids():
    """Guard: tool outcomes carry evidence WITHOUT ids; only the loop + ledger mint EV- ids."""
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx()
    out = build_registry("basic").dispatch(
        "http_request", {"method": "GET", "url": "http://127.0.0.1:9/"}, ctx
    )
    assert out.ok and "EV-" not in out.result_for_model
    eid = ctx.ledger.add_evidence("R-ROYAL", "http_exchange", {"url": "http://127.0.0.1:9/"})
    assert eid.startswith("EV-")


def test_royal_r2_forged_evidence_blocked_rehash_verified():
    """Guard: forged/unknown evidence ids are BLOCKED (R2 re-resolve); stored digests rehash."""
    from hunter.agent.tools import build_registry
    from hunter.kernel.events import canonical_json, sha256_hex
    from hunter.kernel.redaction import redact_payload

    ctx, _ = _ctx()
    registry = build_registry("basic")
    base = {
        "check_id": "reflected-xss", "title": "T", "severity": "high", "cwe": "CWE-79",
        "endpoint": "/search", "method": "GET", "description": "D", "impact": "I",
        "severity_justification": "J", "counterevidence": "C", "confidence": "high",
        "evidence_ids": ["EV-9999"],
    }
    out = registry.dispatch("create_finding_request", dict(base), ctx)
    assert out.blocked and "r2" in out.code, "forged ids must fail R2 re-resolve"
    eid = ctx.ledger.add_evidence("R-ROYAL", "note", {"text": "note only"})
    out2 = registry.dispatch("create_finding_request", {**base, "evidence_ids": [eid]}, ctx)
    assert out2.blocked and out2.code.startswith("finding.r3"), "RULE-E1/R3: notes alone carry no finding"
    row = next(r for r in ctx.ledger.evidence("R-ROYAL") if r["id"] == eid)
    assert row["sha256"] == sha256_hex(canonical_json(redact_payload({"text": "note only"})))


def test_royal_rule_e1_e4_claim_gate_matrix():
    """Guard: empty evidence (E1), no-http (E1/R3), out-of-scope endpoint (R4) all BLOCKED."""
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx()
    registry = build_registry("basic")
    base = {
        "check_id": "c", "title": "T", "severity": "high", "cwe": "CWE-79",
        "endpoint": "http://evil.example.net/x", "method": "GET", "description": "D",
        "impact": "I", "severity_justification": "J", "counterevidence": "C",
        "confidence": "high", "evidence_ids": [],
    }
    assert registry.dispatch("create_finding_request", dict(base), ctx).blocked  # E1: no ids
    eid = ctx.ledger.add_evidence("R-ROYAL", "note", {"text": "x"})
    scope_out = registry.dispatch("create_finding_request", {**base, "evidence_ids": [eid]}, ctx)
    assert scope_out.blocked  # R3/R4: note-only + out-of-scope endpoint


# -- 2. scope: no redirects, no aliases ----------------------------------------------------------------

def test_royal_http_client_never_follows_redirects():
    """Guard: the ONLY network path has follow_redirects=False; 302 surfaces raw."""
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    client = ScopedHttpClient(
        localhost_scope(),
        transport=_ok_transport(status=302, headers={"location": "http://evil.example.net/"}),
    )
    exchange = client.request("GET", "http://127.0.0.1:9/")
    assert exchange.status == 302, "redirects must NOT be followed automatically"
    client.close()


def test_royal_scope_rejects_loopback_aliases_and_trailing_dot():
    """Guard: decimal/hex/shorthand/mapped loopback aliases + trailing-dot FQDNs are BLOCKED."""
    from hunter.tools.scope import ScopeViolation, localhost_scope

    scope = localhost_scope()
    for alias in ("http://2130706433/", "http://0x7f000001/", "http://127.1/",
                  "http://[::ffff:127.0.0.1]/", "http://127.0.0.1./", "http://0.0.0.0/"):
        with pytest.raises(ScopeViolation):
            scope.check_url(alias)


# -- 3. shell: cwd jail + minimal env + ledgered -----------------------------------------------------------

def test_royal_shell_cwd_jail_blocks_escape(tmp_path):
    """Guard: cwd must resolve strictly inside the state dir (.., absolute, symlink escapes blocked)."""
    from hunter.agent.tools import _shell_cwd

    state = tmp_path / "state"
    state.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    class Ctx:
        config = {"state_dir": str(state)}

    cwd, err = _shell_cwd({"cwd": "../outside"}, Ctx())  # type: ignore[arg-type]
    assert err == "shell.cwd_outside_state" and cwd is None
    cwd2, err2 = _shell_cwd({"cwd": str(outside)}, Ctx())  # type: ignore[arg-type]
    assert err2 == "shell.cwd_outside_state"
    ok_cwd, ok_err = _shell_cwd({}, Ctx())  # type: ignore[arg-type]
    assert ok_err is None and ok_cwd == str(state.resolve())


def test_royal_shell_minimal_env_no_operator_leak(tmp_path, monkeypatch):
    """Guard: child env is allowlisted only; HOME is the jail; operator secrets never pass."""
    from hunter.agent.tools import _SHELL_ENV_ALLOWLIST, _minimal_shell_env

    monkeypatch.setenv("HUNTER_OPERATOR_SECRET", "s3cr3t-operator-value")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY")
    env = _minimal_shell_env(str(tmp_path))
    assert "HUNTER_OPERATOR_SECRET" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert set(env) <= set(_SHELL_ENV_ALLOWLIST) | {"HOME", "HUNTER_SANDBOX"}
    assert env["HOME"] == str(tmp_path) and env["HUNTER_SANDBOX"] == "1"


def test_royal_shell_runs_are_ledgered(tmp_path):
    """Guard: every shell run — blocked or allowed — emits a ledger-visible engine_event."""
    from hunter.agent.tools import build_registry

    ctx, events = _ctx(config={
        "tier": "advanced", "state_dir": str(tmp_path),
        "approval_gate": lambda *a: None,  # pass-through: reach the handler's cwd jail
    })
    out = build_registry("advanced").dispatch("shell_exec", {"command": "ls", "cwd": "../.."}, ctx)
    assert out.blocked and out.code == "shell.cwd_outside_state"
    assert any(k == "engine_event" and p.get("tool") == "shell_exec" for k, p in events)


# -- 4. approval fail-closed without a gate ------------------------------------------------------------------

def test_royal_approval_fail_closed_without_gate():
    """Guard: danger=approval tools without a configured gate refuse (approval.unavailable)."""
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx(config={"tier": "advanced", "state_dir": "x"})
    out = build_registry("advanced").dispatch("shell_exec", {"command": "ls"}, ctx)
    assert out.blocked and out.code == "approval.unavailable"
    assert "approval gate" in out.result_for_model.lower()


def test_royal_catastrophic_never_runs_even_with_auto_allow(tmp_path):
    """Guard: catastrophic commands always pend — auto_allow, denylist, handler triple-gate."""
    from hunter.agent.approval import ApprovalStore, make_approval_gate
    from hunter.agent.tools import _shell_exec
    from hunter.kernel.ledger import Ledger

    store = ApprovalStore(tmp_path / "approvals")
    ledger = Ledger(":memory:")
    gate = make_approval_gate(store, ledger=ledger, run_id="R-ROYAL", auto_allow=True)
    ctx, _ = _ctx(config={"tier": "advanced", "state_dir": str(tmp_path)})
    decision = gate("shell_exec", {"command": "rm -rf /"}, ctx)
    assert decision is not None and decision.code == "approval.catastrophic"
    direct = _shell_exec({"command": "rm -rf /"}, ctx)
    assert direct.blocked, "handler denylist is defense-in-depth behind the gate"
    ledger.close()
    assert os.environ.get("HUNTER_ROYAL_SENTINEL", "absent") == "absent"  # env hygiene, no-op pin
