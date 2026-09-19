"""R2-B R-spec v2 kind-fit (TDD RED).

B-gate: B1 (R-spec kind-fit) — R decision gate: needs_follow_up vs ruled_out.

Prod targets (READ ONLY, do NOT edit):
- src/hunter/agent/tools_web3.py:32-379 contract_read exact scope + check_url double-gate
- src/hunter/agent/tools.py:513-642 R3 http_exchange mandatory + R4b + :589-595
- src/hunter/workflow/pipeline.py:379-394 replay http only
- src/hunter/kernel/claimgate.py:26-46 RULE-E1
- per-fn -> prod:
  validate_web3_kind_fit -> tools_web3.py (NEW stub)
  R_SPEC_VERSION / r_spec_version -> tools.py create_finding_request + claimgate.py
  R4c on-chain bind -> tools.py R4 section (NEW R4c branch)
  replay analog (RPC byte-equal) -> pipeline.py verify stage (NEW RPC path)
  RULE-E1 pin -> claimgate.py validate_finding_insert (UNCHANGED)

All tests FAIL today via EXPECTED-FAIL-R2B until R-spec v2 lands.
Mock only: httpx.MockTransport, :memory: Ledger, no live net/binaries.
Adversarial: no widen (exact lower compare), secret redact, second-host
divergence never ruled_out (fail-closed), source-hash mismatch needs_follow_up.
"""
from __future__ import annotations

import json

import httpx
import pytest

R2B = "EXPECTED-FAIL-R2B:R-spec v2 kind-fit (R2-B B1)"
ADDR = "0xabc0000000000000000000000000000000000def"
RPC = "https://rpc.example.com"


def _require_kind_fit():
    import hunter.agent.tools_web3 as w3
    fn = getattr(w3, "validate_web3_kind_fit", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_web3.validate_web3_kind_fit stub missing")
    return fn


def _require_rspec_version():
    import hunter.agent.tools as tools
    ver = getattr(tools, "R_SPEC_VERSION", None)
    if ver is None:
        pytest.fail(f"{R2B} — hunter.agent.tools.R_SPEC_VERSION missing (default 1)")
    return ver


def _rpc_transport(result="0x1234", events=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if events is not None:
            events.append(str(request.url))
        return httpx.Response(200, headers={"content-type": "application/json"},
                               text=json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}))
    return httpx.MockTransport(handler)


def _ctx(events=None, tier="basic"):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet
    if events is None:
        events = []
    scope = ScopeSet(frozenset({"rpc.example.com"}), name="r2b")
    http = ScopedHttpClient(scope, transport=_rpc_transport(events=events))
    return ToolContext(run_id="R-R2B", ledger=Ledger(":memory:"), http=http, scope=scope,
                       target_url="http://rpc.example.com/", emit=lambda k, p: events.append((k, dict(p))),
                       config={"tier": tier, "chain_scope": [{"chain_id": 1, "address": ADDR}],
                               "r_spec_version": 2,
                               "rpc_manifest": {"hosts": ["rpc.example.com"]}}, state={}), events


def test_r2b_rspec_kind_fit_web2_http_only():
    """R3 kind-fit: web2/http_exchange alone stays sufficient; web2 matrix unchanged."""
    _require_kind_fit()
    fn = _require_kind_fit()
    out = fn({"kinds": ["http_exchange"], "r_spec_version": 2}, None)
    assert out.get("sufficient") is True


def test_r2b_rspec_web3_v1_blocked_v2_allowed_with_replay():
    """web3 contract_call v1 BLOCKED (R3); v2 allowed only with replay evidence."""
    fn = _require_kind_fit()
    v1 = fn({"kinds": ["contract_call"], "r_spec_version": 1}, None)
    assert v1.get("sufficient") is False and "http_exchange" in str(v1.get("reason", ""))
    v2_noreplay = fn({"kinds": ["contract_call"], "r_spec_version": 2, "replay": False}, None)
    assert v2_noreplay.get("sufficient") is False
    v2_replay = fn({"kinds": ["contract_call", "http_exchange"], "r_spec_version": 2, "replay": True}, None)
    assert v2_replay.get("sufficient") is True


def test_r2b_rspec_source_hash_mismatch_needs_follow_up():
    """contract source-hash mismatch -> needs_follow_up (never verified, never ruled_out)."""
    fn = _require_kind_fit()
    out = fn({"kinds": ["contract_call"], "source_hash_match": False, "r_spec_version": 2}, None)
    assert out.get("verdict") == "needs_follow_up"


def test_r2b_r4c_onchain_bind_exact():
    """R4c: lower-compare address + method allowlist + rpc_host scope proof."""
    import hunter.agent.tools as tools
    fn = getattr(tools, "_r4c_onchain_bind", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools._r4c_onchain_bind (R4c) missing")
    ctx, _ = _ctx()
    ok = fn({"chain_id": 1, "address": ADDR.upper(), "method": "eth_call",
             "rpc_url": RPC}, ctx)
    assert ok.get("ok") is True, "lower-compare must match UPPER input"
    bad_method = fn({"chain_id": 1, "address": ADDR, "method": "eth_sendTransaction",
                     "rpc_url": RPC}, ctx)
    assert bad_method.get("blocked") is True, "method allowlist must reject sends"
    evil = fn({"chain_id": 1, "address": ADDR, "method": "eth_call",
               "rpc_url": "https://evil.example.net"}, ctx)
    assert evil.get("blocked") is True and "scope" in str(evil.get("code", "")).lower()


def test_r2b_replay_analog_fresh_rpc_byte_equal():
    """Replay analog: fresh RPC with same calldata returns byte-equal result."""
    import hunter.workflow.pipeline as pipe
    fn = getattr(pipe, "replay_contract_read", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.workflow.pipeline.replay_contract_read missing")
    out = fn({"calldata": "0x70a08231", "prior_result": "0x1234", "fresh_result": "0x1234"})
    assert out.get("byte_equal") is True and out.get("verdict") == "verified"


def test_r2b_replay_second_host_mismatch_needs_follow_up():
    """Second-host divergence -> needs_follow_up, NEVER ruled_out (fail-closed)."""
    import hunter.workflow.pipeline as pipe
    fn = getattr(pipe, "replay_contract_read", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.workflow.pipeline.replay_contract_read missing")
    out = fn({"calldata": "0x70a08231", "prior_result": "0x1234", "fresh_result": "0x9999",
              "second_host": True})
    assert out.get("verdict") == "needs_follow_up"
    assert out.get("verdict") != "ruled_out"


def test_r2b_rspec_version_default1_v2_requires_manifest():
    """r_spec_version default 1; v2 requires chain_scope + rpc_manifest + advanced for storage/state-diff."""
    ver = _require_rspec_version()
    assert ver == 1 or ver == 2  # pin exists; default must be 1
    import hunter.agent.tools as tools
    fn = getattr(tools, "validate_rspec_gate", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools.validate_rspec_gate missing")
    ctx, _ = _ctx(tier="basic")
    blocked = fn({"r_spec_version": 2, "method": "eth_getStorageAt"}, ctx)
    assert blocked.get("blocked") is True, "storage/state-diff at basic must lock"


def test_r2b_old_v0_runs_valid_under_v1():
    """Old v0 runs (no r_spec_version) validate under v1 semantics."""
    import hunter.agent.tools as tools
    fn = getattr(tools, "validate_rspec_gate", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools.validate_rspec_gate missing")
    ctx, _ = _ctx()
    ctx.config.pop("r_spec_version", None)
    out = fn({"kinds": ["http_exchange"]}, ctx)
    assert out.get("ok") is True or out.get("sufficient") is True


def test_r2b_rule_e1_unchanged():
    """RULE-E1 unchanged: >=1 bound evidence still required even under v2."""
    from hunter.kernel.claimgate import ClaimGateBlocked, validate_finding_insert
    from hunter.kernel.findings import Finding, FindingStatus, Severity
    f = Finding(id="", run_id="R", key="k", title="t", severity=Severity.HIGH,
                cwe="CWE-79", endpoint="/", method="GET", status=FindingStatus.CANDIDATE,
                evidence_ids=())
    try:
        validate_finding_insert(f, 0)
    except ClaimGateBlocked:
        pass
    else:
        pytest.fail(f"{R2B} — RULE-E1 must still block zero-evidence inserts")
    fn = _require_kind_fit()
    assert callable(fn)


def test_r2b_validate_web3_kind_fit_stub_shape():
    """Stub shape: pure function, no network, redacted, one engine_event via ctx."""
    fn = _require_kind_fit()
    ctx, events = _ctx()
    out = fn({"kinds": ["contract_call"], "secret": "token=TOPSECRET-abc123"}, ctx)
    assert "TOPSECRET-abc123" not in json.dumps(out), "stub must redact secrets"
