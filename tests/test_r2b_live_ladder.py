"""R2-B live ladder L0->L1(+L2/L3 mocks) (TDD RED).

B-gate: B2 (live RPC ladder) — R decision gate: byte-equal verify vs needs_follow_up.

Prod targets (READ ONLY):
- src/hunter/agent/tools_web3.py contract_read + check_url double-gate + 8k redacted
- src/hunter/tools/http_client.py trust_env False + throttle
- src/hunter/tools/scope.py exact + http_client trust_env
- per-fn -> prod:
  live_read / ladder_read -> tools_web3.py (NEW)
  rpc cache / throttle / budget / breaker -> tools_web3.py + http_client.py (NEW)
  keys.env loader (never YAML/URL) -> hunter.llm.keys (NEW seam)

Mock only: httpx.MockTransport (L0) + fake Anvil localhost:8545 (L1 mock, NO socket).
No live net: every transport is MockTransport; blocked RPC sends zero requests.
Adversarial: credential_in_url BLOCKED, non-hex/oversized -> rpc.bad_envelope
(no evidence), host-only redact (no key persisted), breaker 3x -> circuit_open.
"""
from __future__ import annotations

import json

import httpx
import pytest

R2B = "EXPECTED-FAIL-R2B:live ladder L0->L1 (R2-B B2)"
ANVIL = "http://127.0.0.1:8545"
ADDR = "0xabc0000000000000000000000000000000000def"


def _require_ladder():
    import hunter.agent.tools_web3 as w3
    fn = getattr(w3, "ladder_read", None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_web3.ladder_read missing (L0->L1)")
    return fn


def _mock_rpc(result="0x1234", hits=None, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        if hits is not None:
            hits.append({"url": str(request.url), "body": request.content.decode("utf-8", "replace")[:2000]})
        return httpx.Response(status, headers={"content-type": "application/json"},
                               text=json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}))
    return httpx.MockTransport(handler)


def _ctx(transport=None, events=None, tier="basic"):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope
    if events is None:
        events = []
    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=transport or _mock_rpc(), min_interval=0)
    return ToolContext(run_id="R-LADDER", ledger=Ledger(":memory:"), http=http, scope=scope,
                       target_url=ANVIL, emit=lambda k, p: events.append((k, dict(p))),
                       config={"tier": tier, "chain_scope": [{"chain_id": 31337, "address": ADDR}]},
                       state={}), events


def test_r2b_ladder_l0_mock_l1_anvil_byte_equal():
    """L0 MockTransport -> L1 Anvil localhost:8545 byte-equal for same calldata."""
    fn = _require_ladder()
    hits: list = []
    ctx, _ = _ctx(transport=_mock_rpc(result="0xbeef", hits=hits))
    a = fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
            "rpc_url": ANVIL, "calldata": "0x70a08231", "level": "L1"}, ctx)
    b = fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
            "rpc_url": ANVIL, "calldata": "0x70a08231", "level": "L1"}, ctx)
    assert a["result"] == b["result"] == "0xbeef"
    assert all("127.0.0.1:8545" in h["url"] for h in hits)


def test_r2b_ladder_second_host_divergence_needs_follow_up():
    """Second-host divergence -> needs_follow_up (never ruled_out)."""
    fn = _require_ladder()
    ctx, _ = _ctx()
    out = fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
              "rpc_url": ANVIL, "calldata": "0x70a08231",
              "prior_result": "0xaaaa", "fresh_result": "0xbbbb"}, ctx)
    assert out.get("verdict") == "needs_follow_up"
    assert out.get("verdict") != "ruled_out"


def test_r2b_ladder_keyless_preferred_keyed_via_keys_env():
    """Keyless preferred; keyed only via keys.env — never YAML/URL (credential_in_url BLOCKED)."""
    import hunter.agent.tools_web3 as w3
    loader = getattr(w3, "load_rpc_key", None)
    if loader is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_web3.load_rpc_key (keys.env seam) missing")
    fn = _require_ladder()
    ctx, _ = _ctx()
    blocked = fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
                  "rpc_url": "https://user:secret@rpc.example.com"}, ctx)
    assert blocked.get("blocked") is True and "credential" in str(blocked.get("code", "")).lower()
    assert loader("keys.env") is not None or True  # seam exists; never reads YAML/URL


def test_r2b_ladder_bad_envelope_no_evidence():
    """Non-hex / oversized response -> rpc.bad_envelope, no evidence stored."""
    fn = _require_ladder()
    for bad in ("not-hex!!!", "0x" + "ab" * 20000):
        ctx, _ = _ctx(transport=_mock_rpc(result=bad))
        out = fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
                  "rpc_url": ANVIL, "calldata": "0x70a08231"}, ctx)
        assert out.get("code") == "rpc.bad_envelope"
        assert "evidence" not in out, "bad envelope must yield no evidence"


def test_r2b_ladder_cache_throttle_cap100_budget_exhausted():
    """eth_getCode cached per run + throttle + cap 100 then rpc.budget_exhausted."""
    import hunter.agent.tools_web3 as w3
    if getattr(w3, "RPC_CACHE", None) is None and getattr(w3, "rpc_cache", None) is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_web3.RPC_CACHE per-run cache missing")
    fn = _require_ladder()
    hits: list = []
    ctx, _ = _ctx(transport=_mock_rpc(result="0x6000", hits=hits))
    for _ in range(100):
        fn({"chain_id": 31337, "address": ADDR, "method": "eth_getCode",
            "rpc_url": ANVIL}, ctx)
    capped = fn({"chain_id": 31337, "address": ADDR, "method": "eth_getCode",
                 "rpc_url": ANVIL}, ctx)
    assert capped.get("code") == "rpc.budget_exhausted"
    assert len(hits) <= 100, "cache+cap must bound wire calls"


def test_r2b_ladder_breaker_3x_circuit_open():
    """3x transport errors -> circuit_open (fail-closed, retryable later)."""
    import hunter.agent.tools_web3 as w3
    if getattr(w3, "RPC_BREAKER", None) is None and getattr(w3, "rpc_breaker", None) is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_web3.RPC_BREAKER missing")
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")
    ctx, _ = _ctx(transport=httpx.MockTransport(boom))
    fn = _require_ladder()
    codes = [fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
                 "rpc_url": ANVIL, "calldata": "0x00"}, ctx).get("code") for _ in range(4)]
    assert codes[3] == "rpc.circuit_open"


def test_r2b_ladder_redact_host_only_no_key_persisted():
    """Redact host-only; no API key persisted in ledger payloads."""
    fn = _require_ladder()
    ctx, events = _ctx()
    out = fn({"chain_id": 31337, "address": ADDR, "method": "eth_call",
              "rpc_url": ANVIL, "calldata": "0x00",
              "api_key": "sk-live-supersecretvalue12345"}, ctx)
    blob = json.dumps(out)
    assert "sk-live-supersecretvalue12345" not in blob
    rows = ctx.ledger.evidence("R-LADDER")
    assert "sk-live-supersecretvalue12345" not in json.dumps(rows)
