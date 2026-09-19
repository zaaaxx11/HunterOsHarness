"""R2-B heavy tools opt-in: slither/cast/anvil (TDD RED).

B-gate: B3 (heavy opt-in) — R decision gate: unavailable vs approval-gated run.

Prod targets (READ ONLY):
- src/hunter/agent/inventory.py:19-62 + runtime_inventory (pinned 15, append-only)
- src/hunter/agent/tools_web3.py register_unavailable slither/cast (same message pin)
- src/hunter/agent/approval.py catastrophic/TTL300/single-use
- per-fn -> prod:
  INVENTORY_BINARIES (+slither/cast/anvil) -> inventory.py (append-only, order preserved)
  slither_audit -> NEW heavy module (danger approval, advanced, jailed shell argv)
  cast_call -> NEW heavy module (readonly basic, manifest host, budget+redact)
  cast send/tx/publish -> NEVER registered (negative)

Mock only: which_fn seams, MockTransport, tmp ApprovalStore/Ledger. No binaries run.
Adversarial: static-only no exec (slither never executes chain data), hash-verified
input, 8k redacted, one engine_event, no widen, no socket beyond manifest host.
"""
from __future__ import annotations

import json

import httpx
import pytest

R2B = "EXPECTED-FAIL-R2B:heavy opt-in slither/cast/anvil (R2-B B3)"


def _require_inventory_append():
    import hunter.agent.inventory as inv
    missing = [b for b in ("slither", "cast", "anvil") if b not in inv.INVENTORY_BINARIES]
    if missing:
        pytest.fail(
            f"{R2B} — inventory missing append-only {missing}; "
            f"INVENTORY_BINARIES={inv.INVENTORY_BINARIES}"
        )
    return inv


def _require_heavy(name: str):
    for mod in ("hunter.agent.tools_heavy", "hunter.agent.tools_web3"):
        try:
            m = __import__(mod, fromlist=["x"])
        except ImportError:
            continue
        fn = getattr(m, name, None)
        if fn is not None:
            return fn
    pytest.fail(f"{R2B} — heavy tool {name!r} missing (slither_audit/cast_call)")


def _ctx(events=None, tier="advanced", transport=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet
    if events is None:
        events = []
    def _ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="0x1234")
    scope = ScopeSet(frozenset({"rpc.example.com"}), name="r2b-heavy")
    http = ScopedHttpClient(scope, transport=transport or httpx.MockTransport(_ok), min_interval=0)
    return ToolContext(run_id="R-HEAVY", ledger=Ledger(":memory:"), http=http, scope=scope,
                       target_url="http://rpc.example.com/", emit=lambda k, p: events.append((k, dict(p))),
                       config={"tier": tier, "jail": "/tmp/jail-r2b"}, state={}), events


def test_r2b_inventory_append_preserves_order():
    """Inventory append-only: pinned 15 first in order, then slither/cast/anvil."""
    inv = _require_inventory_append()
    assert inv.INVENTORY_BINARIES[:15] == (
        "curl", "wget", "nmap", "sqlmap", "nuclei", "ffuf", "dig", "nslookup",
        "whois", "whatweb", "gobuster", "masscan", "testssl", "openssl", "httpx",
    )
    tail = inv.INVENTORY_BINARIES[15:]
    assert tail == tuple(sorted(tail)) or set(tail) >= {"slither", "cast", "anvil"}
    found = inv.inventory_binaries(which_fn=lambda _n: None)
    assert set(found) == {"available", "missing", "platform"}
    assert found["available"] == {}


def test_r2b_heavy_missing_register_unavailable_same_message():
    """Missing binaries -> register_unavailable with the SAME install-hint message."""
    import hunter.agent.tools_web3 as w3
    from hunter.agent.tools_base import ToolRegistry
    reg = ToolRegistry()
    w3.register_web3_tools(reg)
    for name in ("slither_hint", "cast_hint"):
        out = reg.dispatch(name, {}, _ctx()[0])
        assert out.blocked and out.code == "tool.unavailable"
    _require_inventory_append()
    _require_heavy("slither_audit")


def test_r2b_slither_audit_danger_approval_advanced():
    """slither_audit: danger approval, advanced, jailed argv, hash-verified input, 8k redacted."""
    fn = _require_heavy("slither_audit")
    import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
    assert getattr(heavy, "SLITHER_AUDIT_SPEC", {}).get("danger") == "approval"
    assert getattr(heavy, "SLITHER_AUDIT_SPEC", {}).get("min_tier") == "advanced"
    ctx, events = _ctx()
    out = fn({"path": "contracts/Vault.sol", "source_sha256": "0" * 64,
              "secret_note": "token=TOPSECRET-abc123"}, ctx)
    assert "TOPSECRET-abc123" not in json.dumps(out), "8k redacted"
    assert len(json.dumps(out.get("evidence", {}).get("data", {}))) <= 8192 + 256
    assert sum(1 for k, p in events if k == "engine_event" and p.get("tool") == "slither_audit") == 1
    assert out.get("executed_chain_data") is not True and "exec" not in str(out.get("mode", "static")).lower()


def test_r2b_cast_call_readonly_basic():
    """cast_call readonly basic: manifest host, budget + redact, one engine_event."""
    fn = _require_heavy("cast_call")
    import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
    assert getattr(heavy, "CAST_CALL_SPEC", {}).get("danger") == "none"
    assert getattr(heavy, "CAST_CALL_SPEC", {}).get("min_tier") == "basic"
    ctx, events = _ctx(tier="basic")
    out = fn({"chain_id": 1, "address": "0xabc0000000000000000000000000000000000def",
              "calldata": "0x70a08231", "rpc_url": "https://rpc.example.com"}, ctx)
    assert out.get("ok") is True
    assert sum(1 for k, p in events if k == "engine_event") == 1


def test_r2b_cast_send_tx_publish_never_registered():
    """Negative: cast send/tx/publish verbs are NEVER registered as tools."""
    try:
        import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
        names = set(getattr(heavy, "SPEC_NAMES", ()))
    except ImportError:
        pytest.fail(f"{R2B} — hunter.agent.tools_heavy missing; cannot prove send-negative")
    for evil in ("cast_send", "cast_publish", "cast_tx", "eth_sendTransaction", "sendTransaction"):
        assert evil not in names, f"{evil} must never be registered"


def test_r2b_runtime_inventory_reflects_heavy():
    """runtime_inventory reflects slither/cast/anvil via which_fn seam (no exec)."""
    _require_inventory_append()
    from hunter.agent.tools import build_registry
    ctx, events = _ctx()
    out = build_registry("basic").dispatch("runtime_inventory", {}, ctx)
    assert out.ok is True
    payload = json.loads(out.result_for_model)
    assert "slither" in str(payload) or "cast" in str(payload) or "anvil" in str(payload)
