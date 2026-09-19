"""T4 web3-readonly contracts — contract_read / source / abi_decode / tool hints (TDD red).

Planner B T4: READ-ONLY on-chain audit tools. Sends are never registered.

Production target: ``hunter.agent.tools_web3`` (NEW module to create):
  - ``contract_read``: method enum {eth_call, eth_getCode, eth_getBalance,
    eth_getStorageAt}; on-chain scope = EXACT (chain_id, address) lowercase
    match + RPC URL via scope.check_url; basic tier allows
    eth_call/getCode/getBalance, eth_getStorageAt needs advanced
    (tier.capability_locked); transport over httpx JSON-RPC (NO web3 dep);
    evidence kind contract_call bounded 8k + redacted.
  - ``contract_source_fetch``: explorer-allowlist gate (Etherscan-family only).
  - ``abi_decode_hint``: pure stdlib (no network, no scope needed).
  - ``slither_hint`` / ``cast_hint``: register_unavailable with install hint;
    runtime_inventory reflects the missing binaries.

R-spec gate: contract_call evidence is coverage-only until the R-spec is
amended — it NEVER satisfies R3 http_exchange on its own (asserted below).

Negative asserts: no spec named sendTransaction/sendRawTransaction/eth_send*;
no auto-widening of scope; no ``import web3`` anywhere in the new module.
All tests FAIL today via EXPECTED-FAIL-TDD. RPC is fully mocked (MockTransport).
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import httpx
import pytest

TDD_WEB3 = "EXPECTED-FAIL-TDD:hunter.agent.tools_web3 (Planner B T4: readonly contract tools)"


def _require_web3():
    try:
        import hunter.agent.tools_web3 as web3tools  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(
            f"{TDD_WEB3} — module missing; "
            "create contract_read/contract_source_fetch/abi_decode_hint "
            "+ slither/cast hints"
        )
    return web3tools


def _rpc_transport(result="0x", events=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if events is not None:
            events.append(
                (
                    "rpc",
                    {
                        "url": str(request.url),
                        "body": request.content.decode("utf-8", "replace")[:500],
                    },
                )
            )
        payload = {"jsonrpc": "2.0", "id": 1, "result": result}
        return httpx.Response(200, headers={"content-type": "application/json"}, text=json.dumps(payload))

    return httpx.MockTransport(handler)


def _ctx(rpc_host="rpc.example.com", events=None, tier="basic", transport=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    scope = ScopeSet(frozenset({"rpc.example.com", "api.etherscan.io"}), name="t4")
    http = ScopedHttpClient(scope, transport=transport or _rpc_transport(events=events))
    return ToolContext(
        run_id="R-T4", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://rpc.example.com/", emit=lambda k, p: events.append((k, dict(p))),
        config={
            "tier": tier,
            "chain_scope": [{"chain_id": 1, "address": "0xabc0000000000000000000000000000000000def"}],
        },
        state={},
    ), events


ADDR = "0xabc0000000000000000000000000000000000def"
RPC = "https://rpc.example.com"


# -- scope --------------------------------------------------------------------------

def test_t4_onchain_scope_exact_lowercase():
    """Contract: scope match is EXACT (chain_id, lowercase address);
    case differs -> still match; other addr blocked.
    """
    w3 = _require_web3()
    ctx, _ = _ctx()
    ok = w3.contract_read(
        {"chain_id": 1, "address": ADDR.upper(), "method": "eth_getBalance", "rpc_url": RPC}, ctx
    )
    assert ok["ok"], "address match must be case-insensitive (lowercased compare)"
    blocked = w3.contract_read(
        {
            "chain_id": 1,
            "address": "0x0000000000000000000000000000000000000001",
            "method": "eth_getBalance",
            "rpc_url": RPC,
        },
        ctx,
    )
    assert blocked.get("blocked") is True, "unlisted address must be BLOCKED (no auto-widen)"
    wrong_chain = w3.contract_read(
        {"chain_id": 137, "address": ADDR, "method": "eth_getBalance", "rpc_url": RPC}, ctx
    )
    assert wrong_chain.get("blocked") is True, "wrong chain_id must be BLOCKED"


def test_t4_rpc_url_scope_checked():
    """Contract: RPC URL passes scope.check_url — evil RPC host -> scope BLOCKED, no request sent."""
    w3 = _require_web3()
    events: list = []
    ctx, _ = _ctx(events=events)
    blocked = w3.contract_read(
        {"chain_id": 1, "address": ADDR, "method": "eth_getBalance", "rpc_url": "https://evil-rpc.example.net"},
        ctx,
    )
    assert blocked.get("blocked") is True and blocked.get("code", "").startswith("scope.")
    assert [e for e in events if e[0] == "rpc"] == [], "blocked RPC must send zero requests"


# -- method enum + tiering --------------------------------------------------------------

def test_t4_no_send_methods_registered():
    """Contract (negative): sendTransaction/sendRawTransaction/eth_send* specs must NEVER exist."""
    w3 = _require_web3()
    names = set(w3.SPEC_NAMES if hasattr(w3, "SPEC_NAMES") else [s["name"] for s in w3.SPECS])
    for evil in ("sendTransaction", "sendRawTransaction", "eth_sendTransaction", "eth_sendRawTransaction"):
        assert evil not in names, f"mutating method {evil!r} must never be registered"
    assert "eth_sendTransaction" not in str(getattr(w3, "CONTRACT_READ_METHODS", "")).lower()


def test_t4_basic_vs_advanced_storage_gating():
    """Contract: basic allows eth_call/getCode/getBalance; getStorageAt needs advanced."""
    w3 = _require_web3()
    ctx, _ = _ctx(tier="basic")
    for method in ("eth_call", "eth_getCode", "eth_getBalance"):
        out = w3.contract_read({"chain_id": 1, "address": ADDR, "method": method, "rpc_url": RPC}, ctx)
        assert out["ok"], f"{method} must work at basic tier"
    locked = w3.contract_read(
        {"chain_id": 1, "address": ADDR, "method": "eth_getStorageAt", "rpc_url": RPC}, ctx
    )
    assert locked.get("code") == "tier.capability_locked"
    ctx2, _ = _ctx(tier="advanced")
    assert w3.contract_read(
        {"chain_id": 1, "address": ADDR, "method": "eth_getStorageAt", "rpc_url": RPC}, ctx2
    )["ok"]


def test_t4_httpx_jsonrpc_no_web3_dep():
    """Contract: transport is httpx JSON-RPC; the module must not import web3."""
    w3 = _require_web3()
    source = pathlib.Path(w3.__file__).read_text(encoding="utf-8")
    assert "import web3" not in source and "from web3" not in source, "no web3 dependency allowed"
    events: list = []
    ctx, _ = _ctx(events=events)
    w3.contract_read(
        {"chain_id": 1, "address": ADDR, "method": "eth_call", "rpc_url": RPC, "calldata": "0x70a08231"},
        ctx,
    )
    rpc_calls = [e for e in events if e[0] == "rpc"]
    assert len(rpc_calls) == 1 and '"jsonrpc"' in rpc_calls[0][1]["body"]


def test_t4_contract_call_evidence_bounded_redacted():
    """Contract: evidence kind contract_call, bounded 8k, redacted; coverage-only (never R3)."""
    w3 = _require_web3()
    ctx, _ = _ctx(transport=_rpc_transport(result="0x" + "ab" * 9000))
    out = w3.contract_read({"chain_id": 1, "address": ADDR, "method": "eth_call", "rpc_url": RPC}, ctx)
    assert out["ok"] and out["evidence"]["kind"] == "contract_call"
    blob = json.dumps(out["evidence"]["data"])
    assert len(blob) <= 8_192 + 256, "contract_call evidence bounded at 8k"
    # R-spec gate: contract_call alone must NOT satisfy finding R3.

    assert "contract_call" not in pathlib.Path("src/hunter/agent/tools.py").read_text(
        encoding="utf-8"
    ).split("http_exchange is mandatory")[0][-100:]


def test_t4_source_fetch_explorer_allowlist():
    """Contract: contract_source_fetch only talks to the explorer allowlist via ctx.http."""
    w3 = _require_web3()
    ctx, _ = _ctx()
    blocked = w3.contract_source_fetch(
        {"chain_id": 1, "address": ADDR, "explorer": "https://evil.example.net/api"}, ctx
    )
    assert blocked.get("blocked") is True


def test_t4_abi_decode_hint_pure():
    """Contract: abi_decode_hint is pure stdlib — no network, no scope, deterministic."""
    w3 = _require_web3()
    events: list = []
    ctx, _ = _ctx(events=events)
    out = w3.abi_decode_hint({"sig": "balanceOf(address)", "calldata": "0x70a08231" + "00" * 31 + "01"}, ctx)
    assert out["ok"] and [e for e in events if e[0] == "rpc"] == []


def test_t4_slither_cast_unavailable_with_hint():
    """Contract: slither/cast surface as tool.unavailable + install hint; inventory reflects missing."""
    w3 = _require_web3()
    from hunter.agent.tools_base import ToolContext  # noqa: F401  (seam shape pin)

    registry = w3.build_web3_registry("basic")
    for name in ("slither_hint", "cast_hint"):
        out = registry.dispatch(name, {}, _t4_ctx_for_registry())
        assert out.blocked and out.code == "tool.unavailable"
        assert "install" in out.result_for_model.lower()
    import hunter.agent.inventory as inventory

    found = inventory.inventory_binaries(which_fn=lambda _name: None)
    assert set(found) == {"available", "missing", "platform"}
    assert found["available"] == {} and set(found["missing"]) == set(inventory.INVENTORY_BINARIES)


def _t4_ctx_for_registry() -> Any:
    ctx, _ = _ctx()
    return ctx
