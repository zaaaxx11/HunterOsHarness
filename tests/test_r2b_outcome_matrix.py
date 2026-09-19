"""R2-B 5-outcome matrix: generator registry subset + spot checks (TDD RED).

B-gate: B1-B5 matrix (cross-cutting) — R decision gate: every R2B tool honors
success / blocked / unavailable / redacted / truncated.

Prod targets (READ ONLY, do NOT edit):
- src/hunter/agent/tools_web3.py OUTCOME_TABLE (pinned 3, R2B extends +ladder_read)
- src/hunter/agent/tools_patch.py OUTCOME_TABLE (pinned patch_write)
- src/hunter/agent/tools_local.py + tools_network.py OUTCOME_TABLE (pinned)
- per-fn -> prod:
  OUTCOME_TABLE (+ladder_read/slither_audit/cast_call) -> tools_web3.py / tools_heavy.py (NEW rows)
  iter_tool_specs generator -> tools_heavy.py (NEW generator, registry subset)
  spot redacted/truncated/unavailable -> tools_heavy.py + tools_web3.py (NEW bounds)

All tests FAIL today via EXPECTED-FAIL-R2B until the R2B matrix lands.
Mock only: httpx.MockTransport, tmp_path jail, :memory: Ledger, no live net/binaries.
Adversarial: secret redact (stored + model), 8k/16k truncation markers, missing
binary -> tool.unavailable (no exec), one engine_event even on error, negatives.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

R2B = "EXPECTED-FAIL-R2B:5-outcome matrix generator subset (R2-B matrix)"
FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")


def _require_heavy_table():
    try:
        import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{R2B} — hunter.agent.tools_heavy missing (OUTCOME_TABLE + generator)")
    table = getattr(heavy, "OUTCOME_TABLE", None)
    if table is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_heavy.OUTCOME_TABLE missing")
    return heavy, table


def _require_web3_ladder_row():
    import hunter.agent.tools_web3 as w3

    table = getattr(w3, "OUTCOME_TABLE", {})
    if "ladder_read" not in table:
        pytest.fail(f"{R2B} — tools_web3.OUTCOME_TABLE lacks ladder_read row (subset)")
    return w3, table


def _require_generator():
    try:
        import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{R2B} — hunter.agent.tools_heavy missing; cannot prove generator subset")
    gen = getattr(heavy, "iter_tool_specs", None)
    if gen is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_heavy.iter_tool_specs generator missing")
    return heavy, gen


def _ctx(events=None, tier="advanced", transport=None, jail=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    if transport is None:
        def _ok(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="0x1234")
        transport = httpx.MockTransport(_ok)
    scope = ScopeSet(frozenset({"rpc.example.com"}), name="r2b-matrix")
    http = ScopedHttpClient(scope, transport=transport, min_interval=0)
    config: dict[str, Any] = {"tier": tier, "jail": str(jail) if jail else "/tmp/jail-r2b"}
    return ToolContext(run_id="R-MATRIX", ledger=Ledger(":memory:"), http=http, scope=scope,
                       target_url="http://rpc.example.com/", emit=lambda k, p: events.append((k, dict(p))),
                       config=config, state={}), events


def test_r2b_matrix_heavy_outcome_table_five():
    """Heavy OUTCOME_TABLE: slither_audit + cast_call each document all five outcomes."""
    _, table = _require_heavy_table()
    missing: list[str] = []
    for tool in ("slither_audit", "cast_call"):
        outcomes = set(table.get(tool, ()))
        if not set(FIVE) <= outcomes:
            missing.append(f"{tool} outcomes={sorted(outcomes)}")
    if missing:
        pytest.fail(f"{R2B}: missing five-outcome coverage: {missing}")


def test_r2b_matrix_web3_ladder_outcome_row():
    """Web3 OUTCOME_TABLE subset: ladder_read row exists with all five outcomes."""
    _, table = _require_web3_ladder_row()
    outcomes = set(table.get("ladder_read", ()))
    assert set(FIVE) <= outcomes, f"ladder_read outcomes={sorted(outcomes)}"


def test_r2b_matrix_generator_registry_subset():
    """Generator registry subset: iter_tool_specs yields exactly the OUTCOME_TABLE keys."""
    heavy, gen = _require_generator()
    _, table = _require_heavy_table()
    yielded = [name for name, _spec in gen()]
    assert set(yielded) == set(table.keys()), "generator must stay in subset lockstep with OUTCOME_TABLE"
    assert set(yielded) >= {"slither_audit", "cast_call"}
    names = set(getattr(heavy, "SPEC_NAMES", yielded))
    for evil in ("cast_send", "cast_publish", "cast_tx", "eth_sendTransaction"):
        assert evil not in names, f"{evil} must never appear in the generator subset"


def test_r2b_matrix_spot_redacted(tmp_path):
    """Spot redacted: secret-shaped input never reaches model text or ledger storage."""
    try:
        import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
        fn = getattr(heavy, "slither_audit", None)
    except ImportError:
        pytest.fail(f"{R2B} — tools_heavy.slither_audit missing for redact spot")
    if fn is None:
        pytest.fail(f"{R2B} — tools_heavy.slither_audit missing for redact spot")
    ctx, _ = _ctx(jail=tmp_path)
    out = fn({"path": "contracts/Vault.sol", "source_sha256": "0" * 64,
              "secret_note": "token=TOPSECRET-abc123"}, ctx)
    assert "TOPSECRET-abc123" not in json.dumps(out)
    rows = ctx.ledger.evidence("R-MATRIX")
    assert "TOPSECRET-abc123" not in json.dumps(rows)


def test_r2b_matrix_spot_truncated():
    """Spot truncated: oversized evidence bounded with truncation marker."""
    try:
        import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
        fn = getattr(heavy, "cast_call", None)
    except ImportError:
        pytest.fail(f"{R2B} — tools_heavy.cast_call missing for truncate spot")
    if fn is None:
        pytest.fail(f"{R2B} — tools_heavy.cast_call missing for truncate spot")
    big = "0x" + "ab" * 9000

    def _big(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=big)

    ctx, _ = _ctx(transport=httpx.MockTransport(_big))
    out = fn({"chain_id": 1, "address": "0xabc0000000000000000000000000000000000def",
              "calldata": "0x70a08231", "rpc_url": "https://rpc.example.com"}, ctx)
    blob = json.dumps(out.get("evidence", {}).get("data", out))
    assert len(blob) <= 8192 + 256, "R2B evidence bounded at 8k"
    assert "truncat" in json.dumps(out).lower()


def test_r2b_matrix_spot_unavailable():
    """Spot unavailable: missing binary -> tool.unavailable (no exec, same hint shape)."""
    import hunter.agent.tools_web3 as w3
    from hunter.agent.tools_base import ToolRegistry

    reg = ToolRegistry()
    w3.register_web3_tools(reg)
    for name in ("slither_hint", "cast_hint"):
        out = reg.dispatch(name, {}, _ctx()[0])
        assert out.blocked and out.code == "tool.unavailable"
        assert "install" in out.result_for_model.lower()
    # Heavy generator must also surface unavailable (not success) when which_fn misses.
    _, table = _require_heavy_table()
    assert "unavailable" in table.get("slither_audit", ()) and "unavailable" in table.get("cast_call", ())


def test_r2b_matrix_every_handler_one_engine_event(tmp_path):
    """Every R2B handler emits exactly one engine_event, even on error paths."""
    try:
        import hunter.agent.tools_heavy as heavy  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{R2B} — tools_heavy missing for engine_event spot")
    for tool in ("slither_audit", "cast_call"):
        fn = getattr(heavy, tool, None)
        if fn is None:
            pytest.fail(f"{R2B} — tools_heavy.{tool} missing for engine_event spot")
        ctx, events = _ctx(jail=tmp_path)
        fn({"path": "x", "bogus": True} if tool == "slither_audit" else
           {"chain_id": 999, "address": "0x0", "rpc_url": "https://evil.example.net"}, ctx)
        assert sum(1 for k, p in events if k == "engine_event" and p.get("tool") == tool) == 1, tool


def test_r2b_matrix_no_live_net_transport_guard():
    """Meta-guard: matrix harness uses MockTransport only (blocked RPC sends zero requests)."""
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(str(request.url))
        return httpx.Response(200, text="ok")

    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    scope = ScopeSet(frozenset({"example.com"}), name="r2b-matrix-guard")
    client = ScopedHttpClient(scope, transport=httpx.MockTransport(handler))
    assert client.request("GET", "http://example.com/").status == 200
    assert hits == ["http://example.com/"]
    client.close()
    _require_generator()
