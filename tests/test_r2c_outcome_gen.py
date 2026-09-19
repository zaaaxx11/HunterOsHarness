"""R2-C outcome-matrix generator (TDD RED — EXPECTED-FAIL-R2C).

Prod targets (READ ONLY, do NOT edit):
- hunter.agent.outcome_gen (NEW): OUTCOME_TABLE + iter_tool_specs generator
- hunter.agent.tools_web3/tools_patch/tools_local/tools_network OUTCOME_TABLE rows
- per-fn -> prod:
  registry x FIVE missing fail -> hunter.agent.outcome_gen.OUTCOME_TABLE
  success +1 / blocked zero -> outcome_gen.emit_cell ledger counts
  unavailable advisory -> outcome_gen.unavailable_hint
  redacted absent -> stored + model text lack the secret
  truncated marker -> 8k bound + truncat marker
  unknown + catastrophic once -> exactly one engine_event each

TDD red: EXPECTED-FAIL-R2C until the generator lands.
Mock only: MockTransport, tmp jail, :memory: Ledger. No sockets/sleep.
Adversarial: pin FIVE shapes; count ledger evidence only; seeded ids.
"""
from __future__ import annotations

import json

import httpx
import pytest

R2C = "EXPECTED-FAIL-R2C:outcome generator (R2-C matrix)"
FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")


def _require_gen():
    try:
        import hunter.agent.outcome_gen as gen  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen missing (OUTCOME_TABLE + generator)")
    table = getattr(gen, "OUTCOME_TABLE", None)
    it = getattr(gen, "iter_tool_specs", None)
    if table is None or it is None:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen.OUTCOME_TABLE/iter_tool_specs missing")
    return gen, table, it


def _mock(text="ok", status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=text)

    return httpx.MockTransport(handler)


def _ctx(events=None, tier="advanced", transport=None, jail=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    scope = ScopeSet(frozenset({"example.com"}), name="r2c-matrix")
    http = ScopedHttpClient(scope, transport=transport or _mock(), min_interval=0)
    config: dict = {"tier": tier, "jail": str(jail) if jail else "/tmp/jail-r2c"}
    return ToolContext(run_id="R-R2C", ledger=Ledger(":memory:"), http=http, scope=scope,
                       target_url="http://example.com/", emit=lambda k, p: events.append((k, dict(p))),
                       config=config, state={}), events


def test_r2c_gen_registry_x_five_missing_fail():
    """Registry x FIVE: every tool documents all five outcomes, else fail."""
    _, table, it = _require_gen()
    yielded = [name for name, _ in it()]
    assert set(yielded) == set(table.keys()), "generator stays in lockstep with OUTCOME_TABLE"
    missing = [t for t, outs in table.items() if not set(FIVE) <= set(outs)]
    assert missing == [], f"{R2C} missing five-outcome coverage: {missing}"


def test_r2c_gen_success_plus_one(tmp_path):
    """Success cell persists exactly +1 evidence row for the cell."""
    gen, _, _ = _require_gen()
    fn = getattr(gen, "emit_cell", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen.emit_cell missing")
    ctx, _ = _ctx(jail=tmp_path)
    before = len(ctx.ledger.evidence("R-R2C"))
    fn("tool-a", "success", {"note": "ok EV-00ab"}, ctx)
    assert len(ctx.ledger.evidence("R-R2C")) - before == 1


def test_r2c_gen_blocked_zero(tmp_path):
    """Blocked cell persists zero evidence rows (refusal holds no truth)."""
    gen, _, _ = _require_gen()
    fn = getattr(gen, "emit_cell", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen.emit_cell missing")
    ctx, _ = _ctx(jail=tmp_path)
    before = len(ctx.ledger.evidence("R-R2C"))
    fn("tool-a", "blocked", {"reason": "scope"}, ctx)
    assert len(ctx.ledger.evidence("R-R2C")) - before == 0


def test_r2c_gen_unavailable_advisory(tmp_path):
    """Unavailable cell returns advisory hint (install-shaped), never success."""
    gen, _, _ = _require_gen()
    fn = getattr(gen, "emit_cell", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen.emit_cell missing")
    ctx, _ = _ctx(jail=tmp_path)
    out = fn("tool-a", "unavailable", {}, ctx)
    assert "install" in json.dumps(out).lower()


def test_r2c_gen_redacted_absent(tmp_path):
    """Redacted cell: secret absent from model text and ledger storage."""
    gen, _, _ = _require_gen()
    fn = getattr(gen, "emit_cell", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen.emit_cell missing")
    ctx, _ = _ctx(jail=tmp_path)
    out = fn("tool-a", "redacted", {"secret_note": "token=TOPSECRET-abc123"}, ctx)
    assert "TOPSECRET-abc123" not in json.dumps(out)
    assert "TOPSECRET-abc123" not in json.dumps(ctx.ledger.evidence("R-R2C"))


def test_r2c_gen_truncated_marker(tmp_path):
    """Truncated cell: 8k bound with truncat marker."""
    gen, _, _ = _require_gen()
    fn = getattr(gen, "emit_cell", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.agent.outcome_gen.emit_cell missing")
    ctx, _ = _ctx(jail=tmp_path)
    out = fn("tool-a", "truncated", {"blob": "0x" + "ab" * 9000}, ctx)
    blob = json.dumps(out.get("evidence", {}).get("data", out))
    assert len(blob) <= 8192 + 256
    assert "truncat" in json.dumps(out).lower()


def test_r2c_gen_unknown_catastrophic_once(tmp_path):
    """Unknown tool + catastrophic command each emit exactly one engine_event."""
    gen, _, _ = _require_gen()
    for tool, args in (("no-such-tool-xyz", {}), ("shell", {"command": "rm -rf /"})):
        fn = getattr(gen, "emit_cell", None)
        if fn is None:
            pytest.fail(f"{R2C} — hunter.agent.outcome_gen.emit_cell missing")
        ctx, events = _ctx(jail=tmp_path)
        fn(tool, "blocked", args, ctx)
        assert sum(1 for k, _p in events if k == "engine_event") == 1, tool
