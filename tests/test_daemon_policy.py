"""§10 RED: kebijakan daemon Q1 BOLEH AUTO.

Q1 FINAL: readonly luar MAY auto-allow (daemon convenience). Prod kini
(Opsi B) masih gate luar-readonly -> approval.required = RED.
Builder GREEN: gate auto_allow=True + readonly -> None walau path luar;
catastrophic tetap approval.catastrophic tanpa confirm/auto.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from hunter.agent.approval import ApprovalStore, classify_shell_command, make_approval_gate
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope


def _ctx(tmp_path: Path, run_id: str, surface: str, auto_allow: bool):
    ledger = Ledger(tmp_path / "ledger.db")
    with suppress(Exception):
        ledger.create_run(run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
    http = ScopedHttpClient(localhost_scope(), min_interval=0)
    jail = tmp_path / "jail"
    jail.mkdir(parents=True, exist_ok=True)
    store = ApprovalStore(tmp_path / "approvals")
    gate = make_approval_gate(store, ledger=ledger, run_id=run_id,
                              auto_allow=auto_allow, confirm_fn=None, surface=surface)
    ctx = ToolContext(run_id=run_id, ledger=ledger, http=http, scope=localhost_scope(),
                      target_url="http://127.0.0.1/", emit=lambda k, p: None,
                      config={"tier": "advanced", "state_dir": str(jail),
                              "approval_gate": gate})
    return ledger, http, store, ctx, jail


def test_readonly_outside_auto_ok(tmp_path):
    """RED kini: daemon auto + readonly luar wajib gate None (Q1)."""
    ledger, http, _s, ctx, _j = _ctx(tmp_path, "R-D1", "daemon", True)
    try:
        outside = tmp_path / "luar.txt"
        outside.write_text("x", encoding="utf-8")
        cmd = f"cat {outside.resolve()}"
        assert classify_shell_command(cmd) == "readonly", "syarat: cat luar readonly"
        d = ctx.config["approval_gate"]("shell_exec", {"command": cmd}, ctx)
        assert d is None, f"RED Q1: readonly luar+auto wajib None, dapat {getattr(d, 'code', d)}"
    finally:
        http.close()
        ledger.close()


def test_readonly_inside_auto_ok(tmp_path):
    """Baseline GREEN: readonly dalam + auto wajib None."""
    ledger, http, _s, ctx, jail = _ctx(tmp_path, "R-D2", "daemon", True)
    try:
        (jail / "dalam.txt").write_text("ok", encoding="utf-8")
        d = ctx.config["approval_gate"]("shell_exec", {"command": "cat dalam.txt"}, ctx)
        assert d is None, "dalam-jail readonly+auto wajib None"
    finally:
        http.close()
        ledger.close()


def test_catastrophic_never_auto(tmp_path):
    """GREEN: catastrophic + auto tetap approval.catastrophic, confirm kosong."""
    ledger, http, _s, ctx, _j = _ctx(tmp_path, "R-D3", "daemon", True)
    try:
        seen: list[str] = []
        ctx.config["approval_gate"] = make_approval_gate(
            _s, ledger=ledger, run_id="R-D3", auto_allow=True,
            confirm_fn=lambda r: seen.append(r.request_id) or True, surface="daemon")
        d = ctx.config["approval_gate"]("shell_exec", {"command": "rm -rf /"}, ctx)
        assert d is not None and d.code == "approval.catastrophic", f"wajib catastrophic, dapat {d}"
        assert seen == [], "confirm_fn tak boleh dipanggil untuk catastrophic"
    finally:
        http.close()
        ledger.close()
