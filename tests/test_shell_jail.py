"""Shell jail — Opsi B LONGAR/GATED (TDD STEP 2, NO src/ changes).

Opsi B FINAL: argv di luar state_dir TIDAK auto-allow, wajib GATED
(approval-required, explicit /approve), bukan silent-deny.
Di dalam jail tetap allowed. Daemon auto_allow=True tetap wajib gate.

Harapan: 4 gated RED kini (gate kini return None/auto-allow untuk luar),
1 positif GREEN. Builder green-kan dengan membuat gate jail-aware:
nonaktifkan auto_allow saat argv resolve ke luar state_dir.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from hunter.agent.approval import ApprovalStore, classify_shell_command, make_approval_gate
from hunter.agent.tools import _SHELL_OUTPUT_LIMIT, _shell_cwd, build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

PY = sys.executable.replace("\\", "/")
SECRET = "jail-outside-secret-xyz"


def py_command(code: str) -> str:
    return f'"{PY}" -c "{code}"'


@pytest.fixture()
def shell(tmp_path):
    jail = tmp_path / "jail"
    (jail / "subdir").mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside_secret.txt"
    outside.write_text(SECRET, encoding="utf-8")
    run_id = "R-JAIL"
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run(run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)

    def emit(kind: str, payload: dict[str, Any]) -> None:
        ledger.append(run_id, kind, dict(payload))

    store = ApprovalStore(tmp_path / "approvals")
    gate = make_approval_gate(
        store, ledger=ledger, run_id=run_id,
        auto_allow=True, confirm_fn=lambda _request: True, surface="repl",
    )
    ctx = ToolContext(
        run_id=run_id, ledger=ledger, http=http, scope=scope,
        target_url="http://127.0.0.1/", emit=emit,
        config={"tier": "advanced", "state_dir": str(jail), "approval_gate": gate},
    )
    try:
        yield {"ctx": ctx, "jail": jail, "root": tmp_path, "outside": outside,
               "store": store, "ledger": ledger, "run_id": run_id}
    finally:
        http.close()
        ledger.close()


def _strict_gate(shell, surface="repl"):
    """Gate Opsi B probe: auto_allow=True TANPA confirm_fn -> gated wajib blocked."""
    return make_approval_gate(
        shell["store"], ledger=shell["ledger"], run_id=shell["run_id"],
        auto_allow=True, confirm_fn=None, surface=surface,
    )


def _assert_gated(decision, cmd: str):
    assert decision is not None, (
        f"Opsi B: {cmd!r} luar-jail wajib GATED (blocked), bukan None"
    )
    assert decision.blocked is True, f"Opsi B: {cmd!r} wajib blocked=True (approval-required)"
    assert "approval" in decision.code, f"Opsi B: {cmd!r} code wajib approval.* (got {decision.code})"


def test_cat_absolute_should_be_gated(shell):
    """Opsi B (RED kini): `cat <abs-luar>` + varian bypass wajib GATED."""
    abs_posix = str(shell["outside"].resolve()).replace("\\", "/")
    win_abs = str(shell["outside"].resolve()).replace("/", "\\")
    variants = (
        f"cat {abs_posix}",          # absolut posix
        f"cat    {abs_posix}  ",      # ADVERSARIAL: spasi-ekstra
        f"cat {win_abs}",            # ADVERSARIAL: C:\\ absolut Windows
    )
    for variant in variants:
        assert classify_shell_command(variant) == "readonly", f"syarat: {variant!r} kini readonly"
        decision = _strict_gate(shell)(("shell_exec"), {"command": variant}, shell["ctx"])
        _assert_gated(decision, variant)


def test_dotdot_should_be_gated(shell):
    """Opsi B (RED kini): `../` keluar jail via argv wajib GATED."""
    for cmd in ("cat ../outside_secret.txt", "cat subdir/../../outside_secret.txt"):
        assert classify_shell_command(cmd) == "readonly", f"syarat: {cmd!r} kini readonly"
        decision = _strict_gate(shell)("shell_exec", {"command": cmd}, shell["ctx"])
        _assert_gated(decision, cmd)
    assert _shell_cwd({"cwd": "subdir"}, shell["ctx"])[1] is None, "syarat: cwd subdir dalam-jail tetap sah"


def test_symlink_outside_should_be_gated(shell):
    """Opsi B (RED kini): symlink dalam-jail -> luar wajib GATED."""
    link = shell["jail"] / "link_outside.txt"
    try:
        link.symlink_to(shell["outside"].resolve())
    except OSError as exc:
        pytest.skip(f"symlink tak tersedia di OS ini: {exc}")
    cmd = "cat link_outside.txt"
    assert classify_shell_command(cmd) == "readonly", "syarat: cat symlink kini readonly"
    decision = _strict_gate(shell)("shell_exec", {"command": cmd}, shell["ctx"])
    _assert_gated(decision, cmd)


def test_daemon_autoallow_must_gate_outside(shell):
    """Opsi B (RED kini): daemon auto_allow=True tetap wajib GATE luar-jail."""
    abs_posix = str(shell["outside"].resolve()).replace("\\", "/")
    gate = _strict_gate(shell, surface="daemon")
    for cmd in (f"cat {abs_posix}", f"cat    {abs_posix}"):
        decision = gate("shell_exec", {"command": cmd}, shell["ctx"])
        _assert_gated(decision, f"daemon:{cmd}")


def test_readonly_inside_still_allowed(shell):
    """Opsi B POSITIF (GREEN): baca readonly DI DALAM jail tetap allowed."""
    inside = shell["jail"] / "notes.txt"
    inside.write_text("inside-ok-xyz", encoding="utf-8")
    assert classify_shell_command("cat notes.txt") == "readonly", "syarat: cat dalam-jail readonly"
    decision = _strict_gate(shell)("shell_exec", {"command": "cat notes.txt"}, shell["ctx"])
    assert decision is None, "Opsi B: dalam-jail wajib tetap auto-allow (gate None)"
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": py_command("print(open('notes.txt').read())")}, shell["ctx"],
    )
    assert outcome.ok is True, f"dalam-jail harus ok: {outcome.code}"
    assert "inside-ok-xyz" in outcome.result_for_model, "konten dalam-jail terbaca"
    assert len(outcome.result_for_model) <= _SHELL_OUTPUT_LIMIT + 1200, "output tetap ter-cap"
