"""Shell jail Q1 BOLEH AUTO (rewrite Opsi B).

Q1 FINAL: readonly luar MAY auto (gate None); luar butuh approval HANYA
untuk non-readonly. _shell_argv_escapes_jail DIHAPUS sbg kontrol;
_shell_cwd (validasi cwd) DIPERTAHANKAN. Approve->runs tak boleh
hard-block cwd_outside_state untuk argv-luar.
"""

from __future__ import annotations

import re
import subprocess
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
REQ_RE = re.compile(r"A-[0-9a-f]{8}")


def py_command(code: str) -> str:
    return f'"{PY}" -c "{code}"'


@pytest.fixture()
def shell(tmp_path, monkeypatch):
    monkeypatch.setattr("hunter.agent.tools.subprocess.run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            args=[], returncode=0, stdout="ok\n", stderr=""))
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
    gate = make_approval_gate(store, ledger=ledger, run_id=run_id,
                              auto_allow=True, confirm_fn=lambda _r: True, surface="repl")
    ctx = ToolContext(run_id=run_id, ledger=ledger, http=http, scope=scope,
                      target_url="http://127.0.0.1/", emit=emit,
                      config={"tier": "advanced", "state_dir": str(jail),
                              "approval_gate": gate})
    try:
        yield {"ctx": ctx, "jail": jail, "root": tmp_path, "outside": outside,
               "store": store, "ledger": ledger, "run_id": run_id}
    finally:
        http.close()
        ledger.close()


def _strict_gate(shell, surface="repl"):
    return make_approval_gate(shell["store"], ledger=shell["ledger"],
                              run_id=shell["run_id"], auto_allow=True,
                              confirm_fn=None, surface=surface)


def test_readonly_outside_auto_ok(shell):
    """Q1 RED kini: readonly luar + auto wajib gate None (bukan blocked)."""
    abs_posix = str(shell["outside"].resolve()).replace("\\", "/")
    for cmd in (f"cat {abs_posix}", "cat subdir/../../outside_secret.txt"):
        assert classify_shell_command(cmd) == "readonly", f"syarat: {cmd!r} readonly"
        d = _strict_gate(shell)(("shell_exec"), {"command": cmd}, shell["ctx"])
        assert d is None, f"RED Q1: {cmd!r} wajib auto None, dapat {getattr(d, 'code', d)}"


def test_readonly_outside_approve_lalu_jalan(shell):
    """Q1 RED kini: tanpa auto, approve->runs, BUKAN cwd_outside_state."""
    abs_posix = str(shell["outside"].resolve()).replace("\\", "/")
    cmd = f"cat {abs_posix}"
    gate = make_approval_gate(shell["store"], ledger=shell["ledger"],
                              run_id=shell["run_id"], auto_allow=False, surface="repl")
    shell["ctx"].config["approval_gate"] = gate
    blocked = build_registry("advanced").dispatch("shell_exec", {"command": cmd}, shell["ctx"])
    assert blocked.code == "approval.required", f"syarat: tanpa auto wajib required ({blocked.code})"
    rid = REQ_RE.search(blocked.result_for_model).group(0)
    assert shell["store"].decide(rid, "approved") is not None, "approve wajib ok"
    ok = build_registry("advanced").dispatch("shell_exec", {"command": cmd}, shell["ctx"])
    assert ok.code != "shell.cwd_outside_state", f"RED: argv-luar tak boleh hard-block cwd ({ok.code})"
    assert ok.ok is True, f"approve->runs wajib ok: {ok.code}"


def test_mutating_outside_butuh_approval_lalu_jalan(shell):
    """Baseline: mutating luar required, lalu jalan setelah approve."""
    cmd = "touch /tmp/mutating_luar_marker"
    assert classify_shell_command(cmd) == "mutating", "syarat: touch mutating"
    gate = make_approval_gate(shell["store"], ledger=shell["ledger"],
                              run_id=shell["run_id"], auto_allow=True, surface="repl")
    shell["ctx"].config["approval_gate"] = gate
    blocked = build_registry("advanced").dispatch("shell_exec", {"command": cmd}, shell["ctx"])
    assert blocked.code == "approval.required", f"mutating luar wajib required ({blocked.code})"
    rid = REQ_RE.search(blocked.result_for_model).group(0)
    assert shell["store"].decide(rid, "approved") is not None, "approve mutating wajib ok"
    ok = build_registry("advanced").dispatch("shell_exec", {"command": cmd}, shell["ctx"])
    assert ok.ok is True, f"mutating approve->runs wajib ok: {ok.code}"


def test_flag_equals_dianggap_path_konsisten(shell):
    """Q1: --file= dan --file <sp> konsisten (keduanya auto/approval-lalu-jalan)."""
    abs_posix = str(shell["outside"].resolve()).replace("\\", "/")
    for cmd in (f"grep --file={abs_posix} dummy", f"grep --file {abs_posix} dummy"):
        assert classify_shell_command(cmd) == "readonly", f"syarat: {cmd!r} readonly"
        d = _strict_gate(shell)("shell_exec", {"command": cmd}, shell["ctx"])
        assert d is None, f"RED Q1: {cmd!r} wajib auto None, dapat {getattr(d, 'code', d)}"


def test_readonly_inside_ok_dan_cwd_tetap_dijaga(shell):
    """GREEN: dalam-jail ok; cwd keluar tetap shell.cwd_outside_state."""
    inside = shell["jail"] / "notes.txt"
    inside.write_text("inside-ok-xyz", encoding="utf-8")
    assert classify_shell_command("cat notes.txt") == "readonly", "syarat readonly"
    assert _strict_gate(shell)("shell_exec", {"command": "cat notes.txt"}, shell["ctx"]) is None, \
        "dalam-jail wajib auto None"
    ok = build_registry("advanced").dispatch(
        "shell_exec", {"command": py_command("print(open('notes.txt').read())")}, shell["ctx"])
    assert ok.ok is True and len(ok.result_for_model) <= _SHELL_OUTPUT_LIMIT + 1200, "dalam-jail jalan+cap"
    assert _shell_cwd({"cwd": "..", "command": "pwd"}, shell["ctx"])[1] == "shell.cwd_outside_state", \
        "cwd keluar wajib tetap diblokir"
    # Symlink keluar ikut Q1 readonly-auto (lewati bila WinError 1314).
    link = shell["jail"] / "link_outside.txt"
    try:
        link.symlink_to(shell["outside"].resolve())
    except OSError:
        return  # dalam-jail asserts di atas sudah GREEN; symlink tak tersedia
    d = _strict_gate(shell)("shell_exec", {"command": "cat link_outside.txt"}, shell["ctx"])
    assert d is None, "RED Q1: symlink readonly luar wajib auto None"
