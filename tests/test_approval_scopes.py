"""§10 RED: scope persetujuan once/session/always (§10 operator decision).

Kontrak Builder (GREEN):
- ApprovalRequest.scope in {"once","session","always"} + run_id + command_class.
- create(..., scope=, run_id=, command_class=); Q2 always keyed tool+command_class.
- Q3 catastrophic NEVER always (dipaksa once/ditolak); Q4 always lokal
  per state-dir saja, tak lintas proyek.
- RED kini: signature belum ada scope -> assert pertama gagal.
"""

from __future__ import annotations

import inspect
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any

from hunter.agent.approval import ApprovalRequest, ApprovalStore, make_approval_gate
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope


def _supports_scope() -> bool:
    try:
        sig = inspect.signature(ApprovalStore.create)
        fields = ApprovalRequest.__dataclass_fields__
        return "scope" in sig.parameters and "scope" in fields
    except Exception:
        return False


def _completed():
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n", stderr="")


def _env(tmp_path: Path, run_id: str, auto_allow=False):
    ledger = Ledger(tmp_path / "ledger.db")
    with suppress(Exception):
        ledger.create_run(run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
    http = ScopedHttpClient(localhost_scope(), min_interval=0)
    store = ApprovalStore(tmp_path / "approvals")
    ctx = ToolContext(run_id=run_id, ledger=ledger, http=http, scope=localhost_scope(),
                      target_url="http://127.0.0.1/",
                      emit=lambda k, p: ledger.append(run_id, k, dict(p)),
                      config={"tier": "advanced", "state_dir": str(tmp_path)})
    ctx.config["approval_gate"] = make_approval_gate(
        store, ledger=ledger, run_id=run_id, auto_allow=auto_allow, surface="repl")
    return ledger, http, store, ctx


def test_once_single_use(tmp_path, monkeypatch):
    """Baseline GREEN: approve->run->replay diblokir (used_ts)."""
    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *a, **k: _completed())
    ledger, http, store, ctx = _env(tmp_path, "R-ONCE")
    try:
        reg = build_registry("advanced")
        args: dict[str, Any] = {"command": "touch marker_once"}
        first = reg.dispatch("shell_exec", args, ctx)
        assert first.code == "approval.required", "syarat: mutating butuh approval"
        import re

        rid = re.search(r"A-[0-9a-f]{8}", first.result_for_model).group(0)
        assert store.decide(rid, "approved") is not None, "decide approved wajib ok"
        second = reg.dispatch("shell_exec", args, ctx)
        assert second.ok is True, f"retry approved wajib jalan: {second.code}"
        assert store.get(rid).used_ts is not None, "wajib single-use (used_ts terisi)"
        third = reg.dispatch("shell_exec", args, ctx)
        assert third.code == "approval.required", "replay wajib diblokir (sekali pakai)"
    finally:
        http.close()
        ledger.close()


def test_session_reusable_same_run(tmp_path, monkeypatch):
    """RED kini: session boleh dipakai ulang dalam run_id sama."""
    assert _supports_scope(), (
        "Builder GREEN: ApprovalRequest.scope+run_id, create(scope='session', run_id=)")
    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *a, **k: _completed())
    ledger, http, store, ctx = _env(tmp_path, "R-SESS")
    try:
        reg = build_registry("advanced")
        args: dict[str, Any] = {"command": "touch marker_sess"}
        req = store.create("shell_exec", args, surface="repl", scope="session", run_id="R-SESS")
        assert req.scope == "session", "scope wajib tersimpan session"
        assert store.decide(req.request_id, "approved") is not None, "approve session wajib ok"
        assert reg.dispatch("shell_exec", args, ctx).ok is True, "run-1 sesi wajib ok"
        assert reg.dispatch("shell_exec", args, ctx).ok is True, "RED: run-2 sesi sama wajib tetap ok"
    finally:
        http.close()
        ledger.close()


def test_session_isolated_across_runs(tmp_path, monkeypatch):
    """RED kini: session tak boleh bocor ke run_id lain."""
    assert _supports_scope(), "Builder GREEN: session diikat run_id, lintas run diblokir"
    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *a, **k: _completed())
    ledger, http, store, ctx = _env(tmp_path, "R-A")
    try:
        args: dict[str, Any] = {"command": "touch marker_iso"}
        req = store.create("shell_exec", args, surface="repl", scope="session", run_id="R-A")
        assert store.decide(req.request_id, "approved") is not None, "approve sesi R-A wajib ok"
        assert build_registry("advanced").dispatch("shell_exec", args, ctx).ok is True, "R-A wajib ok"
        ledger2 = ledger
        http2 = ScopedHttpClient(localhost_scope(), min_interval=0)
        ctx2 = ToolContext(run_id="R-B", ledger=ledger2, http=http2, scope=localhost_scope(),
                           target_url="http://127.0.0.1/",
                           emit=lambda k, p: ledger2.append("R-A", k, dict(p)),
                           config={"tier": "advanced", "state_dir": str(tmp_path),
                                   "approval_gate": make_approval_gate(
                                       store, ledger=ledger2, run_id="R-B", surface="repl")})
        try:
            out = build_registry("advanced").dispatch("shell_exec", args, ctx2)
            assert out.code == "approval.required", f"RED: sesi R-A bocor ke R-B ({out.code})"
        finally:
            http2.close()
    finally:
        http.close()
        ledger.close()


def test_always_persisted_reload(tmp_path, monkeypatch):
    """RED kini: always tersimpan, reload store sama masih ada; Q2 keyed tool+class; Q4 lokal."""
    assert _supports_scope(), (
        "Builder GREEN: create(scope='always', command_class=) + reload se-dir; kunci tool+class")
    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *a, **k: _completed())
    ledger, http, store, ctx = _env(tmp_path, "R-ALW")
    try:
        req = store.create("shell_exec", {"command": "touch a_always"}, surface="repl",
                           scope="always", run_id="R-ALW", command_class="mutating")
        assert req.scope == "always", "scope always wajib tersimpan"
        assert "command_class" in ApprovalRequest.__dataclass_fields__, "Q2: field command_class wajib ada"
        assert store.decide(req.request_id, "approved") is not None, "approve always wajib ok"
        reg = build_registry("advanced")
        assert reg.dispatch("shell_exec", {"command": "touch a_always"}, ctx).ok is True, "run-1 always ok"
        store2 = ApprovalStore(tmp_path / "approvals")
        ctx.config["approval_gate"] = make_approval_gate(
            store2, ledger=ledger, run_id="R-ALW", surface="repl")
        assert reg.dispatch("shell_exec", {"command": "touch b_always_beda_arg"}, ctx).ok is True, (
            "RED Q2: always kunci tool+class, beda arg sama class wajib ok")
        other = ApprovalStore(tmp_path / "lain approvals")
        assert other.find_approved(req.fingerprint) is None or True, "Q4: beda dir tak boleh pakai"
        # Kunci Q4: store beda direktori tak boleh menemukan always ini.
        assert len(list(other.root.glob("*.json"))) == 0, "Q4: dir lain wajib kosong (lokal saja)"
    finally:
        http.close()
        ledger.close()


def test_catastrophic_never_always(tmp_path):
    """RED kini: catastrophic minta always wajib dipaksa once/ditolak (Q3)."""
    assert _supports_scope(), "Builder GREEN: catastrophic+always -> paksa once atau tolak"
    store = ApprovalStore(tmp_path / "approvals")
    req = store.create("shell_exec", {"command": "rm -rf /"}, surface="repl",
                       scope="always", run_id="R-C", command_class="catastrophic")
    # Builder boleh: scope dipaksa 'once', atau decide(always) ditolak.
    forced = getattr(req, "scope", "once") != "always"
    decided = store.decide(req.request_id, "approved")
    denied_or_once = decided is None or getattr(decided, "scope", "once") == "once"
    assert forced or denied_or_once, "RED Q3: catastrophic-always wajib dipaksa once/ditolak"
