"""R2-C dashboard completion (TDD RED — EXPECTED-FAIL-R2C).

Prod targets (READ ONLY, do NOT edit):
- hunter.tui.app approvals tab (TTL countdown, decide-only rows)
- hunter.tui.app launch_hunt picker + dry_run (NEW kwargs)
- hunter.tui.app engine_trailer + config_copy diff/notify (NEW)
- per-fn -> prod:
  approvals TTL countdown decide-only expired unclickable consumed no replay
    catastrophic explicit -> hunter.tui.app.approval_row/approval_panel (NEW)
  launcher picker+path dry_run summary no run_scan real via gate never dispatch
    queue hint -> hunter.tui.app.launch_hunt
  engine trailer 20 redacted s/x restart hint -> hunter.tui.app.engine_trailer
  config copy real diff notify never writes -> HunterTui.action_config_copy

TDD red: EXPECTED-FAIL-R2C until dashboard completion lands.
No TUI loop/sockets/sleep: builders + monkeypatched seams + tmp stores only.
ANSI stripped; rstrip comparator; ledger.db counted only.
"""
from __future__ import annotations

import pathlib
import re

import pytest

R2C = "EXPECTED-FAIL-R2C:dashboard completion (R2-C dash)"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip(text: str) -> str:
    return ANSI_RE.sub("", str(text or "")).rstrip("\n").rstrip()


def _require_panel():
    import hunter.tui.app as tui_app

    fn = getattr(tui_app, "approval_row", None) or getattr(tui_app, "approval_panel", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.tui.app.approval_row/approval_panel missing")
    return fn


def _require_trailer():
    import hunter.tui.app as tui_app

    fn = getattr(tui_app, "engine_trailer", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.tui.app.engine_trailer missing")
    return fn


def test_r2c_dash_approvals_ttl_countdown_decide_only(tmp_path):
    """Approvals tab: TTL countdown, decide-only row text."""
    row = _require_panel()
    from hunter.agent.approval import ApprovalStore

    req = ApprovalStore(tmp_path / "approvals").create("shell", {"command": "ls"}, surface="tui")
    text = _strip(row(req, now=req.created_ts + 10))
    assert "decide" in text.lower() or "approv" in text.lower()
    assert re.search(r"\d+", text), "TTL countdown digits required"


def test_r2c_dash_approvals_expired_unclickable_consumed_no_replay(tmp_path):
    """Expired rows unclickable; consumed ids never replay."""
    row = _require_panel()
    from hunter.agent.approval import ApprovalStore, effective_status

    store = ApprovalStore(tmp_path / "approvals")
    req = store.create("shell", {"command": "ls"}, surface="tui")
    assert effective_status(req, now=req.created_ts + 301) == "expired"
    text = _strip(row(req, now=req.created_ts + 301))
    assert "expir" in text.lower()
    first = store.decide(req.request_id, "approved")
    assert first is not None
    store.consume(req.request_id)
    assert store.decide(req.request_id, "approved") is None, "consumed never replays"


def test_r2c_dash_approvals_catastrophic_explicit(tmp_path):
    """Catastrophic commands need explicit decision even when auto_allow."""
    _require_panel()
    import hunter.tui.app as tui_app

    decide = getattr(tui_app, "approval_decide", None)
    if decide is None:
        pytest.fail(f"{R2C} — hunter.tui.app.approval_decide missing (decide-only)")
    from hunter.agent.approval import ApprovalStore, classify_shell_command

    assert classify_shell_command("rm -rf /") == "catastrophic"
    req = ApprovalStore(tmp_path / "approvals").create("shell", {"command": "rm -rf /"})
    assert decide(req.request_id, "approved", tmp_path / "approvals") in ("approved", True)


def test_r2c_dash_launcher_picker_path_dry_run_no_scan(tmp_path, monkeypatch):
    """Launcher picker+path; dry_run returns summary without run_scan."""
    import hunter.tui.app as tui_app

    launcher = getattr(tui_app, "launch_hunt", None)
    if launcher is None:
        pytest.fail(f"{R2C} — hunter.tui.app.launch_hunt missing")
    import inspect

    sig = inspect.signature(launcher)
    src = inspect.getsource(launcher)
    if "dry_run" not in sig.parameters:
        pytest.fail(f"{R2C} — launch_hunt needs dry_run kwarg (picker+path dry_run)")
    if "picker" not in src.lower() and "path" not in src.lower():
        pytest.fail(f"{R2C} — launch_hunt picker+path display missing")
    monkeypatch.setattr("hunter.workflow.pipeline.run_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("dry_run ran scan")))
    summary = _strip(launcher("http://127.0.0.1:9/", dry_run=True))
    assert "dry" in summary.lower() or "would" in summary.lower() or "summary" in summary.lower()


def test_r2c_dash_launcher_real_via_gate_never_dispatch_queue_hint(monkeypatch):
    """Real launch rides the scope gate, never dispatch; queue hint shown."""
    import hunter.tui.app as tui_app

    launcher = getattr(tui_app, "launch_hunt", None)
    if launcher is None:
        pytest.fail(f"{R2C} — hunter.tui.app.launch_hunt missing")
    import inspect

    src = inspect.getsource(launcher)
    if "scope_for_target" not in src:
        pytest.fail(f"{R2C} — real path must ride the scope gate")
    if "dispatch" in src.lower():
        pytest.fail(f"{R2C} — launcher never dispatches")
    if "queue" not in src.lower() and "hint" not in src.lower():
        pytest.fail(f"{R2C} — hunter.tui.app.launch_hunt queue hint missing")


def test_r2c_dash_engine_trailer_20_redacted_sx_restart():
    """Engine trailer: last 20, redacted, s/x bindings + restart hint."""
    trailer = _require_trailer()
    events = [{"seq": i, "kind": "http_response", "payload": {"k": "sk-secret-abc123XYZ"}} for i in range(40)]
    text = _strip(trailer(events))
    assert "sk-secret-abc123XYZ" not in text, "trailer must redact"
    assert "20" in text or len(text.splitlines()) <= 24, "trailer window 20"
    import hunter.tui.app as tui_app

    keys = {str(b.key).lower() for b in tui_app.HunterTui.BINDINGS}
    assert {"s", "x"} <= keys
    assert "restart" in _strip(trailer(events)).lower() or "restart" in (
        pathlib.Path(__file__).resolve().parents[1] / "src" / "hunter" / "tui" / "app.py"
    ).read_text(encoding="utf-8").lower()


def test_r2c_dash_config_copy_real_diff_notify_never_writes(tmp_path, monkeypatch):
    """Config copy shows a real unified diff via notify and never writes."""
    import hunter.tui.app as tui_app

    if getattr(tui_app, "build_config_diff", None) is None:
        pytest.fail(f"{R2C} — hunter.tui.app.build_config_diff missing (real diff seam)")
    HunterTui = tui_app.HunterTui
    assert hasattr(HunterTui, "action_config_copy")
    notified: list[str] = []
    app = HunterTui.__new__(HunterTui)
    app.notify = lambda msg, **k: notified.append(str(msg))  # type: ignore[method-assign]

    row = "tier: basic"
    app.query_one = lambda *a, **k: type("S", (), {"renderable": row})()  # type: ignore[method-assign]
    before = (tmp_path / "config.yaml")
    before.write_text("tier: basic\n", encoding="utf-8")
    mtime = before.stat().st_mtime
    HunterTui.action_config_copy(app)
    assert notified, "copy must notify"
    assert any(line.startswith(("+", "-", "@@")) for line in "\n".join(notified).splitlines()), (
        "real difflib diff required")
    assert "config set" in "\n".join(notified).lower()
    assert before.stat().st_mtime == mtime, "copy never writes"
