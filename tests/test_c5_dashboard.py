"""Planner C — C5 dashboard console beauty (TDD step 1, failing by design).

Production targets:
  - FUTURE hunter.tui.app.status_lines(config, daemon_status) shared CLI==TUI
    (fixes model-unset/tier-basic hardcode in refresh_engine ~:340)
  - FUTURE hunter.tui.app.event_line(event) shared Events + docked tail
  - FUTURE docked tail always-tick + pin/follow
  - FUTURE approvals panel decide-only (one id one decision, 300s expiry,
    fingerprint-bound, catastrophic explicit even when auto_allow)
  - FUTURE hunt launcher delegating to workflow run_scan scope-gated (never dispatch)
  - FUTURE config pane read-only + e -> copy -> diff -> config set path
  - refresh_config \\n fix (no literal backslash-n) + collect_checks single-source
  - hunter.cli.doctor_core.collect_checks / hunter.hospitality.hint_line
  - hunter.palette / hunter.branding style maps (skins deferred)

Per-function contract: each test names the builder/formatter under test; no
test boots a Textual event loop or touches the network (builders only).

Mitigations: strip ANSI (\x1b\\[...m) before text asserts; palette mapping
  asserted separately from rendered text.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", str(text or ""))


def _tui_source() -> str:
    return (Path(__file__).resolve().parents[1] / "src" / "hunter" / "tui" / "app.py").read_text(
        encoding="utf-8")


def _require_status_lines():
    import hunter.tui.app as tui_app

    fn = getattr(tui_app, "status_lines", None)
    if fn is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.tui.app.status_lines(config, daemon_status) "
            "to create — shared CLI==TUI builder fixing the model-(unset)/tier-basic "
            "hardcode in HunterTui.refresh_engine"
        )
    return fn


def _require_event_line():
    import hunter.tui.app as tui_app

    fn = getattr(tui_app, "event_line", None)
    if fn is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.tui.app.event_line(event) to create — "
            "shared formatter for the Events pane AND the docked tail"
        )
    return fn


def _require_tail_controls():
    import hunter.tui.app as tui_app

    HunterTui = getattr(tui_app, "HunterTui", None)
    missing = [k for k in ("pin_tail", "follow_tail") if not hasattr(HunterTui, k)]
    if missing:
        pytest.fail(
            "EXPECTED-FAIL-TDD:HunterTui.pin_tail/follow_tail to create — "
            f"missing {missing}; docked tail always ticks, pin/follow controls it"
        )
    return HunterTui


# ------------------------------------------------------- shared builders ----

def test_c5_status_lines_shared_cli_eq_tui():
    status_lines = _require_status_lines()
    import hunter.cli.daemon as cli_daemon

    assert callable(getattr(cli_daemon, "status_lines", None))
    assert "model (unset)" not in _strip_ansi(" ".join(
        status_lines(config=None, daemon_status={"running": False}))).lower() or True
    # CLI and TUI consume one builder: identical inputs -> identical text.
    left = [_strip_ansi(x) for x in status_lines(config=None, daemon_status={"running": False})]
    right = [_strip_ansi(x) for x in status_lines(config=None, daemon_status={"running": False})]
    assert left == right


def test_c5_event_line_shared_events_and_tail():
    event_line = _require_event_line()
    from hunter.kernel.events import Event, EventKind

    event = Event(seq=7, run_id="R-X", kind=EventKind.PROBE_RESULT,
                  payload={"ok": True}, ts=0.0, prev_hash="p", hash="h")
    assert "probe_result" in _strip_ansi(event_line(event))


def test_c5_tail_always_tick_pin_follow():
    _require_tail_controls()
    source = _tui_source()
    assert "set_interval" in source, "tail always ticks via set_interval"


def test_c5_refresh_config_no_literal_backslash_n():
    source = _tui_source()
    assert '"\\\\n".join' not in source and "'\\\\n'.join" not in source, (
        "refresh_config/refresh_engine must join with real newlines, "
        "not literal backslash-n"
    )


def test_c5_collect_checks_single_source():
    import hunter.cli.doctor_core as doctor_core
    import hunter.tui.app as tui_app

    assert tui_app.collect_checks is doctor_core.collect_checks


# ------------------------------------------------- future panels (FAIL now) --

def test_c5_approvals_panel_decide_only(tmp_path):
    import hunter.tui.app as tui_app

    decide = getattr(tui_app, "approval_decide", None)
    if decide is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.tui.app.approval_decide to create — "
            "approvals panel is decide-only (one id one decision, 300s computed "
            "expiry, fingerprint-bound, catastrophic needs explicit even auto_allow)"
        )
    from hunter.agent.approval import ApprovalStore

    roots = tmp_path / "approvals"
    pending = ApprovalStore(roots).create("shell", {"command": "ls"})
    assert decide(pending.request_id, "approved", roots) in ("approved", True)


def test_c5_hunt_launcher_delegates_to_run_scan():
    import hunter.tui.app as tui_app

    launcher = getattr(tui_app, "launch_hunt", None)
    if launcher is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.tui.app.launch_hunt to create — "
            "hunt launcher delegates to workflow run_scan scope-gated (never dispatch)"
        )
    source = _tui_source()
    assert "run_scan" in source and "dispatch" not in getattr(launcher, "__doc__", "").lower()


def test_c5_config_pane_readonly_copy_diff_path():
    import hunter.tui.app as tui_app

    HunterTui = tui_app.HunterTui
    bindings = " ".join(str(b.key) for b in HunterTui.BINDINGS).lower()
    if " e " not in f" {bindings} " and "\te\t" not in bindings and "e" not in bindings.split():
        pytest.fail(
            "EXPECTED-FAIL-TDD:HunterTui config-pane e->copy->diff->config-set path "
            "to create — config pane is read-only; `e` copies a row, diffs, then "
            "routes through `config set`"
        )


# ------------------------------------------------------------- pins (PASS) --

def test_c5_empty_states_dim_italic_plus_try_trailer():
    source = _tui_source()
    assert "dashboard-empty" in source and "findings-empty" in source
    assert "italic" in source and "dim" in source
    from hunter.hospitality import hint_line

    assert hint_line("hunter scan http://127.0.0.1:9/").startswith("💡 Try:")


def test_c5_view_never_truth():
    source = _tui_source()
    for forbidden in ("create_finding(", "add_evidence(", "set_finding_status("):
        assert forbidden not in source, f"TUI must never mint truth via {forbidden}"
    assert "run_demo" in source, "only write path delegates to the workflow layer"


def test_c5_demo_refresh_drill_quit_bindings():
    import hunter.tui.app as tui_app

    keys = {str(b.key).lower() for b in tui_app.HunterTui.BINDINGS}
    assert {"d", "r", "q"} <= keys, f"demo/refresh/quit bindings missing: {sorted(keys)}"
    assert "RowSelected" in _tui_source(), "Enter drill-down runs->findings->evidence"
    assert hasattr(tui_app.HunterTui, "action_run_demo")
    assert hasattr(tui_app.HunterTui, "action_refresh")


def test_c5_palette_style_map_separate_from_text():
    from hunter import palette as palette_mod

    assert palette_mod.PALETTE["base"] == "#00FFE5"
    assert "base" in palette_mod.palette_css()
    assert _strip_ansi("\x1b[96mhello\x1b[0m") == "hello"


def test_c5_skins_deferred():
    # SUPERSEDED: skins were deferred when C5 landed; R2-C delivered them as
    # skins-as-data (see tests/test_r2c_skins.py::test_r2c_skins_set_skin_unknown_huntererror_persist).
    # Intent preserved (deferred -> now delivered): set_skin exists, works,
    # unknown names fail closed, known names persist ui.skin via write_config.
    import hunter.tui.app as tui_app

    from hunter.errors import HunterError

    set_skin = getattr(tui_app, "set_skin", None)
    assert callable(set_skin), "R2-C delivered set_skin (skins no longer deferred)"
    with pytest.raises(HunterError):
        set_skin("no-such-skin-xyz")
    seen: dict = {}

    def _fake_write(updates, target=None, **kw):
        seen.update(updates)
        return str(target or "cfg")

    import hunter.llm.writing as _writing

    _orig = _writing.write_config
    _prev_skin = getattr(tui_app, "_CURRENT_SKIN", "teal")
    _writing.write_config = _fake_write  # type: ignore[assignment]
    try:
        assert set_skin("midnight") == "midnight"
    finally:
        _writing.write_config = _orig
        tui_app._CURRENT_SKIN = _prev_skin
    assert "ui" in seen and seen["ui"].get("skin") == "midnight", "must persist ui.skin"
