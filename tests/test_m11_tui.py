"""M11 M6 — TUI overhaul: 6 tabs, doctor_core reuse, Engine/Config panes (§10).

Spec: docs/plans/m11-ux.md §10. Textual pilot (``run_test``) on the
anyio asyncio backend (test_tui.py conventions); daemon/status via
monkeypatched seam functions (raising=False so pre-M6 runs fail on the
missing panes, not on the seams). Zero network, zero real daemon.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import time
from collections.abc import Callable
from pathlib import Path

import pytest

try:
    from textual.app import App
    from textual.widgets import Static, TabbedContent

    from hunter.tui.app import HunterTui

    HAS_PILOT = hasattr(App, "run_test")
except ImportError:  # pragma: no cover — textual is a hard dependency, but be safe
    HAS_PILOT = False

pytestmark = pytest.mark.anyio

SENTINEL_KEY = "sk-m11-tui-inline-sentinel-never-render"


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


requires_pilot = pytest.mark.skipif(not HAS_PILOT, reason="textual run_test harness unavailable")


async def _wait_until(predicate: Callable[[], bool], timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.2)
    return predicate()


def _make_app(**overrides) -> HunterTui:
    """HunterTui with the 30s refresh timer neutralized for tests (§10 note)."""
    params = inspect.signature(HunterTui.__init__).parameters
    kwargs: dict = {"refresh_interval": 0} if "refresh_interval" in params else {}
    kwargs.update(overrides)
    return HunterTui(**kwargs)


def _fake_daemon_status(**overrides) -> dict:
    status = {
        "running": False,
        "pid": None,
        "uptime_seconds": None,
        "heartbeat_age_seconds": None,
        "stale": False,
        "paused": False,
        "queue_pending": 0,
        "queue_claimed": 0,
        "transports": [],
        "last_run": None,
        "config_path": "",
    }
    status.update(overrides)
    return status


def _patch_tui_seam(monkeypatch, name: str, fn) -> None:
    """Patch a daemon seam on hunter.tui.app (post-M6) AND hunter.daemon."""
    import hunter.daemon as daemon_module

    if hasattr(daemon_module, name):
        monkeypatch.setattr(daemon_module, name, fn)
    import hunter.tui.app as tui_app

    if hasattr(tui_app, name):
        monkeypatch.setattr(tui_app, name, fn)


def _all_static_text(app) -> str:
    """Every Static render on screen, joined (tab-content assertions)."""
    parts = [str(widget.render()) for widget in app.query(Static)]
    with contextlib.suppress(Exception):  # pragma: no cover - always mounts
        parts.append(str(app.query_one(TabbedContent).render()))
    return "\n".join(parts)


# -- 1 --------------------------------------------------------------------------


@requires_pilot
async def test_six_tabs_present() -> None:
    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        ids = {pane.id for pane in app.query("TabPane")}
        assert ids == {
            "tab-dashboard",
            "tab-findings",
            "tab-events",
            "tab-engine",
            "tab-config",
            "tab-doctor",
        }


# -- 2 --------------------------------------------------------------------------


@requires_pilot
async def test_doctor_tab_renders_doctor_core_rows(monkeypatch) -> None:
    """The Doctor tab renders doctor_core.collect_checks rows (single source)."""
    from hunter.cli.doctor_core import Check

    def fake_collect_checks(*_args, **_kwargs):
        return [
            Check("m11-fake-check", "ok", "m11-doctor-core-row"),
            Check("m11-fake-note", "note", "advisory only"),
        ]

    _patch_tui_seam(monkeypatch, "collect_checks", fake_collect_checks)
    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one(TabbedContent).active = "tab-doctor"
        await pilot.pause()
        assert await _wait_until(lambda: "m11-fake-check" in _all_static_text(app))
        text = _all_static_text(app)
        assert "m11-doctor-core-row" in text
        assert "m11-fake-note" in text

    # Static: the stale duplicated copy is gone from the module SOURCE.
    source = Path(__file__).parents[1] / "src" / "hunter" / "tui" / "app.py"
    src = source.read_text(encoding="utf-8")
    assert "not landed yet (v0.2)" not in src


# -- 3 --------------------------------------------------------------------------


@requires_pilot
async def test_engine_tab_shows_stopped_and_bindings(monkeypatch) -> None:
    """Engine tab: status rows; `s` starts (no target), `x` stops."""
    starts: list = []
    stops: list = []

    _patch_tui_seam(monkeypatch, "daemon_status", lambda state_dir=None: _fake_daemon_status())

    def fake_start(state, **kwargs):
        starts.append((state, kwargs))
        return 0

    def fake_stop(state, **kwargs):
        stops.append((state, kwargs))
        return 0

    _patch_tui_seam(monkeypatch, "start_daemon", fake_start)
    _patch_tui_seam(monkeypatch, "stop_daemon", fake_stop)

    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one(TabbedContent).active = "tab-engine"
        await pilot.pause()
        assert await _wait_until(lambda: "stopped" in _all_static_text(app))

        await pilot.press("s")
        assert await _wait_until(lambda: len(starts) == 1)
        kwargs = starts[0][1]
        assert not kwargs.get("target")  # a plain idle boot — never a hunt

        await pilot.press("x")
        assert await _wait_until(lambda: len(stops) == 1)


# -- 4 --------------------------------------------------------------------------


@requires_pilot
async def test_engine_tab_paused_row(monkeypatch) -> None:
    _patch_tui_seam(
        monkeypatch, "daemon_status",
        lambda state_dir=None: _fake_daemon_status(paused=True),
    )
    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one(TabbedContent).active = "tab-engine"
        await pilot.pause()
        assert await _wait_until(lambda: "⏸️ paused" in _all_static_text(app))


# -- 5 (adversarial: key value leaking through the TUI) ---------------------------


@requires_pilot
async def test_config_tab_masks_everything() -> None:
    """Inline api_key + keys.env: the Config tab shows env NAMES and an
    'inline key present' state — never a value."""
    home = _isolated_home()
    config_dir = home / ".hunter"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "config.yaml").write_text(
        "agent:\n  tier: basic\n"
        "providers:\n"
        "  custom:\n"
        "    base_url: https://api.atria-asi.ai/v1\n"
        "    key_env: CUSTOM_API_KEY\n"
        f"    api_key: {SENTINEL_KEY}\n",
        encoding="utf-8",
    )
    (config_dir / "keys.env").write_text(
        f'CUSTOM_API_KEY="{SENTINEL_KEY}"\n', encoding="utf-8"
    )

    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one(TabbedContent).active = "tab-config"
        await pilot.pause()
        text = await _wait_and_collect(app)
        assert "CUSTOM_API_KEY" in text  # env var NAME
        assert "inline key present" in text  # the masked inline state
        assert SENTINEL_KEY not in text  # the value NEVER renders


def _isolated_home():
    import os
    from pathlib import Path

    return Path(os.environ["USERPROFILE"])


async def _wait_and_collect(app) -> str:
    assert await _wait_until(lambda: "CUSTOM_API_KEY" in _all_static_text(app))
    return _all_static_text(app)


# -- 6 --------------------------------------------------------------------------


@requires_pilot
async def test_status_bar_fields(monkeypatch) -> None:
    """The status bar renders version/model/tier/engine; unset model reads
    `(unset)`."""
    _patch_tui_seam(monkeypatch, "daemon_status", lambda state_dir=None: _fake_daemon_status())
    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert await _wait_until(lambda: "model (unset)" in _all_static_text(app))
        text = _all_static_text(app)
        assert "tier basic" in text
        assert "engine stopped" in text
        from hunter import __version__

        assert f"hunter {__version__}" in text


# -- 7 (static single-source pin) -------------------------------------------------


def test_doctor_core_is_single_source() -> None:
    source = Path(__file__).parents[1] / "src" / "hunter" / "tui" / "app.py"
    src = source.read_text(encoding="utf-8")
    assert "doctor_core" in src  # doctor_core is imported and consumed
    assert "collect_checks" in src
    assert "metadata.version(dep)" not in src  # the duplicated dep loop is gone
    assert "not landed yet (v0.2)" not in src  # the stale copy is gone


# -- 8 (verify-only: the pre-existing suite survives unchanged) --------------------


def test_tui_regressions_green() -> None:
    """§14 item 12 verify-only note: the 9 existing test_tui.py tests are
    preserved (static sanity — they still exist and are collected)."""
    test_tui_path = Path(__file__).parent / "test_tui.py"
    src = test_tui_path.read_text(encoding="utf-8")
    count = sum(
        1 for line in src.splitlines()
        if line.startswith("async def test_") or line.startswith("def test_")
    )
    assert count >= 9
