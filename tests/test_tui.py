"""TUI tests — Textual pilot harness (``run_test``) on the anyio asyncio backend.

The suite is written to be robust across the parallel build: the workflow
modules (``hunter.workflow.bench``) may land at any moment, so the demo test
handles both the "not landed" (warning notification) and "landed" (real local
demo scan) worlds.
"""

from __future__ import annotations

import asyncio
import importlib.util
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger

try:
    from textual.app import App
    from textual.widgets import DataTable, RichLog, Static, TabbedContent

    from hunter.tui.app import HunterTui

    HAS_PILOT = hasattr(App, "run_test")
except ImportError:  # pragma: no cover — textual is a hard dependency, but be safe
    HAS_PILOT = False

pytestmark = pytest.mark.anyio


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


def _bench_available() -> bool:
    return importlib.util.find_spec("hunter.workflow.bench") is not None


requires_pilot = pytest.mark.skipif(not HAS_PILOT, reason="textual run_test harness unavailable")


# -- fixtures and helpers ----------------------------------------------------


@pytest.fixture()
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture()
def ledger(state_dir: Path) -> Ledger:
    return Ledger(state_dir / "ledger.db")


def _seed_run_with_findings(ledger: Ledger) -> str:
    """One run, one candidate finding, one ruled-out finding (RULE-E4 trail)."""
    run_id = "run-seed-1"
    ledger.create_run(run_id, "http://127.0.0.1:8765", "deterministic", "localhost-only")
    evidence_id = ledger.add_evidence(
        run_id,
        "http_exchange",
        {
            "request": "GET /search?q=%3Cscript%3Ealert(1)",
            "response": "<script>alert(1)</script> echoed in body",
            "status": 200,
        },
    )
    candidate = ledger.create_finding(
        Finding(
            id="",
            run_id=run_id,
            key="reflected-xss|GET|/search|q",
            title="Reflected XSS in search parameter",
            severity=Severity.HIGH,
            cwe="CWE-79",
            endpoint="/search",
            method="GET",
            param="q",
            payload_used="<script>alert(1)</script>",
            evidence_ids=(evidence_id,),
        )
    )
    evidence_two = ledger.add_evidence(
        run_id,
        "http_exchange",
        {"request": "GET /search?q=benign", "response": "no echo", "status": 200},
    )
    ruled_out = ledger.create_finding(
        Finding(
            id="",
            run_id=run_id,
            key="reflected-xss|GET|/other|q",
            title="Reflected XSS in other parameter",
            severity=Severity.MEDIUM,
            cwe="CWE-79",
            endpoint="/other",
            method="GET",
            param="q",
            evidence_ids=(evidence_two,),
        )
    )
    ledger.set_finding_status(ruled_out.id, FindingStatus.RULED_OUT, "payload not echoed on replay")
    ledger.finish_run(run_id, "completed")
    return candidate.id


class _RecordingTui(HunterTui):
    """HunterTui that records notifications for assertions."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.notifications: list[tuple[str, str, str]] = []

    def notify(self, *args: object, **kwargs: object) -> None:
        message = str(args[0]) if args else ""
        title = str(kwargs.get("title", ""))
        severity = str(kwargs.get("severity", "information"))
        self.notifications.append((title, message, severity))
        super().notify(*args, **kwargs)  # type: ignore[arg-type]


async def _wait_until(predicate: Callable[[], bool], timeout: float = 60.0) -> bool:
    """Poll a predicate while the textual event loop keeps running."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.2)
    return predicate()


# -- tests --------------------------------------------------------------------


@requires_pilot
async def test_app_mounts_with_dashboard_table() -> None:
    app = HunterTui()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#runs-table", DataTable) is not None
        assert app.query_one(TabbedContent).active == "tab-dashboard"
        assert app.title == "HunterOs Harness — evidence or nothing"


@requires_pilot
async def test_empty_ledger_shows_friendly_message(ledger: Ledger) -> None:
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        await pilot.pause()
        empty = app.query_one("#dashboard-empty", Static)
        assert empty.display
        assert "No runs yet" in str(empty.render())
        assert not app.query_one("#runs-table", DataTable).display


@requires_pilot
async def test_dashboard_lists_seeded_run(ledger: Ledger) -> None:
    _seed_run_with_findings(ledger)
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        table = app.query_one("#runs-table", DataTable)
        assert await _wait_until(lambda: table.row_count == 1)
        assert str(table.get_row_at(0)[3]) == "completed"  # status column
        assert not app.query_one("#dashboard-empty", Static).display
        await pilot.pause()


@requires_pilot
async def test_refresh_binding_does_not_crash(ledger: Ledger) -> None:
    _seed_run_with_findings(ledger)
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("r")
        table = app.query_one("#runs-table", DataTable)
        assert await _wait_until(lambda: table.row_count == 1)
        # the app must still be mounted and responsive after the refresh worker
        assert app.query_one("#runs-table", DataTable) is not None
        await pilot.pause()


@requires_pilot
async def test_selecting_run_switches_to_findings(ledger: Ledger) -> None:
    _seed_run_with_findings(ledger)
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        table = app.query_one("#runs-table", DataTable)
        assert await _wait_until(lambda: table.row_count == 1)
        table.focus()
        await pilot.press("enter")
        assert app.query_one(TabbedContent).active == "tab-findings"
        findings = app.query_one("#findings-table", DataTable)
        assert await _wait_until(lambda: findings.row_count == 2)


@requires_pilot
async def test_finding_detail_shows_evidence_digest(ledger: Ledger) -> None:
    candidate_id = _seed_run_with_findings(ledger)
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        table = app.query_one("#runs-table", DataTable)
        assert await _wait_until(lambda: table.row_count == 1)
        app._selected_run_id = "run-seed-1"  # white-box: skip navigation, load findings
        app._populate_findings()
        await pilot.pause()
        findings = app.query_one("#findings-table", DataTable)
        findings.focus()
        await pilot.press("enter")
        assert await _wait_until(lambda: "sha256=" in app.finding_detail_text)
        assert "EV-" in app.finding_detail_text
        assert candidate_id in app.finding_detail_text


@requires_pilot
async def test_events_tab_shows_ledger_events(ledger: Ledger) -> None:
    _seed_run_with_findings(ledger)
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_show_tab("tab-events")
        await pilot.pause()
        log = app.query_one("#events-log", RichLog)
        assert await _wait_until(lambda: len(log.lines) > 0)


@requires_pilot
async def test_doctor_tab_renders_version_and_engines(ledger: Ledger) -> None:
    app = HunterTui(ledger=ledger)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_show_tab("tab-doctor")
        assert await _wait_until(lambda: "0.1.0" in app.doctor_summary)
        assert "engine: deterministic" in app.doctor_summary
        assert "state dir" in app.doctor_summary


@requires_pilot
async def test_demo_action_is_safe_in_both_worlds(ledger: Ledger, state_dir: Path) -> None:
    """Pressing d never crashes: warning when bench is missing, run when present."""
    app = _RecordingTui(ledger=ledger, state_dir=state_dir)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("d")
        if _bench_available():
            # workflow landed: the demo must complete and surface its summary
            done = await _wait_until(
                lambda: any(title == "Demo complete" for title, _, _ in app.notifications),
                timeout=90.0,
            )
            assert done, f"demo did not complete; notifications={app.notifications}"
            assert await _wait_until(
                lambda: app.query_one("#runs-table", DataTable).row_count >= 1
            )
            assert not any(
                severity in ("error", "warning") for _, _, severity in app.notifications
            )
        else:
            warned = await _wait_until(
                lambda: any(
                    severity == "warning" and "Demo unavailable" in message
                    for _, message, severity in app.notifications
                ),
                timeout=10.0,
            )
            assert warned, f"expected a warning notification; got {app.notifications}"
        await pilot.pause()  # app alive after everything
        assert app.query_one("#runs-table", DataTable) is not None
