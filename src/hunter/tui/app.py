"""HunterOs TUI — the interactive surface over the hash-chained ledger.

The TUI is a view, never a second source of truth: every number on screen is
read from the ledger at refresh time. The only write path is the demo scan
(``d``), which delegates to the workflow layer. Everything that can fail
inside a worker is contained — errors surface as notifications, the app keeps
running. Evidence or nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import platform
import sys
import time
from importlib import metadata, util
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table as RichTable
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from hunter import __version__
from hunter.kernel.events import Event
from hunter.kernel.findings import Finding
from hunter.kernel.ledger import Ledger
from hunter.phases import current_phase

TAIL_WINDOW = 100  # events shown in the live tail
PAYLOAD_WIDTH = 64  # characters of payload preview in the tail
EVIDENCE_EXCERPT_CHARS = 280

SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
STATUS_STYLES = {
    "verified": "bold green",
    "candidate": "yellow",
    "ruled_out": "dim",
}
RUN_STATUS_STYLES = {
    "running": "yellow",
    "completed": "green",
    "failed": "red",
    "error": "red",
}
KIND_STYLES = {
    "run_started": "bold magenta",
    "run_ended": "magenta",
    "phase_started": "cyan",
    "phase_ended": "cyan",
    "http_request": "blue",
    "http_response": "bright_blue",
    "probe_started": "green",
    "probe_result": "bright_green",
    "evidence_stored": "yellow",
    "finding_created": "bold yellow",
    "finding_status_changed": "bright_yellow",
    "scope_check": "grey50",
    "engine_event": "grey50",
    "error": "bold red",
    # v0.3 phase-machine kinds
    "classification_recorded": "bright_cyan",
    "report_rendered": "bold blue",
    "retro_recorded": "bold magenta",
}

CSS = """
#dashboard-empty, #findings-empty {
    display: none;
    height: 1fr;
    content-align: center middle;
    color: $text-muted;
    text-style: italic;
}
#runs-table {
    height: 1fr;
}
#findings-table {
    height: 1fr;
}
#finding-detail {
    height: 42%;
    border-top: heavy $primary 30%;
    padding: 0 1;
    overflow-y: auto;
}
#events-log {
    height: 1fr;
    padding: 0 1;
}
#doctor-report {
    padding: 1 2;
}
TabPane {
    padding: 0;
}
"""


def _value(raw: Any) -> str:
    """Plain string of a (str, Enum) member or anything else."""
    return raw.value if hasattr(raw, "value") else str(raw)


def _severity_cell(severity: Any) -> Text:
    value = _value(severity)
    return Text(value, style=SEVERITY_STYLES.get(value, ""))


def _status_cell(status: Any) -> Text:
    value = _value(status)
    return Text(value, style=STATUS_STYLES.get(value, ""))


def _run_status_cell(status: str) -> Text:
    return Text(status, style=RUN_STATUS_STYLES.get(status, ""))


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%m-%d %H:%M:%S", time.localtime(ts))


def _package_version() -> str:
    try:
        return metadata.version("hunteros-harness")
    except Exception:
        return __version__


def _module_available(name: str) -> bool:
    try:
        return util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _renderable_text(renderable: Any) -> str:
    """Plain-text rendering of a rich renderable (for summaries and diagnostics)."""
    console = Console(width=200)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


def _demo_runner():
    """Import the workflow demo lazily; raise when the module has not landed."""
    from hunter.workflow.bench import run_demo  # noqa: PLC0415 — lazy by design

    return run_demo


class HunterTui(App[None]):
    """Evidence-first dashboard: runs, findings, live events, doctor."""

    TITLE = "HunterOs Harness — evidence or nothing"
    SUB_TITLE = f"v{__version__}"
    CSS = CSS

    BINDINGS = [
        Binding("d", "run_demo", "Run demo"),
        Binding("r", "refresh", "Refresh"),
        Binding("1", "show_tab('tab-dashboard')", "Dashboard", show=False),
        Binding("2", "show_tab('tab-findings')", "Findings", show=False),
        Binding("3", "show_tab('tab-events')", "Events", show=False),
        Binding("4", "show_tab('tab-doctor')", "Doctor", show=False),
        Binding("q", "quit", "Quit", priority=True),
    ]

    def __init__(
        self,
        ledger: Ledger | None = None,
        state_dir: str | Path | None = None,
    ) -> None:
        super().__init__()
        self._state_dir = Path(state_dir) if state_dir is not None else None
        if ledger is not None:
            self._ledger = ledger
            self._owns_ledger = False
        else:
            self._ledger = (
                Ledger(self._state_dir / "ledger.db")
                if self._state_dir is not None
                else Ledger()
            )
            self._owns_ledger = True
        self._runs: list[dict[str, Any]] = []
        self._findings: list[Finding] = []
        self._selected_run_id: str | None = None
        self._last_seq = 0
        self._demo_running = False
        # Plain-text snapshots of rendered panels — handy for logging/debugging.
        self.doctor_summary = ""
        self.finding_detail_text = ""

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent():
            with TabPane("Dashboard", id="tab-dashboard"):
                yield Static(
                    "No runs yet — press [b]d[/b] to run the demo scan.",
                    id="dashboard-empty",
                )
                yield DataTable(
                    id="runs-table", cursor_type="row", zebra_stripes=True
                )
            with TabPane("Findings", id="tab-findings"):
                yield Static(
                    "No findings yet — run a scan, then pick a run on the Dashboard.",
                    id="findings-empty",
                )
                yield DataTable(
                    id="findings-table", cursor_type="row", zebra_stripes=True
                )
                yield Static(
                    "Select a finding (Enter) to inspect its evidence.",
                    id="finding-detail",
                )
            with TabPane("Events", id="tab-events"):
                yield RichLog(
                    id="events-log", markup=True, highlight=True, wrap=True, max_lines=2000
                )
            with TabPane("Doctor", id="tab-doctor"), VerticalScroll():
                yield Static("Checking environment…", id="doctor-report")
        yield Footer()

    def on_mount(self) -> None:
        with contextlib.suppress(Exception):  # theme names are cosmetic — never fatal
            self.theme = "tokyo-night"
        runs_table = self.query_one("#runs-table", DataTable)
        runs_table.add_columns("run", "target", "engine", "status", "v/c", "ended", "phase")
        findings_table = self.query_one("#findings-table", DataTable)
        findings_table.add_columns("id", "severity", "status", "title", "endpoint")
        self.refresh_data()
        self.refresh_doctor()
        self.set_interval(2.0, self._tail_events_tick)

    def on_unmount(self) -> None:
        # The app closes only the ledger it opened itself; an externally
        # supplied ledger stays owned by (and open for) its caller.
        if self._owns_ledger:
            with contextlib.suppress(Exception):
                self._ledger.close()

    # -- actions ------------------------------------------------------------

    @work(exclusive=True, group="refresh", exit_on_error=False)
    async def refresh_data(self) -> None:
        """Reload runs, findings and events from the ledger (off the UI thread)."""
        try:
            snapshot = await asyncio.to_thread(self._snapshot)
        except Exception as error:
            self.notify(f"Ledger read failed: {error}", title="Refresh", severity="error")
            return
        self._apply_snapshot(snapshot)

    @work(exclusive=True, group="doctor", exit_on_error=False)
    async def refresh_doctor(self) -> None:
        try:
            report = await asyncio.to_thread(self._doctor_report)
        except Exception as error:
            self.notify(f"Doctor failed: {error}", title="Doctor", severity="error")
            return
        self.doctor_summary = _renderable_text(report)
        self.query_one("#doctor-report", Static).update(report)

    def action_refresh(self) -> None:
        self.refresh_data()
        self.refresh_doctor()

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    @work(exclusive=True, group="demo", exit_on_error=False)
    async def action_run_demo(self) -> None:
        """Run the end-to-end demo scan in a worker; never block the UI."""
        if self._demo_running:
            self.notify("A demo scan is already running — hold on.", title="Demo", severity="warning")
            return
        try:
            run_demo = _demo_runner()
        except Exception as error:
            self.notify(
                f"Demo unavailable: the workflow module has not landed yet ({error}).",
                title="Demo",
                severity="warning",
            )
            return
        self._demo_running = True
        self.notify("Booting the practice target and running the deterministic scan…", title="Demo")
        try:
            result = await asyncio.to_thread(
                run_demo,
                state_dir=str(self._state_dir) if self._state_dir else None,
                port=0,
            )
        except Exception as error:
            self.notify(f"Demo failed: {error}", title="Demo", severity="error")
            return
        finally:
            self._demo_running = False
        summary = getattr(result, "summary_line", None) or str(result)
        self.notify(summary, title="Demo complete", timeout=10)
        self.refresh_data()

    @work(exclusive=True, group="tail", exit_on_error=False)
    async def _tail_events(self) -> None:
        """Live tail: append events newer than the last one rendered."""
        try:
            events = await asyncio.to_thread(self._ledger.events)
        except Exception:
            return
        log = self.query_one("#events-log", RichLog)
        fresh = [event for event in events if event.seq > self._last_seq]
        for event in fresh[-TAIL_WINDOW:]:
            log.write(self._event_line(event))
            self._last_seq = event.seq

    def _tail_events_tick(self) -> None:
        if self.query_one(TabbedContent).active == "tab-events":
            self._tail_events()

    # -- dashboard / findings ------------------------------------------------

    def _snapshot(self) -> dict[str, Any]:
        runs = list(reversed(self._ledger.runs()))  # newest first
        findings = self._ledger.findings()
        events = self._ledger.events()[-TAIL_WINDOW:]
        # v0.3: canonical phase per run, computed from events (off the UI thread).
        phases = {run["run_id"]: current_phase(self._ledger, run["run_id"]) or "-" for run in runs}
        return {"runs": runs, "findings": findings, "events": events, "phases": phases}

    def _apply_snapshot(self, snapshot: dict[str, Any]) -> None:
        self._runs = snapshot["runs"]
        self._findings = snapshot["findings"]

        runs_table = self.query_one("#runs-table", DataTable)
        runs_table.clear()
        for run in self._runs:
            run_id = run["run_id"]
            run_findings = [f for f in self._findings if f.run_id == run_id]
            verified = sum(1 for f in run_findings if _value(f.status) == "verified")
            candidates = sum(1 for f in run_findings if _value(f.status) == "candidate")
            runs_table.add_row(
                Text(run_id, style="bold"),
                run["target"],
                run["engine"],
                _run_status_cell(str(run["status"])),
                f"{verified}v/{candidates}c",
                _fmt_ts(run["ended_ts"] or run["started_ts"]),
                str(snapshot["phases"].get(run_id, "-")),
                key=run_id,
            )
        self.query_one("#dashboard-empty", Static).display = not self._runs
        self.query_one("#runs-table", DataTable).display = bool(self._runs)

        self._populate_findings()
        self._write_new_events(snapshot["events"])

    def _populate_findings(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        shown = [f for f in self._findings if self._selected_run_id in (None, f.run_id)]
        table.clear()
        for finding in shown:
            table.add_row(
                Text(finding.id, style="cyan"),
                _severity_cell(finding.severity),
                _status_cell(finding.status),
                finding.title,
                Text(f"{finding.method} {finding.endpoint}", style="dim"),
                key=finding.id,
            )
        self.query_one("#findings-empty", Static).display = not shown
        self.query_one("#findings-table", DataTable).display = bool(shown)

    @on(DataTable.RowSelected, "#runs-table")
    def _on_run_selected(self, event: DataTable.RowSelected) -> None:
        run_id = event.row_key.value
        if not run_id:
            return
        self._selected_run_id = run_id
        self._populate_findings()
        self.query_one(TabbedContent).active = "tab-findings"
        self.query_one("#findings-table", DataTable).focus()

    @on(DataTable.RowHighlighted, "#findings-table")
    def _on_finding_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_finding_detail(event.row_key.value)

    @on(DataTable.RowSelected, "#findings-table")
    def _on_finding_selected(self, event: DataTable.RowSelected) -> None:
        self._show_finding_detail(event.row_key.value)

    def _show_finding_detail(self, finding_id: str | None) -> None:
        if not finding_id:
            return
        try:
            finding = self._ledger.get_finding(finding_id)
            evidence_rows = [
                item
                for item in self._ledger.evidence(finding.run_id)
                if item["id"] in finding.evidence_ids
            ]
        except Exception:
            return
        detail = self._render_finding(finding, evidence_rows)
        self.finding_detail_text = _renderable_text(detail)
        self.query_one("#finding-detail", Static).update(detail)

    def _render_finding(
        self, finding: Finding, evidence_rows: list[dict[str, Any]]
    ) -> RichTable:
        table = RichTable(show_header=False, box=box.SIMPLE_HEAD, expand=True, pad_edge=False)
        table.add_column("field", style="bold dim", no_wrap=True)
        table.add_column("value")

        status = _status_cell(finding.status)
        severity = _severity_cell(finding.severity)
        title_line = Text.assemble(
            (f"{finding.id}  ", "bold cyan"),
            (finding.title, "bold"),
        )
        meta_line = Text.assemble(
            ("severity ", "dim"), severity, ("    status ", "dim"), status,
            ("    cwe ", "dim"), (finding.cwe or "—", ""),
        )
        table.add_row("", title_line)
        table.add_row("", meta_line)
        table.add_row("key", finding.key)
        request = f"{finding.method} {finding.endpoint}"
        if finding.param:
            request += f"  ·  param: {finding.param}"
        table.add_row("request", Text(request))
        if finding.payload_used:
            table.add_row("payload", Text(finding.payload_used, style="italic"))
        for label, body in (
            ("description", finding.description),
            ("impact", finding.impact),
            ("remediation", finding.remediation),
        ):
            if body:
                table.add_row(label, Text(body))
        label = f"evidence ({len(evidence_rows)})"
        if not evidence_rows:
            table.add_row(label, Text("none bound", style="dim italic"))
            return table
        first = True
        for item in evidence_rows:
            digest = Text(f"sha256={item['sha256'][:12]}…", style="dim")
            head = Text.assemble(
                (f"{item['id']}  ", "bold"),
                (f"{item['kind']}  ", "italic"),
            )
            row_label = label if first else ""
            first = False
            table.add_row(row_label, Text.assemble(head, "  ", digest))
            excerpt = json.dumps(item["data"], indent=2, sort_keys=True, default=str)
            if len(excerpt) > EVIDENCE_EXCERPT_CHARS:
                excerpt = excerpt[: EVIDENCE_EXCERPT_CHARS - 1] + "…"
            table.add_row("", Text(excerpt, style="grey62"))
        return table

    # -- events tail ----------------------------------------------------------

    def _event_line(self, event: Event) -> str:
        payload = json.dumps(event.payload, sort_keys=True, default=str)
        if len(payload) > PAYLOAD_WIDTH:
            payload = payload[: PAYLOAD_WIDTH - 1] + "…"
        kind = event.kind_value()
        style = KIND_STYLES.get(kind, "white")
        return f"[dim]#{event.seq:>4}[/] [{style}]{escape(kind):<24}[/] {escape(payload)}"

    def _write_new_events(self, events: list[Event]) -> None:
        log = self.query_one("#events-log", RichLog)
        fresh = [event for event in events if event.seq > self._last_seq]
        for event in fresh:
            log.write(self._event_line(event))
            self._last_seq = event.seq
        if self._last_seq == 0 and not log.lines:
            log.write(Text("No events yet — press d to run the demo scan.", style="dim italic"))

    # -- doctor ----------------------------------------------------------------

    def _state_display(self) -> Path:
        if self._state_dir is not None:
            return self._state_dir
        env = os.environ.get("HUNTER_STATE_DIR")
        if env:
            return Path(env)
        return Path.cwd() / ".hunter"

    def _doctor_report(self) -> RichTable:
        table = RichTable(
            title="Doctor",
            show_header=False,
            box=box.SIMPLE,
            expand=True,
            pad_edge=False,
        )
        table.add_column("check", style="bold", no_wrap=True)
        table.add_column("result")

        table.add_row(
            "python",
            Text(f"{platform.python_version()}  ({sys.executable})", style="cyan"),
        )
        table.add_row("hunteros", Text(_package_version(), style="cyan"))

        for dep in ("textual", "rich", "httpx", "typer"):
            try:
                table.add_row(f"dep: {dep}", Text(metadata.version(dep), style="green"))
            except Exception:
                table.add_row(f"dep: {dep}", Text("MISSING", style="bold red"))

        state_dir = self._state_display()
        db_path = state_dir / "ledger.db"
        table.add_row("state dir", str(state_dir))
        if db_path.exists():
            size_kb = db_path.stat().st_size / 1024
            table.add_row("ledger db", f"{db_path}  ({size_kb:.1f} KB)")
        else:
            table.add_row("ledger db", Text("not created yet (runs will create it)", style="dim"))

        try:
            report = self._ledger.verify_chain()
            if report.ok:
                table.add_row(
                    "ledger chain", Text(f"OK — {report.checked} events verified", style="green")
                )
            else:
                where = f" at seq {report.broken_at_seq}" if report.broken_at_seq is not None else ""
                table.add_row("ledger chain", Text(f"BROKEN{where}", style="bold red"))
        except Exception as error:
            table.add_row("ledger chain", Text(f"unavailable ({error})", style="red"))

        for name, module in (
            ("deterministic", "hunter.engine.deterministic"),
            ("mock", "hunter.engine.mock"),
        ):
            style = "green" if _module_available(module) else "bold red"
            state = "available" if _module_available(module) else "unavailable"
            table.add_row(f"engine: {name}", Text(state, style=style))
        if _module_available("litellm"):
            table.add_row("engine: llm", Text("available (litellm installed)", style="green"))
        else:
            table.add_row(
                "engine: llm",
                Text("needs litellm — pip install 'hunteros-harness[llm]'", style="dim"),
            )

        workflow_ok = _module_available("hunter.workflow.pipeline") and _module_available(
            "hunter.workflow.bench"
        )
        if workflow_ok:
            table.add_row("workflow", Text("available (pipeline + bench)", style="green"))
        else:
            table.add_row("workflow", Text("not landed yet (v0.2)", style="dim"))

        return table


def run() -> None:
    """Entry point for ``hunter tui`` and ``python -m hunter.tui.app``."""
    HunterTui().run()


if __name__ == "__main__":
    run()
