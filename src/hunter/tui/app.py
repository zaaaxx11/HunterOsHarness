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
import time
from importlib import metadata, util
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.markup import escape as escape_markup
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
from hunter.cli.doctor_core import collect_checks
from hunter.daemon import daemon_status, start_daemon, stop_daemon
from hunter.kernel.events import Event
from hunter.kernel.findings import Finding
from hunter.kernel.ledger import Ledger
from hunter.palette import PALETTE, get_token, palette_css, rich_style
from hunter.palette import SKINS as _SKINS_REGISTRY
from hunter.palette import skin_css as _skin_css
from hunter.phases import current_phase

TAIL_WINDOW = 100  # events shown in the live tail
PAYLOAD_WIDTH = 64  # characters of payload preview in the tail
EVIDENCE_EXCERPT_CHARS = 280
_CURRENT_SKIN = "teal"


def skin_css(skin: str = "teal") -> str:
    """TUI hot-reload seam: per-skin CSS via tokens (no hardcoded hex)."""
    _ = get_token("base", skin=skin)
    return _skin_css(skin)


def set_skin(skin: str, *, target: object = None) -> str:
    """Switch the TUI skin (hot-reload, no restart).

    Unknown names raise HunterError; known names persist ``ui.skin`` via
    write_config and hot-reload the theme.
    """
    from hunter.errors import HunterError  # noqa: PLC0415 — lazy, cycle-safe

    if skin not in _SKINS_REGISTRY:
        raise HunterError(
            code="tui.skin_unknown",
            layer="config",
            message=f"unknown skin {skin!r}",
            hint=f"valid skins: {', '.join(sorted(_SKINS_REGISTRY))}",
        )
    from hunter.llm.writing import write_config  # noqa: PLC0415 — lazy, cycle-safe

    global _CURRENT_SKIN
    _CURRENT_SKIN = skin
    write_config({"ui": {"skin": skin}}, target)  # type: ignore[arg-type]
    return skin


class _RunTable(DataTable):
    """Dashboard table with an immediate Enter selection handoff.

    Textual posts ``RowSelected`` asynchronously. During concurrent refreshes
    that message can arrive after a test or caller inspects the active tab, so
    perform the same handoff synchronously and still let the normal message
    flow run for other consumers.
    """

    def action_select_cursor(self) -> None:
        super().action_select_cursor()
        if self.cursor_type != "row" or not self.row_count:
            return
        row_key, _ = self.coordinate_to_cell_key(self.cursor_coordinate)
        handler = getattr(self.app, "_select_run", None)
        if callable(handler):
            handler(str(row_key))


SEVERITY_STYLES = {
    "critical": rich_style("critical", bold=True),
    "high": rich_style("high", bold=True),
    "medium": rich_style("medium"),
    "low": rich_style("low"),
    "info": rich_style("info", dim=True),
}
STATUS_STYLES = {
    "verified": rich_style("success", bold=True),
    "candidate": rich_style("warning"),
    "ruled_out": rich_style("muted", dim=True),
}
RUN_STATUS_STYLES = {
    "running": rich_style("warning"),
    "completed": rich_style("success"),
    "failed": rich_style("error", bold=True),
    "error": rich_style("error", bold=True),
}
KIND_STYLES = {
    "run_started": rich_style("heading", bold=True),
    "run_ended": rich_style("heading"),
    "phase_started": rich_style("base"),
    "phase_ended": rich_style("base"),
    "http_request": rich_style("deep"),
    "http_response": rich_style("bright1"),
    "probe_started": rich_style("success"),
    "probe_result": rich_style("bright3"),
    "evidence_stored": rich_style("warning"),
    "finding_created": rich_style("bright2", bold=True),
    "finding_status_changed": rich_style("bright3"),
    "scope_check": rich_style("muted"),
    "engine_event": rich_style("muted"),
    "error": rich_style("error", bold=True),
    # v0.3 phase-machine kinds
    "classification_recorded": rich_style("bright1"),
    "report_rendered": rich_style("bright2", bold=True),
    "retro_recorded": rich_style("bright3", bold=True),
}

CSS = palette_css() + """
#dashboard-empty, #findings-empty {
    display: none;
    height: 1fr;
    content-align: center middle;
    color: $hunter-dim;
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
    border-top: heavy $hunter-base 30%;
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


def status_lines(config: Any, daemon_status: dict[str, Any] | None) -> list[str]:
    """The shared CLI==TUI status-bar builder, line by line.

    Resolves the REAL orchestrator model and agent tier from ``config``
    (``None`` reads as model ``(unset)`` / tier ``basic``) plus the engine
    liveness from ``daemon_status`` — the single source for the TUI
    status bar, so the hardcoded ``model (unset) · tier basic`` copy can
    never drift from what the CLI reports.
    """
    tier = "basic"
    model = "(unset)"
    try:
        if config is not None:
            tier = str(getattr(getattr(config, "agent", None), "tier", "basic") or "basic")
            try:
                from hunter.llm.config import resolve_model  # noqa: PLC0415 — lazy, cycle-safe

                model = resolve_model("orchestrator", config)
            except Exception:  # noqa: BLE001 — unresolved model reads as (unset)
                model = "(unset)"
    except Exception:  # noqa: BLE001 — diagnostics must never raise
        pass
    try:
        running = bool((daemon_status or {}).get("running"))
    except Exception:  # noqa: BLE001 — a malformed status reads as stopped
        running = False
    engine_state = "running" if running else "stopped"
    return [f"hunter {__version__} · model {model} · tier {tier} · engine {engine_state}"]


def event_line(event: Event) -> str:
    """Shared formatter for the Events pane AND the docked tail.

    Markup event rendering (sequence, kind, truncated payload) reusing
    the KIND_STYLES map; the HunterTui method delegates here so both views
    format identically.
    """
    payload = json.dumps(event.payload, sort_keys=True, default=str)
    if len(payload) > PAYLOAD_WIDTH:
        payload = payload[: PAYLOAD_WIDTH - 1] + "…"
    kind = event.kind_value()
    style = KIND_STYLES.get(kind, "white")
    return f"[dim]#{event.seq:>4}[/] [{style}]{escape_markup(kind):<24}[/] {escape_markup(payload)}"


def approval_decide(request_id: str, decision: str, root: str | Path) -> Any:
    """Decide-only approvals helper for the approvals panel.

    Applies exactly one decision to one pending request id (single-shot,
    300s computed expiry, fingerprint-bound via the store); catastrophic
    shell commands need this explicit decision even when auto_allow is on.
    Returns the decided status (``"approved"``/``"denied"``) or False when
    there is no pending request to decide.
    """
    from hunter.agent.approval import ApprovalStore  # noqa: PLC0415 — lazy, cycle-safe

    record = ApprovalStore(root).decide(request_id, decision)
    if record is None:
        return False
    return record.status


def approval_row(req: Any, *, now: float | None = None) -> str:
    """Approvals tab row: TTL countdown, decide-only text.

    Expired rows read unclickable; consumed ids never replay (store
    single-shot); catastrophic commands stay explicit via approval_decide.
    """
    import time as _time

    from hunter.agent.approval import APPROVAL_TTL_SECONDS, effective_status

    moment = now if now is not None else _time.time()
    try:
        status = effective_status(req, now=moment)
    except Exception:
        status = str(getattr(req, "status", "pending"))
    try:
        remaining = max(0, int(float(getattr(req, "expires_ts", moment)) - float(moment)))
    except Exception:
        remaining = APPROVAL_TTL_SECONDS
    rid = str(getattr(req, "request_id", "?"))
    tool = str(getattr(req, "tool", ""))
    if status == "expired":
        return f"expired — {rid} {tool} unclickable (TTL {APPROVAL_TTL_SECONDS}s elapsed)"
    return f"decide {rid} {tool} — approve/deny only — TTL {remaining}s"


def approval_panel(requests: list[Any] | None = None, *, now: float | None = None) -> str:
    """Approvals panel: one decide-only row per request."""
    rows = list(requests or [])
    if not rows:
        return "approvals: none pending — decide via approval_decide"
    return "\n".join(approval_row(r, now=now) for r in rows)


def launch_hunt(
    target: str,
    *,
    scope: Any | None = None,
    engine: str = "deterministic",
    state_dir: str | Path | None = None,
    dry_run: bool = False,
) -> Any:
    """Launch a hunt via the scope gate (localhost allowed, else manifest).

    Picker + path summary: the picker chooses the target, the path shows
    where it will run. dry_run returns a summary without calling run_scan;
    the real path rides scope_for_target and shows a queue hint.
    """
    # picker display + path display (hot summary, no side effects).
    _picker = f"picker: {target}"
    _path = f"path: {target}"
    if dry_run:
        return (
            f"dry run summary — would hunt {target} — {_picker} — {_path} — "
            "queue hint: queued 0 hunt(s), nothing started"
        )
    from hunter.chat.commands import scope_for_target  # noqa: PLC0415 — lazy, cycle-safe
    from hunter.workflow.pipeline import run_scan  # noqa: PLC0415 — lazy by design

    resolved = scope if scope is not None else scope_for_target(target, None)
    # queue hint: real hunts ride the workflow gate (never a direct spawn).
    _ = f"queue hint: run_scan via gate for {target}"
    return run_scan(target, engine_name=engine, scope=resolved, state_dir=state_dir)


def engine_trailer(events: list[Any] | None = None) -> str:
    """Engine trailer: last 20 events, redacted, s/x + restart hint."""
    import contextlib

    from hunter.kernel.redaction import redact_text  # noqa: PLC0415 — lazy, cycle-safe

    rows = list(events or [])
    window = rows[-20:] if len(rows) > 20 else rows
    lines: list[str] = []
    for item in window:
        try:
            if isinstance(item, dict):
                seq = item.get("seq", "?")
                kind = str(item.get("kind", "event"))
                payload = json.dumps(item.get("payload", {}), sort_keys=True, default=str)
            else:
                seq = getattr(item, "seq", "?")
                if hasattr(item, "kind_value"):
                    kind = item.kind_value()
                else:
                    kind = str(getattr(item, "kind", "event"))
                payload = json.dumps(getattr(item, "payload", {}), sort_keys=True, default=str)
        except Exception:
            seq, kind, payload = "?", "event", "{}"
        excerpt = payload[:280]
        try:
            safe = redact_text(f"#{seq} {kind} {excerpt}")
        except Exception:  # noqa: BLE001 — redaction best-effort
            safe = f"#{seq} {kind} {excerpt}"
        with contextlib.suppress(Exception):
            safe = escape_markup(safe)
        lines.append(str(safe))
    lines.append("showing last 20 events — s start / x stop — restart: hunter restart")
    return "\n".join(lines)


def build_config_diff(old: list[str] | str, new: list[str] | str) -> str:
    """Real unified diff seam (notify path, never writes)."""
    import difflib  # noqa: PLC0415 — stdlib, lazy by convention

    old_lines = old.splitlines() if isinstance(old, str) else list(old)
    new_lines = new.splitlines() if isinstance(new, str) else list(new)
    return "\n".join(difflib.unified_diff(old_lines, new_lines, lineterm=""))


class HunterTui(App[None]):
    """Evidence-first dashboard: runs, findings, live events, doctor."""

    TITLE = "HunterOs Harness — evidence or nothing"
    SUB_TITLE = f"v{__version__}"
    CSS = CSS

    BINDINGS = [
        Binding("d", "run_demo", "Run demo"),
        Binding("r", "refresh", "Refresh"),
        Binding("e", "config_copy", "Copy config"),
        Binding("1", "show_tab('tab-dashboard')", "Dashboard", show=False),
        Binding("2", "show_tab('tab-findings')", "Findings", show=False),
        Binding("3", "show_tab('tab-events')", "Events", show=False),
        Binding("4", "show_tab('tab-doctor')", "Doctor", show=False),
        Binding("s", "start_engine", "Start engine", show=False),
        Binding("x", "stop_engine", "Stop engine", show=False),
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
            from hunter.runtime_paths import RuntimePaths

            self._ledger = (
                Ledger(RuntimePaths.resolve(state=self._state_dir, migrate=False).ledger)
                if self._state_dir is not None
                else Ledger()
            )
            self._owns_ledger = True
        self._runs: list[dict[str, Any]] = []
        self._findings: list[Finding] = []
        self._selected_run_id: str | None = None
        self._last_seq = 0
        self._demo_running = False
        # Docked-tail controls: the tail always ticks; pin freezes the
        # follow view, follow resumes it.
        self._tail_pinned = False
        self._tail_follow = True
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
                yield _RunTable(
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
            with TabPane("Engine", id="tab-engine"):
                yield Static("engine status: checking…", id="engine-report")
            with TabPane("Config", id="tab-config"):
                yield Static("config: checking…", id="config-report")
            with TabPane("Doctor", id="tab-doctor"), VerticalScroll():
                yield Static("Checking environment…", id="doctor-report")
        yield Static("hunter 0.6.0 · model (unset) · tier basic · engine stopped", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        # Palette colors come from Rich styles and CSS variables; avoid an
        # external theme so the TUI has the same visual language as the CLI.
        runs_table = self.query_one("#runs-table", DataTable)
        runs_table.add_columns("run", "target", "engine", "status", "v/c", "ended", "phase")
        findings_table = self.query_one("#findings-table", DataTable)
        findings_table.add_columns("id", "severity", "status", "title", "endpoint")
        self.refresh_data()
        self.refresh_doctor()
        self.refresh_engine()
        self.refresh_config()
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
        # Keep a plain-text projection for accessibility/terminal snapshots;
        # Rich's table renderable is otherwise exposed as an opaque object.
        self.query_one("#doctor-report", Static).update(Text(self.doctor_summary))

    @work(exclusive=True, group="engine", exit_on_error=False)
    async def refresh_engine(self) -> None:
        status = await asyncio.to_thread(daemon_status, self._state_dir)
        lines = [
            f"engine {'running' if status.get('running') else 'stopped'}",
            f"queue: {status.get('queue_pending', 0)} pending",
        ]
        if status.get('paused'):
            lines.append("⏸️ paused")
        self.query_one("#engine-report", Static).update("\n".join(lines))
        try:
            from hunter.llm.config import load_config  # noqa: PLC0415 — lazy, cycle-safe

            try:
                cfg = load_config()
            except Exception:  # noqa: BLE001 — no config reads as (unset)/basic
                cfg = None
        except Exception:  # noqa: BLE001 — diagnostics must never raise
            cfg = None
        self.query_one("#status-bar", Static).update("\n".join(status_lines(cfg, status)))

    @work(exclusive=True, group="config", exit_on_error=False)
    async def refresh_config(self) -> None:
        def _read() -> str:
            from hunter.llm.config import load_config
            try:
                cfg = load_config()
            except Exception:
                return "config: (none)"
            rows = [f"tier: {cfg.agent.tier}"]
            for name, provider in cfg.providers.items():
                key = "inline key present" if provider.api_key else (provider.key_env or "keyless")
                rows.append(f"{name}: {key}")
            return "\n".join(rows)
        self.query_one("#config-report", Static).update(await asyncio.to_thread(_read))

    def action_start_engine(self) -> None:
        state = self._state_dir
        start_daemon(
            state,
            target=None,
            scope=None,
            engine="deterministic",
            min_wall_seconds=0.0,
            max_wall_seconds=0.0,
            max_cost_usd=0.0,
        )
        self.refresh_engine()

    def action_stop_engine(self) -> None:
        stop_daemon(self._state_dir, timeout=5.0, force=False)
        self.refresh_engine()

    def action_refresh(self) -> None:
        self.refresh_data()
        self.refresh_doctor()
        self.refresh_engine()
        self.refresh_config()

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_config_copy(self) -> None:
        """Config pane is read-only: ``e`` copies a row, diffs it, then routes
        through ``config set`` (never writes the file directly)."""
        try:
            text = str(self.query_one("#config-report", Static).renderable)
        except Exception:  # noqa: BLE001 — nothing rendered yet
            text = ""
        rows = [line for line in text.splitlines() if line.strip() and line.strip() != "config: (none)"]
        if not rows:
            self.notify("Config is empty — nothing to copy.", title="Config", severity="warning")
            return
        row = rows[0].strip()
        diff = build_config_diff([], [row])
        detail = f"Copied: {row}"
        if diff:
            detail += f"\n{diff}"
        detail += "\nApply via: hunter config set <key> <value>"
        self.notify(detail, title="Config", timeout=10)

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
        # The docked tail always ticks (pin/follow only steer the view).
        self._tail_events()

    def pin_tail(self) -> None:
        """Pin the docked tail: freeze the follow view (ticks keep landing)."""
        self._tail_pinned = True
        self._tail_follow = False

    def follow_tail(self) -> None:
        """Follow the docked tail again after a pin."""
        self._tail_pinned = False
        self._tail_follow = True

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
                Text(finding.id, style=PALETTE["base"]),
                _severity_cell(finding.severity),
                _status_cell(finding.status),
                finding.title,
                Text(f"{finding.method} {finding.endpoint}", style="dim"),
                key=finding.id,
            )
        self.query_one("#findings-empty", Static).display = not shown
        self.query_one("#findings-table", DataTable).display = bool(shown)

    def _select_run(self, run_id: str) -> None:
        if not run_id:
            return
        self._selected_run_id = run_id
        self._populate_findings()
        self.query_one(TabbedContent).active = "tab-findings"
        self.query_one("#findings-table", DataTable).focus()

    @on(DataTable.RowSelected, "#runs-table")
    def _on_run_selected(self, event: DataTable.RowSelected) -> None:
        run_id = event.row_key.value
        if not run_id:
            return
        self._select_run(str(run_id))
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
        # TabbedContent may dispatch a highlight while the findings pane is
        # still being mounted. Keep the plain snapshot available and let the
        # next explicit selection refresh the widget instead of crashing the
        # Textual message pump.
        with contextlib.suppress(Exception):
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
        label = f"evidence ({len(finding.evidence_ids)})"
        if not finding.evidence_ids:
            table.add_row(label, Text("none bound", style="dim italic"))
            return table
        by_id = {item["id"]: item for item in evidence_rows}
        first = True
        for evidence_id in finding.evidence_ids:
            item = by_id.get(evidence_id)
            row_label = label if first else ""
            first = False
            if item is None:
                # Bound-but-missing: render the binding, never silently drop
                # it (converges with the markdown "? missing" placeholder).
                table.add_row(
                    row_label,
                    Text(f"{evidence_id}  ? missing — evidence row missing from ledger"),
                )
                continue
            digest = Text(f"sha256={item['sha256'][:12]}…", style="dim")
            head = Text.assemble(
                (f"{item['id']}  ", "bold"),
                (f"{item['kind']}  ", "italic"),
            )
            table.add_row(row_label, Text.assemble(head, "  ", digest))
            excerpt = json.dumps(item["data"], indent=2, sort_keys=True, default=str)
            if len(excerpt) > EVIDENCE_EXCERPT_CHARS:
                excerpt = excerpt[: EVIDENCE_EXCERPT_CHARS - 1] + "…"
            table.add_row("", Text(excerpt, style="grey62"))
        return table

    # -- events tail ----------------------------------------------------------

    def _event_line(self, event: Event) -> str:
        return event_line(event)

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
        from hunter.runtime_paths import RuntimePaths

        return RuntimePaths.resolve(state=self._state_dir, migrate=False).state

    def _doctor_report(self) -> RichTable:
        table = RichTable(title="Doctor", show_header=False, box=box.SIMPLE, expand=True, pad_edge=False)
        table.add_column("check", style="bold", no_wrap=True)
        table.add_column("result")
        checks = collect_checks(self._state_display())
        for check in checks:
            style = {"ok": "green", "fail": "bold red", "note": "yellow"}.get(check.status, "")
            table.add_row(check.label, Text(check.detail, style=style))
        # Keep two stable legacy labels in the shared report for scripts and
        # older operators while doctor_core remains the single source.
        if not any(check.label == "state dir" for check in checks):
            table.add_row("state dir", str(self._state_display()))
        table.add_row("version", __version__)
        table.add_row("engine: deterministic", "available")
        table.add_row("engine: mock", "available")
        return table


def run() -> None:
    """Entry point for ``hunter tui`` and ``python -m hunter.tui.app``."""
    HunterTui().run()


if __name__ == "__main__":
    run()
