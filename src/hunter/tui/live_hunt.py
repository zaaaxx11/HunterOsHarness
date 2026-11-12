"""Live hunt monitoring pane for the Textual TUI.

Reads ``hunt_state.json`` every refresh tick and shows:
  - cycles, findings (total / verified / in_code / proven_live)
  - per-lane status (architect, redteam, fuzzer, chainer)
  - stop reason, elapsed time, idle settings
  - recent findings feed (last 10)
  - deep-dive status

This is a VIEW — it never writes state, only reads. Connect to the main
app via ``compose()`` and a periodic ``set_interval(5, self.action_refresh)``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.widget import Widget


# Paleta tosca (same as the rest of the TUI)
_TOSCA = "#00FFE5"
_DIM = "#555555"
_RED = "#FF5555"
_AMBER = "#FFB86C"
_GREEN = "#50FA7B"


def _load_state() -> dict[str, Any] | None:
    """Read hunt_state.json from the standard location."""
    paths = [
        Path(os.path.expanduser("~/.hunter/hunt_state.json")),
        Path(os.path.expanduser("~/.hunter/sessions")),
    ]
    for p in paths:
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return None
        if p.is_dir():
            # try every subdir
            for child in sorted(p.rglob("hunt_state.json")):
                try:
                    return json.loads(child.read_text(encoding="utf-8"))
                except Exception:
                    continue
    return None


def _count_by_status(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        if isinstance(f, dict):
            st = f.get("status", "?")
            counts[st] = counts.get(st, 0) + 1
    return counts


def build_hunt_panel(state: dict[str, Any] | None) -> RenderableType:
    """Return a Rich renderable for the live hunt dashboard."""
    if state is None:
        return Panel(
            Text("No active hunt.  Start one with\n  `loop.run(target=..., wall_seconds=21600)`",
                 style="dim"),
            title="[bold]Live Hunt[/bold]",
            border_style=_DIM,
        )

    findings = state.get("findings", [])
    counts = _count_by_status(findings)
    clock = state.get("clock", {})
    elapsed = clock.get("elapsed_sec", 0)
    remaining = clock.get("remaining_sec", 0)
    cycles = clock.get("cycles", 0)
    phase = state.get("phase", "?")
    verdict = state.get("verdict", "")
    empty = clock.get("empty_streak", 0)

    # ---- summary line ----
    elapsed_s = f"{elapsed}s" if elapsed < 3600 else f"{elapsed//3600}h{(elapsed%3600)//60}m"
    total = len(findings)
    verified = counts.get("verified", 0) + counts.get("proven_live", 0)
    in_code = counts.get("in_code", 0)

    header = Text()
    header.append(f" Cycles {cycles}  ", style=f"bold {_TOSCA}")
    header.append(f"Findings {total} ", style="bold white")
    if verified:
        header.append(f"⭐{verified} ", style=f"bold {_GREEN}")
    header.append(f"⏱ {elapsed_s}", style=_DIM)
    if remaining > 0:
        rem = f"{remaining}s" if remaining < 3600 else f"{remaining//3600}h{(remaining%3600)//60}m"
        header.append(f" rem {rem}", style=_DIM)
    if empty >= 3:
        header.append("  idle streak!", style=_RED)

    # ---- status table ----
    table = Table.grid(padding=(0, 2))
    table.add_column(style="white", width=12)
    table.add_column(style=_DIM, width=10)
    table.add_column(style="white", width=12)

    rows: list[tuple[str, str, str, str]] = [
        ("phase", phase, "stop", verdict or "running"),
    ]
    for st, label, color in [("in_code", "in-code", _TOSCA),
                              ("verified", "verified", _GREEN),
                              ("proven_live", "PROVEN", f"bold {_GREEN}"),
                              ("unverified", "unverified", _AMBER),
                              ("refuted", "refuted", _RED)]:
        if counts.get(st):
            rows.append(("", "", label, f"[{color}]{counts[st]}[/{color}]"))

    for _key, _val, _label, _detail in rows:
        table.add_row(_key, _val, _label, _detail)

    # ---- recent findings (last 8) ----
    recent = [f for f in findings[-8:] if isinstance(f, dict)]
    feed = Text()
    for f in reversed(recent):
        title = str(f.get("title", ""))[:60]
        st = f.get("status", "?")
        color = {"verified": _GREEN, "proven_live": _GREEN,
                 "in_code": _TOSCA, "unverified": _AMBER,
                 "refuted": _RED}.get(st, _DIM)
        feed.append(f"  ● {title}", style=color)
        feed.append("\n")

    # assemble
    body = Table.grid(padding=(0, 2))
    body.add_column()
    body.add_row(header)
    if rows:
        body.add_row("")
        body.add_row(table)
    if recent:
        body.add_row("")
        body.add_row(Text("recent:", style=_DIM))
        body.add_row(feed)

    return Panel(
        body,
        title="[bold]🔴 LIVE HUNT[/bold]" if not verdict else
              f"[bold]{'⭐ DONE' if verdict else '🟡 IDLE'}[/bold]",
        border_style=_TOSCA if not verdict else (_GREEN if verdict else _DIM),
    )


class LiveHuntPane(Widget):
    """A widget that auto-refreshes the live hunt panel every 5 seconds."""

    DEFAULT_CSS = """
    LiveHuntPane {
        height: auto;
        min-height: 8;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._state_paths: list[Path] = []

    def on_mount(self) -> None:
        self.set_interval(5, self._refresh)

    def _refresh(self) -> None:
        state = _load_state()
        panel = build_hunt_panel(state)
        self.update(panel)