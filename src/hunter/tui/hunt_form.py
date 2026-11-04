"""Hunt form — Textual widget with input fields and confirm screen.

Used inside the Hunt tab. Collects target, time, budget, goals, loop idle,
model override, then shows a confirm overlay before launching the loop.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from rich.text import Text as RichText
from textual import work
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, Static


class HuntForm(Vertical, can_focus=True):
    """Collect hunt parameters and launch `hunter loop`."""

    def __init__(self, *, state_dir: str = "~/.hunter", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._state_dir = str(Path(state_dir).expanduser())

    def compose(self) -> Any:
        yield Label("[bold]HUNT MODE[/bold] — configure your hunt", id="hunt-form-title")
        yield Label("Target (URL, dir, or repo)", classes="form-label")
        yield Input(placeholder="/home/user/project or https://target.com", id="hf-target")
        yield Label("Time — minimum wall time in seconds (e.g. 3600 = 1h)", classes="form-label")
        yield Input(placeholder="3600", value="21600", id="hf-time")
        yield Label("Budget in USD (optional, 0 = unlimited)", classes="form-label")
        yield Input(placeholder="0", value="0", id="hf-budget")
        yield Label("Goals — comma-separated (e.g. rce-proven-live:1,findings-min:500)", classes="form-label")
        yield Input(
            placeholder="rce-proven-live:1",
            value="rce-proven-live:1,findings-min:500",
            id="hf-goals",
        )
        yield Label("Loop idle seconds between cycles", classes="form-label")
        yield Input(placeholder="15", value="15", id="hf-idle")
        yield Label("Model (optional — leave blank for config default)", classes="form-label")
        yield Input(placeholder="auto", value="", id="hf-model")
        yield Label("Session name (optional)", classes="form-label")
        yield Input(placeholder="hunt-session", value="", id="hf-session")
        yield Label("Scope manifest path (optional)", classes="form-label")
        yield Input(placeholder="scope.json", value="", id="hf-scope")
        with Horizontal(id="hf-actions"):
            yield Button("✗ Cancel", id="hf-cancel", variant="default")
            yield Button("▶ Launch Hunt", id="hf-launch", variant="primary")
        yield Static("Ready.", id="hf-status")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hf-cancel":
            self._clear()
        elif event.button.id == "hf-launch":
            self._confirm_and_launch()

    def _read_form(self) -> dict[str, str]:
        return {
            "target": self.query_one("#hf-target", Input).value.strip(),
            "time": self.query_one("#hf-time", Input).value.strip() or "21600",
            "budget": self.query_one("#hf-budget", Input).value.strip() or "0",
            "goals": self.query_one("#hf-goals", Input).value.strip(),
            "idle": self.query_one("#hf-idle", Input).value.strip() or "15",
            "model": self.query_one("#hf-model", Input).value.strip(),
            "session": self.query_one("#hf-session", Input).value.strip(),
            "scope": self.query_one("#hf-scope", Input).value.strip(),
        }

    def _clear(self) -> None:
        self.query_one("#hf-status", Static).update("Cancelled.")

    def _confirm_and_launch(self) -> None:
        form = self._read_form()
        if not form["target"]:
            self.query_one("#hf-status", Static).update("[red]Target is required.[/red]")
            return

        status = self.query_one("#hf-status", Static)
        lines = [
            f"Target:      {form['target']}",
            f"Time (min):  {form['time']}s",
            f"Budget:      ${form['budget']}",
            f"Goals:       {form['goals']}",
            f"Idle:        {form['idle']}s",
        ]
        if form["model"]:
            lines.append(f"Model:       {form['model']}")
        if form["session"]:
            lines.append(f"Session:     {form['session']}")

        status.update("[bold green]CONFIRMED — launching...[/bold green]\n" + "\n".join(lines))
        self._launch(form)

    @work(exclusive=True, group="hunt-launch", exit_on_error=False)
    async def _launch(self, form: dict[str, str]) -> None:
        import subprocess
        import sys

        status = self.query_one("#hf-status", Static)
        state = self._state_dir

        cmd = [
            sys.executable, "-m", "hunter", "loop",
            form["target"],
            "--time", form["time"],
            "--goals", form["goals"],
            "--idle", form["idle"],
            "--state", state,
            "--yes",
        ]
        if form["budget"] and form["budget"] != "0":
            cmd += ["--budget", form["budget"]]
        if form["model"]:
            cmd += ["--engine", form["model"]]
        if form["scope"]:
            cmd += ["--scope", form["scope"]]

        status.update("[bold yellow]Hunt running — check Dashboard (tab 4) for progress...[/bold yellow]")

        # Run in background thread so TUI stays alive
        try:
            await asyncio.to_thread(
                subprocess.run, cmd, check=False, timeout=28800  # max 8h
            )
            status.update("[bold green]Hunt finished — check the Findings tab.[/bold green]")
        except subprocess.TimeoutExpired:
            status.update("[bold yellow]Hunt time limit reached (8h max).[/bold yellow]")
        except Exception as exc:
            status.update(f"[red]Hunt error: {exc}[/red]")