"""``hunter gc`` — archive-then-purge retention for runs and chat sessions.

Design contract (docs/RETENTION-SPEC.md, Part B):

* The live ledger is append-only by SQLite triggers. Purging therefore goes
  through :func:`hunter.archive.purge_run`, which drops the guards, deletes the
  rows and restores the guards inside one transaction. If anything fails the
  transaction rolls back and the live rows survive untouched.
* A run is only ever touched when it is *closed* and older than the cutoff.
  An open run is never archived, never purged — no matter how old it is.
* ``--dry-run`` reports what *would* happen and changes nothing: no archive
  file, no deleted row, no schema mutation.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import typer

from hunter.archive import gc_chat, gc_runs
from hunter.home import hunter_home
from hunter.kernel.ledger import Ledger


def _emit(payload: dict, as_json: bool) -> None:
    """Print the report. ``--json`` must be machine-pure: nothing else on stdout."""
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo("garbage-collect (retention)")
    typer.echo(f"  state:        {payload.get('state')}")
    typer.echo(f"  run_days:     {payload.get('run_days')}")
    typer.echo(f"  chat_days:    {payload.get('chat_days')}")
    typer.echo(f"  dry_run:      {payload.get('dry_run')}")
    runs = payload.get("runs", {})
    typer.echo("  runs:")
    for key in ("candidates", "archived", "purged", "skipped_open", "skipped_recent"):
        if key in runs:
            typer.echo(f"    {key:<15} {runs[key]}")
    chat = payload.get("chat", {})
    typer.echo("  chat:")
    for key in ("candidates", "deleted", "retained"):
        if key in chat:
            typer.echo(f"    {key:<15} {chat[key]}")


def _resolve_state(state: Path | None) -> Path:
    return Path(state) if state is not None else hunter_home()


def run_gc(
    *,
    state: Path | None = None,
    run_days: int = 30,
    chat_days: int = 7,
    dry_run: bool = False,
    now: float | None = None,
) -> dict:
    """Collect retention statistics and (unless dry-run) apply them."""
    base = _resolve_state(state)
    base.mkdir(parents=True, exist_ok=True)
    archive_dir = base / "archive"
    ledger_path = base / "ledger.db"
    chat_path = base / "chat.db"

    report: dict = {
        "status": "ok",
        "state": str(base),
        "run_days": run_days,
        "chat_days": chat_days,
        "dry_run": dry_run,
        # Flattened totals. The nested blocks below carry the detail, but the
        # contract tests (and cron triage) read these scalars directly, so a
        # missing key here is a silent contract break, not a cosmetic one.
        "candidates": 0,
        "archived": 0,
        "purged": 0,
        "skipped_open": 0,
        "skipped_recent": 0,
        "deleted": 0,
        "retained": 0,
        "runs": {"candidates": 0, "archived": 0, "purged": 0,
                 "skipped_open": 0, "skipped_recent": 0},
        "chat": {"candidates": 0, "deleted": 0, "retained": 0},
    }

    if ledger_path.exists():
        ledger = Ledger(ledger_path)
        try:
            stats = gc_runs(
                ledger,
                archive_dir,
                run_days=run_days,
                now=now,
                dry_run=dry_run,
            )
            report["runs"].update(stats)
            for _k in ("candidates", "archived", "purged",
                       "skipped_open", "skipped_recent"):
                report[_k] = report["runs"].get(_k, 0)
        finally:
            ledger.close()

    if chat_path.exists():
        store = _open_chat(chat_path)
        try:
            stats = gc_chat(store, chat_days=chat_days, now=now, dry_run=dry_run)
            report["chat"].update(stats)
            for _k in ("deleted", "retained"):
                report[_k] = report["chat"].get(_k, 0)
        finally:
            store.close()

    return report


def _open_chat(path: Path):
    from hunter.chat.sessions import ChatStore

    return ChatStore(path)


def register_gc_command(app: typer.Typer) -> None:
    """Attach the ``gc`` command to the root app."""

    @app.command("gc")
    def gc_cmd(
        state: Path | None = typer.Option(None, "--state", help="State directory."),
        run_days: int = typer.Option(30, "--run-days", help="Purge closed runs older than N days."),
        chat_days: int = typer.Option(7, "--chat-days", help="Delete chat rows older than N days."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Report only; change nothing."),
        apply: bool = typer.Option(False, "--apply", help="Apply the retention policy."),
        json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
    ) -> None:
        """Garbage-collect old runs (archive+purge) and expired chat sessions."""
        # --dry-run is the default posture: destroying evidence requires an
        # explicit --apply so a stray invocation can never erase a hunt.
        effective_dry = not apply
        if dry_run:
            effective_dry = True
        try:
            report = run_gc(
                state=state,
                run_days=run_days,
                chat_days=chat_days,
                dry_run=effective_dry,
                now=time.time(),
            )
        except (OSError, sqlite3.Error) as exc:
            if json_out:
                typer.echo(json.dumps({"status": "error", "error": str(exc)}))
            else:
                typer.echo(f"gc failed: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        _emit(report, json_out)
