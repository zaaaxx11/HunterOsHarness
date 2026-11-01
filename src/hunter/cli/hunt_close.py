"""``hunter hunt close <run_id>`` — seal a run (RETENTION-SPEC Part A).

Click hands ``hunt close R-1`` to the ``hunt`` command (``close`` becomes the
positional target), so ``close`` rides the SAME verb-interception seam the
daemon verbs use: ``hunt`` checks its first positional against
:data:`hunt_close.HUNT_CLOSE_VERBS` on its first body line and delegates here
before any hunt path can touch the token. That keeps one dispatch rule for
``hunt <verb>`` instead of a rival command object that click could shadow.

Exit codes: 0 sealed · 1 unknown run / already closed / ledger error ·
2 usage (unknown ``--outcome``, missing ``--yes``-style argument errors are
click's own 2).

stdout discipline: with ``--json`` stdout carries ONLY the JSON document;
every human line and every error goes to stderr.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from hunter.kernel.runs import (
    OUTCOMES,
    RunAlreadyClosed,
    RunClosed,
    RunClosure,
    RunNotFound,
    close_run,
)
from hunter.palette import make_console

__all__ = ["HUNT_CLOSE_VERBS", "OUTCOME_CHOICES", "hunt_close"]

#: First-positional verbs owned by this module (intercepted by `hunt`).
HUNT_CLOSE_VERBS = ("close",)

#: Stable, sorted choice list for --help.
OUTCOME_CHOICES = sorted(OUTCOMES)

console = make_console()
err_console = make_console(stderr=True)


def _emit_json(payload: dict[str, Any]) -> None:
    typer.echo(json.dumps(payload, sort_keys=True, indent=2))


def _fail(json_out: bool, message: str, reason: str, code: int = 1) -> typer.Exit:
    """Classified refusal: human line on stderr, optional JSON error on stdout."""
    err_console.print(f"[hunter.error]{message}[/hunter.error]")
    if json_out:
        _emit_json({"error": message, "reason": reason, "status": "error"})
    return typer.Exit(code)


def hunt_close(
    run_id: Annotated[str, typer.Argument(help="Run id to seal (e.g. R-0001).")],
    outcome: Annotated[
        str | None,
        typer.Option(
            "--outcome",
            help=f"Override the derived outcome: {' | '.join(OUTCOME_CHOICES)}.",
            case_sensitive=False,
        ),
    ] = None,
    state: Annotated[
        Path | None, typer.Option("--state", help="State directory.")
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Machine-readable JSON on stdout.")
    ] = False,
) -> None:
    """Seal a run: write outcome/closed_at/summary, append a `run_closed` event.

    After sealing, the run refuses new evidence, findings and status changes;
    reading (report, verify, replay) is unaffected. Exits 0 on success.
    """
    from hunter.cli.main import _open_ledger

    if outcome is not None and outcome.strip().lower() not in OUTCOMES:
        raise _fail(
            json_out,
            f"BLOCKED: unknown outcome {outcome!r}; choose from {OUTCOME_CHOICES}.",
            "usage",
            code=2,
        )

    ledger = None
    try:
        ledger = _open_ledger(state)
        closure: RunClosure = close_run(ledger, run_id, outcome=outcome)
    except RunNotFound as exc:
        raise _fail(json_out, f"BLOCKED: {exc} — nothing was changed.", "not_found") from exc
    except RunAlreadyClosed as exc:
        raise _fail(
            json_out, f"BLOCKED: {exc} — the first seal stands.", "already_closed"
        ) from exc
    except RunClosed as exc:  # pragma: no cover - close_run never raises this
        raise _fail(json_out, f"BLOCKED: {exc}", "closed") from exc
    except ValueError as exc:  # defence in depth: same validation as close_run
        raise _fail(json_out, f"BLOCKED: {exc}", "usage", code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - unreadable ledger is a diagnosis
        raise _fail(
            json_out,
            f"ledger error: {type(exc).__name__}: {exc}",
            "ledger_error",
        ) from exc
    finally:
        if ledger is not None:
            ledger.close()

    if json_out:
        _emit_json(dict(closure.summary()))
    else:
        _render_human(closure)


def _render_human(closure: RunClosure) -> None:
    """Human summary on stdout (--json path keeps stdout pure via the caller)."""
    typer.echo(
        f"run {closure.run_id} closed: outcome {closure.outcome}"
    )
    typer.echo(
        f"  findings {closure.findings_total} ({closure.findings_proven} proven)"
        f" · evidence {closure.evidence_total} · events {closure.events_total}"
    )
    if closure.findings_by_severity:
        typer.echo(
            "  severities: "
            + ", ".join(f"{k}={v}" for k, v in closure.findings_by_severity.items())
        )
    if closure.promotions:
        typer.echo(f"  promotion candidates: {', '.join(closure.promotions)}")
    typer.echo("  sealed: no new evidence, findings or status changes.")


def dispatch_hunt_close(
    run_id: str,
    *,
    outcome: str | None = None,
    state: Path | None = None,
    json_out: bool = False,
) -> int:
    """Exit-code wrapper for the ``hunt`` verb seam (returns, never raises)."""
    try:
        hunt_close(run_id, outcome=outcome, state=state, json_out=json_out)
        return 0
    except typer.Exit as exc:
        return int(exc.exit_code)
