"""``hunter daemon`` / ``hunt <verb>`` — the 24/7 hunt daemon CLI (M8 F2).

The daemon commands live here and are registered on the root Typer app by
:func:`register_daemon_commands` (called at the bottom of ``cli/main.py``):
the ``daemon`` sub-app PLUS the top-level ``start`` / ``stop`` / ``status``
aliases (so ``hunter start --target ...`` works).

Click dispatches ``hunt start --target URL`` to the ``hunt`` command (the
``start`` token becomes its positional target), so ``hunt`` itself delegates
daemon verbs through :func:`dispatch_hunt_alias` — which validates (start
requires ``--target``, the other verbs reject it), parses durations via
:mod:`hunter.duration`, and applies the SAME non-localhost scope gate as
``hunt``. Plain ``hunter hunt <URL>`` can never be misrouted: the verb check
fires only when the positional IS one of the five verbs.

Exit codes: status 0 always · stop 0 stopped / 1 not running · start 0 / 3
refused (no target, invalid target, scope refused, already running) / 8
config error (mirrors ``gateway start``) · logs 0 · restart = stop's code on
failure else start's.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated, Any

import typer

from hunter.daemon import (
    daemon_running,
    daemon_status,
    log_path,
    start_daemon,
    stop_daemon,
)
from hunter.palette import make_console

__all__ = [
    "HUNT_VERBS",
    "daemon_start",
    "dispatch_hunt_alias",
    "register_daemon_commands",
]

HUNT_VERBS = ("start", "stop", "status", "restart", "logs")

console = make_console()
err_console = make_console(stderr=True)

_DEFAULT_MAX_WALL_SECONDS = 7200.0  # 2h when neither --time nor config says otherwise


# -- shared internals ------------------------------------------------------------


def _resolve_state(state: Path | None) -> Path:
    """Explicit ``--state`` wins; else ``$HUNTER_STATE_DIR`` or ``./.hunter``
    (the Ledger default convention)."""
    if state is not None:
        return Path(state)
    import os

    return Path(os.environ.get("HUNTER_STATE_DIR") or ".hunter")


def _load_budget_config() -> tuple[Any | None, int]:
    """Load the harness config for budget defaults; a BROKEN config is the
    pinned exit-8 path (mirrors ``gateway start``). Returns (config, code)."""
    from hunter.errors import HunterError
    from hunter.llm.config import load_config

    try:
        return load_config(), 0
    except HunterError as exc:
        from hunter.cli.handle import handle_cli_error

        return None, handle_cli_error(exc, verbose=False)


def _resolve_engine(explicit: str | None) -> tuple[str, int]:
    """Validate ``--engine``; without one, mirror ``hunt``: the llm engine
    when a brain is configured, else the deterministic engine."""
    if explicit is not None:
        if explicit not in {"deterministic", "mock", "llm"}:
            err_console.print(
                "[hunter.error]BLOCKED:[/hunter.error] unknown engine; engines: deterministic, mock, llm"
            )
            return "", 3
        return explicit, 0
    try:
        from hunter.llm.config import find_config_path, load_config
        from hunter.llm.router import provider_from_config

        path = find_config_path()
        if path is None or not path.is_file():
            raise FileNotFoundError("no HunterOS LLM config")
        provider_from_config(load_config(path))
        return "llm", 0
    except Exception:  # noqa: BLE001 — the probe must never block a start
        err_console.print("no brain configured — using the deterministic engine.")
        return "deterministic", 0


def _scope_gate(target: str, scope: Path | None, *, yes: bool) -> tuple[Any | None, int]:
    """The SAME gate as ``hunt``: localhost is always allowed; anything else
    needs an authorized scope manifest (``--scope``, or ``--yes`` accepts the
    proposed minimal scope). Returns (ScopeSet | None, exit_code)."""
    from urllib.parse import urlparse

    from hunter.tools.scope import LOCAL_HOSTS, ScopeSet, localhost_scope, scope_from_manifest

    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError:
        err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] target {target!r} is not a valid URL.")
        return None, 3
    if host in LOCAL_HOSTS:
        return localhost_scope(), 0
    if scope is not None:
        try:
            return scope_from_manifest(scope), 0
        except (ValueError, OSError) as exc:
            err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] invalid scope manifest: {exc}")
            return None, 3
    if yes:
        return ScopeSet(frozenset({host}), False, name=host), 0
    err_console.print(
        f"[hunter.error]BLOCKED:[/hunter.error] target '{host}' is not localhost. Pass "
        "[bold]--scope scope.json[/bold] with an authorized scope manifest, "
        f"or --yes to authorize the proposed minimal scope for '{host}'."
    )
    return None, 3


def _parse_duration_or_exit(text: str | None, *, option: str) -> float | None:
    from hunter.duration import parse_duration
    from hunter.errors import HunterError

    if text is None:
        return None
    try:
        return parse_duration(text)
    except HunterError as exc:
        err_console.print(f"[hunter.error]config error:[/hunter.error] {exc.message}\nHint: {exc.hint}")
        raise typer.Exit(8) from exc


def _cmd_start(
    *,
    target: str | None,
    scope: Path | None,
    engine: str | None,
    time_text: str | None,
    min_time_text: str | None,
    budget_text: str | None = None,
    yes: bool,
    force: bool,
    state: Path | None,
) -> int:
    """Validate and start the persistent engine, optionally with one task."""
    state_dir = _resolve_state(state)
    already_running, _ = daemon_running(state_dir)
    if already_running and not force:
        typer.echo("engine already on — 24/7 engine is on")
        return 0
    from hunter.hunt import normalize_hunt_target

    normalized = None
    chosen_scope = None
    if target:
        normalized, kind = normalize_hunt_target(target)
        if kind == "invalid":
            err_console.print("[hunter.error]BLOCKED:[/hunter.error] invalid hunt target")
            return 3
        chosen_scope, code = _scope_gate(normalized, scope, yes=yes)
        if code:
            return code
    engine_name, code = _resolve_engine(engine)
    if code:
        return code
    max_wall = _parse_duration_or_exit(time_text, option="--time")
    min_wall = _parse_duration_or_exit(min_time_text, option="--min-time")
    if budget_text is None:
        max_cost = 0.0
    else:
        try:
            import math
            max_cost = float(budget_text)
            if not math.isfinite(max_cost) or max_cost < 0:
                raise ValueError
        except (TypeError, ValueError):
            err_console.print(
                "[hunter.error]config error:[/hunter.error] --budget must be a finite non-negative"
                " USD value"
            )
            return 8
    cfg, code = _load_budget_config()
    if code:
        return code
    budget = getattr(cfg, "budget", None)
    if target:
        if max_wall is None:
            max_wall = float(getattr(budget, "wall_seconds", 0.0) or 0.0) or _DEFAULT_MAX_WALL_SECONDS
        if min_wall is None:
            min_wall = float(getattr(budget, "min_wall_seconds", 0.0) or 0.0)
        if budget_text is None:
            max_cost = float(getattr(budget, "max_cost_usd", 0.0) or 0.0)
    else:
        max_wall = float(max_wall or 0.0)
        min_wall = float(min_wall or 0.0)
    code = start_daemon(
        state_dir,
        target=normalized,
        scope=chosen_scope,
        engine=engine_name,
        min_wall_seconds=min_wall or 0.0,
        max_wall_seconds=max_wall or 0.0,
        max_cost_usd=max_cost,
        force=force,
    )
    if code == 0:
        if not target:
            typer.echo("engine started — 24/7 engine is on")
        else:
            typer.echo(
                f"engine started — 24/7 engine is on\n"
                f"daemon started against {normalized} — state: {state_dir}\n"
                f"budget: min {min_wall:.0f}s / max {max_wall:.0f}s / ${max_cost:.2f} "
                f"· stop with: hunter stop"
            )
        return 0
    if code == 3:
        err_console.print(
            "[hunter.error]BLOCKED:[/hunter.error] daemon is already running (pass --force to replace it)."
        )
    else:
        err_console.print(
            "[hunter.error]daemon failed to start[/hunter.error] — see the log: " + str(log_path(state_dir))
        )
    return code


def _cmd_stop(*, state: Path | None, timeout: float, force: bool) -> int:
    state_dir = _resolve_state(state)
    code = stop_daemon(state_dir, timeout=timeout, force=force)
    if code == 0:
        typer.echo("daemon stopped.")
    else:
        typer.echo("daemon not running." if not force else "daemon did not stop cleanly.")
    return code


def _human_uptime(seconds: float | None) -> str:
    if seconds is None:
        return "unknown uptime"
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def _render_status(status: dict[str, Any], *, state_dir: Path) -> None:
    if status.get("running"):
        heartbeat = status.get("heartbeat_age_seconds")
        heartbeat_text = "heartbeat n/a" if heartbeat is None else f"heartbeat {heartbeat:.0f}s ago"
        console.print(
            f"daemon: [hunter.success]running[/hunter.success] (pid {status.get('pid')}, "
            f"up {_human_uptime(status.get('uptime_seconds'))}, {heartbeat_text})"
        )
    elif status.get("stale"):
        console.print(
            f"daemon: [hunter.error]stale[/hunter.error] (pid {status.get('pid')} — heartbeat too"
            " old, presumed dead)"
        )
    else:
        console.print("daemon: [hunter.warning]stopped[/hunter.warning]")
    typer.echo(f"state: {state_dir}")
    transports = status.get("transports") or []
    typer.echo("transports: " + (", ".join(transports) if transports else "(none)"))
    typer.echo(f"queue: {status.get('queue_pending', 0)} pending, {status.get('queue_claimed', 0)} claimed")
    last = status.get("last_run")
    if last:
        typer.echo(f"last run: {last.get('run_id')} {last.get('status')} ({last.get('findings')} findings)")
    else:
        typer.echo("last run: (none)")


def _cmd_status(*, state: Path | None, json_out: bool) -> int:
    state_dir = _resolve_state(state)
    status = daemon_status(state_dir)
    if json_out:
        typer.echo(json.dumps(status, indent=2))
    else:
        _render_status(status, state_dir=state_dir)
    return 0


def _cmd_logs(*, state: Path | None, lines: int | None, follow: bool) -> int:
    path = log_path(_resolve_state(state))
    if not path.is_file():
        typer.echo(f"no daemon log yet: {path}")
        return 0
    shown = 0
    content = path.read_text(encoding="utf-8", errors="replace")
    all_lines = content.splitlines()
    if lines is not None and lines >= 0:
        shown = max(0, len(all_lines) - lines)
    for line in all_lines[shown:]:
        typer.echo(line)
    shown = len(all_lines)
    if not follow:
        return 0
    try:
        while True:
            time.sleep(0.5)
            current = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(current) > shown:
                for line in current[shown:]:
                    typer.echo(line)
                shown = len(current)
    except KeyboardInterrupt:
        return 0


def _cmd_restart(
    *,
    target: str | None,
    scope: Path | None,
    engine: str | None,
    time_text: str | None,
    min_time_text: str | None,
    budget_text: str | None = None,
    yes: bool = False,
    force: bool = False,
    state: Path | None = None,
) -> int:
    """Stop (force on stale) then start; stop's code on failure, else start's."""
    from hunter.daemon import read_pid

    state_dir = _resolve_state(state)
    status = daemon_status(state_dir)
    if status.get("running"):
        code = stop_daemon(state_dir, timeout=15.0, force=False)
    elif read_pid(state_dir) is not None:
        code = stop_daemon(state_dir, timeout=5.0, force=True)  # stale: force cleanup
    else:
        code = 0
    if code:
        return code
    return _cmd_start(
        target=target,
        scope=scope,
        engine=engine,
        time_text=time_text,
        min_time_text=min_time_text,
        yes=yes,
        force=force,
        state=state,
    )


# -- dispatch (the `hunt <verb>` interception) -------------------------------------


def dispatch_hunt_alias(
    verb: str,
    *,
    target: str | None = None,
    scope: Path | None = None,
    engine: str | None = None,
    state: Path | None = None,
    json_out: bool = False,
    yes: bool = False,
    time_text: str | None = None,
    min_time_text: str | None = None,
    budget_text: str | None = None,
    force: bool = False,
    lines: int | None = None,
) -> int:
    """Run a daemon verb dispatched from the ``hunt`` command's first body
    line. Validates verb/option compatibility (start requires --target, the
    other verbs reject it) and returns the process exit code."""
    if verb not in HUNT_VERBS:  # pragma: no cover — guarded by the caller
        err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] unknown hunt verb {verb!r}")
        return 3
    if verb == "start":
        return _cmd_start(
            target=target,
            scope=scope,
            engine=engine,
            time_text=time_text,
            min_time_text=min_time_text,
            budget_text=budget_text,
            yes=yes,
            force=force,
            state=state,
        )
    if target is not None:
        err_console.print(
            f"[hunter.error]BLOCKED:[/hunter.error] `hunt {verb}` does not take --target "
            "(pass it to `hunt start`)."
        )
        return 3
    if verb == "stop":
        return _cmd_stop(state=state, timeout=15.0, force=force)
    if verb == "status":
        return _cmd_status(state=state, json_out=json_out)
    if verb == "logs":
        return _cmd_logs(state=state, lines=lines, follow=False)
    return _cmd_restart(
        target=target,
        scope=scope,
        engine=engine,
        time_text=time_text,
        min_time_text=min_time_text,
        yes=yes,
        force=force,
        state=state,
    )


# -- typer command wrappers --------------------------------------------------------


def daemon_start(
    target: Annotated[str | None, typer.Option("--target", help="Hunt target URL (required).")] = None,
    scope: Annotated[
        Path | None, typer.Option("--scope", help="Scope manifest JSON (required off-localhost).")
    ] = None,
    engine: Annotated[str | None, typer.Option("--engine", help="deterministic | mock | llm.")] = None,
    time_opt: Annotated[
        str | None,
        typer.Option("--time", help="Max wall time [Nh][Nm][Ns] (default: budget config / 2h)."),
    ] = None,
    budget_opt: Annotated[
        str | None, typer.Option("--budget", help="Maximum hunt budget in USD (0 is unlimited).")
    ] = None,
    min_time_opt: Annotated[
        str | None, typer.Option("--min-time", help="Minimum wall time floor [Nh][Nm][Ns].")
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", help="Authorize the proposed minimal scope off-localhost.")
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Replace an already-running daemon.")] = False,
    state: Annotated[Path | None, typer.Option("--state", help="State directory.")] = None,
) -> None:
    """Start the 24/7 hunt daemon and enqueue one hunt task."""
    raise typer.Exit(
        _cmd_start(
            target=target,
            scope=scope,
            engine=engine,
            time_text=time_opt,
            min_time_text=min_time_opt,
            budget_text=budget_opt,
            yes=yes,
            force=force,
            state=state,
        )
    )


def daemon_stop(
    state: Annotated[Path | None, typer.Option("--state", help="State directory.")] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Seconds to wait for a cooperative stop.")
    ] = 15.0,
    force: Annotated[bool, typer.Option("--force", help="Terminate/kill after the timeout.")] = False,
) -> None:
    """Stop the daemon (cooperative stop.flag, then --force escalation)."""
    raise typer.Exit(_cmd_stop(state=state, timeout=timeout, force=force))


def daemon_status_cmd(
    state: Annotated[Path | None, typer.Option("--state", help="State directory.")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable JSON.")] = False,
) -> None:
    """Show the daemon status (running/stale/stopped, queue, last run)."""
    raise typer.Exit(_cmd_status(state=state, json_out=json_out))


def daemon_restart(
    target: Annotated[str | None, typer.Option("--target", help="Hunt target URL (required).")] = None,
    scope: Annotated[
        Path | None, typer.Option("--scope", help="Scope manifest JSON (required off-localhost).")
    ] = None,
    engine: Annotated[str | None, typer.Option("--engine", help="deterministic | mock | llm.")] = None,
    time_opt: Annotated[str | None, typer.Option("--time", help="Max wall time [Nh][Nm][Ns].")] = None,
    budget_opt: Annotated[str | None, typer.Option("--budget", help="Maximum hunt budget in USD.")] = None,
    min_time_opt: Annotated[
        str | None, typer.Option("--min-time", help="Minimum wall time floor [Nh][Nm][Ns].")
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", help="Authorize the proposed minimal scope off-localhost.")
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Replace an already-running daemon.")] = False,
    state: Annotated[Path | None, typer.Option("--state", help="State directory.")] = None,
) -> None:
    """Restart the daemon: stop (force on stale) then start."""
    raise typer.Exit(
        _cmd_restart(
            target=target,
            scope=scope,
            engine=engine,
            time_text=time_opt,
            min_time_text=min_time_opt,
            budget_text=budget_opt,
            yes=yes,
            force=force,
            state=state,
        )
    )


def daemon_logs(
    state: Annotated[Path | None, typer.Option("--state", help="State directory.")] = None,
    lines: Annotated[int, typer.Option("--lines", help="Print the last N lines.")] = 50,
    follow: Annotated[
        bool, typer.Option("--follow", help="Keep the log open and print new lines.")
    ] = False,
) -> None:
    """Tail the daemon log."""
    raise typer.Exit(_cmd_logs(state=state, lines=lines, follow=follow))


# -- registration --------------------------------------------------------------------


def register_daemon_commands(app: typer.Typer) -> None:
    """Attach the ``daemon`` sub-app and the top-level ``start`` / ``stop`` /
    ``status`` aliases to the root Typer app (same functions, so
    ``hunter start --target ...`` === ``hunter daemon start --target ...``)."""
    daemon_app = typer.Typer(help="The 24/7 hunt daemon (start/stop/status/restart/logs).")
    app.add_typer(daemon_app, name="daemon")
    daemon_app.command("start")(daemon_start)
    daemon_app.command("stop")(daemon_stop)
    daemon_app.command("status")(daemon_status_cmd)
    daemon_app.command("restart")(daemon_restart)
    daemon_app.command("logs")(daemon_logs)
    app.command("start")(daemon_start)
    app.command("stop")(daemon_stop)
    app.command("status")(daemon_status_cmd)
