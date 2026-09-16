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
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer

from hunter.daemon import (
    daemon_running,
    daemon_status,
    drain_daemon,
    log_path,
    pause_flag_path,
    restart_marker_path,
    start_daemon,
    stop_daemon,
    write_json_atomic,
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
    """Explicit ``--state`` wins; else ``$HUNTER_STATE_DIR`` or the M11 home
    default ``~/.hunter`` (cwd is never the default anymore)."""
    from hunter.home import state_dir

    return state_dir(state)


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


def _scope_gate(
    target: str,
    scope: Path | None,
    *,
    yes: bool,
    config: Any | None = None,
) -> tuple[Any | None, int]:
    """The daemon-start scope gate (M11 locked decision 3): localhost is
    always allowed; off-localhost with ``--scope`` uses the manifest; WITHOUT
    a manifest the minimal ``ScopeSet({host})`` is AUTO-AUTHORIZED and
    recorded under ``agent.approved_scopes`` (audit trail, capped at 50) —
    unless ``agent.scope_confirm`` is true, which restores the old
    refuse-without-``--yes`` behavior verbatim (exit 3). A failed recording
    never fails the start."""
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

    if cfg_scope_confirm(config):
        err_console.print(
            f"[hunter.error]BLOCKED:[/hunter.error] target '{host}' is not localhost. Pass "
            "[bold]--scope scope.json[/bold] with an authorized scope manifest, "
            f"or --yes to authorize the proposed minimal scope for '{host}'."
        )
        return None, 3
    chosen = ScopeSet(frozenset({host}), False, name=host)
    _record_approved_scope(host, config)
    return chosen, 0


def cfg_scope_confirm(config: Any | None) -> bool:
    """``agent.scope_confirm`` from the given config (loaded on demand); a
    broken config reads as False (the budget loader reports it separately)."""
    from hunter.errors import HunterError
    from hunter.llm.config import load_config

    try:
        cfg = config if config is not None else load_config()
    except HunterError:
        return False
    return bool(getattr(getattr(cfg, "agent", None), "scope_confirm", False))


def _record_approved_scope(host: str, config: Any | None) -> None:
    """Append the auto-authorized minimal scope to ``agent.approved_scopes``
    (audit trail; capped at the last 50 entries). Best-effort: a failed write
    warns and continues — the hunt start itself must not fail over bookkeeping."""
    import time as _time

    from hunter.errors import HunterError
    from hunter.llm.config import load_config
    from hunter.llm.writing import write_config

    try:
        cfg = config if config is not None else load_config()
    except HunterError:
        cfg = None
    entries: list[dict[str, Any]] = []
    for item in (getattr(getattr(cfg, "agent", None), "approved_scopes", None) or []):
        entries.append(
            {
                "host": item.host,
                "name": item.name or item.host,
                "allow_subdomains": item.allow_subdomains,
                "ts": item.ts,
                "source": item.source,
            }
        )
    entries.append(
        {
            "host": host,
            "name": host,
            "allow_subdomains": False,
            "ts": _time.time(),
            "source": "hunt-start",
        }
    )
    try:
        write_config({"agent": {"approved_scopes": entries[-50:]}})
    except HunterError as exc:
        err_console.print(
            f"⚠️ could not record the approved scope in the config: {exc.message}",
            markup=False,
            highlight=False,
        )


def _configured_wall_seconds() -> float:
    """``budget.wall_seconds`` when EXPLICITLY set in the config file (the
    dataclass default 1800 does not count — the daemon default is 2h);
    0.0 when unset/unreadable."""
    import yaml as _yaml

    from hunter.errors import HunterError
    from hunter.llm.config import load_config

    try:
        cfg = load_config()
    except HunterError:
        return 0.0
    source = getattr(cfg, "source_path", None)
    if not source:
        return 0.0
    try:
        raw = _yaml.safe_load(Path(source).read_text(encoding="utf-8")) or {}
    except (OSError, _yaml.YAMLError, UnicodeDecodeError):
        return 0.0
    budget = raw.get("budget") if isinstance(raw, dict) else None
    if isinstance(budget, dict) and "wall_seconds" in budget:
        try:
            return float(budget["wall_seconds"] or 0.0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _wall_label(seconds: float) -> str:
    """Human ``[Nh][Nm][Ns]`` label for the interactive time prompt default."""
    seconds = int(max(0, seconds))
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _default_interactive_ask():
    """The typer-echo ask used on a TTY when no seam is injected."""

    def ask(prompt: str, default: str = "") -> str:
        try:
            return input(f"{prompt} ").strip() or default
        except EOFError:
            return default

    return ask


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
    interactive_ask: Callable[[str, str], str] | None = None,
    idle_tip: bool = True,
) -> int:
    """Validate and start the persistent engine, optionally with one task.

    M11 two-question flow: with no target, no ``--yes`` and a TTY (or an
    injected seam) the CLI asks EXACTLY ``Target URL:`` and
    ``Time — how long may the hunt run? [2h]:`` — never a y/N. Blank target
    cancels; garbage time re-asks twice then cancels; blank time takes the
    default. After the answers the flow is the flag path with the minimal
    scope auto-authorized and recorded.
    """
    import sys as _sys

    from hunter.duration import parse_duration
    from hunter.errors import HunterError

    state_dir = _resolve_state(state)
    already_running, _ = daemon_running(state_dir)
    if already_running and not force:
        typer.echo("engine already on — 24/7 engine is on")
        return 0

    # ---- M7: the two-question interactive flow (no y/N exists on this path) --
    if target is None and not yes and (
        interactive_ask is not None or _sys.stdin.isatty()
    ):
        ask = interactive_ask if interactive_ask is not None else _default_interactive_ask()
        default_wall = _configured_wall_seconds() or _DEFAULT_MAX_WALL_SECONDS
        time_prompt = f"Time — how long may the hunt run? [{_wall_label(default_wall)}]:"
        target = ask("Target URL:").strip()
        if not target:
            typer.echo("⏸️ cancelled — nothing was started.")
            return 0
        answer = ask(time_prompt).strip()
        parsed_ok = False
        for _retry in range(2):
            if not answer:
                # Materialize the resolved default so the later budget merge
                # cannot replace the two-question answer with dataclass defaults.
                time_text = _wall_label(default_wall)
                parsed_ok = True
                break
            try:
                parse_duration(answer)
            except HunterError as exc:
                err_console.print(
                    f"[hunter.error]config error:[/hunter.error] {exc.message}\nHint: {exc.hint}",
                    markup=False,
                    highlight=False,
                )
                answer = ask(time_prompt).strip()
                continue
            time_text = answer
            parsed_ok = True
            break
        if not parsed_ok:
            typer.echo("⏸️ cancelled — nothing was started.")
            return 0
        yes = True  # the two-question flow auto-authorizes (recorded) — no y/N

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
            # Interactive blank time is deliberately the daemon's 2h default;
            # config.wall_seconds controls explicit hunt budgets, not the
            # two-question onboarding flow.
            max_wall = _DEFAULT_MAX_WALL_SECONDS if interactive_ask is not None else (
                float(getattr(budget, "wall_seconds", 0.0) or 0.0) or _DEFAULT_MAX_WALL_SECONDS
            )
        if min_wall is None:
            min_wall = float(getattr(budget, "min_wall_seconds", 0.0) or 0.0)
        if budget_text is None:
            max_cost = float(getattr(budget, "max_cost_usd", 0.0) or 0.0)
    else:
        max_wall = float(max_wall or 0.0)
        min_wall = float(min_wall or 0.0)
    if pause_flag_path(state_dir).exists():
        # M8 ESTOP: the engine is paused — the task still ENQUEUES (work holds
        # in the queue); the paused line leads the output.
        from hunter.hospitality import paused_message

        typer.echo(paused_message())
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
            if idle_tip:
                typer.echo("💡 tip: hunt start <url> --time 30m to queue a hunt immediately")
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
    for line in status_lines(status, state_dir=state_dir):
        if line.startswith("daemon:") or line.startswith("config:"):
            console.print(line)
        else:
            typer.echo(line)


def status_lines(status: dict[str, Any], *, state_dir: Path) -> list[str]:
    """The human status render, line by line — the SINGLE source consumed by
    the CLI and the TUI Engine pane (M11 M6), so the two cannot drift."""
    lines: list[str] = []
    paused = bool(status.get("paused"))
    paused_suffix = "  ⏸️ paused" if paused else ""
    if status.get("running"):
        heartbeat = status.get("heartbeat_age_seconds")
        heartbeat_text = "heartbeat n/a" if heartbeat is None else f"heartbeat {heartbeat:.0f}s ago"
        lines.append(
            f"daemon: [hunter.success]running[/hunter.success] (pid {status.get('pid')}, "
            f"up {_human_uptime(status.get('uptime_seconds'))}, {heartbeat_text})"
            f"{paused_suffix}"
        )
    elif status.get("stale"):
        lines.append(
            f"daemon: [hunter.error]stale[/hunter.error] (pid {status.get('pid')} — heartbeat too"
            " old, presumed dead)"
        )
    else:
        lines.append(f"daemon: [hunter.warning]stopped[/hunter.warning]{paused_suffix}")
    config_path = str(status.get("config_path") or "")
    lines.append(f"config: {config_path or '(none)'}")
    lines.append(f"state: {state_dir}")
    transports = status.get("transports") or []
    lines.append("transports: " + (", ".join(transports) if transports else "(none)"))
    lines.append(f"queue: {status.get('queue_pending', 0)} pending, {status.get('queue_claimed', 0)} claimed")
    last = status.get("last_run")
    if last:
        lines.append(f"last run: {last.get('run_id')} {last.get('status')} ({last.get('findings')} findings)")
    else:
        lines.append("last run: (none)")
    if status.get("running"):
        lines.append(
            "💡 logs: hunter logs --follow · stop: hunter stop · restart: hunter restart"
        )
    else:
        lines.append(
            "💡 start it: hunter start (foreground transports: hunter gateway start)"
        )
    return lines


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


def _resolve_drain_timeout(drain_timeout: float | None) -> float:
    """``--drain-timeout`` (seconds) → ``$HUNTEROS_DRAIN_TIMEOUT`` (parsed via
    parse_duration) → 60.0. Garbage env values die with the classified config
    error and the duration grammar hint (exit 8)."""
    import os

    from hunter.duration import parse_duration
    from hunter.errors import HunterError

    if drain_timeout is not None:
        return float(drain_timeout)
    from_env = (os.environ.get("HUNTEROS_DRAIN_TIMEOUT") or "").strip()
    if from_env:
        try:
            return parse_duration(from_env)
        except HunterError as exc:
            err_console.print(
                f"[hunter.error]config error:[/hunter.error] {exc.message}\nHint: {exc.hint}"
            )
            raise typer.Exit(8) from exc
    return 60.0


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
    drain_timeout: float | None = None,
) -> int:
    """Drain-first restart (M11): a running daemon gets the restart marker and
    drains (in-flight work finishes); a drain timeout escalates to a forced
    stop; a stale pid is force-cleaned; nothing running simply starts (Q4)."""
    state_dir = _resolve_state(state)
    status = daemon_status(state_dir)
    if status.get("running"):
        timeout = _resolve_drain_timeout(drain_timeout)
        write_json_atomic(
            restart_marker_path(state_dir),
            {"ts": time.time(), "pid": status.get("pid")},
        )
        drained = drain_daemon(state_dir, timeout=timeout)
        if drained:
            stop_daemon(state_dir, timeout=5.0, force=True)
            err_console.print(
                f"drain timed out after {timeout:.1f}s — stopped after cutting the in-flight run short",
                markup=False,
                highlight=False,
            )
    elif status.get("stale") or status.get("pid"):
        # A stale/dead registration: force cleanup, never a drain attempt
        # against a dead pid (the pre-M11 contract, preserved).
        stop_daemon(state_dir, timeout=5.0, force=True)
    else:
        typer.echo("engine was not running — starting it")
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
    target_pos: Annotated[
        str | None, typer.Argument(help="Hunt target URL (same as --target; Q11 positional form).")
    ] = None,
    target: Annotated[str | None, typer.Option("--target", help="Hunt target URL.")] = None,
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
            target=target_pos or target,
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
    drain_timeout: Annotated[
        float | None,
        typer.Option(
            "--drain-timeout",
            help="Seconds to wait for the running engine to drain before forcing ($HUNTEROS_DRAIN_TIMEOUT).",
        ),
    ] = None,
) -> None:
    """Restart the engine: drain first (in-flight work finishes), then start.

    Nothing running? It simply starts. A drain timeout escalates to a forced
    stop; a stale pid is force-cleaned before the fresh boot.
    """
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
            drain_timeout=drain_timeout,
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
    ``status`` / ``restart`` / ``logs`` aliases to the root Typer app (same
    functions, so ``hunter start ...`` === ``hunter daemon start ...``)."""
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
    app.command("restart")(daemon_restart)
    app.command("logs")(daemon_logs)
