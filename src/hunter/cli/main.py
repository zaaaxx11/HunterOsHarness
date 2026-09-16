"""`hunter` — the HunterOs Harness CLI.

Every command reads/writes through the ledger; reports render only from
ledger rows; the claim gate cannot be bypassed from here (enforced below it).

State directory: ``--state`` option, env ``HUNTER_STATE_DIR``, or ``.hunter``
under the current directory (in that order of precedence per invocation).

Error doctrine: per-command handlers cover the classified paths; everything
that still escapes is rendered by :mod:`hunter.cli.handle` — one line plus a
``where:`` location, never a surprise traceback.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

import typer
import yaml
from rich.markdown import Markdown as RichMarkdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hunter.cli.handle import handle_cli_error, is_verbose, set_verbose
from hunter.kernel.findings import SEVERITY_ORDER
from hunter.kernel.ledger import Ledger
from hunter.palette import PALETTE, make_console
from hunter.tools.scope import (
    LOCAL_HOSTS,
    ScopeSet,
    ScopeViolation,
    localhost_scope,
    scope_from_manifest,
)

app = typer.Typer(
    help="HunterOs Harness — evidence-first security-audit harness.",
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = make_console()
err_console = make_console(stderr=True)


def _version() -> str:
    # Source version is authoritative in editable/dev checkouts; stale wheel
    # metadata must not make the CLI announce an older release.
    from hunter import __version__

    return __version__


# ------------------------------------------------------------- root callback --

@app.callback(invoke_without_command=True)
def _root_callback(
    ctx: typer.Context,
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Print full tracebacks for unexpected errors (or set HUNTEROS_VERBOSE=1).",
    ),
    version_flag: bool = typer.Option(
        False,
        "--version",
        is_eager=True,
        help="Print the version and exit without touching user state.",
    ),
) -> None:
    """Global options. Run `hunter` with no subcommand for the welcome panel."""
    set_verbose(verbose)
    if version_flag:
        typer.echo(f"hunter {_version()}")
        raise typer.Exit(0)
    # keys.env (written by `hunter init` / `hunter config key set` when a key
    # is pasted) is loaded into the environment with setdefault semantics at
    # every startup — real env vars win. load_keys_env cannot raise
    # (best-effort by contract).
    from hunter.llm.keys import load_keys_env

    load_keys_env()
    # M11 one home: resolve ~/.hunter and run the copy-once legacy migration
    # (originals in ~/.hunteros are NEVER deleted). The pinned notice prints
    # once per process — only when THIS command actually migrated something
    # (the notes diff), so later commands in the same process stay quiet.
    from hunter.home import MIGRATION_NOTICE, ensure_home, migration_notes

    notes_before = migration_notes()
    ensure_home()
    if migration_notes() != notes_before:
        # Keep the pinned migration notice byte-stable; Rich may soft-wrap a
        # long line at narrow test/PowerShell widths.
            # Migration is diagnostics, not command data. Keep JSON stdout
            # byte-pure while still showing the notice in normal CLI output.
            typer.echo(MIGRATION_NOTICE, err=True)

    # M4: polite background version check — one daemon thread per process,
    # never for `hunter update` (it checks forcefully itself) and never for
    # the long-lived surfaces; the notice prints AFTER command output via a
    # context-close hook (click closes the root context last, even when a
    # subcommand raises Exit).
    from hunter.cli import update_core

    sub = ctx.invoked_subcommand
    if sub != "update":  # the update command performs its own forced check
        update_core.start_background_check(suppress_notice=sub in update_core.QUIET_COMMANDS)
    ctx.call_on_close(update_core.emit_notice)  # pop is empty when nothing spawned
    if ctx.invoked_subcommand is None:
        from hunter._data.branding import welcome_lines

        body = Text("\n".join(welcome_lines(_version())))
        console.print(
            Panel(body, title="hunter", border_style=PALETTE["base"], subtitle="Evidence or Nothing")
        )
        # First-run offer: fires only when no config exists anywhere; a
        # decline sets $HUNTEROS_ONBOARD_DECLINED so it never re-prompts
        # within this process. --help never reaches the callback.
        from hunter.cli.init_wizard import offer_onboarding

        offer_onboarding(console=console)


def _open_ledger(state: Path | None) -> Ledger:
    # `state` is a state DIRECTORY (pipeline convention); the db lives inside it.
    db = None if state is None else Path(state) / "ledger.db"
    return Ledger(db) if db is not None else Ledger()


def _ledger_guard(exc: Exception) -> typer.Exit:
    """A corrupt/unreadable ledger is a diagnosis, not a traceback."""
    err_console.print(f"[hunter.error]ledger error:[/hunter.error] {type(exc).__name__}: {exc}")
    return typer.Exit(1)


def _latest_run_id(ledger: Ledger) -> str:
    runs = ledger.runs()
    if not runs:
        err_console.print("[hunter.error]No runs in the ledger yet — run `hunter demo` or `hunter scan` first.[/hunter.error]")
        raise typer.Exit(1)
    return str(runs[-1]["run_id"])


def _scope_for_target(target: str, scope_file: Path | None) -> ScopeSet:
    """localhost targets are always allowed; anything else needs a manifest."""
    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError:  # malformed IPv6 literal etc. — fail closed, exit 2
        err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] target {target!r} is not a valid URL.")
        raise typer.Exit(2) from None
    if host in LOCAL_HOSTS:
        # stderr on purpose: with --json this line must never touch stdout.
        if scope_file is not None:
            err_console.print("[dim]note: target is localhost; scope manifest ignored[/dim]")
        return localhost_scope()
    if scope_file is None:
        err_console.print(
            f"[hunter.error]BLOCKED:[/hunter.error] target '{host}' is not localhost. "
            "Pass [bold]--scope scope.json[/bold] with an authorized scope manifest "
            '(e.g. {"name": "client-x", "hosts": ["example.com"]}).'
        )
        raise typer.Exit(2)
    try:
        return scope_from_manifest(scope_file)
    except ValueError as exc:  # invalid/empty manifest — usage error, exit 2
        err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] invalid scope manifest: {exc}")
        raise typer.Exit(2) from exc


_SEV_COLOR = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _sev_markup(severity) -> str:
    value = severity.value
    return f"[{_SEV_COLOR.get(value, 'white')}]{value}[/{_SEV_COLOR.get(value, 'white')}]"


# ------------------------------------------------------------------ version ---

@app.command()
def version() -> None:
    """Print the harness version."""
    console.print(f"hunter {_version()}")


@app.command("pause")
def pause(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Pause new daemon work without killing an in-flight hunt."""
    from hunter.daemon import daemon_running, pause_flag_path
    from hunter.home import state_dir
    from hunter.hospitality import paused_message

    resolved = state_dir(state)
    running, _pid = daemon_running(resolved)
    if not running:
        typer.echo("engine is off — nothing to pause")
        raise typer.Exit(1)
    pause_flag_path(resolved).parent.mkdir(parents=True, exist_ok=True)
    pause_flag_path(resolved).write_text("", encoding="utf-8")
    typer.echo(paused_message())


@app.command("resume")
def resume(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Resume queued daemon work and clear a stale pause flag."""
    from hunter.daemon import daemon_running, pause_flag_path, queue_dir
    from hunter.home import state_dir
    from hunter.hospitality import resume_message

    resolved = state_dir(state)
    flag = pause_flag_path(resolved)
    running, _pid = daemon_running(resolved)
    flag.unlink(missing_ok=True)
    if not running:
        typer.echo("engine was off — pause flag cleared")
        return
    pending = len(list(queue_dir(resolved).glob("task-*.json"))) if queue_dir(resolved).exists() else 0
    typer.echo(resume_message(pending))


# --------------------------------------------------------------------- hunt ---

@app.command()
def hunt(
    target: str = typer.Argument("", help="URL, host[:port], or local directory."),
    scope: Path | None = typer.Option(None, "--scope", help="Scope manifest JSON."),
    engine: str | None = typer.Option(None, "--engine", help="deterministic | mock | llm."),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable JSON."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Assume yes for proposed scope."),
    daemon_target: str | None = typer.Option(
        None, "--target", help="Daemon verb: hunt target for `hunt start`."
    ),
    budget_opt: str | None = typer.Option(
        None, "--budget", help="Daemon verb: maximum hunt budget in USD (0 is unlimited)."
    ),
    time_opt: str | None = typer.Option(
        None, "--time", help="Daemon verb: max wall time [Nh][Nm][Ns] (ignored for plain hunts)."
    ),
    min_time_opt: str | None = typer.Option(
        None, "--min-time", help="Daemon verb: minimum wall time floor (ignored for plain hunts)."
    ),
    force: bool = typer.Option(
        False, "--force", help="Daemon verb: force start/stop (ignored for plain hunts)."
    ),
    lines: int | None = typer.Option(
        None, "--lines", help="Daemon verb: line count for `hunt logs` (ignored for plain hunts)."
    ),
) -> None:
    """One-command hunt with Strix exit codes: 0 clean, 1 error, 2 findings, 3 refused.

    Daemon verbs ride the same command: `hunt start --target URL --time 2h`,
    `hunt stop`, `hunt status [--json]`, `hunt restart`, `hunt logs --lines N`.
    """
    # F2 verb interception: click turns `hunt start --target URL` into THIS
    # command (the verb becomes the positional target) — delegate before the
    # plain-hunt path can touch it. A plain `hunter hunt <URL>` is never
    # misrouted: normalize_hunt_target rejects those tokens as targets.
    if target in {"start", "stop", "status", "restart", "logs"}:
        from hunter.cli.daemon import dispatch_hunt_alias

        raise typer.Exit(
            dispatch_hunt_alias(
                target,
                target=daemon_target,
                scope=scope,
                engine=engine,
                state=state,
                json_out=json_out,
                yes=yes,
                time_text=time_opt,
                min_time_text=min_time_opt,
                budget_text=budget_opt,
                force=force,
                lines=lines,
            )
        )
    import json

    from hunter.hunt import (
        confirm_prompt,
        mount_local_dir,
        normalize_hunt_target,
        propose_manifest,
        run_hunt,
    )
    from hunter.tools.scope import ScopeSet, scope_from_manifest

    normalized, kind = normalize_hunt_target(target)
    if kind == "invalid":
        err_console.print("[hunter.error]BLOCKED:[/hunter.error] invalid hunt target")
        raise typer.Exit(3)
    selected_engine = engine
    if selected_engine is not None and selected_engine not in {"deterministic", "mock", "llm"}:
        err_console.print("[hunter.error]BLOCKED:[/hunter.error] unknown engine; engines: deterministic, mock, llm")
        raise typer.Exit(3)
    chosen_scope = None
    if kind == "dir":
        mount = mount_local_dir(normalized)
        with mount:
            if not json_out:
                typer.echo(
                    f"mounting local directory {normalized} on {mount.url} "
                    "(temporary, localhost-only) — everything inside is reachable by the audit."
                )
            chosen_scope = localhost_scope()
            selected_engine = selected_engine or "deterministic"
            from hunter.agent.skills import selected_skill_names
            selected = selected_skill_names(mount.url, mount.url)
            if not json_out:
                typer.echo(f"target check: {mount.url} — valid URL (host: 127.0.0.1)")
                typer.echo(f"skills mounted: {len(selected)}" + (f" ({', '.join(f'{name} [{source}]' for name, source in selected)})" if selected else ""))
            outcome = run_hunt(mount.url, scope=chosen_scope, engine_name=selected_engine, state_dir=state)
            _render_hunt_outcome(outcome, json_out=json_out)
            raise typer.Exit(outcome.exit_code)

    host = (urlparse(normalized).hostname or "").lower()
    if host in LOCAL_HOSTS:
        # Plain `hunter hunt <url>` retains its explicit authorization gate;
        # only daemon `hunt start` gets the two-question auto-authorize UX.
        if not yes and scope is None and not confirm_prompt("Authorize this exact scope? [y/N] "):
            err_console.print("[hunter.error]BLOCKED:[/hunter.error] refused — nothing ran.")
            raise typer.Exit(3)
        chosen_scope = localhost_scope()
    elif scope is not None:
        try:
            chosen_scope = scope_from_manifest(scope)
        except (ValueError, OSError) as exc:
            err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] invalid scope manifest: {exc}")
            raise typer.Exit(3) from exc
    else:
        proposed = propose_manifest(host)
        console.print(f"target {host} is not localhost — a scope manifest is required.")
        console.print("proposed minimal scope manifest (JSON):")
        console.print(json.dumps(proposed))
        if not (yes or confirm_prompt("Authorize this exact scope? [y/N] ")):
            err_console.print("refused — nothing ran.")
            raise typer.Exit(3)
        chosen_scope = ScopeSet(frozenset({host}), False, name=host)
    if selected_engine is None:
        try:
            from hunter.llm.config import find_config_path, load_config
            from hunter.llm.router import provider_from_config

            config_path = find_config_path()
            if config_path is None or not config_path.is_file():
                raise FileNotFoundError("no HunterOS LLM config")
            config = load_config(config_path)
            provider_from_config(config)
            selected_engine = "llm"
        except Exception:
            selected_engine = "deterministic"
            err_console.print("no brain configured — using the deterministic engine.")
    from hunter.agent.skills import selected_skill_names
    selected = selected_skill_names(normalized, normalized)
    if not json_out:
        typer.echo(f"target check: {normalized} — valid URL (host: {host})")
        typer.echo(f"skills mounted: {len(selected)}" + (f" ({', '.join(f'{name} [{source}]' for name, source in selected)})" if selected else ""))
    outcome = run_hunt(normalized, scope=chosen_scope, engine_name=selected_engine, state_dir=state)
    _render_hunt_outcome(outcome, json_out=json_out)
    raise typer.Exit(outcome.exit_code)


def _render_hunt_outcome(outcome, *, json_out: bool) -> None:
    import json
    if json_out:
        console.print_json(json.dumps({
            "run_id": outcome.run_id, "status": outcome.status,
            "verified": outcome.verified, "candidates": outcome.candidates,
            "findings": outcome.finding_rows or [], "stats": outcome.stats or {},
            "report": outcome.report_path,
        }))
        return
    if outcome.status != "completed":
        err_console.print(f"[hunter.error]run failed[/hunter.error] {outcome.stats.get('error', '') if outcome.stats else ''}")
        return
    typer.echo(f"{outcome.verified} verified / {outcome.candidates} candidates — {outcome.findings} findings")
    if outcome.report_path:
        typer.echo(f"report: {outcome.report_path}")
    else:
        typer.echo("report unavailable — chain blocked")


# ---------------------------------------------------------------------- model ---

@app.command("model")
def model(
    set_model: str | None = typer.Option(
        None, "--set", help="Set this model id directly — never prompts (scriptable)."
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="Provider name for --set (known names or 'custom')."
    ),
    tier: str | None = typer.Option(
        None, "--tier", help="Restrict the write to one tier (orchestrator/hunter/verifier/utility)."
    ),
) -> None:
    """Pick the model for every tier (or swap one with --set).

    Env-only path: HUNTEROS_MODEL overrides the model at use time without any
    config change.
    """
    from hunter.cli.model_cmd import run_model_picker

    code = run_model_picker(
        console=console, err_console=err_console,
        set_model=set_model, provider=provider, tier=tier,
    )
    if code:
        raise typer.Exit(code)


# --------------------------------------------------------------------- where ---

@app.command("where")
def where(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable JSON."),
) -> None:
    """Print where every piece of HunterOS state lives (home, config, keys,
    chat db, state dir, legacy plumbing)."""
    import json as _json

    from hunter.home import hunter_home, legacy_home
    from hunter.home import state_dir as resolve_state
    from hunter.llm.keys import keys_env_path

    home = hunter_home()
    legacy = legacy_home()
    keys_path = keys_env_path()
    if state is not None:
        resolved_state, source = Path(state), "flag"
    else:
        env_state = (os.environ.get("HUNTER_STATE_DIR") or "").strip()
        if env_state:
            resolved_state, source = Path(env_state), "env"
            # `where` is the one command that reports the env override; once
            # reported it is consumed for the rest of THIS process so a
            # follow-up `where` shows what a fresh `hunter` (the real
            # deployment unit — every invocation is a new process) resolves.
            os.environ.pop("HUNTER_STATE_DIR", None)
        else:
            resolved_state, source = resolve_state(None), "home"
    if json_out:
        payload = {
            "home": str(home),
            "config": str(home / "config.yaml"),
            "keys": str(keys_path),
            "chat_db": str(home / "chat.db"),
            "state": str(resolved_state),
            "state_source": source,
            "legacy": str(legacy),
        }
        typer.echo(_json.dumps(payload, indent=2))
        return
    suffix = "  (HUNTER_STATE_DIR)" if source == "env" else ""
    typer.echo(f"home:    {home}")
    typer.echo(f"config:  {home / 'config.yaml'}")
    typer.echo(f"keys:    {keys_path}")
    typer.echo(f"chat db: {home / 'chat.db'}")
    typer.echo(f"state:   {resolved_state}{suffix}")
    typer.echo(f"legacy:  {legacy}  (kept: venv, bin shims, update-check)")


# --------------------------------------------------------------------- update ---

@app.command()
def update(
    yes: bool = typer.Option(
        False, "--yes", help="Skip the confirmation prompt (for scripts and automation)."
    ),
) -> None:
    """Update the harness (or print the exact manual command)."""
    from hunter.cli.update_core import run_update

    code = run_update(console=console, err_console=err_console, yes=yes)
    if code:
        raise typer.Exit(code)


# ---------------------------------------------------------------------- init ---

@app.command()
def init(
    path: Path | None = typer.Option(
        None, "--path", help="Config file to write (default: $HUNTEROS_CONFIG or ~/.hunter/config.yaml)."
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="Non-interactive provider name (e.g. openrouter, ollama)."
    ),
    yes: bool = typer.Option(False, "--yes", help="Non-interactive: take defaults, never prompt."),
) -> None:
    """First-run wizard: pick a brain, capture a key, write the config."""
    # ONE wizard (M11 init 3.0): interactive, --provider/--yes, and the
    # bare-`hunter` offer all ride run_init_wizard (Q9 — no v1/v2 split).
    from hunter.cli.init_wizard import run_init_wizard

    code = run_init_wizard(
        path=path, provider=provider, yes=yes, console=console, err_console=err_console
    )
    if code:
        raise typer.Exit(code)


# -------------------------------------------------------------------- doctor ---

@app.command()
def doctor(
    state: Path | None = typer.Option(
        None, "--state", help="State directory (default: .hunter or $HUNTER_STATE_DIR)."
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    live: bool = typer.Option(
        False, "--live", help="Probe configured provider endpoints (real network, bounded)."
    ),
) -> None:
    """Check the environment: python, deps, ledger, engines, providers, chat db."""
    import json
    from dataclasses import asdict

    from hunter.cli.doctor_core import collect_checks

    checks = collect_checks(state, live=live, ledger_factory=lambda: _open_ledger(state))
    ok = all(check.status != "fail" for check in checks)
    if json_out:
        console.print_json(json.dumps({"checks": [asdict(c) for c in checks], "ok": ok}))
    else:
        console.print(f"[bold]HunterOs Harness doctor[/bold] — hunter {_version()}")
        marks = {"ok": "[hunter.success]OK[/hunter.success]", "fail": "[hunter.error]FAIL[/hunter.error]", "note": "[hunter.warning]OK[/hunter.warning]"}
        for check in checks:
            console.print(f"  {marks[check.status]}  [bold]{check.label}[/bold] {check.detail}")
        if ok:
            console.print("[hunter.success]All checks passed.[/hunter.success]")
    if not ok:
        raise typer.Exit(1)


# ---------------------------------------------------------------------- demo ---

@app.command()
def demo(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    port: int = typer.Option(0, "--port", help="PracticeVault port (0 = ephemeral)."),
    engine: str = typer.Option("deterministic", "--engine", help="Engine to use."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Scan the built-in vulnerable PracticeVault end-to-end (first-blood run)."""
    from hunter.workflow.bench import run_demo

    try:
        result = run_demo(state_dir=state, port=port, engine_name=engine)
    except Exception as exc:
        err_console.print(f"[hunter.error]demo failed:[/hunter.error] {exc}")
        raise typer.Exit(1) from exc

    phase_line = getattr(result.summary, "phase_line", "")
    if json_out:
        import json

        payload = {
            "run_id": result.run_id,
            "recall": result.recall,
            "first_blood": result.first_blood,
            "matched": result.matched,
            "missing": result.missing,
            "extra": result.extra,
            "summary": result.summary_line,
            "server_port": result.server_port,
        }
        if phase_line:
            payload["phase_line"] = phase_line
        console.print_json(json.dumps(payload))
    else:
        table = Table(title=f"Demo run {result.run_id} — target PracticeVault :{result.server_port}")
        table.add_column("severity", style="bold")
        table.add_column("status")
        table.add_column("finding")
        table.add_column("endpoint")
        for f in sorted(result.summary.findings, key=lambda x: -SEVERITY_ORDER.get(x.severity.value, 0)):
            table.add_row(_sev_markup(f.severity), f.status.value, f.title, f"{f.method} {f.endpoint}")
        console.print(table)
        console.print(f"[bold]{result.summary_line}[/bold]")
        if phase_line:
            console.print(phase_line)
        chain_ledger = _open_ledger(state)
        try:
            chain = chain_ledger.verify_chain(result.run_id)
        finally:
            chain_ledger.close()
        chain_note = (
            f"chain ok ({chain.checked} events)" if chain.ok else f"chain BROKEN at seq {chain.broken_at_seq}"
        )
        console.print(
            f"ledger: {result.summary.stats.get('requests', '?')} requests, {chain_note} — "
            f"next: [bold]hunter report --run {result.run_id}[/bold]"
        )
    raise typer.Exit(0 if result.first_blood else 1)


# ---------------------------------------------------------------------- scan ---

@app.command()
def scan(
    target: str = typer.Argument(..., help="Base URL to scan, e.g. http://127.0.0.1:8941/"),
    scope: Path | None = typer.Option(
        None, "--scope", help="Scope manifest JSON (required for non-localhost targets)."
    ),
    engine: str = typer.Option("deterministic", "--engine", help="Engine: deterministic | mock | llm."),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Scan an authorized target. localhost is always allowed; else --scope is mandatory."""
    from hunter.errors import HunterError
    from hunter.workflow.pipeline import run_scan

    try:
        chosen_scope = _scope_for_target(target, scope)
    except ScopeViolation as exc:
        err_console.print(f"[hunter.error]{exc}[/hunter.error]")
        raise typer.Exit(2) from exc

    try:
        summary = run_scan(target, engine_name=engine, scope=chosen_scope, state_dir=state)
    except ValueError as exc:  # unknown engine — usage error, not a scan outcome
        err_console.print(f"[hunter.error]BLOCKED:[/hunter.error] {exc}")
        raise typer.Exit(2) from exc
    except HunterError as exc:  # classified pipeline failure
        raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc
    except (sqlite3.DatabaseError, OSError) as exc:
        raise _ledger_guard(exc) from exc

    phase_line = getattr(summary, "phase_line", "")
    if json_out:
        import json

        payload = {
            "run_id": summary.run_id,
            "status": summary.status,
            "verified": summary.verified,
            "candidates": summary.candidates,
            "findings": [
                {
                    "id": f.id, "title": f.title, "severity": f.severity.value,
                    "status": f.status.value, "cwe": f.cwe, "endpoint": f.endpoint,
                    "method": f.method, "param": f.param, "evidence": list(f.evidence_ids),
                }
                for f in summary.findings
            ],
            "stats": summary.stats,
        }
        if phase_line:
            payload["phase_line"] = phase_line
        console.print_json(json.dumps(payload))
    else:
        if summary.status != "completed":
            err_console.print(
                f"[hunter.error]scan {summary.run_id} failed[/hunter.error] — see events: hunter report --run {summary.run_id}"
            )
            raise typer.Exit(1)
        table = Table(title=f"Scan {summary.run_id} — {summary.target}")
        table.add_column("severity", style="bold")
        table.add_column("status")
        table.add_column("finding")
        table.add_column("endpoint")
        for f in sorted(summary.findings, key=lambda x: -SEVERITY_ORDER.get(x.severity.value, 0)):
            table.add_row(_sev_markup(f.severity), f.status.value, f.title, f"{f.method} {f.endpoint}")
        console.print(table)
        console.print(
            f"[bold]{summary.verified} verified / {summary.candidates} candidates[/bold] — "
            f"{summary.stats.get('requests', '?')} requests — "
            f"next: [bold]hunter report --run {summary.run_id}[/bold]"
        )
        if phase_line:
            console.print(phase_line)
    raise typer.Exit(0 if summary.status == "completed" else 1)


# -------------------------------------------------------------------- report ---

@app.command()
def report(
    run_id: str | None = typer.Option(None, "--run", help="Run id (default: latest run)."),
    fmt: str = typer.Option("markdown", "--fmt", help="Output format: markdown | sarif."),
    out: Path | None = typer.Option(None, "--out", help="Write to file instead of stdout."),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Render a report from the ledger (markdown or SARIF). Refuses if the chain is broken."""
    from hunter.reporting.markdown import ReportBlocked

    ledger = _open_ledger(state)
    try:
        rid = run_id or _latest_run_id(ledger)

        if fmt == "markdown":
            from hunter.reporting.markdown import render_markdown

            try:
                text = render_markdown(ledger, rid)
            except KeyError as exc:
                err_console.print(f"[hunter.error]unknown run:[/hunter.error] {rid}")
                raise typer.Exit(1) from exc
            if out is not None:
                try:
                    out.write_text(text, encoding="utf-8")
                except OSError as exc:
                    err_console.print(f"[hunter.error]could not write {out}:[/hunter.error] {exc}")
                    raise typer.Exit(1) from exc
                console.print(f"[hunter.success]wrote[/hunter.success] {out}")
            else:
                console.print(RichMarkdown(text))
            _mark_report_rendered(ledger, rid, text=text, out=out)
        elif fmt == "sarif":
            import json

            from hunter.reporting.sarif import to_sarif, write_sarif

            if out is not None:
                path = write_sarif(ledger, rid, out)
                console.print(f"[hunter.success]wrote[/hunter.success] {path}")
            else:
                console.print_json(json.dumps(to_sarif(ledger, rid)))
        else:
            err_console.print(f"[hunter.error]unknown format:[/hunter.error] {fmt} (use markdown | sarif)")
            raise typer.Exit(2)
    except ReportBlocked as exc:
        # Both renderers refuse a broken chain — the ledger may be tampered.
        err_console.print(f"[hunter.error]{exc}[/hunter.error]")
        raise typer.Exit(2) from exc
    except KeyError as exc:
        err_console.print(f"[hunter.error]unknown run:[/hunter.error] {run_id or '(latest)'}")
        raise typer.Exit(1) from exc
    except sqlite3.DatabaseError as exc:
        raise _ledger_guard(exc) from exc
    except OSError as exc:
        err_console.print(f"[hunter.error]state error:[/hunter.error] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from exc
    finally:
        ledger.close()


def _mark_report_rendered(ledger: Ledger, run_id: str, *, text: str, out: Path | None) -> None:
    """B9 phase contract: digest-stamp the rendered markdown into the ledger's
    REPORT phase. Best-effort — a phase-engine hiccup must never break a
    report that already rendered from verified rows."""
    try:
        import hashlib

        from hunter.phases import mark_report_rendered

        mark_report_rendered(
            ledger,
            run_id,
            fmt="markdown",
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            chars=len(text),
            out=str(out) if out is not None else "",
        )
    except Exception:  # noqa: BLE001 — phase bookkeeping is best-effort
        pass


# ----------------------------------------------------------------------- runs ---

@app.command()
def runs(state: Path | None = typer.Option(None, "--state", help="State directory.")) -> None:
    """List scan runs recorded in the ledger."""
    ledger = _open_ledger(state)
    try:
        table = Table(title="Runs")
        for col in ("run_id", "target", "engine", "status", "findings", "ended"):
            table.add_column(col)
        for r in ledger.runs():
            n = len(ledger.findings(str(r["run_id"])))
            table.add_row(
                str(r["run_id"]), str(r.get("target", "")), str(r.get("engine", "")),
                str(r.get("status", "")), str(n), str(r.get("ended_ts", "")),
            )
        console.print(table)
    except sqlite3.DatabaseError as exc:
        raise _ledger_guard(exc) from exc
    except OSError as exc:
        err_console.print(f"[hunter.error]state error:[/hunter.error] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from exc
    finally:
        ledger.close()


# ------------------------------------------------------------------ findings ---

@app.command()
def findings(
    run_id: str | None = typer.Option(None, "--run", help="Run id (default: latest)."),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """List findings of a run."""
    ledger = _open_ledger(state)
    try:
        rid = run_id or _latest_run_id(ledger)
        table = Table(title=f"Findings — {rid}")
        for col in ("id", "severity", "status", "title", "endpoint", "evidence"):
            table.add_column(col)
        for f in sorted(ledger.findings(rid), key=lambda x: -SEVERITY_ORDER.get(x.severity.value, 0)):
            table.add_row(
                f.id, _sev_markup(f.severity), f.status.value, f.title,
                f"{f.method} {f.endpoint}", str(len(f.evidence_ids)),
            )
        console.print(table)
    except sqlite3.DatabaseError as exc:
        raise _ledger_guard(exc) from exc
    except OSError as exc:
        err_console.print(f"[hunter.error]state error:[/hunter.error] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from exc
    finally:
        ledger.close()


# ---------------------------------------------------------------------- retro ---

@app.command()
def retro(
    run_id: str | None = typer.Argument(None, help="Run id (default: --run or the latest run)."),
    run: str | None = typer.Option(None, "--run", help="Run id."),
    record: bool = typer.Option(False, "--record", help="Persist the retro (phase engine)."),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Show (or with --record, persist) the phase retro for a run."""
    ledger = _open_ledger(state)
    try:
        rid = run or run_id
        if not rid:
            rid = _latest_run_id(ledger)
        elif not any(row["run_id"] == rid for row in ledger.runs()):
            err_console.print(f"[hunter.error]unknown run:[/hunter.error] {rid}")
            raise typer.Exit(1)
        lines = _phase_retro_lines(ledger, rid, record=record)
        if record and lines is not None:
            from hunter.agent.curator import extract_candidates
            from hunter.phases import compute_retro
            retro = compute_retro(ledger, rid)
            candidates = extract_candidates(retro, ledger.findings(rid))
            if candidates:
                lines.append(
                    f"curator: {len(candidates)} candidate technique(s) — run /curate (or 'hunter curate {rid}') to review and save"
                )
    except sqlite3.DatabaseError as exc:
        raise _ledger_guard(exc) from exc
    finally:
        ledger.close()
    if lines is None:
        err_console.print("phase engine not available")
        raise typer.Exit(1)
    table = Table(title=f"Retro — {rid}")
    table.add_column("phase timeline")
    for line in lines:
        table.add_row(line)
    console.print(table)


def _phase_retro_lines(ledger: Ledger, run_id: str, *, record: bool) -> list[str] | None:
    """B9 phase contract, consumed lazily: None when the phase engine is not
    importable (the command then answers "phase engine not available")."""
    try:
        from hunter.phases import compute_retro, record_retro
    except ImportError:
        return None
    retro = record_retro(ledger, run_id) if record else compute_retro(ledger, run_id)
    lines: list[str] = []
    coverage = getattr(retro, "coverage_pct", None)
    lines.append(f"coverage: {'n/a' if coverage is None else f'{coverage:.0f}%'}")
    lines.extend(f"gap: {gap}" for gap in getattr(retro, "gaps", []) or [])
    lines.extend(f"lesson: {lesson}" for lesson in getattr(retro, "lessons", []) or [])
    stats = getattr(retro, "stats", {}) or {}
    lines.extend(f"{key}: {value}" for key, value in sorted(stats.items()))
    return lines or ["(no retro data)"]


# --------------------------------------------------------------------- curate ---

@app.command()
def curate(
    run_id: str | None = typer.Argument(None, help="Run id (default: latest run)."),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Preview and optionally save methodology skills from a run retro."""
    ledger = _open_ledger(state)
    try:
        rid = run_id or _latest_run_id(ledger)
        from hunter.agent.curator import curate as run_curator
        result = run_curator(rid, ledger=ledger, home=Path.home(), console=console)
    finally:
        ledger.close()
    console.print(result)


# --------------------------------------------------------------------- skills ---

@app.command()
def skills(
    view: str | None = typer.Option(None, "--view", help="Print the full SKILL.md of this skill name."),
) -> None:
    """List or view the merged bundled and user methodology skills."""
    from hunter.agent.skills import load_corpus

    corpus = load_corpus()
    if view is not None:
        skill = next((item for item in corpus.skills if item.name == view), None)
        if skill is None:
            err_console.print(f"[hunter.error]unknown skill or unreadable file:[/hunter.error] {view}")
            raise typer.Exit(1)
        for note in corpus.notes:
            if view in note and "shadows the bundled" in note:
                console.print(f"note: {note}")
        console.print(RichMarkdown(f"# {skill.name}\n\n{skill.description}\n\n{skill.body}"))
        return
    table = Table(title="Skills (bundled + user)")
    table.add_column("name")
    table.add_column("description")
    table.add_column("source")
    for skill in corpus.skills:
        table.add_row(skill.name, skill.description, "quarantined" if skill.quarantined else skill.source)
    for note in corpus.notes:
        console.print(f"note: {note}")
    console.print(table)


# ------------------------------------------------------------------------ tui ---

@app.command()
def tui(
    state: Path | None = typer.Option(
        None, "--state", help="State directory (also reads $HUNTER_STATE_DIR)."
    ),
) -> None:
    """Launch the interactive TUI dashboard."""
    if state is not None:
        os.environ["HUNTER_STATE_DIR"] = str(state)
    try:
        from hunter.tui.app import run as run_tui
    except ImportError as exc:  # textual missing — clean failure, no traceback
        err_console.print(
            "[hunter.error]TUI unavailable:[/hunter.error] the 'textual' package is missing — "
            "reinstall with: pip install -e ."
        )
        raise typer.Exit(1) from exc

    run_tui()


# ----------------------------------------------------------------------- chat ---

def _build_engine(
    *,
    session_id: str | None = None,
    state_dir: str | None = None,
    store: Any = None,
    config: Any = None,
    provider: Any = None,
    options: dict | None = None,
    confirm_fn: Any = None,
) -> Any:
    """The chat engine factory — a module-level seam so tests (and embedders)
    can swap the engine construction without touching the CLI flow."""
    from hunter.chat.repl import ChatEngine

    return ChatEngine(
        session_id=session_id,
        state_dir=state_dir,
        store=store,
        config=config,
        provider=provider,
        options=options,
        confirm_fn=confirm_fn,
    )


@app.command()
def chat(
    prompt: Annotated[
        str | None, typer.Argument(help="One-shot: send this text, print the reply, exit.")
    ] = None,
    session: Annotated[str | None, typer.Option("--session", help="Alias of --resume.")] = None,
    resume: Annotated[str | None, typer.Option("--resume", "-r", help="Resume session id or 'last'.")] = None,
    cont: Annotated[bool, typer.Option("--continue", "-c", help="Resume the most recent session.")] = False,
    list_sessions: Annotated[bool, typer.Option("--list", help="List sessions and exit.")] = False,
    state: Annotated[Path | None, typer.Option("--state", help="State directory.")] = None,
) -> None:
    """Chat with the HunterOs brain: interactive REPL, or one-shot with PROMPT."""
    if state is not None:
        os.environ["HUNTER_STATE_DIR"] = str(state)

    from hunter.chat.repl import _print_output, resolve_session_request, run_repl
    from hunter.chat.sessions import ChatStore

    if list_sessions:
        # No provider, no onboarding offer — a pure store listing.
        store = ChatStore()
        try:
            sessions = store.list_sessions()
            if not sessions:
                console.print("no sessions yet — chat a little first: hunter chat",
                              markup=False, highlight=False)
                return
            table = Table(title="Chat sessions")
            for col in ("session_id", "title", "last active", "model"):
                table.add_column(col)
            for row in sessions:
                table.add_row(
                    str(row["session_id"]),
                    str(row.get("title") or "(untitled)"),
                    _relative_age(row.get("last_active_at")),
                    str(row.get("model") or "-"),
                )
            console.print(table)
        finally:
            store.close()
        return

    store = ChatStore()
    try:
        resolved = resolve_session_request(store, resume, cont, session)
    finally:
        store.close()
    if resume and (resume.strip().lower() != "last") and resolved is None and not cont:
        # Unknown explicit id: friendly, with the recent sessions (exit 2).
        from hunter.hospitality import unknown_session_message

        store2 = ChatStore()
        try:
            recent = store2.list_sessions()[:5]
        finally:
            store2.close()
        err_console.print(unknown_session_message(resume.strip(), recent),
                          markup=False, highlight=False)
        raise typer.Exit(2)

    if prompt is not None:
        # One-shot: answer once, persist, exit. The first-run offer fires only
        # for an interactive stdin (a piped one-shot never gets a prompt).
        if sys.stdin.isatty():
            from hunter.cli.init_wizard import offer_onboarding

            offer_onboarding(console=console)
        engine = _build_engine(session_id=resolved, state_dir=str(state) if state else None)
        try:
            out = engine.handle_text(prompt)
            _print_output(console, out)
            if out.data.get("no_provider"):
                raise typer.Exit(8)  # Q14: config layer
            if out.kind == "interrupted":
                raise typer.Exit(130)
            if out.kind == "error":
                raise typer.Exit(1)
        finally:
            engine.close()
        return

    # Interactive REPL (offer first; a decline does NOT abort). The engine
    # comes from the same _build_engine seam as the one-shot path.
    from hunter.cli.init_wizard import offer_onboarding

    offer_onboarding(console=console)
    engine = _build_engine(session_id=resolved, state_dir=str(state) if state else None)
    try:
        # Preserve the long-standing injectable call shape for embedders/tests;
        # the real function receives the prepared engine for session continuity.
        if getattr(run_repl, "__name__", "") == "<lambda>":
            run_repl(session_id=resolved, state_dir=str(state) if state else None)
        else:
            run_repl(engine=engine)
    except ImportError as exc:
        err_console.print(
            "[hunter.error]chat unavailable:[/hunter.error] the chat surface failed to import "
            f"({type(exc).__name__}) — reinstall with: pip install -e ."
        )
        raise typer.Exit(1) from exc


def _relative_age(ts: Any) -> str:
    """Human age for a session's ``last_active_at`` epoch (list view)."""
    import time as _time

    try:
        seconds = max(0.0, _time.time() - float(ts or 0.0))
    except (TypeError, ValueError):
        return "a while ago"
    if float(ts or 0.0) <= 0.0:
        return "a while ago"
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


# -------------------------------------------------------------------- gateway ---

gateway_app = typer.Typer(help="Chat-platform gateway (Telegram, webhook).")
app.add_typer(gateway_app, name="gateway")


@gateway_app.command("start")
def gateway_start(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Start the transports the environment configures (fail-closed by omission)."""
    from hunter.errors import HunterError
    from hunter.gateway.app import GatewayApp, transports_from_env
    from hunter.llm.config import load_config

    # QA red-audit v0.2: config/transport errors (bad config file, token
    # without an allowlist, INSECURE_NO_AUTH on a non-loopback bind, a
    # non-integer HUNTEROS_WEBHOOK_PORT) must die with the classified error
    # line and its mapped exit code — never a traceback with exit 1.
    try:
        cfg = load_config()
        transports = transports_from_env()
    except (HunterError, ValueError) as exc:
        if isinstance(exc, HunterError):
            raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc
        err_console.print(f"[hunter.error]config error:[/hunter.error] {exc}")
        raise typer.Exit(8) from exc
    if not transports:
        err_console.print(
            "[hunter.warning]no transports configured.[/hunter.warning]\n"
            "Hint: set HUNTEROS_TELEGRAM_TOKEN + HUNTEROS_TELEGRAM_ALLOWED_USERS, or "
            "HUNTEROS_WEBHOOK_SECRET — see docs/GATEWAY.md.\n"
            "💡 start the 24/7 engine instead: hunter start"
        )
        raise typer.Exit(8)
    gateway = GatewayApp(cfg, transports, state_dir=str(state) if state is not None else None)
    try:
        gateway.run()
    except HunterError as exc:
        raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc
    except KeyboardInterrupt:
        console.print("[dim]gateway stopped.[/dim]")


# M11 (M5): the gateway gains the full Hermes verb set — stop/restart/status/
# logs DELEGATE to the daemon verbs (the same single implementation), so
# `hunter gateway restart` === `hunter restart`.

@gateway_app.command("stop")
def gateway_stop(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    timeout: float = typer.Option(15.0, "--timeout", help="Seconds to wait for a cooperative stop."),
    force: bool = typer.Option(False, "--force", help="Terminate/kill after the timeout."),
) -> None:
    """Stop the 24/7 engine (drain-safe cooperative stop)."""
    from hunter.cli.daemon import _cmd_stop

    raise typer.Exit(_cmd_stop(state=state, timeout=timeout, force=force))


@gateway_app.command("restart")
def gateway_restart(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    drain_timeout: float | None = typer.Option(
        None, "--drain-timeout", help="Seconds to wait for the engine to drain before forcing."
    ),
) -> None:
    """Restart the engine (drain-first; auto-starts when nothing runs)."""
    from hunter.cli.daemon import _cmd_restart

    raise typer.Exit(
        _cmd_restart(
            target=None, scope=None, engine=None, time_text=None, min_time_text=None,
            yes=False, force=False, state=state, drain_timeout=drain_timeout,
        )
    )


@gateway_app.command("status")
def gateway_status(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable JSON."),
) -> None:
    """Show engine status (running/paused/stopped, queue, last run)."""
    from hunter.cli.daemon import _cmd_status

    raise typer.Exit(_cmd_status(state=state, json_out=json_out))


@gateway_app.command("logs")
def gateway_logs(
    state: Path | None = typer.Option(None, "--state", help="State directory."),
    lines: int = typer.Option(50, "--lines", help="Print the last N lines."),
    follow: bool = typer.Option(False, "--follow", help="Keep the log open and print new lines."),
) -> None:
    """Tail the engine log."""
    from hunter.cli.daemon import _cmd_logs

    raise typer.Exit(_cmd_logs(state=state, lines=lines, follow=follow))


# --------------------------------------------------------------------- config ---

config_app = typer.Typer(help="Inspect and manage harness configuration.")
app.add_typer(config_app, name="config")

# M11 config verbs (path/get/set/unset/edit/check + key set/list) live in
# cli/config_cmd.py and register on THIS sub-app; `example`/`show` and the
# provider sub-commands stay below.
from hunter.cli.config_cmd import register_config_commands  # noqa: E402

register_config_commands(config_app)


@config_app.command("example")
def config_example() -> None:
    """Print a fully commented example ~/.hunter/config.yaml."""
    import typer as _typer

    from hunter.llm.config import config_example_yaml

    # Raw stdout on purpose: the example is meant to be piped into a file
    # (`hunter config example > config.yaml`) and rich's soft-wrapping would
    # corrupt the YAML on narrow terminals.
    _typer.echo(config_example_yaml())


@config_app.command("show")
def config_show() -> None:
    """Print the effective configuration (key values never shown, env names only)."""
    from hunter.errors import HunterError
    from hunter.llm.base import TIERS
    from hunter.llm.config import load_config

    try:
        cfg = load_config()
    except HunterError as exc:
        raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc
    table = Table(title="Effective HunterOs configuration")
    table.add_column("key")
    table.add_column("value")
    table.add_row("agent.tier", str(getattr(cfg.agent, "tier", "basic")))
    table.add_row("agent.api_max_retries", str(getattr(cfg.agent, "api_max_retries", 3)))
    # Legacy rename notes ride on the loaded config — printed at most once
    # per command, right here (never inside resolve/complete).
    legacy_notes = tuple(getattr(cfg, "legacy_notes", ()) or ())
    if legacy_notes:
        table.add_row("legacy names", "; ".join(legacy_notes))
    for t in TIERS:
        tc = (getattr(cfg, "model_tiers", {}) or {}).get(t)
        table.add_row(f"model_tiers.{t}", str(getattr(tc, "model", "") or "(default)"))
    for name, prov in (getattr(cfg, "providers", {}) or {}).items():
        table.add_row(f"providers.{name}", f"key_env={getattr(prov, 'key_env', '') or '-'}")
    fb = getattr(cfg, "fallback_providers", []) or []
    table.add_row(
        "fallback_providers",
        ", ".join(f"{getattr(e, 'provider', '?')}/{getattr(e, 'model', '?')}" for e in fb) or "-",
    )
    b = cfg.budget
    table.add_row("budget", f"${b.max_cost_usd} / {b.max_iterations} iters / {b.wall_seconds}s")
    console.print(table)


# --- config provider sub-commands (custom / third-party brains) ----------------

provider_app = typer.Typer(help="Manage LLM providers in the config file.")
config_app.add_typer(provider_app, name="provider")
# Top-level shortcut: `hunter provider ...` === `hunter config provider ...`
# (the SAME Typer instance under a second parent — help text identical).
app.add_typer(provider_app, name="provider")


def _raw_config_or_exit(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        err_console.print(f"[hunter.error]config error:[/hunter.error] {path} is not readable YAML: {exc}")
        raise typer.Exit(8) from exc
    return loaded if isinstance(loaded, dict) else {}


@provider_app.command("add")
def provider_add(
    name: str = typer.Argument(
        "", help="Provider name (omit it for the interactive wizard)."
    ),
    base_url: str = typer.Option(
        "", "--base-url", help="OpenAI-compatible endpoint (required for unknown names)."
    ),
    key_env: str = typer.Option("", "--key-env", help="Env var holding the API key (preferred)."),
    api_key_stdin: bool = typer.Option(
        False, "--api-key-stdin", help="Read ONE line (the key) from stdin — never argv."
    ),
    default_model: str = typer.Option(
        "", "--default-model", help="Also pin model_tiers.orchestrator.model."
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing provider block."),
) -> None:
    """Add (or with --force, replace) a provider in the config file.

    Omitting NAME opens the interactive wizard (provider pick, key capture,
    endpoint auto-detect, model auto-add, role assignment); every flagged
    invocation keeps its exact scripted semantics.
    """
    from hunter.llm.providers import PROVIDER_NAME_RE, known_provider, known_provider_names
    from hunter.llm.writing import resolve_config_target, write_config

    if not name:
        # Wizard trigger is NAME-OMISSION only — flagged paths never reach it.
        from hunter.cli.provider_add import run_provider_add_wizard

        code = run_provider_add_wizard(console=console, err_console=err_console)
        if code:
            raise typer.Exit(code)
        return

    if not PROVIDER_NAME_RE.match(name):
        err_console.print(
            f"[hunter.error]invalid provider name:[/hunter.error] {name!r} — lowercase letters/digits/'-'/'_', "
            "starting with a letter"
        )
        raise typer.Exit(2)
    known = known_provider(name)
    if not base_url and known is not None:
        base_url = known.base_url
    if not base_url and known is None:
        err_console.print(
            f"[hunter.error]missing --base-url:[/hunter.error] '{name}' is not a known provider — pass --base-url "
            "(any OpenAI-compatible endpoint), or pick a known name: "
            f"{', '.join(known_provider_names())}"
        )
        raise typer.Exit(2)

    api_key = ""
    if api_key_stdin:
        import sys

        sys.stdout.write(f"paste the API key for '{name}' (one line, input is not echoed to logs): ")
        sys.stdout.flush()
        api_key = sys.stdin.readline().rstrip("\r\n").strip()
        err_console.print(
            "[hunter.warning]note:[/hunter.warning] inline api_key written to the config file — --key-env is preferred"
        )
    if key_env and api_key:
        err_console.print(
            "[dim]note: --key-env and an inline key were both given — the env var wins at runtime[/dim]"
        )

    target = resolve_config_target()
    raw = _raw_config_or_exit(target)
    existing = (raw.get("providers") or {}).get(name)
    if isinstance(existing, dict) and existing and not force:
        err_console.print(
            f"[hunter.error]provider '{name}' already exists in {target}[/hunter.error] — pass --force to replace it"
        )
        raise typer.Exit(2)

    block: dict = {}
    if key_env:
        block["key_env"] = key_env
    elif known is not None and known.key_env and not api_key:
        block["key_env"] = known.key_env  # sane default for known keyed providers
    if api_key:
        block["api_key"] = api_key
    if base_url:
        block["base_url"] = base_url
    if not block:  # pragma: no cover — base_url is required for unknown names
        block["base_url"] = base_url
    updates: dict = {"providers": {name: block}}
    if default_model:
        updates["model_tiers"] = {"orchestrator": {"model": default_model}}
    write_config(updates, target)
    console.print(f"[hunter.success]added provider '{name}'[/hunter.success] → {target}")
    console.print("next: [bold]hunter config provider test " + name + "[/bold] · provider list")


@provider_app.command("list")
def provider_list() -> None:
    """Show providers: name / key source / base_url / default model."""
    from hunter.errors import HunterError
    from hunter.llm.config import load_config

    try:
        cfg = load_config()
    except HunterError as exc:
        raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc
    if not cfg.providers:
        console.print(
            "no providers configured — add one: "
            "[bold]hunter config provider add <name> --base-url <url>[/bold]"
        )
        return
    orchestrator = cfg.model_tiers.get("orchestrator")
    table = Table(title="LLM providers")
    for col in ("name", "key source", "base_url", "default model"):
        table.add_column(col)
    for name, prov in sorted(cfg.providers.items()):
        if prov.key_env:
            key_source = f"env:{prov.key_env}"
            if not os.environ.get(prov.key_env):
                key_source += " (not set)"
        elif prov.api_key:
            key_source = "inline"
        else:
            key_source = "keyless"
        model = ""
        if orchestrator is not None and orchestrator.provider == name and orchestrator.model:
            model = orchestrator.model
        table.add_row(name, key_source, prov.base_url or "-", model or "-")
    console.print(table)


@provider_app.command("remove")
def provider_remove(
    name: str = typer.Argument(..., help="Provider name to remove."),
    force: bool = typer.Option(False, "--force", help="Remove even if tiers/fallbacks still reference it."),
) -> None:
    """Remove a provider from the config file (refuses while referenced)."""
    from hunter.llm.writing import resolve_config_target, write_config

    target = resolve_config_target()
    raw = _raw_config_or_exit(target)
    if name not in (raw.get("providers") or {}):
        err_console.print(f"[hunter.error]unknown provider:[/hunter.error] '{name}' is not in {target}")
        raise typer.Exit(1)
    referenced: list[str] = []
    for tier_name, block in sorted((raw.get("model_tiers") or {}).items()):
        if isinstance(block, dict) and block.get("provider") == name:
            referenced.append(f"model_tiers.{tier_name}.provider")
    for index, entry in enumerate(raw.get("fallback_providers") or []):
        if isinstance(entry, dict) and entry.get("provider") == name:
            referenced.append(f"fallback_providers[{index}].provider")
    if referenced and not force:
        err_console.print(
            f"[hunter.error]provider '{name}' is still referenced by:[/hunter.error] {', '.join(referenced)}\n"
            "point those tiers/fallbacks elsewhere first, or pass --force"
        )
        raise typer.Exit(2)
    write_config({"providers": {name: None}}, target)  # None deletes the block
    dangling = " (references left dangling by --force)" if referenced else ""
    console.print(f"[hunter.success]removed[/hunter.success] provider '{name}' from {target}{dangling}")


@provider_app.command("test")
def provider_test(
    name: str = typer.Argument(..., help="Provider name to ping."),
    model: str = typer.Option("", "--model", help="Model id (default: orchestrator tier / table default)."),
    timeout: int = typer.Option(15, "--timeout", help="Seconds to wait for the 1-token reply."),
) -> None:
    """Ping a provider live with a 1-token completion."""
    from hunter.errors import EXIT_AUTH, HunterError
    from hunter.llm.config import load_config, resolve_key
    from hunter.llm.ping import ping_provider
    from hunter.llm.providers import known_provider

    try:
        cfg = load_config()
    except HunterError as exc:
        raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc

    prov = cfg.providers.get(name)
    known = known_provider(name)
    base_url = (prov.base_url if prov is not None else "") or (known.base_url if known else "")
    api_key = ""
    if prov is not None:
        try:
            api_key = resolve_key(name, cfg)
        except HunterError as exc:
            err_console.print(f"[hunter.error]key missing[/hunter.error] ({prov.key_env or name}) — {exc.hint}")
            raise typer.Exit(EXIT_AUTH) from exc
    elif known is not None and known.key_env:
        api_key = os.environ.get(known.key_env, "").strip()
        if not api_key:
            err_console.print(f"[hunter.error]key missing[/hunter.error] ({known.key_env}) — set it and re-run")
            raise typer.Exit(EXIT_AUTH)

    model_id = model
    if not model_id and prov is not None and cfg.model_tiers.get("orchestrator") is not None:
        orchestrator = cfg.model_tiers["orchestrator"]
        # The orchestrator model is the top default: it applies when this
        # provider owns the tier or when the tier left the provider on "auto".
        if orchestrator.provider in ("", "auto", name) and orchestrator.model:
            model_id = orchestrator.model
    if not model_id and known is not None:
        model_id = known.default_model
    if not model_id:
        err_console.print(f"[hunter.error]no model to test:[/hunter.error] pass --model <model-id> for '{name}'")
        raise typer.Exit(2)

    try:
        result = ping_provider(
            name, model_id, base_url, api_key, timeout,
            endpoint=(prov.endpoint if prov is not None else ""),
        )
    except HunterError as exc:
        raise typer.Exit(handle_cli_error(exc, verbose=is_verbose())) from exc
    if result.ok:
        console.print(f"{name}: [hunter.success]{result.message}[/hunter.success]")
        raise typer.Exit(0)
    err_console.print(result.message)
    raise typer.Exit(result.exit_code or 1)


# --------------------------------------------------------------------- verify ---

@app.command()
def verify(
    run_id: str | None = typer.Option(
        None, "--run", help="Verify one run's subchain (default: whole ledger)."
    ),
    state: Path | None = typer.Option(None, "--state", help="State directory."),
) -> None:
    """Recompute the ledger hash chain — the tamper check behind every report."""
    ledger = _open_ledger(state)
    try:
        # A verification of a run that does not exist must FAIL, not report a
        # vacuous "chain OK — 0 events verified" (a security tool never
        # claims success over nothing).
        if run_id is not None and not any(r["run_id"] == run_id for r in ledger.runs()):
            err_console.print(f"[hunter.error]unknown run:[/hunter.error] {run_id}")
            raise typer.Exit(1)
        result = ledger.verify_chain(run_id)
    except sqlite3.DatabaseError as exc:
        raise _ledger_guard(exc) from exc
    except OSError as exc:
        err_console.print(f"[hunter.error]state error:[/hunter.error] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from exc
    finally:
        ledger.close()
    if result.ok:
        console.print(f"[hunter.success]chain OK[/hunter.success] — {result.checked} events verified.")
        raise typer.Exit(0)
    console.print(f"[hunter.error]CHAIN BROKEN[/hunter.error] at seq {result.broken_at_seq}")
    for line in result.details[:5]:
        console.print(f"  - {line}")
    raise typer.Exit(7)


def main() -> None:
    from typer.main import get_command

    from hunter.cli.handle import run_app

    # Non-standalone: the backstop (handle.py) owns interrupts and escapes;
    # argument errors keep typer's own rendering and exit codes.
    run_app(get_command(app))


# --------------------------------------------------------------------- daemon ---
# The daemon CLI (M8 F2) lives in cli/daemon.py and registers the `daemon`
# sub-app plus the top-level start/stop/status aliases on THIS app. The
# import sits at the bottom because it needs the fully-built app object.
from hunter.cli.daemon import register_daemon_commands  # noqa: E402

register_daemon_commands(app)


if __name__ == "__main__":
    main()
