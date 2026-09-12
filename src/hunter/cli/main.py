"""`hunter` — the HunterOs Harness CLI.

Every command reads/writes through the ledger; reports render only from
ledger rows; the claim gate cannot be bypassed from here (enforced below it).

State directory: ``--state`` option, env ``HUNTER_STATE_DIR``, or ``.hunter``
under the current directory (in that order of precedence per invocation).
"""

from __future__ import annotations

import platform
from importlib import metadata
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.markdown import Markdown as RichMarkdown
from rich.table import Table

from hunter.kernel.findings import SEVERITY_ORDER
from hunter.kernel.ledger import Ledger
from hunter.tools.scope import (
    LOCAL_HOSTS,
    ScopeSet,
    ScopeViolation,
    localhost_scope,
    scope_from_manifest,
)

app = typer.Typer(
    help="HunterOs Harness — evidence-first security-audit harness.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()
err_console = Console(stderr=True)


def _version() -> str:
    try:
        return metadata.version("hunteros-harness")
    except metadata.PackageNotFoundError:
        from hunter import __version__

        return __version__


def _open_ledger(state: Path | None) -> Ledger:
    # `state` is a state DIRECTORY (pipeline convention); the db lives inside it.
    db = None if state is None else Path(state) / "ledger.db"
    return Ledger(db) if db is not None else Ledger()


def _latest_run_id(ledger: Ledger) -> str:
    runs = ledger.runs()
    if not runs:
        err_console.print("[red]No runs in the ledger yet — run `hunter demo` or `hunter scan` first.[/red]")
        raise typer.Exit(1)
    return str(runs[-1]["run_id"])


def _scope_for_target(target: str, scope_file: Path | None) -> ScopeSet:
    """localhost targets are always allowed; anything else needs a manifest."""
    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError:  # malformed IPv6 literal etc. — fail closed, exit 2
        err_console.print(f"[red]BLOCKED:[/red] target {target!r} is not a valid URL.")
        raise typer.Exit(2) from None
    if host in LOCAL_HOSTS:
        # stderr on purpose: with --json this line must never touch stdout.
        if scope_file is not None:
            err_console.print("[dim]note: target is localhost; scope manifest ignored[/dim]")
        return localhost_scope()
    if scope_file is None:
        err_console.print(
            f"[red]BLOCKED:[/red] target '{host}' is not localhost. "
            "Pass [bold]--scope scope.json[/bold] with an authorized scope manifest "
            '(e.g. {"name": "client-x", "hosts": ["example.com"]}).'
        )
        raise typer.Exit(2)
    try:
        return scope_from_manifest(scope_file)
    except ValueError as exc:  # invalid/empty manifest — usage error, exit 2
        err_console.print(f"[red]BLOCKED:[/red] invalid scope manifest: {exc}")
        raise typer.Exit(2) from exc


_SEV_COLOR = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _sev_markup(severity) -> str:
    value = severity.value
    return f"[{_SEV_COLOR.get(value, 'white')}]{value}[/{_SEV_COLOR.get(value, 'white')}]"


# ---------------------------------------------------------------- version ---

@app.command()
def version() -> None:
    """Print the harness version."""
    console.print(f"hunter {_version()}")


# ----------------------------------------------------------------- doctor ---

@app.command()
def doctor(
    state: Path | None = typer.Option(
        None, "--state", help="State directory (default: .hunter or $HUNTER_STATE_DIR)."
    ),
) -> None:
    """Check the environment: python, deps, ledger, engines."""
    ok = True

    def check(label: str, good: bool, detail: str = "") -> None:
        nonlocal ok
        mark = "[green]OK[/green]" if good else "[red]FAIL[/red]"
        if not good:
            ok = False
        console.print(f"  {mark}  [bold]{label}[/bold] {detail}")

    console.print(f"[bold]HunterOs Harness doctor[/bold] — hunter {_version()}")
    check("python", True, f"{platform.python_version()} on {platform.system()}")

    for dep in ("typer", "rich", "textual", "httpx"):
        try:
            check(f"dep:{dep}", True, metadata.version(dep))
        except metadata.PackageNotFoundError:
            check(f"dep:{dep}", False, "missing — pip install -e .")

    ledger = _open_ledger(state)
    try:
        db_path = ledger.path
        runs = ledger.runs()
        check("state-dir", True, f"{db_path} — {len(runs)} run(s)")
        if runs:
            report = ledger.verify_chain()
            detail = (
                f"{report.checked} events verified"
                if report.ok
                else f"BROKEN at seq {report.broken_at_seq}"
            )
            check("ledger-chain", report.ok, detail)
        else:
            check("ledger-chain", True, "empty ledger")
    finally:
        ledger.close()

    from hunter.tools.registry import available_engines

    engines = available_engines()
    check("engines", "deterministic" in engines, ", ".join(engines))

    try:
        from hunter.workflow.bench import run_demo  # noqa: F401

        check("workflow", True, "pipeline + demo ready")
    except Exception as exc:  # pragma: no cover
        check("workflow", False, str(exc))

    if not ok:
        raise typer.Exit(1)
    console.print("[green]All checks passed.[/green]")


# ------------------------------------------------------------------- demo ---

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
        err_console.print(f"[red]demo failed:[/red] {exc}")
        raise typer.Exit(1) from exc

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


# ------------------------------------------------------------------- scan ---

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
    from hunter.workflow.pipeline import run_scan

    try:
        chosen_scope = _scope_for_target(target, scope)
    except ScopeViolation as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    try:
        summary = run_scan(target, engine_name=engine, scope=chosen_scope, state_dir=state)
    except ValueError as exc:  # unknown engine — usage error, not a scan outcome
        err_console.print(f"[red]BLOCKED:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_out:
        import json

        console.print_json(
            json.dumps(
                {
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
            )
        )
    else:
        if summary.status != "completed":
            err_console.print(
                f"[red]scan {summary.run_id} failed[/red] — see events: hunter report --run {summary.run_id}"
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
    raise typer.Exit(0 if summary.status == "completed" else 1)


# ----------------------------------------------------------------- report ---

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
                err_console.print(f"[red]unknown run:[/red] {rid}")
                raise typer.Exit(1) from exc
            if out is not None:
                out.write_text(text, encoding="utf-8")
                console.print(f"[green]wrote[/green] {out}")
            else:
                console.print(RichMarkdown(text))
        elif fmt == "sarif":
            import json

            from hunter.reporting.sarif import to_sarif, write_sarif

            if out is not None:
                path = write_sarif(ledger, rid, out)
                console.print(f"[green]wrote[/green] {path}")
            else:
                console.print_json(json.dumps(to_sarif(ledger, rid)))
        else:
            err_console.print(f"[red]unknown format:[/red] {fmt} (use markdown | sarif)")
            raise typer.Exit(2)
    except ReportBlocked as exc:
        # Both renderers refuse a broken chain — the ledger may be tampered.
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    except KeyError as exc:
        err_console.print(f"[red]unknown run:[/red] {run_id or '(latest)'}")
        raise typer.Exit(1) from exc
    finally:
        ledger.close()


# ------------------------------------------------------------------- runs ---

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
    finally:
        ledger.close()


# --------------------------------------------------------------- findings ---

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
    finally:
        ledger.close()


# ----------------------------------------------------------------- skills ---

@app.command()
def skills(
    view: str | None = typer.Option(None, "--view", help="Print the full SKILL.md of this skill name."),
) -> None:
    """List (or view) bundled methodology skills."""
    from importlib import resources

    root = resources.files("hunter") / "_data" / "skills"  # type: ignore[assignment]
    if view is not None:
        skill_file = root / view / "SKILL.md"
        try:
            console.print(RichMarkdown(skill_file.read_text(encoding="utf-8")))
        except FileNotFoundError as exc:
            err_console.print(f"[red]unknown skill:[/red] {view}")
            raise typer.Exit(1) from exc
        return
    table = Table(title="Skills (hunter/_data/skills)")
    table.add_column("name")
    table.add_column("description")
    try:
        for entry in sorted(resource.name for resource in root.iterdir()):
            if entry == "INDEX.md" or entry.startswith("_"):
                continue
            skill_md = root / entry / "SKILL.md"
            desc = ""
            if skill_md.is_file():
                for line in skill_md.read_text(encoding="utf-8").splitlines():
                    if line.lower().startswith("description:"):
                        desc = line.split(":", 1)[1].strip()
                        break
            table.add_row(entry, desc)
    except FileNotFoundError:
        err_console.print("[yellow]skills corpus not installed[/yellow]")
    console.print(table)


# -------------------------------------------------------------------- tui ---

@app.command()
def tui(
    state: Path | None = typer.Option(
        None, "--state", help="State directory (also reads $HUNTER_STATE_DIR)."
    ),
) -> None:
    """Launch the interactive TUI dashboard."""
    import os

    if state is not None:
        os.environ["HUNTER_STATE_DIR"] = str(state)
    try:
        from hunter.tui.app import run as run_tui
    except ImportError as exc:  # textual missing — clean failure, no traceback
        err_console.print(
            "[red]TUI unavailable:[/red] the 'textual' package is missing — "
            "reinstall with: pip install -e ."
        )
        raise typer.Exit(1) from exc

    run_tui()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
