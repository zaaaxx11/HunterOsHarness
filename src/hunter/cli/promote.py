"""`hunter promote` command — list, promote-to-skill, promote-to-tool.

Exposes:
    register_promote_commands(app) — mount list/skill/tool on a Typer app.

This module keeps imports lazy so test discovery is fast and quiet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from hunter.errors import HunterError
from hunter.promote import eligible_promotions, promote_to_skill, promote_to_tool


def _err():
    from hunter.branding import make_console

    return make_console(stderr=True)


def _ledger():
    from hunter.kernel.ledger import Ledger
    from hunter.runtime_paths import RuntimePaths

    return Ledger(RuntimePaths.resolve(migrate=False).ledger)


def _skill_dir() -> Path:
    from hunter.agent.skills import user_skills_dir

    return user_skills_dir()


def register_promote_commands(app: Any) -> None:
    @app.command("list")
    def promote_list(
        json_out: bool = typer.Option(False, "--json", help="Emit JSON only on stdout."),
    ) -> None:
        """List findings eligible for promotion."""
        try:
            ledger = _ledger()
            candidates = eligible_promotions(ledger)
            rows = [
                {
                    "finding_id": c.finding_id,
                    "finding_key": c.finding_key,
                    "title": c.title,
                    "severity": c.severity,
                    "status": c.status,
                    "klass": c.klass,
                    "endpoint": c.endpoint,
                    "poc_path": c.poc_path,
                }
                for c in candidates
            ]
            blob = json.dumps(rows, ensure_ascii=False)
            if json_out:
                typer.echo(blob)
            else:
                _err().print(blob)
        except HunterError:
            raise
        except Exception as exc:
            from hunter.cli.handle import handle_cli_error

            handle_cli_error(exc)

    @app.command("skill")
    def promote_skill(
        finding_key: str = typer.Argument(..., help="Finding key to promote."),
        skills_dir: Path | None = typer.Option(
            None,
            "--skills-dir",
            help="Destination skills root (default ~/.hunter/skills).",
        ),
        json_out: bool = typer.Option(False, "--json", help="Emit JSON only on stdout."),
    ) -> None:
        """Promote a proven-live critical/high finding to a SKILL.md card."""
        try:
            dest = skills_dir or _skill_dir()
            ledger = _ledger()
            path = promote_to_skill(ledger, finding_key, skills_dir=dest)
            payload = {
                "finding_key": finding_key,
                "path": str(path),
                "skills_dir": str(dest),
            }
            if json_out:
                typer.echo(json.dumps(payload, ensure_ascii=False))
            else:
                _err().print(json.dumps(payload, ensure_ascii=False))
        except HunterError:
            raise
        except Exception as exc:
            from hunter.cli.handle import handle_cli_error

            handle_cli_error(exc)

    @app.command("tool")
    def promote_tool(
        finding_key: str = typer.Argument(..., help="Finding key to promote."),
        tools_dir: Path | None = typer.Option(
            None,
            "--tools-dir",
            help="Destination tools root (default ~/.hunter/tools).",
        ),
        json_out: bool = typer.Option(False, "--json", help="Emit JSON only on stdout."),
    ) -> None:
        """Promote a proven-live critical/high finding to a Python tool script."""
        try:
            dest = tools_dir or (Path.home() / ".hunter" / "tools")
            ledger = _ledger()
            path = promote_to_tool(ledger, finding_key, tools_dir=dest)
            payload = {
                "finding_key": finding_key,
                "path": str(path),
                "tools_dir": str(dest),
            }
            if json_out:
                typer.echo(json.dumps(payload, ensure_ascii=False))
            else:
                _err().print(json.dumps(payload, ensure_ascii=False))
        except HunterError:
            raise
        except Exception as exc:
            from hunter.cli.handle import handle_cli_error

            handle_cli_error(exc)
