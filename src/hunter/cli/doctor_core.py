"""Doctor checks — pure collection, no rendering.

:func:`collect_checks` gathers every environment check as a list of
:class:`Check` rows; ``hunter doctor`` (cli/main.py) owns the table/JSON
rendering and the exit code. Notes (status ``"note"``) are opt-in readiness
gaps — they NEVER flip the exit code; only ``"fail"`` does.

This module must never raise for diagnoseable conditions: broken ledgers,
corrupt chat databases, unreadable configs, and dead provider endpoints all
become FAIL rows with a readable detail instead of tracebacks.
"""

from __future__ import annotations

import os
import platform
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from hunter.errors import HunterError

__all__ = ["Check", "collect_checks"]


@dataclass(frozen=True)
class Check:
    """One doctor row: ``status`` is ok | fail | note."""

    label: str
    status: str
    detail: str = ""


def collect_checks(
    state: Path | None = None,
    *,
    live: bool = False,
    ledger_factory: Callable[[], Any] | None = None,
) -> list[Check]:
    """Run every check. ``state`` is the state DIRECTORY (ledger.db inside);
    ``live`` opts in to provider endpoint probes (real network, bounded);
    ``ledger_factory`` lets the CLI keep one ledger convention (and its test
    seams) — the default opens ``Ledger(state/ledger.db)``."""
    checks: list[Check] = []
    checks.append(
        Check("python", "ok", f"{platform.python_version()} on {platform.system()}")
    )
    checks.extend(_dep_checks())
    checks.extend(_ledger_checks(state, ledger_factory))
    checks.extend(_engine_checks())
    checks.extend(_llm_checks())
    checks.extend(_provider_checks(live=live))
    checks.append(_chat_db_check())
    checks.extend(_home_checks(state))
    return checks


# --------------------------------------------------------------------- deps --


def _dep_checks() -> list[Check]:
    checks: list[Check] = []
    for dep in ("typer", "rich", "textual", "httpx"):
        try:
            checks.append(Check(f"dep:{dep}", "ok", metadata.version(dep)))
        except metadata.PackageNotFoundError:
            checks.append(Check(f"dep:{dep}", "fail", "missing — pip install -e ."))
    return checks


# ------------------------------------------------------------------- ledger --


def _open_ledger(state: Path | None, ledger_factory: Callable[[], Any] | None) -> Any:
    if ledger_factory is not None:
        return ledger_factory()
    from hunter.kernel.ledger import Ledger

    return Ledger(None if state is None else Path(state) / "ledger.db")


def _ledger_checks(state: Path | None, ledger_factory: Callable[[], Any] | None) -> list[Check]:
    try:
        ledger = _open_ledger(state, ledger_factory)
    except (sqlite3.DatabaseError, OSError) as exc:
        return [Check("state-dir", "fail", f"cannot open ledger: {type(exc).__name__}: {exc}")]
    try:
        runs = ledger.runs()
        checks = [Check("state-dir", "ok", f"{ledger.path} — {len(runs)} run(s)")]
        try:
            if runs:
                report = ledger.verify_chain()
                detail = (
                    f"{report.checked} events verified"
                    if report.ok
                    else f"BROKEN at seq {report.broken_at_seq}"
                )
                checks.append(Check("ledger-chain", "ok" if report.ok else "fail", detail))
            else:
                checks.append(Check("ledger-chain", "ok", "empty ledger"))
        except (sqlite3.DatabaseError, OSError) as exc:
            checks.append(Check("ledger-chain", "fail", f"unreadable: {type(exc).__name__}: {exc}"))
    except (sqlite3.DatabaseError, OSError) as exc:
        checks.append(Check("state-dir", "fail", f"unreadable: {type(exc).__name__}: {exc}"))
    finally:
        ledger.close()
    return checks


def _engine_checks() -> list[Check]:
    from hunter.tools.registry import available_engines

    engines = available_engines()
    checks = [
        Check(
            "engines",
            "ok" if "deterministic" in engines else "fail",
            ", ".join(engines),
        )
    ]
    try:
        from hunter.workflow.bench import run_demo  # noqa: F401

        checks.append(Check("workflow", "ok", "pipeline + demo ready"))
    except Exception as exc:  # pragma: no cover — broken workflow install
        checks.append(Check("workflow", "fail", str(exc)))
    return checks


# ----------------------------------------------------------------- llm brain --


def _llm_checks() -> list[Check]:
    from hunter.llm.config import AGENT_TIERS, load_config, resolve_model

    checks: list[Check] = []
    try:
        cfg = load_config()
    except HunterError as exc:
        # config errors carry file + line numbers — surface them verbatim.
        return [Check("llm-config", "fail", str(exc).replace("\n", " — "))]

    # The source line carries the legacy-rename notes at most once per
    # command (resolution paths never warn).
    source_detail = cfg.source_path or "defaults, no config file"
    if cfg.legacy_notes:
        source_detail = f"{source_detail} — {'; '.join(cfg.legacy_notes)}"
    checks.append(Check("llm-config", "ok", source_detail))
    if cfg.agent.tier == "basic":
        checks.append(
            Check(
                "llm-tier",
                "note",
                "basic — pin a brain with agent.tier or $HUNTEROS_TIER "
                f"({', '.join(AGENT_TIERS)})",
            )
        )
    else:
        checks.append(Check("llm-tier", "ok", cfg.agent.tier))

    try:
        orchestrator_model = resolve_model("orchestrator", cfg)
    except HunterError:
        checks.append(
            Check(
                "llm-model",
                "note",
                "unset — set HUNTEROS_MODEL or model_tiers.orchestrator.model "
                "in ~/.hunteros/config.yaml",
            )
        )
    else:
        checks.append(Check("llm-model", "ok", f"orchestrator: {orchestrator_model}"))

    key_notes = []
    for provider_name, provider_cfg in sorted(cfg.providers.items()):
        if provider_cfg.key_env:
            state_str = "set" if os.environ.get(provider_cfg.key_env) else "not set"
            key_notes.append(f"{provider_name}:{provider_cfg.key_env}={state_str}")
        elif provider_cfg.api_key:
            key_notes.append(f"{provider_name}:inline key")
        else:
            key_notes.append(f"{provider_name}:keyless")
    checks.append(
        Check("llm-keys", "note", ", ".join(key_notes) if key_notes else "no providers configured")
    )

    try:
        litellm_version = metadata.version("litellm")
    except metadata.PackageNotFoundError:
        checks.append(
            Check(
                "llm-litellm",
                "note",
                "LLM brain not installed (extra [llm]) — pip install 'hunteros-harness[llm]'",
            )
        )
    else:
        checks.append(Check("llm-litellm", "ok", litellm_version))
    return checks


# ---------------------------------------------------------------- providers --


def _probe_base_url(base_url: str) -> str:
    """Live reachability: ANY http response counts (HEAD may 405); only
    connect/timeout errors mean unreachable."""
    try:
        import httpx

        response = httpx.head(base_url, timeout=4, follow_redirects=False)
    except Exception as exc:  # noqa: BLE001 — classified into one word below
        return f"unreachable ({type(exc).__name__})"
    return f"reachable (HTTP {response.status_code})"


def _provider_checks(*, live: bool) -> list[Check]:
    from hunter.llm.config import load_config, resolve_model

    try:
        cfg = load_config()
    except HunterError:
        return []  # the llm-config row already carries the diagnosis
    orchestrator_model = ""
    try:
        orchestrator_model = resolve_model("orchestrator", cfg)
    except HunterError:
        orchestrator_model = ""  # no model resolved — the llm-model row already notes it
    checks: list[Check] = []
    for name, provider in sorted(cfg.providers.items()):
        parts: list[str] = []
        status = "ok"
        if provider.key_env:
            if os.environ.get(provider.key_env):
                parts.append(f"key set ({provider.key_env})")
            else:
                parts.append(f"key NOT set ({provider.key_env})")
                status = "note"
        elif provider.api_key:
            parts.append("inline key set")
        else:
            parts.append("keyless (no key_env / api_key)")
            status = "note"
        if provider.base_url:
            parts.append(provider.base_url)
            if live:
                parts.append(_probe_base_url(provider.base_url))
        orchestrator_tier = cfg.model_tiers.get("orchestrator")
        if orchestrator_model and orchestrator_tier is not None and orchestrator_tier.provider == name:
            parts.append(f"model {orchestrator_model}")
        checks.append(Check(f"provider:{name}", status, " — ".join(parts)))
    return checks


# ----------------------------------------------------------------- chat db --


def _chat_db_path() -> Path:
    from_env = (os.environ.get("HUNTEROS_CHAT_DB") or "").strip()
    if from_env:
        return Path(from_env)
    from hunter.home import hunter_home

    return hunter_home() / "chat.db"


def _chat_db_check() -> Check:
    path = _chat_db_path()
    if not path.is_file():
        return Check("chat-db", "note", "no chat db yet (created on first `hunter chat`)")
    try:
        conn = sqlite3.connect(str(path))
        try:
            result = conn.execute("PRAGMA quick_check").fetchone()[0]
            sessions = conn.execute("SELECT COUNT(*) FROM chat_sessions").fetchone()[0]
        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError) as exc:
        return Check("chat-db", "fail", f"unreadable: {type(exc).__name__}: {exc}")
    if result != "ok":
        return Check("chat-db", "fail", f"quick_check: {result} — the chat db is corrupt")
    return Check("chat-db", "ok", f"quick_check ok — {sessions} session(s)")


# ------------------------------------------------------------------- home --
# M11 (§5 item 10): the unified-home rows — resolved home, the copy-once
# migration state, and a pointer at pre-existing project-local `./.hunter`
# state (Q8: nothing silently abandoned). Notes never flip the exit code.


def _migrated_item_count(notes: tuple[str, ...], home: Path | None = None) -> int:
    """Count this home's copied entries, not stale notes from other tests/runs."""
    candidates = (note for note in notes if not note.startswith("skipped: "))
    if home is None:
        return sum(1 for _ in candidates)
    root = str(home.resolve())
    return sum(1 for note in candidates if str(note).startswith(root))


def _legacy_project_run_count(db_path: Path) -> int:
    """How many runs the project-local ``./.hunter/ledger.db`` holds (0 when
    unreadable — the row is advisory only)."""
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            return int(conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0])
        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError, ValueError):
        return 0


def _home_checks(state: Path | None = None) -> list[Check]:
    from hunter.home import hunter_home, legacy_home, migration_notes, state_dir

    checks: list[Check] = []
    home = hunter_home()
    checks.append(Check("home", "ok", str(home)))

    notes = migration_notes()
    if notes:
        checks.append(
            Check("migration", "note", f"migrated {_migrated_item_count(notes, home)} item(s) this session")
        )
    elif legacy_home().exists():
        checks.append(
            Check("migration", "note", "legacy ~/.hunteros kept (plumbing + originals)")
        )

    legacy_state = Path.cwd() / ".hunter" / "ledger.db"
    try:
        differs = (
            legacy_state.is_file()
            and legacy_state.resolve() != state_dir(state).resolve() / "ledger.db"
        )
    except OSError:  # pragma: no cover — resolve failures are advisory only
        differs = legacy_state.is_file()
    if differs:
        runs = _legacy_project_run_count(legacy_state)
        checks.append(
            Check(
                "legacy-state",
                "note",
                f"project state ./.hunter holds {runs} run(s) — view with --state ./.hunter",
            )
        )
    return checks
