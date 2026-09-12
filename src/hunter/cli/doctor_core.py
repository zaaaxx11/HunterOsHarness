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

    checks.append(Check("llm-config", "ok", cfg.source_path or "defaults, no config file"))
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
        planner_model = resolve_model("planner", cfg)
    except HunterError:
        checks.append(
            Check(
                "llm-model",
                "note",
                "unset — set HUNTEROS_MODEL or model_tiers.planner.model "
                "in ~/.hunteros/config.yaml",
            )
        )
    else:
        checks.append(Check("llm-model", "ok", f"planner: {planner_model}"))

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
    planner_model = ""
    try:
        planner_model = resolve_model("planner", cfg)
    except HunterError:
        planner_model = ""  # no model resolved — the llm-model row already notes it
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
        planner_tier = cfg.model_tiers.get("planner")
        if planner_model and planner_tier is not None and planner_tier.provider == name:
            parts.append(f"model {planner_model}")
        checks.append(Check(f"provider:{name}", status, " — ".join(parts)))
    return checks


# ----------------------------------------------------------------- chat db --


def _chat_db_path() -> Path:
    from_env = (os.environ.get("HUNTEROS_CHAT_DB") or "").strip()
    if from_env:
        return Path(from_env)
    return Path.home() / ".hunteros" / "chat.db"


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
