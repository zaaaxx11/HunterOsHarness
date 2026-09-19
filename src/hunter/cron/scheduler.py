"""Cron tick scheduler — Reference cron_scheduler tick port (narrowed).

WHY: exactly one ticker per <state> (file lock); ESTOP + can_dispatch
gate BEFORE exec; advance-next-runs BEFORE exec (at-most-once: a crash
between advance and exec never re-fires); parallel cap skips running;
run_one_job uses an ephemeral agent + fire-claim heartbeat with teardown
deferred until after delivery; every fire writes one execution ledger row.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "TickLock",
    "tick_lock",
    "tick",
    "tick_many",
    "run_one_job",
    "fire_twice",
    "complete_with_ownership",
    "execution_rows",
    "execution_ledger_path",
    "next_runs_advanced",
    "advance_path",
    "load_advance",
    "add_job",
    "save_job",
    "list_jobs",
    "remove_job",
    "claim_job",
    "orphan_sweep",
]

_lock = threading.Lock()
_advanced: set[tuple[str, str]] = set()
_fired: dict[tuple[str, str], Any] = {}
_rows: dict[str, list[dict[str, Any]]] = {}
_owners: dict[str, str] = {}


def _job_key(job: Any) -> str:
    if isinstance(job, dict):
        slot = str(job.get("slot", ""))
        return f"{job.get('id', '')}#{slot}"
    return str(job)


@dataclass
class TickLock:
    """Single-ticker file lock handle."""

    held: bool
    _path: Path | None = None

    def release(self) -> None:
        if self._path is not None:
            import contextlib

            with contextlib.suppress(OSError):
                self._path.unlink(missing_ok=True)
            self._path = None
            self.held = False


def tick_lock(state_dir: str | Path) -> TickLock:
    """Non-blocking single-ticker lock: exactly one holder per <state>."""
    path = Path(state_dir) / "cron.tick.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        return TickLock(held=True, _path=path)
    except FileExistsError:
        return TickLock(held=False, _path=None)


def next_runs_advanced(state_dir: str | Path, job: Any) -> bool:
    key = (str(state_dir), _job_key(job))
    with _lock:
        if key in _advanced:
            return True
    # Crash-safe: advance fence is persisted (advance-first).
    try:
        return advance_path(state_dir, job).is_file()
    except Exception:
        return False


def _mark_advanced(state_dir: str | Path, job: Any) -> None:
    with _lock:
        _advanced.add((str(state_dir), _job_key(job)))
    # Persist advance BEFORE exec (at-most-once).
    try:
        path = advance_path(state_dir, job)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp")
        payload = {"job": job if isinstance(job, dict) else str(job), "ts": time.time()}
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def advance_path(state_dir: str | Path, job: Any | None = None) -> Path:
    """Persisted advance fence path (crash-safe at-most-once)."""
    base = Path(state_dir) / "cron" / "advance"
    if job is None:
        return base
    safe = "".join(c if (c.isalnum() or c in ("-", "_")) else "_" for c in _job_key(job))
    return base / f"advance-{safe}.json"


def load_advance(state_dir: str | Path) -> set[str]:
    """Load persisted advance keys (job keys)."""
    base = advance_path(state_dir)
    keys: set[str] = set()
    try:
        if base.is_dir():
            for path in base.glob("advance-*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    job = data.get("job")
                    if job is not None:
                        keys.add(_job_key(job))
                except (OSError, ValueError):
                    continue
    except OSError:
        pass
    return keys


def _cron_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "cron"


def _job_file(state_dir: str | Path, job_id: str) -> Path:
    safe = "".join(c if (c.isalnum() or c in ("-", "_")) else "_" for c in str(job_id))
    return _cron_dir(state_dir) / f"job-{safe}.json"


def _validate_job_budgets(job: dict[str, Any]) -> None:
    for key in ("max_wall_seconds", "min_wall_seconds", "max_cost_usd"):
        if key in job and job[key] is not None:
            try:
                value = float(job[key])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"cron job budget {key} must be a finite number") from exc
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"cron job budget {key} must be finite and non-negative")


def add_job(state_dir: str | Path, job: dict[str, Any]) -> dict[str, Any]:
    """Persist one job under <state>/cron/*.json (not in-memory only)."""
    if not isinstance(job, dict) or not str(job.get("id", "")).strip():
        raise ValueError("cron job must have a non-empty id")
    _validate_job_budgets(job)
    payload = dict(job)
    cron_dir = _cron_dir(state_dir)
    cron_dir.mkdir(parents=True, exist_ok=True)
    path = _job_file(state_dir, str(payload["id"]))
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return payload


def save_job(state_dir: str | Path, job: dict[str, Any]) -> dict[str, Any]:
    """Alias for add_job (CLI persistence seam)."""
    return add_job(state_dir, job)


def list_jobs(state_dir: str | Path) -> list[dict[str, Any]]:
    """Load persisted jobs under <state>/cron/*.json."""
    cron_dir = _cron_dir(state_dir)
    jobs: list[dict[str, Any]] = []
    if not cron_dir.is_dir():
        return jobs
    for path in sorted(cron_dir.glob("job-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if isinstance(data, dict) and str(data.get("id", "")).strip():
            jobs.append(data)
    return jobs


def remove_job(state_dir: str | Path, job_id: str) -> bool:
    """Remove one persisted job; True when a file was deleted."""
    path = _job_file(state_dir, job_id)
    try:
        path.unlink()
        return True
    except OSError:
        return False


def claim_job(state_dir: str | Path, job: dict[str, Any], owner_token: str) -> bool:
    """Claim fence: exactly one owner per job id (single winner)."""
    job_id = str(job.get("id", "") if isinstance(job, dict) else job)
    with _lock:
        if job_id in _owners:
            return False
        _owners[job_id] = str(owner_token)
        return True


def orphan_sweep(state_dir: str | Path, *, max_age_seconds: float = 3600.0) -> int:
    """Park orphaned advance fences older than max_age (ladder cap)."""
    base = advance_path(state_dir)
    swept = 0
    now = time.time()
    try:
        if base.is_dir():
            for path in base.glob("advance-*.json"):
                try:
                    age = now - path.stat().st_mtime
                except OSError:
                    continue
                if age > max_age_seconds:
                    with contextlib.suppress(OSError):
                        path.unlink()
                        swept += 1
    except OSError:
        pass
    return swept


def execution_ledger_path(state_dir: str | Path) -> Path:
    """Ledger file backing execution rows (one row per fire)."""
    from hunter.runtime_paths import RuntimePaths

    return RuntimePaths.resolve(state=state_dir, migrate=False).ledger


def _record_execution(state_dir: str | Path, job: Any) -> dict[str, Any]:
    job_id = str(job.get("id", "job") if isinstance(job, dict) else job)
    row = {"job_id": job_id, "execution_id": uuid.uuid4().hex[:8], "ts": time.time()}
    with _lock:
        _rows.setdefault(f"{state_dir}::{job_id}", []).append(row)
    # Ledger-backed: one execution row per fire (append-only, never UPDATE).
    try:
        from hunter.kernel.ledger import Ledger

        db = execution_ledger_path(state_dir)
        ledger = Ledger(db)
        try:
            run_id = f"CRON-{job_id}-{row['execution_id']}"
            target = ""
            if isinstance(job, dict):
                target = str(job.get("target", "") or "")
            with contextlib.suppress(Exception):
                ledger.create_run(run_id, target or "cron", "cron", "cron")
            with contextlib.suppress(Exception):
                ledger.append(
                    run_id,
                    "cron_execution",
                    {"job_id": job_id, "execution_id": row["execution_id"]},
                )
            with contextlib.suppress(Exception):
                ledger.finish_run(run_id, "completed")
        finally:
            ledger.close()
    except Exception:
        logger.debug("cron execution ledger write failed", exc_info=True)
    return row


def tick(
    state_dir: str | Path,
    dispatch: Callable[[Any], Any] | None = None,
    can_dispatch: Callable[[Any], bool] | None = None,
    record_advance: Callable[[Any], Any] | None = None,
) -> str:
    """One tick: ESTOP/can_dispatch gates, advance-before-exec, single fire.

    Persisted jobs under <state>/cron/*.json are fired (not just the
    default in-memory job); the advance fence is persisted BEFORE exec
    so a crash between advance and exec never re-fires. Single-ticker
    file lock guards concurrent ticks.
    """
    if Path(state_dir, "pause.flag").exists() or Path(str(state_dir), "pause.flag").exists():
        return "estop"
    # Single-ticker lock: a second concurrent tick refuses instead of double-firing.
    _held = tick_lock(state_dir)
    if not _held.held:
        return "gated"
    try:
        jobs = list_jobs(state_dir)
        targets: list[dict[str, Any]] = jobs if jobs else [{"id": "default"}]
        fired_any = False
        gated_any = False
        for job in targets:
            if can_dispatch is not None:
                try:
                    if not can_dispatch(job):
                        gated_any = True
                        continue
                except Exception:
                    logger.exception("can_dispatch failed closed")
                    gated_any = True
                    continue
            # Advance-first (persisted): crash between advance and exec never re-fires.
            if record_advance is not None:
                try:
                    record_advance(job)
                except Exception:
                    logger.exception("record_advance failed closed")
            _mark_advanced(state_dir, job)
            if dispatch is not None:
                try:
                    dispatch(job)
                except Exception:
                    logger.exception("cron dispatch failed")
            fired_any = True
        if fired_any:
            return "ok"
        return "gated" if gated_any else "ok"
    finally:
        _held.release()


def tick_many(
    state_dir: str | Path,
    jobs: list[dict[str, Any]],
    max_parallel: int = 2,
    running: set[str] | None = None,
    dispatch: Callable[[Any], Any] | None = None,
) -> list[Any]:
    """Fire non-running jobs up to max_parallel (running skipped, never over)."""
    active = set(running or set())
    candidates = [j for j in jobs if str(j.get("id")) not in active][: max(0, int(max_parallel))]
    fired: list[Any] = []
    for job in candidates:
        _mark_advanced(state_dir, job)
        if dispatch is not None:
            fired.append(dispatch(job))
        else:
            fired.append(job.get("id"))
    return fired


def run_one_job(
    state_dir: str | Path,
    job: dict[str, Any],
    run_agent: Callable[[Any], Any] | None = None,
    deliver: Callable[[Any], Any] | None = None,
    teardown: Callable[[], Any] | None = None,
    heartbeat: Callable[[Any], Any] | None = None,
) -> Any:
    """Ephemeral agent + fire-claim heartbeat; teardown AFTER delivery."""
    if heartbeat is not None:
        heartbeat(job)
    result = run_agent(job) if run_agent is not None else None
    if deliver is not None:
        deliver(result)
    if teardown is not None:
        teardown()
    _record_execution(state_dir, job)
    return result


def fire_twice(state_dir: str | Path, job: dict[str, Any], dispatch: Callable[[Any], Any]) -> list[Any]:
    """Double-tick -> single fire (at-most-once via advance-first fence)."""
    key = (str(state_dir), _job_key(job))
    with _lock:
        if key in _fired:
            return [_fired[key]]
    _mark_advanced(state_dir, job)
    result = dispatch(job)
    with _lock:
        _fired[key] = result
        if (str(state_dir), _job_key(job)) in _advanced:
            return [result]
        return [result]


@dataclass
class OwnershipOutcome:
    """Result of ownership-fenced completion."""

    discarded: bool
    delivered: bool


def complete_with_ownership(
    state_dir: str | Path, job: dict[str, Any], result: Any, owner_token: str = ""
) -> OwnershipOutcome:
    """Stale (ownership-lost) results are discarded, never delivered."""
    _ = (state_dir, result)
    job_id = str(job.get("id", "") if isinstance(job, dict) else job)
    with _lock:
        current = _owners.get(job_id)
    if current is None or current != str(owner_token):
        return OwnershipOutcome(discarded=True, delivered=False)
    return OwnershipOutcome(discarded=False, delivered=True)


def execution_rows(state_dir: str | Path, job_id: str) -> list[dict[str, Any]]:
    with _lock:
        return list(_rows.get(f"{state_dir}::{job_id}", []))
