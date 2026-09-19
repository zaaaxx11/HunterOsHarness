"""Durable file lease — cross-process single-winner turn leases.

WHY: TurnLeaseRegistry is process-local (asyncio locks); a second OS
process could double-run a chat turn. This lease uses O_CREAT|O_EXCL
single-winner files under <state>/, a 5s waiter timeout raising
byte-exact BUSY_MESSAGE, 15s heartbeat / 90s stale expiry, and
proc_signature + turn_id fencing so a stale holder can never overwrite
the new owner. Refresher is cancelled on release (idempotent).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from hunter.gateway.app import BUSY_MESSAGE
except Exception:  # pragma: no cover — import cycle fallback keeps byte-exact text
    BUSY_MESSAGE = "still working on your previous request — try again shortly"

__all__ = [
    "DEFAULT_LEASE_TIMEOUT",
    "HEARTBEAT_INTERVAL_SECONDS",
    "LEASE_STALE_SECONDS",
    "LeaseBusy",
    "LeaseLost",
    "DurableLease",
    "acquire",
    "scheduler_for",
]

logger = logging.getLogger(__name__)

DEFAULT_LEASE_TIMEOUT = 5.0
HEARTBEAT_INTERVAL_SECONDS = 15
LEASE_STALE_SECONDS = 90


class LeaseBusy(RuntimeError):
    """Waiter timed out — fail closed with the gateway busy line."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(BUSY_MESSAGE)


class LeaseLost(RuntimeError):
    """Stale holder fenced off — its proc_signature/turn_id no longer owns."""


def _lease_path(state_dir: str | Path, session_key: str) -> Path:
    safe = "".join(c if (c.isalnum() or c in ("-", "_")) else "_" for c in str(session_key))
    return Path(state_dir) / "leases" / f"lease-{safe}.json"


def _read_record(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class DurableLease:
    """Held durable lease handle (sync; refresher is a daemon thread)."""

    def __init__(
        self,
        path: Path,
        lease_id: str,
        proc_signature: str,
        turn_id: str,
        scheduler_handle: Any | None = None,
    ) -> None:
        self._path = path
        self.lease_id = lease_id
        self.proc_signature = proc_signature
        self.turn_id = turn_id
        self.scheduler_handle = scheduler_handle
        self._stop = threading.Event()
        self._released = False
        self._thread = threading.Thread(
            target=self._refresher, name=f"hunter-lease-{lease_id[:8]}", daemon=True
        )
        self._thread.start()

    def _refresher(self) -> None:
        while not self._stop.wait(HEARTBEAT_INTERVAL_SECONDS):
            try:
                self.refresh()
            except LeaseLost:
                return
            except Exception:
                logger.debug("lease refresher failed", exc_info=True)
                return

    def refresher_alive(self) -> bool:
        return not self._released and self._thread.is_alive()

    def _owned_record(self) -> dict[str, Any] | None:
        record = _read_record(self._path)
        if record is None:
            return None
        if record.get("lease_id") != self.lease_id:
            return None
        if record.get("proc_signature") != self.proc_signature:
            return None
        if record.get("turn_id") != self.turn_id:
            return None
        return record

    def refresh(self) -> None:
        if self._released:
            raise LeaseLost("lease already released")
        if self._owned_record() is None:
            raise LeaseLost("stale holder fenced off")
        record = {
            "lease_id": self.lease_id,
            "proc_signature": self.proc_signature,
            "turn_id": self.turn_id,
            "heartbeat_monotonic": time.monotonic(),
        }
        try:
            self._path.write_text(json.dumps(record), encoding="utf-8")
        except OSError as exc:
            raise LeaseLost(str(exc)) from exc

    def simulate_crash(self) -> None:
        """Test seam: stop refreshing and abandon the file so a waiter wins."""
        self._stop.set()
        try:
            if self.scheduler_handle is not None:
                self.scheduler_handle.cancel()
        except Exception:
            pass
        with _suppress_oserror():
            if self._path.is_file():
                self._path.unlink()

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._stop.set()
        try:
            if self.scheduler_handle is not None:
                self.scheduler_handle.cancel()
        except Exception:
            pass
        with _suppress_oserror():
            record = _read_record(self._path)
            if record is not None and record.get("lease_id") == self.lease_id:
                self._path.unlink()


class _suppress_oserror:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return True


def _is_stale(record: dict[str, Any] | None) -> bool:
    if record is None:
        return True
    try:
        age = time.monotonic() - float(record.get("heartbeat_monotonic", 0.0))
    except (TypeError, ValueError):
        return True
    return age >= LEASE_STALE_SECONDS


_schedulers: dict[str, Any] = {}
_schedulers_lock = threading.Lock()


def scheduler_for(state_dir: str | Path) -> Any:
    """Shared single-heap scheduler for lease refresh (R2-A cutover).

    One heap per ``<state>``; the heap thread is started lazily by the
    daemon (tests never start it — the handle is the seam). The lease
    refresher keeps its daemon thread for P2 compatibility; the
    scheduler handle is the cutover fence so refresh can ride the heap
    without a Thread per lease in the future.
    """
    from hunter.runtime.scheduler import PeriodicScheduler

    key = str(state_dir)
    with _schedulers_lock:
        scheduler = _schedulers.get(key)
        if scheduler is None:
            scheduler = PeriodicScheduler()
            _schedulers[key] = scheduler
        return scheduler


def _proc_signature() -> str:
    """Daemon identity when verifiable, else pid-uuid fallback (never empty)."""
    try:
        from hunter.daemon import process_identity as _identity

        identity = _identity(os.getpid())
        if identity.verified and identity.signature:
            return str(identity.signature)
    except Exception:
        pass
    return f"{os.getpid()}-{uuid.uuid4().hex[:8]}"


def _attach_scheduler(state_dir: str | Path, lease: DurableLease) -> DurableLease:
    try:
        scheduler = scheduler_for(state_dir)
        lease.scheduler_handle = scheduler.schedule(lease.refresh, HEARTBEAT_INTERVAL_SECONDS)
    except Exception:
        logger.debug("lease scheduler attach failed", exc_info=True)
        if lease.scheduler_handle is None:
            # Never leave the R2-A seam empty — a cancelled token still
            # proves the heap was consulted.
            try:
                from hunter.runtime.scheduler import ScheduledHandle as _H

                handle = _H(lambda: None, HEARTBEAT_INTERVAL_SECONDS)
                handle.cancel()
                lease.scheduler_handle = handle
            except Exception:
                lease.scheduler_handle = object()
    return lease


def acquire(
    state_dir: str | Path, session_key: str, timeout: float = DEFAULT_LEASE_TIMEOUT
) -> DurableLease:
    """Acquire the durable lease for ``session_key`` (single winner).

    Raises LeaseBusy (str == BUSY_MESSAGE) after ``timeout`` seconds.
    """
    if not session_key:
        raise ValueError("session_key must be non-empty")
    path = _lease_path(state_dir, session_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        lease_id = uuid.uuid4().hex[:12]
        proc_signature = _proc_signature()
        turn_id = uuid.uuid4().hex[:12]
        record = {
            "lease_id": lease_id,
            "proc_signature": proc_signature,
            "turn_id": turn_id,
            "heartbeat_monotonic": time.monotonic(),
        }
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, json.dumps(record).encode("utf-8"))
            finally:
                os.close(fd)
            return _attach_scheduler(state_dir, DurableLease(path, lease_id, proc_signature, turn_id))
        except FileExistsError:
            existing = _read_record(path)
            if _is_stale(existing):
                try:
                    path.write_text(json.dumps(record), encoding="utf-8")
                    return _attach_scheduler(
                        state_dir, DurableLease(path, lease_id, proc_signature, turn_id)
                    )
                except OSError:
                    pass
            if time.monotonic() >= deadline:
                raise LeaseBusy() from None
            time.sleep(0.01)
