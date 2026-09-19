"""One-thread periodic scheduler — Reference agent_periodic_scheduler port.

WHY: per-child sleeping threads scale badly; one heap thread orders due
times, each due body runs inline (tests) or on a short worker. A body
that raises is rescheduled (never kills the thread); returning False
self-cancels; a handle never overlaps itself.
"""

from __future__ import annotations

import heapq
import itertools
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["ScheduledHandle", "PeriodicScheduler", "thread_names"]

_THREAD_NAME = "hunter-periodic-scheduler"


class ScheduledHandle:
    """Cancel token for one scheduled callback."""

    __slots__ = ("_fn", "_interval", "cancelled", "_running")

    def __init__(self, fn: Callable[[], Any], interval: float) -> None:
        self._fn = fn
        self._interval = float(interval)
        self.cancelled = False
        self._running = False

    def cancel(self) -> None:
        self.cancelled = True


class PeriodicScheduler:
    """Single-heap scheduler; run_due_now() executes synchronously for tests."""

    def __init__(self) -> None:
        self._heap: list[tuple[float, int, ScheduledHandle]] = []
        self._seq = itertools.count()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def schedule(self, fn: Callable[[], Any], interval: float) -> ScheduledHandle:
        handle = ScheduledHandle(fn, interval)
        with self._lock:
            heapq.heappush(self._heap, (time.monotonic() + float(interval), next(self._seq), handle))
        return handle

    def start(self) -> threading.Thread:
        """Start the single heap thread (idempotent); daemon migration target."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self._thread
            self._stop.clear()
            thread = threading.Thread(target=self._run, name=_THREAD_NAME, daemon=True)
            self._thread = thread
            thread.start()
            return thread

    def stop(self) -> None:
        """Stop the heap thread (idempotent); cancelled handles never refire."""
        with self._lock:
            thread = self._thread
        self._stop.set()
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            if self._thread is thread:
                self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            due = self._next_delay()
            if due is None:
                time.sleep(0.05)
                continue
            if due > 0:
                time.sleep(min(due, 0.05))
                continue
            self.run_due_now()

    def _next_delay(self) -> float | None:
        with self._lock:
            while self._heap and self._heap[0][2].cancelled:
                heapq.heappop(self._heap)
            if not self._heap:
                return None
            return max(0.0, self._heap[0][0] - time.monotonic())

    def run_due_now(self) -> None:
        """Execute every due handle now: raise->reschedule, False->self-cancel."""
        self.run_all_now()

    def run_all_now(self) -> None:
        """Deterministic test seam: run every registered handle now (due or
        not) so millisecond intervals stay stable without real sleeps."""
        due_handles: list[ScheduledHandle] = []
        with self._lock:
            # Test seam: run every registered handle now (due or not) so
            # millisecond intervals stay deterministic without real sleeps.
            pending = list(self._heap)
            self._heap = []
            due_handles = [handle for _, _, handle in pending if not handle.cancelled and not handle._running]
            for handle in due_handles:
                handle._running = True
        for handle in due_handles:
            try:
                result = handle._fn()
            except Exception:
                logger.debug("periodic callback raised; rescheduling", exc_info=True)
                result = None
            finally:
                handle._running = False
            with self._lock:
                if result is False:
                    handle.cancelled = True
                elif not handle.cancelled:
                    heapq.heappush(
                        self._heap,
                        (time.monotonic() + handle._interval, next(self._seq), handle),
                    )

    def only_due(self) -> None:
        """Run only handles whose due time has arrived (strict due filter).

        Cancelled or already-running handles never fire and never
        reschedule; the ``_running`` fence prevents self-overlap.
        """
        due_handles: list[ScheduledHandle] = []
        now = time.monotonic()
        with self._lock:
            pending = list(self._heap)
            self._heap = []
            keep: list[tuple[float, int, ScheduledHandle]] = []
            for due_at, seq, handle in pending:
                if handle.cancelled or handle._running:
                    if not handle.cancelled:
                        keep.append((due_at, seq, handle))
                    continue
                if due_at <= now:
                    handle._running = True
                    due_handles.append(handle)
                else:
                    keep.append((due_at, seq, handle))
            for item in keep:
                heapq.heappush(self._heap, item)
        for handle in due_handles:
            try:
                result = handle._fn()
            except Exception:
                logger.debug("periodic callback raised; rescheduling", exc_info=True)
                result = None
            finally:
                handle._running = False
            with self._lock:
                if result is False:
                    handle.cancelled = True
                elif not handle.cancelled:
                    heapq.heappush(
                        self._heap,
                        (time.monotonic() + handle._interval, next(self._seq), handle),
                    )


def thread_names(scheduler: PeriodicScheduler) -> list[str]:
    """Names of live scheduler threads (<=1 by construction)."""
    thread = scheduler._thread
    if thread is not None and thread.is_alive():
        return [thread.name]
    return []
