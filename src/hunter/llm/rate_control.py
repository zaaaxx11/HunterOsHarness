"""Rate-limit survival kit — process-wide gates for every LLM dial.

Three cooperating primitives, all keyed by canonical provider name:

* :class:`ProviderLimiter` — one semaphore per provider (default 1 slot) plus
  ``time.monotonic()`` start-to-start pacing. This is the single door every
  HTTP call must pass through; it is what stops an agent loop (or two hunts in
  two terminals sharing a process) frombursting a provider into 429.
* :class:`CircuitBreaker` — CLOSED -> OPEN after N consecutive 429s, then a
  HALF_OPEN probe after a cooldown, then CLOSED again on success. A provider
  that is drowning is no longer re-dialed on every iteration.
* :class:`AdaptiveThrottle` — AIMD: a 429 multiplies the pacing delay, a
  success subtracts a fixed amount, always clamped to ``[min, max]``.

The module-level singletons (``limiter``, ``breaker``, ``throttle``) are the
instances production code shares. Tests may construct fresh instances;
``reset()`` is provided on each class for isolation.
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from contextlib import ExitStack, contextmanager
from enum import Enum
from pathlib import Path
from typing import Iterator

try:  # POSIX only; Windows degrades to in-process only.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "AdaptiveThrottle",
    "CircuitBreaker",
    "CircuitState",
    "FileGate",
    "ProviderLimiter",
    "breaker",
    "limiter",
    "throttle",
]


def _safe_name(provider: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", provider) or "_"


class FileGate:
    """Cross-process per-provider mutex + start-to-start pacing.

    ``fcntl.flock`` on a per-provider file gives mutual exclusion BETWEEN
    processes (a ``threading.Semaphore`` cannot). A sibling timestamp file
    carries the last slot entry in wall-clock time so two hunts in two
    terminals honour the same ``min_interval``. The lock is held across the
    whole slot, so only one process dials a provider at a time.

    State lives under ``$HUNTEROS_STATE_DIR/llm_locks`` (default
    ``~/.hunter/llm_locks``), alongside the existing rate-limit guard.
    """

    def __init__(self, state_dir: str | os.PathLike[str] | None = None) -> None:
        self._state_dir = state_dir
        self._enabled = fcntl is not None

    def _lock_dir(self) -> Path:
        base = self._state_dir or os.environ.get("HUNTEROS_STATE_DIR") or Path.home() / ".hunter"
        return Path(base) / "llm_locks"

    def _paths(self, provider: str) -> tuple[Path, Path]:
        name = _safe_name(provider)
        directory = self._lock_dir()
        return directory / f"{name}.lock", directory / f"{name}.ts"

    @contextmanager
    def slot(self, provider: str, interval: float) -> Iterator[None]:
        if not self._enabled or fcntl is None:
            yield
            return
        directory = self._lock_dir()
        directory.mkdir(parents=True, exist_ok=True)
        lock_path, ts_path = self._paths(provider)
        with lock_path.open("a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                try:
                    last = float(ts_path.read_text(encoding="utf-8").strip())
                except (OSError, ValueError):
                    last = None
                now = time.time()
                if last is not None and interval > 0:
                    wait = interval - (now - last)
                    if wait > 0:
                        time.sleep(wait)
                tmp = ts_path.with_name(f"{ts_path.name}.{os.getpid()}.tmp")
                tmp.write_text(str(time.time()), encoding="utf-8")
                os.replace(tmp, ts_path)
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def reset(self) -> None:
        with contextlib.suppress(OSError):
            for path in self._lock_dir().glob("*.ts"):
                path.unlink()


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ProviderLimiter:
    """Per-provider concurrency gate + monotonic start-to-start pacing.

    ``slot()`` acquires the provider's semaphore FIRST, then sleeps until the
    configured minimum interval since the previous slot entry has elapsed.
    Pacing inside the semaphore is deliberate: if we paced before acquiring,
    two waiting threads would both wake and enter back-to-back, defeating the
    interval. The semaphore makes the pacing reference unambiguous.

    ``note_429`` / ``note_success`` are reserved hooks for adaptive policy;
    adaptive pacing itself lives in :class:`AdaptiveThrottle`, which production
    feeds into ``configure(min_interval=throttle.delay(provider))``.
    """

    def __init__(
        self,
        *,
        min_interval: float = 0.0,
        max_concurrent: int = 1,
        file_gate: FileGate | None = None,
    ) -> None:
        self._default_interval = max(0.0, float(min_interval))
        self._max_concurrent = max(1, int(max_concurrent))
        self._file_gate = file_gate
        self._intervals: dict[str, float] = {}
        self._semaphores: dict[str, threading.Semaphore] = {}
        self._last_entry: dict[str, float] = {}
        self._lock = threading.Lock()

    def configure(self, provider: str, *, min_interval: float | None = None) -> None:
        """Set (or clear with ``None``) a provider-specific pacing interval."""
        with self._lock:
            if min_interval is None:
                self._intervals.pop(provider, None)
            else:
                self._intervals[provider] = max(0.0, float(min_interval))

    def _semaphore(self, provider: str) -> threading.Semaphore:
        with self._lock:
            sem = self._semaphores.get(provider)
            if sem is None:
                sem = threading.Semaphore(self._max_concurrent)
                self._semaphores[provider] = sem
            return sem

    @contextmanager
    def slot(self, provider: str) -> Iterator[None]:
        with self._lock:
            interval = self._intervals.get(provider, self._default_interval)
        if self._file_gate is not None:
            # Cross-process door; resolves HUNTEROS_STATE_DIR at each slot.
            with ExitStack() as stack:
                gate = self._file_gate
                stack.enter_context(gate.slot(provider, interval))
                yield
            return
        sem = self._semaphore(provider)
        sem.acquire()
        try:
            now = time.monotonic()
            with self._lock:
                last = self._last_entry.get(provider)
            if last is not None:
                wait = interval - (now - last)
                if wait > 0:
                    time.sleep(wait)
            with self._lock:
                self._last_entry[provider] = time.monotonic()
            yield
        finally:
            sem.release()

    def note_success(self, provider: str) -> None:  # noqa: ARG002 - stable hook
        """Reserved for future per-provider policy; currently a no-op."""

    def note_429(self, provider: str) -> None:  # noqa: ARG002 - stable hook
        """Reserved for future per-provider policy; currently a no-op."""

    def reset(self, provider: str | None = None) -> None:
        """Forget pacing/lock state (test isolation)."""
        with self._lock:
            if provider is None:
                self._intervals.clear()
                self._semaphores.clear()
                self._last_entry.clear()
            else:
                self._intervals.pop(provider, None)
                self._semaphores.pop(provider, None)
                self._last_entry.pop(provider, None)


class CircuitBreaker:
    """CLOSED -> OPEN -> HALF_OPEN -> CLOSED, per provider.

    ``state()`` lazily performs the OPEN -> HALF_OPEN transition when the
    cooldown has elapsed, so reading the state and calling ``allows()`` agree.
    ``allows()`` in HALF_OPEN admits a single probe; a failure re-opens the
    breaker, a success closes it.
    """

    def __init__(self, *, failure_threshold: int = 3, open_seconds: float = 120.0) -> None:
        self._threshold = max(1, int(failure_threshold))
        self._open_seconds = max(0.0, float(open_seconds))
        self._states: dict[str, CircuitState] = {}
        self._failures: dict[str, int] = {}
        self._opened_at: dict[str, float] = {}
        self._probe_in_flight: dict[str, bool] = {}
        self._lock = threading.Lock()

    def _maybe_half_open(self, provider: str) -> CircuitState:
        state = self._states.get(provider, CircuitState.CLOSED)
        if state is CircuitState.OPEN:
            opened_at = self._opened_at.get(provider, 0.0)
            if time.monotonic() - opened_at >= self._open_seconds:
                state = CircuitState.HALF_OPEN
                self._states[provider] = state
                self._probe_in_flight[provider] = False
        return state

    def allows(self, provider: str) -> bool:
        with self._lock:
            state = self._maybe_half_open(provider)
            if state is CircuitState.CLOSED:
                return True
            if state is CircuitState.OPEN:
                return False
            # HALF_OPEN: exactly one probe at a time.
            if self._probe_in_flight.get(provider):
                return False
            self._probe_in_flight[provider] = True
            return True

    def note_success(self, provider: str) -> None:
        with self._lock:
            self._states[provider] = CircuitState.CLOSED
            self._failures[provider] = 0
            self._opened_at.pop(provider, None)
            self._probe_in_flight.pop(provider, None)

    def note_failure(self, provider: str) -> None:
        with self._lock:
            state = self._states.get(provider, CircuitState.CLOSED)
            if state is CircuitState.HALF_OPEN:
                # probe failed -> straight back to OPEN for a fresh window
                self._states[provider] = CircuitState.OPEN
                self._opened_at[provider] = time.monotonic()
                self._failures[provider] = self._threshold
                self._probe_in_flight.pop(provider, None)
                return
            failures = self._failures.get(provider, 0) + 1
            self._failures[provider] = failures
            if failures >= self._threshold:
                self._states[provider] = CircuitState.OPEN
                self._opened_at[provider] = time.monotonic()

    def state(self, provider: str) -> CircuitState:
        with self._lock:
            return self._maybe_half_open(provider)

    def reset(self, provider: str | None = None) -> None:
        with self._lock:
            if provider is None:
                self._states.clear()
                self._failures.clear()
                self._opened_at.clear()
                self._probe_in_flight.clear()
            else:
                for store in (self._states, self._failures, self._opened_at, self._probe_in_flight):
                    store.pop(provider, None)


class AdaptiveThrottle:
    """AIMD pacing: multiplicative increase on 429, additive decrease on success."""

    def __init__(
        self,
        *,
        base_delay: float = 0.0,
        min_delay: float = 0.0,
        max_delay: float = 30.0,
        alpha: float = 0.5,
        beta: float = 2.0,
    ) -> None:
        self._base = max(0.0, float(base_delay))
        self._min = max(0.0, float(min_delay))
        self._max = max(self._min, float(max_delay))
        self._alpha = max(0.0, float(alpha))
        self._beta = max(1.0, float(beta))
        self._delays: dict[str, float] = {}
        self._lock = threading.Lock()

    def _clamp(self, value: float) -> float:
        return min(self._max, max(self._min, value))

    def delay(self, provider: str) -> float:
        with self._lock:
            return self._clamp(self._delays.get(provider, self._base))

    def note_success(self, provider: str) -> None:
        with self._lock:
            current = self._delays.get(provider, self._base)
            self._delays[provider] = self._clamp(current - self._alpha)

    def note_429(self, provider: str) -> None:
        with self._lock:
            current = self._delays.get(provider, self._base)
            self._delays[provider] = self._clamp(current * self._beta)

    def reset(self, provider: str | None = None) -> None:
        with self._lock:
            if provider is None:
                self._delays.clear()
            else:
                self._delays.pop(provider, None)


limiter = ProviderLimiter(file_gate=FileGate())
breaker = CircuitBreaker()
throttle = AdaptiveThrottle()
