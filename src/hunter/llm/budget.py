"""RunBudget — thread-safe iteration + cost + wall-clock governor for one run.

Implements the ``hunter.llm.base.RunBudget`` data contract (hermes
IterationBudget semantics + Strix-style staged cost warnings, merged):

- ``consume_iteration()`` → False once ``max_iterations`` is hit; pairing tool
  turns call ``refund_iteration()`` for work that must not eat the budget.
- ``add_cost()`` / ``cost_breakpoint()`` → staged ONE-TIME warnings at
  70 / 85 / 95 % of ``max_cost_usd`` ("wind down" advisories).
- ``exhausted()`` → a human reason when cost, iterations, or wall clock (via
  ``time.monotonic`` since ``start()``) says the run must stop — else None.

All checks treat a non-positive limit as "off", and every public method takes
the lock, so the single-threaded agent loop stays correct even if a tool
callback re-enters.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from hunter.llm.base import RunBudget as RunBudgetContract

# (level, fraction) pairs, ascending — each warning fires exactly once.
_COST_LEVELS: tuple[tuple[int, float], ...] = ((70, 0.70), (85, 0.85), (95, 0.95))


@dataclass
class RunBudget(RunBudgetContract):
    """Concrete budget. Subclasses the base contract, so
    ``isinstance(RunBudget(), base.RunBudget)`` holds for callers that annotate
    against ``hunter.llm.base.RunBudget``."""

    _lock: threading.Lock = field(init=False, repr=False, compare=False, default_factory=threading.Lock)

    def start(self) -> None:
        """Arm the wall clock (call once when the run begins)."""
        with self._lock:
            self.started_monotonic = time.monotonic()

    def elapsed_seconds(self) -> float:
        """Seconds since ``start()``; 0.0 when the clock was never armed."""
        with self._lock:
            return self._elapsed_locked()

    def consume_iteration(self) -> bool:
        """Consume one iteration; False when ``max_iterations`` is reached."""
        with self._lock:
            if self.max_iterations > 0 and self.iterations_used >= self.max_iterations:
                return False
            self.iterations_used += 1
            return True

    def refund_iteration(self) -> None:
        """Give back one iteration (e.g. a sub-turn that must not count)."""
        with self._lock:
            if self.iterations_used > 0:
                self.iterations_used -= 1

    def add_cost(self, usd: float) -> None:
        """Accumulate spend for this run (negative values are clamped to 0)."""
        with self._lock:
            self.spent_usd = max(0.0, self.spent_usd + float(usd))

    def cost_breakpoint(self) -> str | None:
        """One-time staged warning at 70/85/95% of ``max_cost_usd``.

        Returns the highest newly-crossed level not warned about yet (one per
        call), or None. Levels already fired are recorded in ``warned_levels``.
        """
        with self._lock:
            if self.max_cost_usd <= 0:
                return None
            for level, fraction in _COST_LEVELS:
                if level in self.warned_levels:
                    continue
                if self.spent_usd >= self.max_cost_usd * fraction:
                    self.warned_levels = tuple(sorted((*self.warned_levels, level)))
                    return (
                        f"[BUDGET {level}%] ${self.spent_usd:.2f} of "
                        f"${self.max_cost_usd:.2f} spent — wind down"
                    )
            return None

    def exhausted(self) -> str | None:
        """Human reason when the run must wind down (cost, iterations, or
        wall clock), else None. Cost is checked first: money is the hardest
        limit. Wall clock only counts once ``start()`` armed it."""
        with self._lock:
            if self.max_cost_usd > 0 and self.spent_usd >= self.max_cost_usd:
                return (
                    f"cost budget exhausted: ${self.spent_usd:.2f} of "
                    f"${self.max_cost_usd:.2f}"
                )
            if self.max_iterations > 0 and self.iterations_used >= self.max_iterations:
                return (
                    f"iteration budget exhausted: {self.iterations_used} of "
                    f"{self.max_iterations}"
                )
            elapsed = self._elapsed_locked()
            wall_armed = self.wall_seconds > 0 and self.started_monotonic > 0.0 and elapsed > 0.0
            if wall_armed and elapsed >= self.wall_seconds:
                return (
                    f"wall-clock budget exhausted: {elapsed:.0f}s of "
                    f"{self.wall_seconds:.0f}s"
                )
            return None

    # -- internals ----------------------------------------------------------

    def _elapsed_locked(self) -> float:
        if self.started_monotonic <= 0.0:
            return 0.0
        return max(0.0, time.monotonic() - self.started_monotonic)


__all__ = ["RunBudget"]
