"""Parallel multi-target hunt runner.

The old CLI walked targets sequentially: three targets meant three times the
wall time, with the shared LLM sitting idle between runs. This module fans the
targets out over a bounded thread pool while keeping every LLM dial behind the
process-wide :mod:`hunter.llm.rate_control` gate — so parallel targets never
turn into a 429 burst.

Safety contract
---------------
* Order of *results* is preserved (indexed slots), regardless of completion
  order. Logs stay readable via an optional ``log`` callback.
* Shared state files (``rag-state.json``, the task queue, the ledger) are
  guarded by a process-wide lock: ``RagLoop`` does load-modify-save on the RAG
  state, which is not atomic on its own even though ``save_rag_state`` writes
  via ``os.replace``.
* ``max_workers`` is capped (default 3) — a hunt is I/O bound, and an
  unbounded pool would just trade 429s for thread contention.
* Exceptions are contained per target: one bad target never aborts the rest.
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hunter.workflow.rag import STATE_LOCK, RagConfig, RagLoop

__all__ = ["TargetSpec", "run_targets", "STATE_LOCK"]


class TargetSpec:
    """One unit of work: a target plus the config needed to hunt it."""

    __slots__ = ("target", "scope", "log_prefix")

    def __init__(self, target: str, scope: Any, log_prefix: str = "") -> None:
        self.target = target
        self.scope = scope
        self.log_prefix = log_prefix


def _build_config(
    spec: TargetSpec,
    *,
    state_dir: Path,
    engine: str,
    time_budget_s: float,
    provider: Any,
) -> RagConfig:
    return RagConfig(
        state_dir=state_dir,
        target=spec.target,
        scope=spec.scope,
        engine=engine,
        time_budget_s=float(time_budget_s),
        interval_s=15.0,
        high_water=8,
        dry_run=False,
        once=True,
        manage_daemon=False,
        run_inline=True,
        provider=provider,
    )


def _run_one(
    index: int,
    spec: TargetSpec,
    *,
    state_dir: Path,
    engine: str,
    time_budget_s: float,
    provider: Any,
    log: Callable[[str], None] | None,
) -> tuple[int, bool, str]:
    if log and spec.log_prefix:
        log(spec.log_prefix)
    try:
        config = _build_config(
            spec,
            state_dir=state_dir,
            engine=engine,
            time_budget_s=time_budget_s,
            provider=provider,
        )
        # The LLM call is NOT under a global lock — it is already serialized
        # per provider by the rate limiter, and holding a lock across a
        # network call would erase the benefit of parallelism. The shared
        # rag-state load-modify-save is protected by STATE_LOCK inside
        # rag.py's state helpers instead.
        RagLoop(config).run()
        return (index, True, "")
    except Exception as exc:  # noqa: BLE001 - contain failures per target
        return (index, False, f"{spec.target}: {exc}")


def run_targets(
    specs: list[TargetSpec],
    *,
    state_dir: Path,
    engine: str,
    time_budget_s: float,
    provider: Any = None,
    max_workers: int = 3,
    parallel: bool = True,
    log: Callable[[str], None] | None = None,
) -> tuple[int, int, list[str]]:
    """Run all targets; return ``(ok_count, failed_count, errors)``.

    ``parallel=False`` degrades to the original sequential behaviour (useful
    for tests and for operators who want deterministic ordering). With
    ``parallel=True`` a bounded thread pool is used, capped at the number of
    targets and at ``max_workers``.
    """
    if not specs:
        return (0, 0, [])

    errors: list[str] = ["" for _ in specs]
    outcomes: list[bool] = [False for _ in specs]

    def apply(result: tuple[int, bool, str]) -> None:
        index, ok, error = result
        outcomes[index] = ok
        errors[index] = error

    if parallel and len(specs) > 1:
        workers = max(1, min(int(max_workers), len(specs)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(
                    _run_one,
                    i,
                    spec,
                    state_dir=state_dir,
                    engine=engine,
                    time_budget_s=time_budget_s,
                    provider=provider,
                    log=log,
                )
                for i, spec in enumerate(specs)
            ]
            for future in futures:
                apply(future.result())
    else:
        for i, spec in enumerate(specs):
            apply(
                _run_one(
                    i,
                    spec,
                    state_dir=state_dir,
                    engine=engine,
                    time_budget_s=time_budget_s,
                    provider=provider,
                    log=log,
                )
            )

    ok = sum(1 for outcome in outcomes if outcome)
    return (ok, len(specs) - ok, [e for e in errors if e])
