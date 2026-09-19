"""Bounded parallel executor for pure-read tools only.

WHY: pure reads (http GET, ledger_search, note_*) can fan out safely;
writes, lifecycle, and approval-danger tools must stay synchronous.
Scope + claim gates stay on the dispatch thread (single owner); ledger
writes go through the existing lock (BEGIN IMMEDIATE, no database-is-locked
escapes); replay stays sequential on a fresh client; order is preserved.
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ParallelCall",
    "ParallelResult",
    "is_parallelizable",
    "run_parallel",
    "gates_run_on_pool_thread",
    "scope_gate_owner",
    "claim_gate_owner",
    "store_parallel_evidence",
    "replay_is_parallel",
    "replay_client_policy",
]


@dataclass
class ParallelCall:
    """One tool call eligible for fan-out."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParallelResult:
    """Ordered result for one ParallelCall."""

    name: str
    ok: bool
    payload: Any = None
    error: str = ""


def is_parallelizable(name: str, args: dict[str, Any] | None) -> bool:
    """True only for pure-read tools: http GET, ledger_search, note_*."""
    tool = str(name)
    params = args or {}
    if tool == "http_request":
        return str(params.get("method", "GET")).upper() == "GET"
    if tool == "ledger_search":
        return True
    return bool(tool.startswith("note_"))


def run_parallel(
    calls: list[ParallelCall],
    max_workers: int = 4,
    timeout: float = 5.0,
    dispatch: Callable[[ParallelCall], Any] | None = None,
) -> list[ParallelResult]:
    """Execute calls concurrently; order preserved; timeout->tool error."""
    if dispatch is None:
        raise ValueError("dispatch is required")
    workers = max(1, min(int(max_workers), max(1, len(calls))))
    results: list[ParallelResult | None] = [None] * len(calls)

    def _one(index: int, call: ParallelCall) -> ParallelResult:
        try:
            payload = dispatch(call)
        except TimeoutError as exc:
            return ParallelResult(name=call.name, ok=False, error=f"timeout: {exc}")
        except Exception as exc:  # noqa: BLE001 — per-tool errors become tool results
            text = str(exc)
            if "timeout" in text.lower() or "timed out" in text.lower():
                return ParallelResult(name=call.name, ok=False, error=f"timeout: {text}")
            return ParallelResult(name=call.name, ok=False, error=text or "error")
        return ParallelResult(name=call.name, ok=True, payload=payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, index, call) for index, call in enumerate(calls)]
        for index, future in enumerate(futures):
            try:
                results[index] = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                results[index] = ParallelResult(
                    name=calls[index].name, ok=False, error="timeout: pool wait exceeded"
                )
            except TimeoutError as exc:
                results[index] = ParallelResult(
                    name=calls[index].name, ok=False, error=f"timeout: {exc}"
                )
            except Exception as exc:  # noqa: BLE001
                results[index] = ParallelResult(name=calls[index].name, ok=False, error=str(exc))
    missing = [ParallelResult(name=c.name, ok=False, error="timeout: missing") for c in calls]
    return [r if r is not None else missing[i] for i, r in enumerate(results)]


def gates_run_on_pool_thread() -> bool:
    """Scope/claim gates never leave the dispatch thread."""
    return False


def scope_gate_owner() -> str:
    return "dispatch-thread"


def claim_gate_owner() -> str:
    return "dispatch-thread"


def store_parallel_evidence(
    ledger: Any, run_id: str, items: list[dict[str, Any]], max_workers: int = 4
) -> list[str]:
    """Store evidence via the ledger's existing lock (BEGIN IMMEDIATE)."""
    workers = max(1, min(int(max_workers), max(1, len(items))))
    ids: list[str | None] = [None] * len(items)

    def _store(index: int, item: dict[str, Any]) -> str:
        return str(ledger.add_evidence(run_id, str(item.get("kind", "note")), dict(item.get("data", {}))))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_store, i, item): i for i, item in enumerate(items)}
        for future, index in futures.items():
            ids[index] = future.result()
    return [str(v) for v in ids]


def replay_is_parallel() -> bool:
    return False


def replay_client_policy() -> str:
    return "fresh-client-per-replay"
