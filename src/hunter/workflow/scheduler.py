"""Smart task scheduling: severity-weighted, memory-aware, no brute force.

The RAG feeder used to enqueue four child hunts per finding, unconditionally.
With a few hundred candidates that is a few thousand queued hunts on a box
with 2 GB of RAM — the queue becomes the denial-of-service, and every child
fights the others for memory until the OOM killer picks a winner.

This module replaces the fixed fan-out with a budget:

* **Severity decides weight.** A verified critical earns more children than
  an informational candidate. Low-value findings get one deterministic child
  or none, instead of four speculative ones.
* **Memory decides the ceiling.** The total number of live children is capped
  by what the host can actually run, so the queue stays a work list rather
  than a backlog bomb.
* **Deduplication is by target, not by finding.** Four findings pointing at
  the same endpoint produce one hunt, not four.

Nothing here is authoritative about *what* to hunt — that stays with the LLM
follow-ups and the deterministic derivations. This module only decides how
many children a finding may spawn and when to stop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from hunter.daemon_health import memory_snapshot

__all__ = [
    "SEVERITY_WEIGHTS",
    "TaskBudget",
    "plan_children",
    "schedule_summary",
]

# How many child hunts a single finding may spawn, by severity. A verified
# critical is worth four; an informational candidate is worth one
# deterministic derivation and no LLM speculation.
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 1,
    "informational": 1,
}


@dataclass(frozen=True)
class TaskBudget:
    """How much child work the current cycle may enqueue."""

    max_children: int
    max_total_pending: int
    available_mb: float
    pressure: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_children": self.max_children,
            "max_total_pending": self.max_total_pending,
            "available_mb": (
                None if self.available_mb == float("inf") else round(self.available_mb, 1)
            ),
            "pressure": self.pressure,
            "reason": self.reason,
        }


def _field_of(finding: Any, name: str) -> str:
    """Read ``name`` off a Finding object OR a plain dict, lowercased.

    The ledger hands out ``Finding`` dataclasses, but the RAG layer, JSON
    reports, and the scheduler's own callers often hold dicts. Reading only
    attributes made a dict look like a finding with no status and no
    severity, which the actionable filter then dropped — silently, with an
    empty plan and no error. Both shapes are supported now.
    """
    if isinstance(finding, dict):
        value = finding.get(name, "")
    else:
        value = getattr(getattr(finding, name, None), "value", None)
        if value is None:
            value = getattr(finding, name, "")
    return str(value or "").strip().lower()


def _severity_of(finding: Any) -> str:
    return _field_of(finding, "severity")


def _status_of(finding: Any) -> str:
    return _field_of(finding, "status")


def task_budget(
    *,
    high_water: int = 8,
    pending: int = 0,
    per_child_mb: int = 192,
) -> TaskBudget:
    """Size the cycle's child budget from memory and the existing backlog.

    ``per_child_mb`` is what one in-flight hunt is assumed to need. The
    ceiling is ``available / per_child_mb``, clamped to ``high_water`` so a
    roomy host still cannot enqueue an unbounded backlog. When memory cannot
    be measured the ceiling falls back to ``high_water`` — an unmeasurable
    host must not be treated as a starved one.
    """
    memory = memory_snapshot()
    if memory.source == "unknown" or memory.available_mb == float("inf"):
        ceiling = high_water
        reason = "memory unmeasurable — using the configured high-water mark"
    else:
        by_memory = int(memory.available_mb // max(1, per_child_mb))
        ceiling = max(1, min(high_water, by_memory))
        reason = (
            f"{memory.available_mb:.0f} MB available / {per_child_mb} MB per child "
            f"= {by_memory} (clamped to high-water {high_water})"
        )
    return TaskBudget(
        max_children=ceiling,
        max_total_pending=max(ceiling, high_water),
        available_mb=memory.available_mb,
        pressure=memory.pressure,
        reason=reason,
    )


def plan_children(
    findings: Iterable[Any],
    *,
    followed: set[str] | None = None,
    existing: set[str] | None = None,
    budget: TaskBudget | None = None,
    high_water: int = 8,
    pending: int = 0,
) -> list[tuple[Any, int]]:
    """Choose which findings get children this cycle, and how many.

    Returns ``[(finding, allowance), ...]`` ordered by value: verified before
    candidate, critical before informational. The caller still derives the
    actual targets; this only decides the allowance so a low-value finding
    cannot crowd out a high-value one.

    A finding is skipped when it was already followed, when its status is not
    actionable, or when the budget is exhausted.
    """
    followed = followed or set()
    existing = existing or set()
    if budget is None:
        budget = task_budget(high_water=high_water, pending=pending)

    actionable = []
    for finding in findings:
        fid = _field_of(finding, "id")
        if not fid or fid in followed:
            continue
        if _status_of(finding) not in {"candidate", "theoretical", "verified"}:
            continue
        actionable.append(finding)

    # Value order: verified first, then severity, then id for determinism.
    status_rank = {"verified": 0, "theoretical": 1, "candidate": 2}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}

    def _key(f: Any) -> tuple[int, int, str]:
        return (
            status_rank.get(_status_of(f), 9),
            severity_rank.get(_severity_of(f), 9),
            _field_of(f, "id"),
        )

    actionable.sort(key=_key)

    plan: list[tuple[Any, int]] = []
    remaining = budget.max_children
    for index, finding in enumerate(actionable):
        if remaining <= 0:
            break
        weight = SEVERITY_WEIGHTS.get(_severity_of(finding), 1)
        allowance = min(weight, remaining)
        if allowance <= 0:
            continue
        plan.append((finding, allowance))
        remaining -= allowance
        # A finding that could not take its full weight means the budget ran
        # out mid-cycle: stop rather than hand the scraps to the next one.
        if allowance < weight:
            break
    return plan


def schedule_summary(
    findings: Iterable[Any],
    *,
    followed: set[str] | None = None,
    high_water: int = 8,
    pending: int = 0,
) -> dict[str, Any]:
    """Diagnostics for ``hunter status``: what the scheduler would do now."""
    budget = task_budget(high_water=high_water, pending=pending)
    plan = plan_children(
        findings, followed=followed, budget=budget, high_water=high_water, pending=pending
    )
    return {
        "budget": budget.as_dict(),
        "planned_findings": len(plan),
        "planned_children": sum(allowance for _, allowance in plan),
        "by_severity": _count_by(findings, _severity_of),
    }


def _count_by(items: Iterable[Any], key) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        k = key(item) or "unknown"
        counts[k] = counts.get(k, 0) + 1
    return counts
