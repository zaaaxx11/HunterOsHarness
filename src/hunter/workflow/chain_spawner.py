"""Chain spawner — creates child tasks from verified findings for recursive hunting.

A verified critical finding is a trailhead: it spawns child tasks that
explore related surfaces, chain hypotheses, and variant paths. The chain
spawner decides *whether* to spawn, *how many* children, and *which* findings
naturally chain together (output of one is input to another).

Doctrine:
- critical/high → always spawn (high-value signals demand follow-up)
- medium + verified → spawn (reproducible, worth pursuing)
- low → never spawn (noise)
- Chain candidates pair findings whose output surface matches another's input
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunter.kernel.findings import Finding, FindingStatus, Severity

__all__ = [
    "Task",
    "TaskState",
    "should_spawn_child",
    "spawn_child_tasks",
    "find_chain_candidates",
]


class TaskState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class Task:
    """A unit of hunt work in the BFS task tree."""

    task_id: str
    parent_id: str | None = None
    target: str = ""
    target_kind: str = "web"
    state: TaskState = TaskState.QUEUED
    priority: int = 0
    depth: int = 0
    spawned_from_finding: str | None = None
    chain_hypothesis: str | None = None
    injected_context: dict[str, Any] | None = None
    max_turns: int = 8
    max_wall_s: int = 300
    max_cost_usd: float = 0.50
    run_id: str | None = None
    retry_count: int = 0
    max_retries: int = 2
    last_error: str | None = None
    created_ts: float = field(default_factory=time.time)
    started_ts: float | None = None
    finished_ts: float | None = None


def should_spawn_child(finding: Finding | dict) -> bool:
    """Decide whether a finding deserves a follow-up child task.

    Rules:
    - critical / high severity → always spawn
    - medium severity + verified → spawn (reproducible signal)
    - low / info → never spawn
    - candidate / theoretical (unverified) → skip unless critical/high

    Accepts both ``Finding`` objects and plain dicts (from JSON reports / RAG).
    """
    sev = _field_of(finding, "severity")
    status = _field_of(finding, "status")

    if sev in ("critical", "high"):
        return True
    if sev == "medium" and status == "verified":
        return True
    return False


def spawn_child_tasks(
    parent_task: Task,
    verified_findings: list[Finding],
    ledger: Any | None = None,
) -> list[Task]:
    """Create child tasks for each verified finding that warrants follow-up.

    Children are named ``T-001.1``-style: ``{parent_id}.{n}``. Each child
    inherits context from the parent and carries a chain hypothesis linking
    the finding to the parent's surface.

    Args:
        parent_task: The task spawning children (the parent in the tree).
        verified_findings: Findings discovered by the parent that may spawn children.
        ledger: Optional ledger for persisting tasks (not required for stateless use).

    Returns:
        Newly created ``Task`` objects (one per spawn-worthy finding).
    """
    children: list[Task] = []
    viable = [f for f in verified_findings if should_spawn_child(f)]

    for i, finding in enumerate(viable, start=1):
        child_id = f"{parent_task.task_id}.{i}"
        fid = _field_of(finding, "id")
        sev = _field_of(finding, "severity")
        endpoint = _field_of(finding, "endpoint")
        title = _field_of(finding, "title")

        hypothesis = (
            f"Chain from {parent_task.task_id}: {sev} finding {fid} "
            f"({title}) at {endpoint} suggests related flaws on "
            f"{parent_task.target}"
        )

        injected = {
            "parent_task_id": parent_task.task_id,
            "parent_target": parent_task.target,
            "finding_id": fid,
            "finding_severity": sev,
            "finding_endpoint": endpoint,
            "finding_title": title,
            "chain_depth": parent_task.depth,
        }

        child = Task(
            task_id=child_id,
            parent_id=parent_task.task_id,
            target=parent_task.target,
            target_kind=parent_task.target_kind,
            depth=parent_task.depth + 1,
            priority=_severity_priority(sev),
            spawned_from_finding=fid,
            chain_hypothesis=hypothesis,
            injected_context=injected,
            max_turns=parent_task.max_turns,
            max_wall_s=parent_task.max_wall_s,
            max_cost_usd=parent_task.max_cost_usd,
            run_id=parent_task.run_id,
        )
        children.append(child)

    return children


def find_chain_candidates(
    all_findings: list[Finding],
) -> list[tuple[str, str, str]]:
    """Find pairs of findings that can be chained together.

    Determines which findings naturally feed into each other — where the output
    surface of one finding matches the input surface of another. This drives
    cross-task context injection.

    Matching rules:
    - Same target → always a chain candidate (findings on the same host)
    - Different target + matching check type → candidate (same vuln class)
    - Different target + different type → skip

    Returns the top 5 candidates as ``(finding_a_id, finding_b_id, reason)``
    tuples, ordered by matching strength (same-target first, then type-match).

    Args:
        all_findings: Flat list of all findings across all tasks.

    Returns:
        Up to 5 chain candidate tuples.
    """
    if len(all_findings) < 2:
        return []

    candidates: list[tuple[str, str, str, int]] = []  # (a_id, b_id, reason, score)

    for i in range(len(all_findings)):
        for j in range(i + 1, len(all_findings)):
            a = all_findings[i]
            b = all_findings[j]

            a_target = _field_of(a, "endpoint")
            b_target = _field_of(b, "endpoint")
            a_type = _check_type(a)
            b_type = _check_type(b)

            # Same target endpoint → strongest signal
            if a_target and b_target and a_target == b_target:
                candidates.append(
                    (a_id(a), a_id(b), f"same_target:{a_target}", 10)
                )
            # Different targets but same check type → weaker but valid
            elif a_target != b_target and a_type == b_type and a_type:
                candidates.append(
                    (a_id(a), a_id(b), f"type_match:{a_type}", 5)
                )
            # Different targets, different types → skip
            else:
                continue

    # Sort by score descending, then by id for determinism
    candidates.sort(key=lambda x: (-x[3], x[0], x[1]))

    # Return top 5 as (a_id, b_id, reason)
    return [(c[0], c[1], c[2]) for c in candidates[:5]]


# ── helpers ──────────────────────────────────────────────────────────────────


def _field_of(obj: Any, name: str) -> str:
    """Read a field off a Finding, dict, or SimpleNamespace, lowercased."""
    if isinstance(obj, dict):
        value = obj.get(name, "")
    else:
        value = getattr(getattr(obj, name, None), "value", None)
        if value is None:
            value = getattr(obj, name, "")
    return str(value or "").strip().lower()


def a_id(finding: Any) -> str:
    """Extract the id from a finding, regardless of shape."""
    return _field_of(finding, "id")


def _check_type(finding: Any) -> str:
    """Extract the check/bug class from a finding for type matching.

    Uses ``klass`` if available (v0.7+), otherwise falls back to the
    first segment of the dedupe key (e.g. 'reflected-xss' from
    'reflected-xss|GET|/search|q').
    """
    klass = _field_of(finding, "klass")
    if klass and klass != "unknown":
        return klass
    key = _field_of(finding, "key")
    if key and "|" in key:
        return key.split("|", 1)[0]
    return ""


def _severity_priority(severity: str) -> int:
    """Map severity string to a numeric priority (higher = more important)."""
    return {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(severity, 0)