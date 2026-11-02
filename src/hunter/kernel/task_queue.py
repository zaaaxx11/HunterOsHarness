"""Task queue — drives the hunt, not the LLM.

The LLM is a worker. It gets one task at a time. The SYSTEM decides what to
do next based on what each task produces.

Flow:
  target → AUDIT task → creates finding → auto-enqueue VERIFY task
  VERIFY task → promotes finding → auto-enqueue PROMOTE task
  PROMOTE task → adversary challenge → auto-enqueue PROVE task
  PROVE task → forge test + logs → PROVEN_LIVE, dequeue

Tasks chain recursively. The queue drains when all tasks reach PROVEN_LIVE
or RULED_OUT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskKind(str, Enum):
    AUDIT = "audit"
    CREATE_FINDING = "create_finding"
    VERIFY = "verify"           # CANDIDATE → VERIFIED
    PROMOTE = "promote"          # VERIFIED → PROMOTED
    PROVE = "prove"             # PROMOTED → PROVEN_LIVE
    INVESTIGATE = "investigate"  # Follow-up from new evidence


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    task_id: str                # "T-0001"
    parent_id: str | None       # spawned from which task
    kind: TaskKind
    target: str                 # contract path or finding_id
    priority: int = 0
    status: TaskStatus = TaskStatus.PENDING
    evidence_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def next_kind(kind: TaskKind) -> TaskKind | None:
    """What kind of task follows this one in the verification ladder?"""
    _ladder = {
        TaskKind.AUDIT: TaskKind.CREATE_FINDING,
        TaskKind.CREATE_FINDING: TaskKind.VERIFY,
        TaskKind.VERIFY: TaskKind.PROMOTE,
        TaskKind.PROMOTE: TaskKind.PROVE,
    }
    return _ladder.get(kind)


def spawn_child(parent: Task, finding_id: str) -> Task:
    """Create the next task in the verification ladder."""
    kind = next_kind(parent.kind)
    if kind is None:
        raise ValueError(f"No next kind for {parent.kind}")
    return Task(
        task_id="",  # assigned on enqueue
        parent_id=parent.task_id,
        kind=kind,
        target=finding_id if kind != TaskKind.AUDIT else parent.target,
        priority=parent.priority + 1,
        evidence_ids=list(parent.evidence_ids),
    )