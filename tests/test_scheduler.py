"""Tests for the smart task scheduler.

The old feeder rule was a flat four children per finding. These tests pin the
replacement: severity decides the allowance, memory decides the ceiling, and
a low-value finding can never crowd out a high-value one.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hunter.workflow.scheduler import MemorySnapshot
from hunter.workflow.scheduler import (
    SEVERITY_WEIGHTS,
    TaskBudget,
    plan_children,
    schedule_summary,
    task_budget,
)


def _finding(fid: str, severity: str = "medium", status: str = "candidate") -> SimpleNamespace:
    return SimpleNamespace(id=fid, severity=severity, status=status)


# ------------------------------------------------------------------- weighting


def test_severity_weights_are_ordered():
    assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"]
    assert SEVERITY_WEIGHTS["high"] > SEVERITY_WEIGHTS["medium"]
    assert SEVERITY_WEIGHTS["medium"] > SEVERITY_WEIGHTS["low"]


def test_verified_critical_gets_the_largest_allowance():
    budget = TaskBudget(max_children=10, max_total_pending=10, available_mb=4000, pressure="low", reason="")
    plan = plan_children(
        [
            _finding("f-low", "low", "candidate"),
            _finding("f-crit", "critical", "verified"),
        ],
        budget=budget,
    )
    allowances = {f.id: a for f, a in plan}
    assert allowances["f-crit"] == 4
    assert allowances["f-low"] == 1


def test_high_value_findings_are_planned_first():
    budget = TaskBudget(max_children=3, max_total_pending=3, available_mb=4000, pressure="low", reason="")
    plan = plan_children(
        [
            _finding("f-info", "info", "candidate"),
            _finding("f-crit", "critical", "verified"),
            _finding("f-med", "medium", "candidate"),
        ],
        budget=budget,
    )
    # Only 3 children of budget: the verified critical takes them all first.
    assert [f.id for f, _ in plan] == ["f-crit"]
    assert plan[0][1] == 3


def test_already_followed_findings_are_skipped():
    budget = TaskBudget(max_children=8, max_total_pending=8, available_mb=4000, pressure="low", reason="")
    plan = plan_children(
        [_finding("f-1", "critical", "verified"), _finding("f-2", "high", "verified")],
        followed={"f-1"},
        budget=budget,
    )
    assert [f.id for f, _ in plan] == ["f-2"]


def test_non_actionable_status_is_skipped():
    budget = TaskBudget(max_children=8, max_total_pending=8, available_mb=4000, pressure="low", reason="")
    plan = plan_children(
        [
            _finding("f-dismissed", "critical", "dismissed"),
            _finding("f-fp", "critical", "false_positive"),
            _finding("f-ok", "high", "verified"),
        ],
        budget=budget,
    )
    assert [f.id for f, _ in plan] == ["f-ok"]


def test_empty_budget_plans_nothing():
    budget = TaskBudget(max_children=0, max_total_pending=0, available_mb=50, pressure="critical", reason="starved")
    assert plan_children([_finding("f-1", "critical", "verified")], budget=budget) == []


def test_unknown_severity_gets_one_child():
    budget = TaskBudget(max_children=8, max_total_pending=8, available_mb=4000, pressure="low", reason="")
    plan = plan_children([_finding("f-x", "bizarre", "candidate")], budget=budget)
    assert plan[0][1] == 1


# ---------------------------------------------------------------------- budget


def test_budget_scales_with_available_memory(monkeypatch):
    from hunter.workflow import scheduler

    monkeypatch.setattr(scheduler, "memory_snapshot", lambda: MemorySnapshot(2000, 2000, 0, "procfs"))
    roomy = task_budget(high_water=8, per_child_mb=192)
    assert roomy.max_children == 8, "a roomy host is still clamped to high-water"

    monkeypatch.setattr(scheduler, "memory_snapshot", lambda: MemorySnapshot(600, 2000, 1400, "procfs"))
    tight = task_budget(high_water=8, per_child_mb=192)
    assert tight.max_children == 3, "600 MB / 192 MB per child = 3"


def test_budget_never_drops_below_one(monkeypatch):
    from hunter.workflow import scheduler

    monkeypatch.setattr(scheduler, "memory_snapshot", lambda: MemorySnapshot(10, 2000, 1990, "procfs"))
    budget = task_budget(high_water=8, per_child_mb=192)
    assert budget.max_children == 1


def test_unmeasurable_memory_falls_back_to_high_water(monkeypatch):
    from hunter.workflow import scheduler

    monkeypatch.setattr(
        scheduler,
        "memory_snapshot",
        lambda: MemorySnapshot(float("inf"), 0.0, 0.0, "unknown"),
    )
    budget = task_budget(high_water=8)
    assert budget.max_children == 8
    assert "unmeasurable" in budget.reason


def test_pressure_is_reported(monkeypatch):
    from hunter.workflow import scheduler

    monkeypatch.setattr(scheduler, "memory_snapshot", lambda: MemorySnapshot(100, 2000, 1900, "procfs"))
    assert task_budget().pressure == "critical"


# --------------------------------------------------------------------- summary


def test_schedule_summary_is_json_safe(monkeypatch):
    from hunter.workflow import scheduler

    monkeypatch.setattr(scheduler, "memory_snapshot", lambda: MemorySnapshot(2000, 2000, 0, "procfs"))
    findings = [
        _finding("f-1", "critical", "verified"),
        _finding("f-2", "high", "candidate"),
        _finding("f-3", "info", "candidate"),
    ]
    summary = schedule_summary(findings, high_water=8)
    assert summary["planned_findings"] == 3
    assert summary["planned_children"] == 4 + 3 + 1
    assert summary["by_severity"] == {"critical": 1, "high": 1, "info": 1}
    import json

    json.dumps(summary)


def test_summary_respects_followed(monkeypatch):
    from hunter.workflow import scheduler

    monkeypatch.setattr(scheduler, "memory_snapshot", lambda: MemorySnapshot(2000, 2000, 0, "procfs"))
    findings = [_finding("f-1", "critical", "verified"), _finding("f-2", "high", "verified")]
    summary = schedule_summary(findings, followed={"f-1"}, high_water=8)
    assert summary["planned_findings"] == 1
    assert summary["planned_children"] == 3


# ------------------------------------------------- dict-shaped findings (RAG/JSON)


def test_plan_children_reads_dict_findings():
    """The RAG layer and JSON reports hold dicts, not Finding objects.

    Reading `finding.id` with getattr on a dict returns '' — which the
    actionable filter treats as "no id" and drops. Every dict finding was
    silently skipped, so the scheduler planned nothing and reported success.
    """
    findings = [
        {"id": "F-1", "severity": "critical", "status": "candidate"},
        {"id": "F-2", "severity": "high", "status": "verified"},
    ]
    budget = TaskBudget(max_children=8, max_total_pending=16, available_mb=2000, pressure="low", reason="test")
    plan = plan_children(findings, budget=budget)
    assert [f["id"] for f, _ in plan] == ["F-2", "F-1"]
    assert [n for _, n in plan] == [3, 4]


def test_plan_children_dict_and_object_shapes_agree():
    """Same data, same plan — whichever shape the caller happens to hold."""
    obj = _finding("f-1", "critical", "verified")
    dic = {"id": "f-1", "severity": "critical", "status": "verified"}
    budget = TaskBudget(max_children=8, max_total_pending=16, available_mb=2000, pressure="low", reason="test")
    a = plan_children([obj], budget=budget)
    b = plan_children([dic], budget=budget)
    assert [(f.id, n) for f, n in a] == [(f["id"], n) for f, n in b] == [("f-1", 4)]


def test_plan_children_spends_the_whole_budget():
    """Leftover children go to the next finding rather than being wasted.

    A cycle that stops at 4 of 5 children throws away a fifth of the budget
    every round; the leftover belongs to the next-highest finding.
    """
    findings = [
        _finding("f-1", "critical", "verified"),
        _finding("f-2", "high", "candidate"),
    ]
    budget = TaskBudget(max_children=5, max_total_pending=16, available_mb=1000, pressure="low", reason="test")
    plan = plan_children(findings, budget=budget)
    assert [(f.id, n) for f, n in plan] == [("f-1", 4), ("f-2", 1)]
