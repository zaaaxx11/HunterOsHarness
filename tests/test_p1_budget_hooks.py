"""P1 — cost_breakpoint advisories + on_budget hook contract tests (TDD step 1).

Planner A target: ``hunter.agent.hooks.on_budget`` + ``AgentLoop`` wiring.
Today ``RunBudget.cost_breakpoint()`` exists (see tests/test_llm_budget.py)
but the loop NEVER calls it — advisories never reach the model. These tests
pin the missing integration:

- ``cost_breakpoint`` fires once per 70/85/95 level, surfaced as a TOOL-role
  advisory message (role alternation preserved — never a user message, never
  an extra provider turn).
- ``wrap_up`` at >= 85%: only lifecycle + read-only tools admitted.
- ``refund_iteration`` for housekeeping-only rounds (no real tool work).
- stop_file outranks every automatic limit at the loop seam too.
- the ``on_budget`` hook injects the advisory WITHOUT extra turn cost
  (provider ``complete`` call count unchanged; budget spend unchanged).

Adversarial mitigations: scripted budgets only (no wall clock — levels are
driven by ``add_cost``); strict asserts on transcript roles AND provider call
counts, not just return values; hook tests importorskip the missing module.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

from hunter.llm.budget import RunBudget


def _needs_hooks() -> Any:
    """The not-yet-existing production module — SKIPPED until implemented."""
    return pytest.importorskip("hunter.agent.hooks")


def test_p1_budget_advisory_once_per_level_as_tool_role() -> None:
    hooks = _needs_hooks()
    budget = RunBudget(max_cost_usd=10.0)
    transcript: list[dict[str, Any]] = []
    budget.add_cost(7.1)
    assert hooks.on_budget(budget, transcript) == "[BUDGET 70%]"
    assert transcript[-1]["role"] == "tool"
    assert hooks.on_budget(budget, transcript) is None  # already warned: silent
    budget.add_cost(1.5)
    assert hooks.on_budget(budget, transcript) == "[BUDGET 85%]"
    budget.add_cost(1.0)
    assert hooks.on_budget(budget, transcript) == "[BUDGET 95%]"
    assert hooks.on_budget(budget, transcript) is None
    assert {message["role"] for message in transcript} <= {"assistant", "tool"}


def test_p1_budget_wrap_up_admits_lifecycle_and_reads_only() -> None:
    hooks = _needs_hooks()
    budget = RunBudget(max_cost_usd=10.0)
    budget.add_cost(8.6)  # past the 85% wrap-up line
    assert hooks.wrap_up(budget, "finish_scan") is True
    assert hooks.wrap_up(budget, "respond_to_user") is True
    assert hooks.wrap_up(budget, "http_request") is True  # read-only probe
    assert hooks.wrap_up(budget, "browser_navigate") is False  # state-changing write path


def test_p1_budget_refund_iteration_for_housekeeping_rounds() -> None:
    hooks = _needs_hooks()
    budget = RunBudget(max_iterations=3)
    budget.consume_iteration()
    budget.consume_iteration()
    hooks.refund_iteration(budget, housekeeping_only=True)
    assert budget.iterations_used == 1
    hooks.refund_iteration(budget, housekeeping_only=False)
    assert budget.iterations_used == 1  # real work is never refunded


def test_p1_budget_stop_file_outranks_all_at_loop_seam(tmp_path: Any) -> None:
    hooks = _needs_hooks()
    flag = tmp_path / "stop.flag"
    budget = RunBudget(stop_file=str(flag), max_cost_usd=5.0, max_iterations=100)
    assert hooks.should_stop(budget) is None
    flag.write_text("", encoding="utf-8")
    reason = hooks.should_stop(budget)
    assert reason is not None and "stop file" in reason


def test_p1_budget_on_budget_hook_costs_no_extra_turn() -> None:
    hooks = _needs_hooks()
    budget = RunBudget(max_cost_usd=10.0)
    calls = {"complete": 0, "spent": budget.spent_usd}

    class _CountingProvider:
        def complete(self, *args: Any, **kwargs: Any) -> None:
            calls["complete"] += 1

    budget.add_cost(7.1)
    hooks.on_budget(budget, [], provider=_CountingProvider())
    assert calls["complete"] == 0
    assert budget.spent_usd == calls["spent"] + 7.1


def test_p1_budget_loop_surfaces_cost_breakpoint_to_model() -> None:
    source = pathlib.Path("src/hunter/agent/loop.py").read_text(encoding="utf-8")
    assert "cost_breakpoint" in source
