"""RunBudget — iteration consume/refund, staged cost warnings, wall clock."""

from __future__ import annotations

import threading
import types

import pytest

from hunter.llm.budget import RunBudget


def test_consume_iteration_bounds_and_refund():
    budget = RunBudget(max_iterations=3)
    assert [budget.consume_iteration() for _ in range(3)] == [True, True, True]
    # Cap hit: consume refuses.
    assert budget.consume_iteration() is False
    assert budget.iterations_used == 3
    # Refund frees exactly one slot.
    budget.refund_iteration()
    assert budget.iterations_used == 2
    assert budget.consume_iteration() is True


def test_refund_at_zero_is_safe():
    budget = RunBudget(max_iterations=2)
    budget.refund_iteration()
    assert budget.iterations_used == 0


def test_cost_breakpoints_fire_once_each_in_order():
    budget = RunBudget(max_cost_usd=10.0)
    # Below the first threshold: silent.
    budget.add_cost(6.9)
    assert budget.cost_breakpoint() is None
    # 70% crossed -> one warning; the immediate second call does not repeat it.
    budget.add_cost(0.2)  # 7.1
    first = budget.cost_breakpoint()
    assert first is not None and "[BUDGET 70%]" in first and "wind down" in first
    assert budget.cost_breakpoint() is None
    # 85% crossed (8.5).
    budget.add_cost(1.5)
    second = budget.cost_breakpoint()
    assert second is not None and "[BUDGET 85%]" in second
    assert budget.cost_breakpoint() is None
    # 95% crossed (9.5).
    budget.add_cost(1.0)
    third = budget.cost_breakpoint()
    assert third is not None and "[BUDGET 95%]" in third
    assert budget.cost_breakpoint() is None
    assert budget.warned_levels == (70, 85, 95)


def test_cost_breakpoint_ladder_fires_one_level_per_call():
    budget = RunBudget(max_cost_usd=10.0)
    budget.add_cost(9.6)  # crosses 70, 85 and 95 at once
    warning = budget.cost_breakpoint()
    assert warning is not None and "[BUDGET 70%]" in warning
    assert "[BUDGET 85%]" in budget.cost_breakpoint()
    assert "[BUDGET 95%]" in budget.cost_breakpoint()


def test_cost_breakpoint_disabled_without_limit():
    budget = RunBudget(max_cost_usd=0.0)
    budget.add_cost(100.0)
    assert budget.cost_breakpoint() is None


def test_exhausted_cost_reason():
    budget = RunBudget(max_cost_usd=5.0)
    budget.add_cost(4.99)
    assert budget.exhausted() is None
    budget.add_cost(0.01)
    reason = budget.exhausted()
    assert reason is not None and "cost" in reason and "5.00" in reason


def test_exhausted_iterations_reason():
    budget = RunBudget(max_iterations=2)
    assert budget.exhausted() is None
    budget.consume_iteration()
    budget.consume_iteration()
    reason = budget.exhausted()
    assert reason is not None and "iteration" in reason


def test_wall_clock_exhausted(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(
        "hunter.llm.budget.time", types.SimpleNamespace(monotonic=lambda: clock["now"])
    )
    budget = RunBudget(wall_seconds=100.0)
    budget.start()
    assert budget.started_monotonic == 1000.0
    assert budget.exhausted() is None
    clock["now"] = 1099.0
    assert budget.exhausted() is None
    clock["now"] = 1100.0
    reason = budget.exhausted()
    assert reason is not None and "wall" in reason


def test_wall_clock_requires_start():
    # Never armed -> the wall clock never fires (started_monotonic stays 0).
    budget = RunBudget(wall_seconds=0.001)
    assert budget.exhausted() is None
    assert budget.elapsed_seconds() == 0.0


def test_start_records_monotonic(monkeypatch):
    monkeypatch.setattr(
        "hunter.llm.budget.time", types.SimpleNamespace(monotonic=lambda: 4242.0)
    )
    budget = RunBudget()
    assert budget.started_monotonic == 0.0
    budget.start()
    assert budget.started_monotonic == 4242.0
    assert budget.elapsed_seconds() == 0.0


def test_exhausted_reason_priority_is_cost_first():
    # Cost and iterations both blown -> the cost reason surfaces first.
    budget = RunBudget(max_cost_usd=1.0, max_iterations=1)
    budget.consume_iteration()
    budget.add_cost(2.0)
    reason = budget.exhausted()
    assert reason is not None and reason.startswith("cost budget exhausted")


def test_add_cost_clamps_negative_totals():
    budget = RunBudget(max_cost_usd=10.0)
    budget.add_cost(3.0)
    budget.add_cost(-10.0)
    assert budget.spent_usd == 0.0


def test_concurrent_consumes_respect_the_cap():
    budget = RunBudget(max_iterations=10)
    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        if lock.acquire():
            try:
                outcomes.append(budget.consume_iteration())
            finally:
                lock.release()

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for allowed in outcomes if allowed) == 10
    assert budget.iterations_used == 10


def test_is_instance_of_base_contract():
    from hunter.llm.base import RunBudget as RunBudgetContract

    assert isinstance(RunBudget(), RunBudgetContract)


@pytest.mark.parametrize(
    ("field", "value"),
    [("max_cost_usd", 5.0), ("max_iterations", 60), ("wall_seconds", 1800.0)],
)
def test_defaults_match_contract(field, value):
    assert getattr(RunBudget(), field) == value
