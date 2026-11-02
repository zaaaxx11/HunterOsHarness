"""Reproduction for the daemon min-time floor bug (floor silently re-armed).

Field symptom: ``hunt start --time 45m --min-time 40m`` builds a RunBudget
with ``min_wall_seconds=2400``, starts it (``src/hunter/daemon.py:1046``),
and the run ended after 422s with status ``completed``.

Root cause: ``AgentLoop.run()`` calls ``_arm_budget()`` on every run, which
re-invokes ``budget.start()`` even when the budget is ALREADY armed. That
RESETS ``budget.started_monotonic`` to "now"; ``remaining_seconds()`` is
``min_wall_seconds - (now - started_monotonic)``, so the floor restarts at the
full ``min_wall_seconds`` whenever the loop begins. Every floor consumer
(``_hold_for_min_time``, ``RunBudget.exhausted``) then measures from the
wrong epoch.

``test_loop_holds_finish_scan_until_min_time`` in tests/test_min_time_budget.py
does not catch this because its fake clock starts at 1000.0 and the loop's
re-anchor lands on the same 1000.0 — a fixed-point that only exists in the
test's own clock seam.

These tests use the SAME fakes (scripted FakeProvider + real registry /
ledger) and no clock mocking: the budget's anchor is simply NOT "now"
(``started_monotonic`` pinned to a timestamp a few hundred seconds in the
past, as when a daemon armed it before the pipeline spawned the loop).
"""

from __future__ import annotations

from typing import Any

import pytest

from hunter.agent.loop import AgentLoop
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ClassifiedError, ToolCall, TurnResult
from hunter.llm.budget import RunBudget as ConcreteRunBudget
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope


class FakeProvider:
    """Scripted ChatProvider (same shape as tests/test_min_time_budget.py)."""

    name = "fake"

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools})
        index = len(self.calls) - 1
        if index >= len(self.script):
            raise AssertionError(f"FakeProvider script exhausted after {len(self.script)} turns")
        step = self.script[index]
        return step(messages=messages) if callable(step) else step

    def classify(self, _exc: BaseException) -> ClassifiedError:
        return ClassifiedError(reason="unknown")


def turn(*calls: ToolCall) -> TurnResult:
    return TurnResult(
        text="",
        tool_calls=tuple(calls),
        finish_reason="tool_calls" if calls else "stop",
        cost_usd=0.0,
        model="fake-model",
        provider="fake",
    )


def tool_call(name: str, **args: Any) -> ToolCall:
    return ToolCall(id=f"c-{name}-{len(args)}", name=name, arguments=dict(args))


@pytest.fixture()
def env(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)
    ctx = ToolContext(
        run_id="R-MIN-FLOOR",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url="http://127.0.0.1/",
        emit=lambda kind, payload: None,
        config={"tier": "basic"},
    )
    try:
        yield ctx
    finally:
        http.close()
        ledger.close()


def _pre_armed_budget(min_wall_seconds: float = 2400.0) -> ConcreteRunBudget:
    """The daemon's construction order (src/hunter/daemon.py:1036-1046):
    budget built, ``start()`` called BEFORE the pipeline runs the loop."""
    budget = ConcreteRunBudget(
        max_cost_usd=0.0,
        wall_seconds=2700.0,
        min_wall_seconds=min_wall_seconds,
        max_iterations=0,
    )
    budget.start()
    return budget


def _assert_floor_survives(budget: ConcreteRunBudget, provider: FakeProvider) -> None:
    # With the budget armed BEFORE this test (the daemon order) the floor has
    # already elapsed: the first lifecycle call must be HONORED, and the model
    # must have been asked for exactly ONE turn. A loop that re-armed the
    # budget at run() pushes the floor 2400s into the future and keeps the
    # agent turning (nudge after nudge) instead of honoring the stop.
    assert len(provider.calls) == 1, (
        f"loop consumed {len(provider.calls)} provider turns — the floor was "
        "re-armed at run() instead of measured from the daemon's start()"
    )


def test_floor_survives_daemon_pre_armed_budget_finish_scan(env):
    budget = _pre_armed_budget(min_wall_seconds=60.0)
    budget.started_monotonic -= 600.0  # the daemon armed it 600s ago
    provider = FakeProvider([turn(tool_call("finish_scan"))])
    result = AgentLoop(provider, build_registry(), budget=budget).run(env, "Audit the target.")
    _assert_floor_survives(budget, provider)
    assert result.finished is True


def test_floor_survives_daemon_pre_armed_budget_respond_to_user(env):
    budget = _pre_armed_budget(min_wall_seconds=60.0)
    budget.started_monotonic -= 600.0  # the daemon armed it 600s ago
    provider = FakeProvider([turn(tool_call("respond_to_user", message="need creds for /admin"))])
    result = AgentLoop(provider, build_registry(), budget=budget).run(env, "Audit the target.")
    _assert_floor_survives(budget, provider)
    assert result.yield_message == "need creds for /admin"
