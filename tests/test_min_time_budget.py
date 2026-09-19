"""M8 F3 — minimum time budget: ``RunBudget.remaining_seconds`` and the
AgentLoop's bounded min-time nudges (test-first).

The loop must HOLD ``finish_scan`` / ``respond_to_user`` lifecycle outcomes
while ``budget.remaining_seconds() > 0`` — re-feeding the tool result with a
``[BUDGET min-time]`` nudge — and honor the lifecycle call after the floor
elapses, with a hard cap of ``max_time_nudges`` (default 50). All offline:
scripted FakeProvider, real Ledger on a tmp path, fake clock via
``hunter.llm.budget.time`` (same seam as tests/test_llm_budget.py).
"""

from __future__ import annotations

import types
from typing import Any

import pytest

from hunter.agent.loop import AgentLoop
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ClassifiedError, RunBudget, ToolCall, TurnResult
from hunter.llm.budget import RunBudget as ConcreteRunBudget
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

CLOCK = {"now": 1000.0}


@pytest.fixture(autouse=True)
def fake_clock(monkeypatch):
    CLOCK["now"] = 1000.0
    monkeypatch.setattr(
        "hunter.llm.budget.time", types.SimpleNamespace(monotonic=lambda: CLOCK["now"])
    )
    return CLOCK


class FakeProvider:
    """Scripted ChatProvider: entries are TurnResults or callables f(messages)."""

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
        if callable(step):
            return step(messages=messages)
        return step

    def classify(self, _exc: BaseException) -> ClassifiedError:
        return ClassifiedError(reason="unknown")


def turn(*calls: ToolCall, cost: float = 0.0) -> TurnResult:
    return TurnResult(
        text="",
        tool_calls=tuple(calls),
        finish_reason="tool_calls" if calls else "stop",
        cost_usd=cost,
        model="fake-model",
        provider="fake",
    )


def tool_call(name: str, **args: Any) -> ToolCall:
    return ToolCall(id=f"c-{name}-{len(args)}", name=name, arguments=dict(args))


def _budget(min_wall_seconds: float) -> ConcreteRunBudget:
    # min time is the ONLY active constraint — cost/iterations/wall are off so
    # every stop below comes from the lifecycle path under test.
    return ConcreteRunBudget(
        min_wall_seconds=min_wall_seconds, max_cost_usd=0.0, max_iterations=0, wall_seconds=0.0
    )


@pytest.fixture()
def env(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)
    ctx = ToolContext(
        run_id="R-MINTIME",
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


def test_min_wall_defaults_off_and_remaining_zero():
    budget = ConcreteRunBudget()
    assert budget.min_wall_seconds == 0.0
    assert budget.stop_file is None
    assert budget.remaining_seconds() == 0.0
    # the base contract carries the same fields (its remaining_seconds is a
    # docstring-only stub, so only the fields are asserted here)
    base = RunBudget()
    assert base.min_wall_seconds == 0.0
    assert base.stop_file is None


def test_remaining_seconds_counts_down_when_armed():
    budget = ConcreteRunBudget(min_wall_seconds=600.0)
    assert budget.remaining_seconds() == 0.0  # clock not armed yet
    budget.start()
    assert budget.remaining_seconds() == pytest.approx(600.0)
    CLOCK["now"] += 60.0
    assert budget.remaining_seconds() == pytest.approx(540.0)
    CLOCK["now"] += 1000.0
    assert budget.remaining_seconds() == 0.0  # floor elapsed — never negative


def test_exhausted_never_fires_on_min_wall():
    # min_wall_seconds is a FLOOR, never a stop reason: even fully blown
    # cost/iterations and an elapsed clock stay None until a real limit hits.
    budget = ConcreteRunBudget(min_wall_seconds=3600.0, max_cost_usd=0.0, max_iterations=0, wall_seconds=0.0)
    budget.start()
    budget.add_cost(1000.0)
    for _ in range(100):
        budget.consume_iteration()
    CLOCK["now"] += 10_000.0
    assert budget.exhausted() is None


def test_loop_holds_finish_scan_until_min_time(env):
    budget = _budget(600.0)

    def hold(messages):
        assert budget.remaining_seconds() > 0
        return turn(tool_call("finish_scan"))

    def release(messages):
        CLOCK["now"] += 700.0  # min time passes -> the finish is honored
        return turn(tool_call("finish_scan"))

    provider = FakeProvider([hold, release])
    loop = AgentLoop(provider, build_registry("basic"), tier="basic", budget=budget)
    result = loop.run(env, "Audit the target.")
    assert result.finished is True
    assert "findings: 0" in result.summary
    held = provider.calls[1]["messages"][-1]
    assert held["role"] == "tool"
    assert "[BUDGET min-time]" in held["content"]
    assert "(min-time nudge 1/50)" in held["content"]


def test_loop_holds_respond_to_user_until_min_time(env):
    budget = _budget(600.0)

    def hold(messages):
        return turn(tool_call("respond_to_user", message="need creds to test /admin"))

    def release(messages):
        CLOCK["now"] += 700.0
        return turn(tool_call("respond_to_user", message="need creds to test /admin"))

    provider = FakeProvider([hold, release])
    loop = AgentLoop(provider, build_registry("basic"), tier="basic", budget=budget)
    result = loop.run(env, "Audit the target.")
    assert result.yield_message == "need creds to test /admin"
    assert result.finished is False
    held = provider.calls[1]["messages"][-1]
    assert held["role"] == "tool"
    assert "[BUDGET min-time]" in held["content"]


def test_loop_min_time_nudges_bounded_at_50(env):
    budget = _budget(3600.0)
    # Each held turn records a distinct follow-up coverage row: finish_scan
    # results must differ per turn or the guardrail's identical-result halt
    # (5) would fire before the 50-nudge bound under test.
    script = []
    for index in range(51):
        def _held(messages, _index=index):
            env.state.setdefault("coverage", []).append(
                {
                    "surface": f"surface-{_index}",
                    "risk_area": f"area-{_index}",
                    "outcome": "needs_follow_up",
                    "note": f"note-{_index}",
                }
            )
            return turn(tool_call("finish_scan"))

        script.append(_held)
    provider = FakeProvider(script)
    loop = AgentLoop(provider, build_registry("basic"), tier="basic", budget=budget, max_time_nudges=50)
    result = loop.run(env, "Audit the target.")
    # the first 50 lifecycle calls were held with bounded nudges...
    final_tool = [m for m in provider.calls[-1]["messages"] if m.get("role") == "tool"]
    assert final_tool and "(min-time nudge 50/50)" in final_tool[-1]["content"]
    # ...and the 51st lifecycle call is honored (fail-open), noting the cap.
    assert result.finished is True
    assert "min-time" in result.summary


def test_nudge_text_names_minutes_left(env):
    budget = _budget(600.0)

    def spend_five_of_ten_minutes(messages):
        CLOCK["now"] += 540.0  # exactly 60s of min time left -> "time left 1m"
        return turn(tool_call("finish_scan"))

    def release(messages):
        CLOCK["now"] += 700.0  # min time fully elapsed -> the yield is honored
        return turn(tool_call("respond_to_user", message="done"))

    provider = FakeProvider([spend_five_of_ten_minutes, release])
    loop = AgentLoop(provider, build_registry("basic"), tier="basic", budget=budget)
    result = loop.run(env, "Audit the target.")
    held = provider.calls[1]["messages"][-1]
    assert "time left 1m" in held["content"]
    assert result.yield_message == "done"
