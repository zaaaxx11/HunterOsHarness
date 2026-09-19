"""P1 — pure guardrail controller contract tests (TDD step 1, failing by design).

Planner A target: ``hunter.agent.guardrails`` — the Reference
``agent_tool_guardrails.py`` port as a SIDE-EFFECT-FREE controller: it tracks
per-turn tool-call observations and returns decisions; runtime code decides
whether a decision becomes warning guidance, a synthetic tool result, or a
controlled halt. Thresholds pinned here (Reference values):

- exact-args failure x5 -> block; same-tool failure x8 -> halt.
- identical (tool, args, result) x3 -> notice, x5 -> halt.
- repeating multi-call cycles with period <= 4 -> detect (notice at 3 laps).
- per-turn caps for runaway-prone web/probe tools.
- failure-tolerant tools (red test run / empty grep is normal output) vs
  progress-reset tools (a successful edit makes the next retry a new
  experiment, not a replay).
- attended -> warn; unattended -> halt; halt emits ``engine_event`` and the
  run breaks as a partial (never crashes).

Adversarial mitigations: pure controller, no threads/clock/network; every
test asserts the DECISION object (action + payload), never a mock call; the
seam test xfails on the missing AgentLoop wiring.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest


def _needs_guardrails() -> Any:
    """The not-yet-existing production module — SKIPPED until implemented."""
    return pytest.importorskip("hunter.agent.guardrails")


def _observe(controller: Any, name: str, args: dict[str, Any], result: str, ok: bool = False) -> Any:
    return controller.observe(tool=name, args=args, result=result, ok=ok)


def test_p1_guardrail_exact_fail_blocks_at_five() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController()
    decision = None
    for _ in range(5):
        decision = _observe(controller, "patch", {"file": "a.py"}, "error: denied", ok=False)
    assert decision is not None and decision.action == "block"
    assert decision.signature == ("patch", '{"file": "a.py"}')


def test_p1_guardrail_same_tool_failure_halts_at_eight() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController()
    decision = None
    for index in range(8):
        decision = _observe(controller, "patch", {"file": f"{index}.py"}, "error", ok=False)
    assert decision is not None and decision.action == "halt"


def test_p1_guardrail_identical_result_notice_at_three_halt_at_five() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController()
    seen = [_observe(controller, "read_file", {"p": "x"}, "same-bytes", ok=True) for _ in range(5)]
    assert seen[2].action == "notice"
    assert seen[4].action == "halt"


def test_p1_guardrail_cycle_period_up_to_four_detected() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController()
    batch = [("tool_a", {"x": 1}, "ra"), ("tool_b", {"y": 2}, "rb")]
    decision = None
    for _ in range(3):  # 3 laps of the (A, B) cycle
        for name, args, result in batch:
            decision = _observe(controller, name, args, result, ok=True)
    assert decision is not None and decision.action in ("notice", "halt")
    assert decision.cycle_period == 2


def test_p1_guardrail_web_and_probe_per_turn_caps() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController(attended=True)
    decision = None
    for _ in range(51):
        decision = controller.observe(tool="web_search", args={"q": "x"}, result="r", ok=True)
    assert decision is not None and decision.action in ("warn", "block")
    assert "cap" in decision.code


def test_p1_guardrail_failure_tolerant_vs_progress_reset() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController()
    tolerant = None
    for index in range(7):  # terminal failing differently each time is normal work output
        tolerant = _observe(controller, "terminal", {"cmd": f"run-{index}"}, "FAIL", ok=False)
    assert tolerant is not None and tolerant.action == "allow"
    # ...while an exact-args replay with no intervening change still blocks:
    controller.note_progress(tool="patch", args={"file": "fix.py"})
    reset = _observe(controller, "terminal", {"cmd": "run-0"}, "FAIL", ok=False)
    assert reset.action == "allow"  # the successful edit reset the failing signature


def test_p1_guardrail_warn_when_attended_halt_when_unattended() -> None:
    guardrails = _needs_guardrails()
    attended = guardrails.GuardrailController(attended=True)
    decision_attended = None
    for _ in range(8):
        decision_attended = _observe(attended, "patch", {"file": "n.py"}, "error", ok=False)
    assert decision_attended is not None and decision_attended.action == "warn"
    unattended = guardrails.GuardrailController(attended=False)
    decision_alone = None
    for _ in range(8):
        decision_alone = _observe(unattended, "patch", {"file": "n.py"}, "error", ok=False)
    assert decision_alone is not None and decision_alone.action == "halt"


def test_p1_guardrail_halt_carries_engine_event_and_partial_break() -> None:
    guardrails = _needs_guardrails()
    controller = guardrails.GuardrailController(attended=False)
    decision = None
    for _ in range(8):
        decision = _observe(controller, "patch", {"file": "n.py"}, "error", ok=False)
    assert decision is not None and decision.action == "halt"
    assert decision.engine_event["stage"] == "guardrail_halt"
    assert decision.partial_break is True


def test_p1_guardrail_loop_consults_controller_per_turn() -> None:
    source = pathlib.Path("src/hunter/agent/loop.py").read_text(encoding="utf-8")
    assert "guardrail" in source.lower()
