"""P0 — hook registry + AgentLoop seam contract tests (TDD step 1, GATE for P1-P4).

Planner A target: ``hunter.agent.hooks`` (hook registry: ``pre_turn`` /
``post_tool`` / ``post_turn`` / ``on_blocked`` / ``on_budget`` /
``on_interrupt``) plus the ``AgentLoop.run`` call sites. NOTHING downstream
(P1 validation/guardrails/budget, P2 lease/ESTOP, P3 parallel, P4 cron) can
land without these seams, so this file gates the whole build order.

Contracts:
- registry defaults are no-ops (a fresh loop behaves EXACTLY like today).
- call sites exist: pre_turn (before each provider call), post_tool (after
  each dispatch), post_turn (after each turn), on_blocked (on BLOCKED
  outcomes), on_interrupt (on interrupt_check firing).
- hook exceptions FAIL CLOSED (refuse / continue / break per hook spec) and
  NEVER crash the run.
- persist-before-execute: intent rows are stored before dispatch; a
  persist failure BREAKS the run with ZERO dispatches.

Adversarial mitigations: seam tests assert literal call-site markers in
``src/hunter/agent/loop.py`` (xfail strict — they fail red-today as XFAIL,
never green-by-accident); behavior tests importorskip the missing registry;
no network/clock/threads involved.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest


def _needs_hooks() -> Any:
    """The not-yet-existing production module — SKIPPED until implemented."""
    return pytest.importorskip("hunter.agent.hooks")


def _loop_source() -> str:
    return pathlib.Path("src/hunter/agent/loop.py").read_text(encoding="utf-8")


def test_p0_hooks_registry_defaults_are_noops() -> None:
    hooks = _needs_hooks()
    registry = hooks.HookRegistry()
    assert registry.pre_turn("ctx", []) is None
    assert registry.post_tool("ctx", "think", {}, None) is None
    assert registry.post_turn("ctx", []) is None
    assert registry.on_blocked("ctx", None) == "continue"
    assert registry.on_budget("ctx", None) is None
    assert registry.on_interrupt("ctx") == "break"


def test_p0_hooks_pre_turn_call_site() -> None:
    assert "pre_turn" in _loop_source()


def test_p0_hooks_post_tool_call_site() -> None:
    assert "post_tool" in _loop_source()


def test_p0_hooks_post_turn_call_site() -> None:
    assert "post_turn" in _loop_source()


def test_p0_hooks_on_blocked_call_site() -> None:
    assert "on_blocked" in _loop_source()


def test_p0_hooks_on_interrupt_call_site() -> None:
    assert "on_interrupt" in _loop_source()


def test_p0_hooks_exception_fail_closed_never_crashes_run() -> None:
    hooks = _needs_hooks()

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("hook blew up")

    registry = hooks.HookRegistry(pre_turn=boom, post_tool=boom, post_turn=boom,
                                  on_blocked=boom, on_interrupt=boom)
    assert registry.safe_pre_turn("ctx", []) == "continue"  # fail closed, run survives
    assert registry.safe_post_tool("ctx", "think", {}, None) == "continue"
    assert registry.safe_on_blocked("ctx", None) == "continue"
    assert registry.safe_on_interrupt("ctx") == "break"


def test_p0_hooks_persist_fail_breaks_with_zero_dispatches() -> None:
    hooks = _needs_hooks()

    def failing_store(intent: Any) -> None:
        raise OSError("disk full")

    recorder = hooks.IntentRecorder(store=failing_store)
    outcome = recorder.record_before_execute({"tool": "think", "args": {}})
    assert outcome.persisted is False
    assert outcome.dispatches == 0  # nothing ran
    assert outcome.run_break is True
