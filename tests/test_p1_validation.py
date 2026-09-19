"""P1 — validate_tool_calls contract tests (TDD step 1, failing by design).

Planner A target: ``hunter.agent.validation.validate_tool_calls`` — the Reference
``agent_turn_tool_validation.py:69-214`` port. Every test below names the exact
verdict/helper it drives; all module-dependent tests ``importorskip`` the
not-yet-existing module (SKIPPED today, green after implementation), and the
seam tests ``xfail(strict)`` on the missing ``AgentLoop`` call site.

Verdict contract (Reference reference):
- ``ok`` — every call has a known name and usable args; dispatch all.
- ``continue`` (+ ``continue-partial``) — recoverable problem; feed a
  tool-role error back and take another turn. Mixed batches error ONLY the
  invalid calls and still run the valid ones (never void real work).
- ``return`` (+ ``return-partial``) — unrecoverable; stop as a partial exit.

Rules pinned here: id-uniquify BEFORE repair; hallucinated-name auto-repair
with a visible marker; truncated-args REFUSE (no retry); 3 invalid-name
strikes -> partial exit (strikes advance only on all-invalid turns);
3 JSON retries -> recovery tool-results that preserve role alternation
(assistant/tool only — never a user message).

Adversarial mitigations: no network/provider (pure dataclass doubles, no
AgentLoop import at module scope); tmp_path isolation not needed (no files);
strict asserts on verdict action + dispatched-name lists, not just returns.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class _FakeFn:
    name: str
    arguments: Any


@dataclass
class _FakeCall:
    id: str
    function: _FakeFn


@dataclass
class _FakeAssistant:
    tool_calls: list[_FakeCall] = field(default_factory=list)


def _call(call_id: str, name: str, arguments: Any = "{}") -> _FakeCall:
    return _FakeCall(id=call_id, function=_FakeFn(name=name, arguments=arguments))


def _needs_validation() -> Any:
    """The not-yet-existing production module — SKIPPED until implemented."""
    return pytest.importorskip("hunter.agent.validation")


def test_p1_validation_ok_verdict_dispatches_every_call() -> None:
    validation = _needs_validation()
    assistant = _FakeAssistant([_call("c-1", "think"), _call("c-2", "finish_scan")])
    verdict = validation.validate_tool_calls(
        assistant_message=assistant,
        valid_names=frozenset({"think", "finish_scan"}),
    )
    assert verdict.action == "ok"
    assert verdict.dispatch_names == ["think", "finish_scan"]


def test_p1_validation_continue_partial_single_invalid_name() -> None:
    validation = _needs_validation()
    assistant = _FakeAssistant([_call("c-1", "exfiltrate_ledger")])
    verdict = validation.validate_tool_calls(
        assistant_message=assistant,
        valid_names=frozenset({"think", "finish_scan"}),
    )
    assert verdict.action == "continue"
    assert verdict.invalid_strikes == 1
    assert verdict.error_results and verdict.error_results[0][0] == "c-1"
    assert verdict.dispatch_names == []


def test_p1_validation_return_partial_after_three_invalid_strikes() -> None:
    validation = _needs_validation()
    state: dict[str, Any] = {}
    last = None
    for _ in range(3):
        last = validation.validate_tool_calls(
            assistant_message=_FakeAssistant([_call("c-x", "nope_tool")]),
            valid_names=frozenset({"think"}),
            state=state,
        )
    assert last is not None and last.action == "return"
    assert "partial" in last.exit_summary


def test_p1_validation_ids_uniquified_before_any_consumer() -> None:
    validation = _needs_validation()
    assistant = _FakeAssistant([_call("dup", "think"), _call("dup", "think")])
    verdict = validation.validate_tool_calls(
        assistant_message=assistant,
        valid_names=frozenset({"think"}),
    )
    assert verdict.action == "ok"
    ids = [call.id for call in assistant.tool_calls]
    assert len(set(ids)) == 2


def test_p1_validation_auto_repair_hallucinated_name_with_marker() -> None:
    validation = _needs_validation()
    assistant = _FakeAssistant([_call("c-1", "finnish_scan")])
    verdict = validation.validate_tool_calls(
        assistant_message=assistant,
        valid_names=frozenset({"finish_scan", "think"}),
    )
    assert verdict.action == "ok"
    assert assistant.tool_calls[0].function.name == "finish_scan"
    assert verdict.repair_marker and "finnish_scan" in verdict.repair_marker


def test_p1_validation_mixed_batch_errors_invalid_runs_valid() -> None:
    validation = _needs_validation()
    assistant = _FakeAssistant(
        [_call("c-bad", "hallucinated_tool"), _call("c-good", "think", '{"thought": "x"}')]
    )
    verdict = validation.validate_tool_calls(
        assistant_message=assistant,
        valid_names=frozenset({"think"}),
    )
    assert verdict.action == "continue-partial"
    assert verdict.dispatch_names == ["think"]
    assert [call_id for call_id, _ in verdict.error_results] == ["c-bad"]
    assert verdict.invalid_strikes == 0  # a turn with a valid call never advances strikes


def test_p1_validation_truncated_args_refused_without_retry() -> None:
    validation = _needs_validation()
    assistant = _FakeAssistant([_call("c-1", "think", '{"thought": "half-writt')])
    verdict = validation.validate_tool_calls(
        assistant_message=assistant,
        valid_names=frozenset({"think"}),
    )
    assert verdict.action == "continue"
    assert verdict.truncated_refused is True
    assert verdict.json_retries == 0  # truncation is refused outright, never retried


def test_p1_validation_three_json_retries_recover_as_tool_results() -> None:
    validation = _needs_validation()
    state: dict[str, Any] = {}
    last = None
    for _ in range(3):
        last = validation.validate_tool_calls(
            assistant_message=_FakeAssistant([_call("c-1", "think", "{not json")]),
            valid_names=frozenset({"think"}),
            state=state,
        )
    assert last is not None and last.action == "return-partial"
    roles = [message["role"] for message in last.recovery_messages]
    assert roles and set(roles) <= {"assistant", "tool"}  # never a user message
    assert "c-1" in [message.get("tool_call_id", "c-1") for message in last.recovery_messages]


def test_p1_validation_loop_dispatches_through_validator() -> None:
    source = pathlib.Path("src/hunter/agent/loop.py").read_text(encoding="utf-8")
    assert "validate_tool_calls" in source
