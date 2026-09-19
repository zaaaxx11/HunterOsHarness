"""Pure guardrail controller — Hermes agent_tool_guardrails port (narrowed).

WHY: looping models (exact-args replay, same-tool thrash, identical-result
stalls, tight A/B cycles, runaway web/probe caps) must halt as a partial
with an engine_event, never crash. The controller is side-effect free: it
returns decisions; runtime code decides warn vs halt. Attended surfaces
warn where unattended halts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = ["GuardrailDecision", "GuardrailController"]

_EXACT_FAIL_BLOCK_AFTER = 5
_SAME_TOOL_HALT_AFTER = 8
_TOLERANT_SAME_TOOL_HALT_AFTER = 100
_IDENTICAL_NOTICE_AFTER = 3
_IDENTICAL_HALT_AFTER = 5
_CYCLE_NOTICE_LAPS = 3
_MAX_CYCLE_PERIOD = 4
_HISTORY_WINDOW = 64

_FAILURE_TOLERANT = frozenset({"terminal", "execute_code", "process_manage", "process"})

_CAP_LIMITS: dict[str, int] = {
    "web_search": 50,
    "web_fetch": 50,
    "web_extract": 50,
    "http_request": 200,
    "probe": 50,
}


@dataclass
class GuardrailDecision:
    """Side-effect-free decision for one observation."""

    action: str  # allow | notice | warn | block | halt
    code: str = ""
    signature: tuple[str, str] | None = None
    cycle_period: int | None = None
    engine_event: dict[str, Any] = field(default_factory=dict)
    partial_break: bool = False


def _args_key(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, default=str)


class GuardrailController:
    """Track observations; return decisions (no side effects)."""

    def __init__(self, attended: bool = False) -> None:
        self.attended = bool(attended)
        self._exact_fail: dict[tuple[str, str], int] = {}
        self._tool_fail: dict[str, int] = {}
        self._identical: dict[tuple[str, str, str], int] = {}
        self._totals: dict[str, int] = {}
        self._history: list[str] = []

    def note_progress(self, tool: str, args: dict[str, Any]) -> None:
        """A successful edit makes the next retry a new experiment: reset fails."""
        _ = (tool, args)
        self._exact_fail.clear()
        self._tool_fail.clear()
        self._identical.clear()

    def observe(self, tool: str, args: dict[str, Any], result: str, ok: bool = False) -> GuardrailDecision:
        name = str(tool)
        key = _args_key(args or {})
        self._totals[name] = self._totals.get(name, 0) + 1
        self._history.append(name)
        if len(self._history) > _HISTORY_WINDOW:
            self._history = self._history[-_HISTORY_WINDOW:]

        cap = self._check_cap(name)
        if cap is not None:
            return cap
        cycle = self._check_cycle()
        if cycle is not None:
            return cycle

        ident_decision = None
        if ok:
            ident_key = (name, key, str(result))
            self._identical[ident_key] = self._identical.get(ident_key, 0) + 1
            ident_count = self._identical[ident_key]
            ident_decision = self._identical_decision(ident_count)
        if ident_decision is not None:
            return ident_decision

        if not ok:
            sig = (name, key)
            self._exact_fail[sig] = self._exact_fail.get(sig, 0) + 1
            self._tool_fail[name] = self._tool_fail.get(name, 0) + 1
            same_count = self._tool_fail[name]
            limit = _TOLERANT_SAME_TOOL_HALT_AFTER if name in _FAILURE_TOLERANT else _SAME_TOOL_HALT_AFTER
            if same_count >= limit:
                return self._halt(f"same_tool_failure:{name}")
            if self._exact_fail[sig] >= _EXACT_FAIL_BLOCK_AFTER:
                return GuardrailDecision(
                    action="block",
                    code="exact_failure",
                    signature=sig,
                )
        return GuardrailDecision(action="allow", code="ok")

    def _check_cap(self, name: str) -> GuardrailDecision | None:
        limit = _CAP_LIMITS.get(name)
        if limit is None or self._totals.get(name, 0) <= limit:
            return None
        if self.attended:
            return GuardrailDecision(action="warn", code=f"cap.{name}")
        return self._halt(f"cap.{name}")

    def _identical_decision(self, count: int) -> GuardrailDecision | None:
        if count >= _IDENTICAL_HALT_AFTER:
            return self._halt("identical_result")
        if count >= _IDENTICAL_NOTICE_AFTER:
            return GuardrailDecision(action="notice", code="identical_result")
        return None

    def _check_cycle(self) -> GuardrailDecision | None:
        hist = self._history
        for period in range(2, _MAX_CYCLE_PERIOD + 1):
            need = period * _CYCLE_NOTICE_LAPS
            if len(hist) < need:
                continue
            window = hist[-need:]
            pattern = window[:period]
            if len(set(pattern)) < 2:
                continue
            if all(window[i * period:(i + 1) * period] == pattern for i in range(_CYCLE_NOTICE_LAPS)):
                return GuardrailDecision(action="notice", code="cycle", cycle_period=period)
        return None

    def _halt(self, code: str) -> GuardrailDecision:
        if self.attended:
            return GuardrailDecision(action="warn", code=code)
        return GuardrailDecision(
            action="halt",
            code=code,
            engine_event={"stage": "guardrail_halt", "code": code},
            partial_break=True,
        )
