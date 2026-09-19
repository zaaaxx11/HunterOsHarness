"""Tool-call validation — Reference agent_turn_tool_validation port (narrowed).

WHY: hallucinated names, duplicate ids, and malformed JSON must recover
without voiding real work or breaking role alternation (assistant/tool
only, never a user message). Verdicts: ok dispatches all; continue /
continue-partial feed tool-role errors back; return / return-partial stop
as a partial exit. Strikes advance only on all-invalid turns.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ValidationVerdict", "validate_tool_calls"]

_MAX_STRIKES = 3
_MAX_JSON_RETRIES = 3


@dataclass
class ValidationVerdict:
    """Outcome of validate_tool_calls (mutates ids/names in place)."""

    action: str  # ok | continue | continue-partial | return | return-partial
    dispatch_names: list[str] = field(default_factory=list)
    invalid_strikes: int = 0
    error_results: list[tuple[str, str]] = field(default_factory=list)
    exit_summary: str = ""
    repair_marker: str = ""
    truncated_refused: bool = False
    json_retries: int = 0
    recovery_messages: list[dict[str, Any]] = field(default_factory=list)


def _call_id(call: Any, fallback: str) -> str:
    """Tool-call id across shapes (FakeCall.id / ToolCall.id)."""
    return str(getattr(call, "id", fallback))


def _call_name(call: Any) -> str:
    """Tool-call name across shapes (function.name / name)."""
    fn = getattr(call, "function", None)
    if fn is not None:
        return str(getattr(fn, "name", ""))
    return str(getattr(call, "name", ""))


def _call_args_raw(call: Any) -> Any:
    fn = getattr(call, "function", None)
    if fn is not None:
        return getattr(fn, "arguments", "{}")
    return getattr(call, "arguments", {})


def _set_call_name(call: Any, name: str) -> None:
    fn = getattr(call, "function", None)
    try:
        if fn is not None:
            fn.name = name
        else:
            call.name = name  # type: ignore[misc]
    except Exception:
        pass  # frozen provider shapes stay read-only; verdict still guides dispatch


def _set_call_args(call: Any, value: Any) -> None:
    fn = getattr(call, "function", None)
    try:
        if fn is not None:
            fn.arguments = value
        else:
            call.arguments = value  # type: ignore[misc]
    except Exception:
        pass


def _uniquify_ids(tool_calls: list[Any]) -> None:
    """Uniquify duplicate tool-call ids BEFORE any downstream consumer."""
    import contextlib

    seen: set[str] = set()
    for index, call in enumerate(tool_calls):
        call_id = _call_id(call, f"c-{index}")
        if call_id not in seen:
            seen.add(call_id)
            continue
        suffix = 1
        candidate = f"{call_id}-dup{suffix}"
        while candidate in seen:
            suffix += 1
            candidate = f"{call_id}-dup{suffix}"
        with contextlib.suppress(Exception):
            call.id = candidate  # type: ignore[misc]
        seen.add(candidate)


def _repair_name(name: str, valid_names: frozenset[str]) -> str | None:
    """Auto-repair a hallucinated name via close-match; None when no repair."""
    if name in valid_names:
        return None
    matches = difflib.get_close_matches(name, sorted(valid_names), n=1, cutoff=0.6)
    return matches[0] if matches else None


def _looks_truncated(raw: str) -> bool:
    """True when invalid JSON looks cut off mid-stream (refuse, never retry)."""
    stripped = (raw or "").strip()
    if not stripped or stripped.endswith(("}", "]")):
        return False
    has_key = '":' in stripped or "':" in stripped or (":" in stripped and '"' in stripped)
    return stripped.startswith("{") and has_key


def validate_tool_calls(
    assistant_message: Any,
    valid_names: frozenset[str] | set[str] | list[str],
    state: dict[str, Any] | None = None,
) -> ValidationVerdict:
    """Validate assistant tool calls in place; see module docstring."""
    valid = frozenset(valid_names)
    owned_state: dict[str, Any] = state if state is not None else {}
    tool_calls: list[Any] = list(getattr(assistant_message, "tool_calls", []) or [])

    _uniquify_ids(tool_calls)

    repairs: list[str] = []
    for call in tool_calls:
        name = _call_name(call)
        if name not in valid:
            repaired = _repair_name(name, valid)
            if repaired:
                repairs.append(f"{name}->{repaired}")
                _set_call_name(call, repaired)
    repair_marker = "; ".join(repairs)

    invalid = [c for c in tool_calls if _call_name(c) not in valid]
    valid_calls = [c for c in tool_calls if _call_name(c) in valid]

    if invalid and valid_calls:
        errors = [(_call_id(c, "c-?"), f"unknown tool '{_call_name(c)}'") for c in invalid]
        return ValidationVerdict(
            action="continue-partial",
            dispatch_names=[_call_name(c) for c in valid_calls],
            invalid_strikes=0,
            error_results=errors,
            repair_marker=repair_marker,
        )
    if invalid:
        strikes = int(owned_state.get("invalid_strikes", 0)) + 1
        owned_state["invalid_strikes"] = strikes
        if strikes >= _MAX_STRIKES:
            return ValidationVerdict(
                action="return",
                dispatch_names=[],
                invalid_strikes=strikes,
                error_results=[(_call_id(c, "c-?"), f"unknown tool '{_call_name(c)}'") for c in invalid],
                exit_summary="partial: 3 invalid tool-name strikes exceeded",
                repair_marker=repair_marker,
            )
        return ValidationVerdict(
            action="continue",
            dispatch_names=[],
            invalid_strikes=strikes,
            error_results=[(_call_id(c, "c-?"), f"unknown tool '{_call_name(c)}'") for c in invalid],
            repair_marker=repair_marker,
        )

    owned_state["invalid_strikes"] = 0 if state is not None else owned_state.get("invalid_strikes", 0)

    bad_json: list[tuple[Any, str]] = []
    truncated = False
    for call in tool_calls:
        raw = _call_args_raw(call)
        if isinstance(raw, dict):
            continue
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            _set_call_args(call, "{}")
            continue
        if not isinstance(raw, str):
            raw = str(raw)
            _set_call_args(call, raw)
        try:
            json.loads(raw)
        except json.JSONDecodeError as exc:
            if _looks_truncated(raw):
                truncated = True
            else:
                bad_json.append((call, str(exc)))

    if truncated:
        return ValidationVerdict(
            action="continue",
            dispatch_names=[],
            invalid_strikes=int(owned_state.get("invalid_strikes", 0)),
            error_results=[(_call_id(c, "c-?"), "truncated arguments refused") for c in tool_calls],
            truncated_refused=True,
            json_retries=0,
            repair_marker=repair_marker,
        )

    if bad_json:
        retries = int(owned_state.get("json_retries", 0)) + 1
        owned_state["json_retries"] = retries
        if retries < _MAX_JSON_RETRIES:
            return ValidationVerdict(
                action="continue",
                dispatch_names=[],
                json_retries=retries,
                repair_marker=repair_marker,
            )
        recovery: list[dict[str, Any]] = [
            {"role": "assistant", "content": "recovery: invalid JSON arguments"}
        ]
        for call, err in bad_json:
            recovery.append(
                {
                    "role": "tool",
                    "tool_call_id": _call_id(call, "c-?"),
                    "content": f"Error: Invalid JSON arguments. {err}. Please retry with valid JSON.",
                }
            )
        # Close any valid-call tail so every call keeps a matching result.
        for call in tool_calls:
            pending = [m.get("tool_call_id") for m in recovery if m.get("role") == "tool"]
            if _call_id(call, "c-?") not in [str(v) for v in pending]:
                recovery.append(
                    {
                        "role": "tool",
                        "tool_call_id": _call_id(call, "c-?"),
                        "content": "Skipped: other tool call in this response had invalid JSON.",
                    }
                )
        return ValidationVerdict(
            action="return-partial",
            dispatch_names=[],
            json_retries=retries,
            recovery_messages=recovery,
            exit_summary="partial: invalid JSON arguments after 3 retries",
            repair_marker=repair_marker,
        )

    owned_state["json_retries"] = 0 if state is not None else owned_state.get("json_retries", 0)
    return ValidationVerdict(
        action="ok",
        dispatch_names=[_call_name(c) for c in tool_calls],
        invalid_strikes=int(owned_state.get("invalid_strikes", 0)),
        json_retries=int(owned_state.get("json_retries", 0)),
        repair_marker=repair_marker,
    )
