"""AgentLoop hook seams — no-op defaults that P1+ wiring fills in.

WHY: the loop needs stable seams (pre_turn / post_tool / post_turn /
on_blocked / on_budget / on_interrupt) so validation, guardrails, budget
advisories, and ESTOP can land without rewriting the run driver. Defaults
are no-ops so a fresh loop behaves EXACTLY like today; hook exceptions
fail closed (refuse / continue / break) and never crash the run.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "HookRegistry",
    "IntentRecorder",
    "IntentOutcome",
    "on_budget",
    "wrap_up",
    "refund_iteration",
    "should_stop",
]

# Tools admitted during wrap-up (>=85% spend): lifecycle + read-only probes.
_WRAP_UP_ALLOW = frozenset(
    {
        "finish_scan",
        "respond_to_user",
        "think",
        "http_request",
        "ledger_search",
        "note_list",
        "note_get",
        "note_search",
        "read_file",
        "web_search",
    }
)


@dataclass
class IntentOutcome:
    """Result of persist-before-execute recording."""

    persisted: bool
    dispatches: int
    run_break: bool


class IntentRecorder:
    """Persist-before-execute seam: intent rows stored before dispatch.

    WHY: a persist failure must BREAK the run with ZERO dispatches so no
    orphan intent rows execute without a ledger trail.
    """

    def __init__(self, store: Callable[[Any], None] | None = None) -> None:
        self._store = store

    def record_before_execute(self, intent: Any) -> IntentOutcome:
        if self._store is None:
            return IntentOutcome(persisted=True, dispatches=1, run_break=False)
        try:
            self._store(intent)
        except Exception:
            logger.exception("intent persist failed; breaking run with zero dispatches")
            return IntentOutcome(persisted=False, dispatches=0, run_break=True)
        return IntentOutcome(persisted=True, dispatches=1, run_break=False)


class HookRegistry:
    """No-op hook defaults with fail-closed safe_* wrappers."""

    def __init__(
        self,
        pre_turn: Callable[..., Any] | None = None,
        post_tool: Callable[..., Any] | None = None,
        post_turn: Callable[..., Any] | None = None,
        on_blocked: Callable[..., Any] | None = None,
        on_budget: Callable[..., Any] | None = None,
        on_interrupt: Callable[..., Any] | None = None,
    ) -> None:
        self._pre_turn = pre_turn
        self._post_tool = post_tool
        self._post_turn = post_turn
        self._on_blocked = on_blocked
        self._on_budget = on_budget
        self._on_interrupt = on_interrupt

    def pre_turn(self, ctx: Any, messages: Any) -> Any:
        if self._pre_turn is None:
            return None
        return self._pre_turn(ctx, messages)

    def post_tool(self, ctx: Any, name: str, args: Any, outcome: Any) -> Any:
        if self._post_tool is None:
            return None
        return self._post_tool(ctx, name, args, outcome)

    def post_turn(self, ctx: Any, messages: Any) -> Any:
        if self._post_turn is None:
            return None
        return self._post_turn(ctx, messages)

    def on_blocked(self, ctx: Any, outcome: Any) -> str:
        if self._on_blocked is None:
            return "continue"
        result = self._on_blocked(ctx, outcome)
        return str(result) if result is not None else "continue"

    def on_budget(self, ctx: Any, info: Any) -> Any:
        if self._on_budget is None:
            return None
        return self._on_budget(ctx, info)

    def on_interrupt(self, ctx: Any) -> str:
        if self._on_interrupt is None:
            return "break"
        result = self._on_interrupt(ctx)
        return str(result) if result is not None else "break"

    def safe_pre_turn(self, ctx: Any, messages: Any) -> str:
        try:
            self.pre_turn(ctx, messages)
        except Exception:
            logger.exception("pre_turn hook failed closed")
            return "continue"
        return "continue"

    def safe_post_tool(self, ctx: Any, name: str, args: Any, outcome: Any) -> str:
        try:
            self.post_tool(ctx, name, args, outcome)
        except Exception:
            logger.exception("post_tool hook failed closed")
            return "continue"
        return "continue"

    def safe_post_turn(self, ctx: Any, messages: Any) -> str:
        try:
            self.post_turn(ctx, messages)
        except Exception:
            logger.exception("post_turn hook failed closed")
            return "continue"
        return "continue"

    def safe_on_blocked(self, ctx: Any, outcome: Any) -> str:
        try:
            return self.on_blocked(ctx, outcome)
        except Exception:
            logger.exception("on_blocked hook failed closed")
            return "continue"

    def safe_on_interrupt(self, ctx: Any) -> str:
        try:
            return self.on_interrupt(ctx)
        except Exception:
            logger.exception("on_interrupt hook failed closed")
            return "break"

    def safe_on_budget(self, ctx: Any, info: Any) -> Any:
        try:
            return self.on_budget(ctx, info)
        except Exception:
            logger.exception("on_budget hook failed closed")
            return None


def _budget_level_fired(text: str | None) -> str | None:
    """Map a cost_breakpoint() warning to its short level marker."""
    if not text:
        return None
    for level in (70, 85, 95):
        if f"[BUDGET {level}%]" in text:
            return f"[BUDGET {level}%]"
    return None


def on_budget(budget: Any, transcript: list[dict[str, Any]], provider: Any = None) -> str | None:
    """Surface one cost_breakpoint advisory as a TOOL-role message.

    WHY: advisories must reach the model without an extra provider turn
    (role alternation preserved, spend unchanged). Each 70/85/95 level
    fires once via the budget's warned_levels.
    """
    _ = provider  # accepted so call sites pass the provider; never used for extra turns.
    marker_fn = getattr(budget, "cost_breakpoint", None)
    if not callable(marker_fn):
        return None
    try:
        warning = marker_fn()
    except Exception:
        logger.exception("cost_breakpoint failed closed")
        return None
    marker = _budget_level_fired(warning)
    if marker is None:
        return None
    transcript.append({"role": "tool", "content": f"{marker} spend high — wind down"})
    return marker


def wrap_up(budget: Any, tool_name: str) -> bool:
    """True when in wrap-up (>=85%) and ``tool_name`` is still admitted."""
    try:
        limit = float(getattr(budget, "max_cost_usd", 0.0) or 0.0)
        spent = float(getattr(budget, "spent_usd", 0.0) or 0.0)
    except (TypeError, ValueError):
        return False
    if limit <= 0:
        return False
    if spent < limit * 0.85:
        return False
    return str(tool_name) in _WRAP_UP_ALLOW


def refund_iteration(budget: Any, housekeeping_only: bool = False) -> None:
    """Refund one iteration for housekeeping-only rounds; real work never."""
    if not housekeeping_only:
        return
    fn = getattr(budget, "refund_iteration", None)
    if callable(fn):
        fn()


def should_stop(budget: Any) -> str | None:
    """Loop-seam stop check: the budget's exhausted() (stop file first)."""
    fn = getattr(budget, "exhausted", None)
    if not callable(fn):
        return None
    try:
        return fn()
    except Exception:
        logger.exception("budget exhausted check failed closed")
        return None
