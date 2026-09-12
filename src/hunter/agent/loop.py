"""AgentLoop — the governed conversation driver for the LLM brain.

Contract with the provider (hunter.llm.base.ChatProvider): the loop calls
``provider.complete(tier="planner", messages, tools=..., stream_cb=...,
budget=...)`` and consumes :class:`TurnResult`. Message format is the
OpenAI-style dict contract documented in ``hunter/llm/base.py``; assistant
tool_calls are appended as ``{"id", "name", "arguments"}`` (arguments kept as
the parsed dict from ToolCall).

Contract with tools (hunter.agent.tools): a handler returns a ToolOutcome.
When ``outcome.evidence`` is set (a single ``{"kind","data"}`` dict or a LIST
of them) the loop — not the handler — persists each artifact via
``ledger.add_evidence`` (deep-redaction + hash chain apply below the loop),
emits ``evidence_stored`` with the new id, and appends
``evidence_id: EV-xxxx`` lines to the tool message in artifact order. BLOCKED
outcomes are fed back verbatim: the model reads its refusals.

Termination states (AgentRunResult):
- ``yield_message``  — respond_to_user was called (turn-level yield; the chat
  layer continues the conversation later by calling run() again on a fresh
  loop instance with more user input).
- ``finished``       — finish_scan was called, the budget ran out, or the
  loop stalled (too many plain-text turns).
- ``interrupted``    — interrupt_check() returned True (checked before each
  provider call and each tool dispatch); an ``error`` event is emitted so the
  ledger shows the abort.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunter.errors import HunterError
from hunter.llm.base import ChatProvider, RunBudget

from .prompts import build_system_prompt, load_skills_index
from .tools_base import TIER_ORDER, ToolContext, ToolRegistry

__all__ = ["AgentLoop", "AgentRunResult"]


def _budget_governed(budget: Any) -> bool:
    """True when ``budget`` implements its own exhausted()/add_cost() — i.e.
    it is a concrete budget like hunter.llm.budget.RunBudget rather than the
    bare base-contract dataclass (whose exhausted() is a docstring-only stub
    returning None and whose add_cost raises NotImplementedError)."""
    klass = type(budget)
    exhausted_overridden = getattr(klass, "exhausted", None) is not RunBudget.__dict__["exhausted"]
    add_cost_overridden = getattr(klass, "add_cost", None) is not RunBudget.__dict__["add_cost"]
    return exhausted_overridden and add_cost_overridden


@dataclass
class AgentRunResult:
    """Outcome of one audit turn-sequence. Consumed by the chat layer (B7)."""

    yield_message: str | None = None  # respond_to_user payload (turn-level yield)
    finished: bool = False  # finish_scan / budget / stall
    stalled: bool = False  # finished because the model stopped calling tools
    interrupted: bool = False  # interrupt_check fired
    summary: str = ""  # last tool result or stop reason (bounded text)
    stats: dict[str, Any] = field(default_factory=dict)
    # stats keys: turns, cost_usd, tokens_in, tokens_out, tool_calls,
    # evidence_stored


class AgentLoop:
    """Drive provider turns and tool dispatch until a lifecycle outcome."""

    def __init__(
        self,
        provider: ChatProvider,
        registry: ToolRegistry,
        *,
        tier: str = "basic",
        budget: RunBudget | None = None,
        max_text_nudges: int = 3,
        interrupt_check: Callable[[], bool] | None = None,
    ) -> None:
        if tier not in TIER_ORDER:
            raise ValueError(f"unknown tier {tier!r} (use basic|advanced)")
        self.provider = provider
        self.registry = registry
        self.tier = tier
        self.budget = budget if budget is not None else RunBudget()
        # Budget governance split (see _budget_governed): a CONCRETE budget
        # (hunter.llm.budget.RunBudget) governs spend itself — the provider
        # contract has the router call add_cost() — while the bare
        # base-contract dataclass gets loop-side accounting so tests and
        # naive providers still exhaust on cost/iterations.
        self._budget_governed = _budget_governed(self.budget)
        self.max_text_nudges = max(1, int(max_text_nudges))
        self.interrupt_check = interrupt_check

    # -- public API ------------------------------------------------------------

    def run(self, ctx: ToolContext, goal: str, *, stream_cb=None) -> AgentRunResult:
        """Run one audit turn-sequence against ``ctx`` until it ends."""
        stats: dict[str, Any] = {
            "turns": 0,
            "cost_usd": 0.0,
            "tokens_in": 0,
            "tokens_out": 0,
            "tool_calls": 0,
            "evidence_stored": 0,
        }
        skills_index = ctx.config.get("skills_index")
        if skills_index is None:
            skills_index = load_skills_index()
        system = build_system_prompt(
            target_url=ctx.target_url,
            scope_summary=ctx.scope.summary(),
            tier=self.tier,
            skills_index=str(skills_index),
            config_note=str(ctx.config.get("config_note", "")),
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": goal},
        ]
        self._arm_budget()
        nudges = 0

        while True:
            if self._interrupted(ctx):
                return AgentRunResult(interrupted=True, stats=stats)
            exhausted = self._budget_reason()
            if exhausted is not None:
                return AgentRunResult(
                    finished=True, summary=f"stopped: budget exhausted ({exhausted})", stats=stats
                )

            try:
                turn = self.provider.complete(
                    "planner",
                    messages,
                    tools=self.registry.schemas_for_tier(self.tier),
                    stream_cb=stream_cb,
                    budget=self.budget,
                )
            except HunterError as exc:
                if exc.code == "budget.exhausted":
                    # A governed budget (router raises when exhausted) is a
                    # NORMAL wind-down, not a crashed run.
                    return AgentRunResult(
                        finished=True, summary=f"stopped: {exc.user_message()}", stats=stats
                    )
                raise
            self.budget.iterations_used += 1  # the loop owns iteration counting
            if not self._budget_governed:  # governed budgets get add_cost from the provider
                self.budget.spent_usd += turn.cost_usd
            stats["turns"] += 1
            stats["cost_usd"] += turn.cost_usd
            stats["tokens_in"] += turn.input_tokens
            stats["tokens_out"] += turn.output_tokens
            ctx.emit(
                "engine_event",
                {
                    "stage": "agent_turn",
                    "turn": stats["turns"],
                    "cost_usd": turn.cost_usd,
                    "tokens_in": turn.input_tokens,
                    "tokens_out": turn.output_tokens,
                    "tool_calls": len(turn.tool_calls),
                },
            )

            if turn.error_surface is not None:
                messages.append({"role": "assistant", "content": turn.text or ""})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"[provider error {turn.error_surface.get('code', 'unknown')}] "
                            f"{turn.error_surface.get('message', '')} "
                            "Continue the audit with exactly one tool call."
                        ),
                    }
                )
                continue

            assistant: dict[str, Any] = {"role": "assistant", "content": turn.text}
            if turn.tool_calls:
                assistant["tool_calls"] = [
                    {"id": call.id, "name": call.name, "arguments": call.arguments}
                    for call in turn.tool_calls
                ]
            messages.append(assistant)

            if not turn.tool_calls:
                nudges += 1
                if nudges > self.max_text_nudges:
                    return AgentRunResult(
                        finished=True,
                        stalled=True,
                        summary="stalled: no lifecycle tool called",
                        stats=stats,
                    )
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Plain text never ends an audit turn. Call exactly one tool. "
                            f"Recovery attempt {nudges}/{self.max_text_nudges}."
                        ),
                    }
                )
                continue

            stats["tool_calls"] += len(turn.tool_calls)
            yield_message: str | None = None
            finished_summary: str | None = None
            for call in turn.tool_calls:
                if self._interrupted(ctx):
                    return AgentRunResult(interrupted=True, stats=stats)
                parsed, format_error = self._parse_arguments(call)
                if format_error is not None:
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": f"[format_error] {format_error}",
                        }
                    )
                    continue
                outcome = self.registry.dispatch(call.name, parsed, ctx)
                content = outcome.result_for_model
                if outcome.evidence is not None:
                    evidence_ids = self._store_evidence(ctx, call.name, outcome.evidence)
                    stats["evidence_stored"] += len(evidence_ids)
                    content = content + "\n" + "\n".join(f"evidence_id: {eid}" for eid in evidence_ids)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
                if outcome.lifecycle_yield is not None:
                    yield_message = outcome.lifecycle_yield
                if outcome.lifecycle_finish:
                    finished_summary = outcome.result_for_model
            if yield_message is not None:
                return AgentRunResult(yield_message=yield_message, finished=False, stats=stats)
            if finished_summary is not None:
                return AgentRunResult(finished=True, summary=finished_summary, stats=stats)

    # -- internals -------------------------------------------------------------

    @staticmethod
    def _parse_arguments(call) -> tuple[dict[str, Any] | None, str | None]:
        """Tool-call argument safety: accept the parsed dict contract and
        recover from raw JSON strings; everything else is a format error that
        goes back to the model."""
        args = call.arguments
        if isinstance(args, dict):
            return args, None
        if isinstance(args, str):
            try:
                parsed = json.loads(args)
            except json.JSONDecodeError as exc:
                return None, f"tool arguments were not valid JSON ({exc})."
            if not isinstance(parsed, dict):
                return None, "tool arguments must decode to a JSON object."
            return parsed, None
        return None, f"unsupported arguments type {type(args).__name__}."

    @staticmethod
    def _store_evidence(ctx: ToolContext, tool_name: str, evidence: Any) -> list[str]:
        """Persist handler-declared evidence (dict or list of dicts) through
        the ledger and emit one attribution event per artifact."""
        artifacts = evidence if isinstance(evidence, list) else [evidence]
        ids: list[str] = []
        for artifact in artifacts:
            kind = str(artifact.get("kind", "http_exchange"))
            data = dict(artifact.get("data") or {})
            evidence_id = ctx.ledger.add_evidence(ctx.run_id, kind, data)
            ctx.emit(
                "evidence_stored",
                {"evidence_id": evidence_id, "kind": kind, "tool": tool_name},
            )
            ids.append(evidence_id)
        return ids

    def _interrupted(self, ctx: ToolContext) -> bool:
        if self.interrupt_check is None:
            return False
        try:
            fired = bool(self.interrupt_check())
        except Exception:  # a broken check must not kill the run  # noqa: BLE001
            return False
        if fired:
            ctx.emit("error", {"stage": "agent_loop", "reason": "interrupted"})
        return fired

    def _arm_budget(self) -> None:
        """Anchor the wall clock once per run, using the concrete budget's
        start() when available (thread-safe) or the bare field."""
        if self._budget_governed:
            start = getattr(self.budget, "start", None)
            if callable(start):
                start()
                return
        if self.budget.started_monotonic == 0:
            self.budget.started_monotonic = time.monotonic()

    def _budget_reason(self) -> str | None:
        """Human reason when the run must wind down, else None.

        Governed budgets (concrete exhausted() implementation, e.g. B5's
        hunter.llm.budget.RunBudget) are authoritative for cost, iterations
        and wall clock — the router also calls add_cost() on them, which is
        why the loop never mutates their spend. The bare base-contract
        dataclass (docstring-only methods) is governed by field math here.
        """
        if self._budget_governed:
            return self.budget.exhausted()
        budget = self.budget
        if budget.iterations_used >= budget.max_iterations:
            return f"iterations {budget.iterations_used}/{budget.max_iterations}"
        if budget.spent_usd >= budget.max_cost_usd:
            return f"cost ${budget.spent_usd:.2f} >= ${budget.max_cost_usd:.2f}"
        if budget.started_monotonic:
            elapsed = time.monotonic() - budget.started_monotonic
            if elapsed > budget.wall_seconds:
                return "wall clock"
        return None
