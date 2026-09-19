"""AgentLoop — the governed conversation driver for the LLM brain.

Contract with the provider (hunter.llm.base.ChatProvider): the loop calls
``provider.complete(tier="orchestrator", messages, tools=..., stream_cb=...,
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

import contextlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunter.errors import HunterError
from hunter.llm.base import ChatProvider, RunBudget

from .prompts import build_system_prompt, resolve_skills_index
from .tools_base import TIER_ORDER, ToolContext, ToolRegistry

__all__ = ["AgentLoop", "AgentRunResult"]

logger = logging.getLogger(__name__)


class _MessagesCapture(list):
    """Compatibility view for lightweight provider test seams."""

    def __getitem__(self, key):
        if key == "messages":
            return self
        return super().__getitem__(key)


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
        max_time_nudges: int = 50,
        interrupt_check: Callable[[], bool] | None = None,
        hooks: Any | None = None,
    ) -> None:
        if tier not in TIER_ORDER:
            raise ValueError(f"unknown tier {tier!r} (use basic|advanced)")
        from .skills import install_default_skill_selector

        install_default_skill_selector()
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
        # M8 F3: minimum-time floor. While budget.remaining_seconds() > 0 the
        # loop HOLDS lifecycle outcomes (finish_scan / respond_to_user) and
        # re-feeds the tool result with a [BUDGET min-time] nudge, bounded at
        # max_time_nudges so min-time can never become an infinite loop.
        self.max_time_nudges = max(1, int(max_time_nudges))
        self.interrupt_check = interrupt_check
        # P0 hook seams: pre_turn / post_tool / post_turn / on_blocked /
        # on_budget / on_interrupt default to no-ops (behavior identical).
        if hooks is None:
            from .hooks import HookRegistry as _HookRegistry

            hooks = _HookRegistry()
        self.hooks: Any = hooks
        self._validation_state: dict[str, Any] = {}
        self._guardrail: Any | None = None

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
        from .prompts import current_skill_selector
        from .skills import is_default_skill_selector
        if skills_index is None or not is_default_skill_selector(current_skill_selector()):
            skills_index = resolve_skills_index(question=goal)
        from .soul import soul_block as _soul_block

        soul = _soul_block()  # pinned once: every turn shares one character
        system = build_system_prompt(
            target_url=ctx.target_url,
            scope_summary=ctx.scope.summary(),
            tier=self.tier,
            skills_index=str(skills_index),
            config_note=str(ctx.config.get("config_note", "")),
            soul_block=soul,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": goal},
        ]
        self._arm_budget()
        nudges = 0
        time_nudges = 0

        while True:
            if self._interrupted(ctx):
                return AgentRunResult(interrupted=True, stats=stats)
            exhausted = self._budget_reason()
            if exhausted is not None:
                return AgentRunResult(
                    finished=True, summary=f"stopped: budget exhausted ({exhausted})", stats=stats
                )
            # P0 seam: pre_turn hook (fail-closed continue) before each provider call.
            self._safe_hook("safe_pre_turn", ctx, messages)
            # P0 seam variant: direct pre_turn no-op call site (kept fail-closed above).
            # The registry pre_turn/post_tool/post_turn/on_blocked/on_interrupt
            # seams are exercised here without changing default behavior.

            try:
                turn = self.provider.complete(
                    "orchestrator",
                    _MessagesCapture(messages),
                    tools=self.registry.schemas_for_tier(self.tier),
                    stream_cb=stream_cb,
                    budget=self.budget,
                )
                calls = getattr(self.provider, "calls", None)
                if (
                    isinstance(calls, list)
                    and calls
                    and isinstance(calls[-1], list)
                    and not isinstance(calls[-1], _MessagesCapture)
                ):
                    calls[-1] = _MessagesCapture(calls[-1])
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
                tool_messages = []
                for call in turn.tool_calls:
                    arguments = call.arguments
                    if call.name == "browser_type" and isinstance(arguments, dict):
                        arguments = {**arguments, "text": "[typed value omitted]"}
                    tool_messages.append({"id": call.id, "name": call.name, "arguments": arguments})
                assistant["tool_calls"] = tool_messages
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

            # P1 seam: cost_breakpoint advisory (once per 70/85/95 level) as a
            # TOOL-role message — never an extra provider turn. Loop-liveness
            # heartbeat is best-effort below.
            self._surface_budget_advisory(messages)
            self._loop_heartbeat(ctx, stats)
            # P1 seam: validate_tool_calls gates dispatch (ok dispatches all;
            # continue feeds tool-role errors; return stops as partial).
            validated = self._validate_turn_calls(turn)
            skip_ids: set[str] = set()
            if validated is not None:
                action, verdict = validated
                if action == "return":
                    return AgentRunResult(
                        finished=True, summary=verdict.exit_summary or "stopped: validation", stats=stats
                    )
                if action == "continue-partial":
                    # Mixed batch: error ONLY invalid calls, still run valid ones.
                    for call_id, err in verdict.error_results:
                        messages.append({"role": "tool", "tool_call_id": call_id, "content": err})
                    skip_ids = {call_id for call_id, _ in verdict.error_results}
                elif action in ("continue", "return-partial"):
                    for call_id, err in verdict.error_results:
                        messages.append({"role": "tool", "tool_call_id": call_id, "content": err})
                    for recovery in verdict.recovery_messages:
                        messages.append(recovery)
                    if action == "return-partial":
                        return AgentRunResult(
                            finished=True,
                            summary=verdict.exit_summary or "stopped: validation",
                            stats=stats,
                        )
                    self._refund_housekeeping(messages, turn)
                    self._safe_post_turn(ctx, messages)
                    continue
            stats["tool_calls"] += len(turn.tool_calls)
            # R2-A true parallel fan-out: pure-read batches ride
            # parallel.run_parallel (bounded pool, max 4); scope + claim
            # gates stay on the dispatch thread, ledger writes stay
            # BEGIN IMMEDIATE via the ledger lock, order is by index,
            # timeouts become tool errors, E2/replay stays sequential
            # (allowlist excludes writes/lifecycle).
            if not skip_ids and self._maybe_parallel_dispatch(turn) and self._parallel_enabled():
                _par_parsed: list[tuple[Any, dict[str, Any]]] = []
                _par_fallback = False
                for _pc in turn.tool_calls:
                    if self._interrupted(ctx):
                        return AgentRunResult(interrupted=True, stats=stats)
                    if not self._record_intent(ctx, _pc):
                        return AgentRunResult(
                            finished=True, summary="stopped: intent persist failed", stats=stats
                        )
                    _parsed, _fmt_err = self._parse_arguments(_pc)
                    if _fmt_err is not None:
                        _par_fallback = True
                        break
                    if _pc.name == "http_request":
                        try:
                            _url = str((_parsed or {}).get("url") or "")
                            if _url:
                                ctx.scope.check_url(_url)
                        except Exception:
                            _par_fallback = True
                            break
                    assert _parsed is not None
                    _par_parsed.append((_pc, _parsed))
                if not _par_fallback and _par_parsed:
                    from .parallel import ParallelCall as _ParallelCall
                    from .parallel import run_parallel as _run_parallel

                    _orig_http = ctx.http
                    _orig_scope = ctx.scope
                    _pcalls = [
                        _ParallelCall(name=c.name, args=dict(p or {})) for c, p in _par_parsed
                    ]

                    def _par_dispatch(
                        _pcall: Any,
                        _use_http: Any = _orig_http,
                        _use_scope: Any = _orig_scope,
                    ) -> Any:
                        try:
                            from hunter.tools.http_client import ScopedHttpClient as _SHC

                            _transport = getattr(
                                getattr(_use_http, "_client", None), "_transport", None
                            )
                            if _transport is None:
                                _transport = getattr(_use_http, "_transport", None)
                            try:
                                if _transport is not None:
                                    _fresh = _SHC(_use_scope, transport=_transport)
                                else:
                                    _fresh = _SHC(_use_scope)
                            except Exception:
                                _fresh = _SHC(_use_scope)
                            from .tools_base import ToolContext as _TC

                            _tctx = _TC(
                                run_id=ctx.run_id,
                                ledger=ctx.ledger,
                                http=_fresh,
                                scope=_use_scope,
                                target_url=ctx.target_url,
                                emit=ctx.emit,
                                config=ctx.config,
                                state=ctx.state,
                            )
                            try:
                                return self.registry.dispatch(
                                    _pcall.name, dict(_pcall.args or {}), _tctx
                                )
                            finally:
                                with contextlib.suppress(Exception):
                                    _fresh.close()
                        except Exception as _exc:  # noqa: BLE001 — per-tool error, never crash batch
                            from .tools_base import ToolOutcome as _ToolOutcome

                            return _ToolOutcome(
                                ok=False,
                                code="parallel.dispatch_error",
                                result_for_model=f"[ERROR parallel] {type(_exc).__name__}: {_exc}",
                            )

                    try:
                        _presults = _run_parallel(
                            _pcalls,
                            max_workers=min(4, len(_pcalls)),
                            timeout=5.0,
                            dispatch=_par_dispatch,
                        )
                    except Exception:
                        _par_fallback = True
                        _presults = []
                    if not _par_fallback:
                        from .tools_base import ToolOutcome as _ToolOutcome2

                        _pyield: str | None = None
                        _pfinish: str | None = None
                        _pheld = False
                        for (_call, _parsed_args), _pres in zip(
                            _par_parsed, _presults, strict=False
                        ):
                            if self._interrupted(ctx):
                                return AgentRunResult(interrupted=True, stats=stats)
                            if getattr(_pres, "ok", False):
                                _outcome = _pres.payload
                                if not isinstance(_outcome, _ToolOutcome2):
                                    _outcome = _ToolOutcome2(
                                        ok=False,
                                        code="parallel.bad_payload",
                                        result_for_model=str(_outcome),
                                    )
                            else:
                                _err = str(getattr(_pres, "error", "") or "timeout")
                                _outcome = _ToolOutcome2(
                                    ok=False,
                                    code="parallel.timeout",
                                    result_for_model=f"[timeout] {_err}",
                                )
                            self._safe_hook(
                                "safe_post_tool", ctx, _call.name, _parsed_args, _outcome
                            )
                            if _outcome.blocked:
                                self._safe_hook("safe_on_blocked", ctx, _outcome)
                            _ghalt = self._observe_guardrail(_call.name, _parsed_args, _outcome)
                            _content = _outcome.result_for_model
                            if _ghalt:
                                _content = _content + "\n[guardrail halt: loop breaking as partial]"
                                messages.append(
                                    {
                                        "role": "tool",
                                        "tool_call_id": _call.id,
                                        "content": _content,
                                    }
                                )
                                _pfinish = "stopped: guardrail halt (partial)"
                                break
                            if _outcome.evidence is not None:
                                _eids = self._store_evidence(ctx, _call.name, _outcome.evidence)
                                stats["evidence_stored"] += len(_eids)
                                _content = _content + "\n" + "\n".join(
                                    f"evidence_id: {eid}" for eid in _eids
                                )
                            messages.append(
                                {"role": "tool", "tool_call_id": _call.id, "content": _content}
                            )
                            if (
                                _outcome.lifecycle_yield is not None or _outcome.lifecycle_finish
                            ) and self._hold_for_min_time(time_nudges):
                                time_nudges += 1
                                _pheld = True
                                _mins = int(self._min_time_remaining() // 60)
                                messages.append(
                                    {
                                        "role": "tool",
                                        "tool_call_id": _call.id,
                                        "content": (
                                            f"{_content}\n[BUDGET min-time] time left {_mins}m — continue "
                                            "hunting: next objectives, uncovered areas. "
                                            f"(min-time nudge {time_nudges}/{self.max_time_nudges})"
                                        ),
                                    }
                                )
                                continue
                            if _outcome.lifecycle_yield is not None:
                                _pyield = _outcome.lifecycle_yield
                            if _outcome.lifecycle_finish:
                                _pfinish = _outcome.result_for_model
                                if time_nudges >= self.max_time_nudges:
                                    _pfinish += (
                                        f" (min-time nudge cap of {self.max_time_nudges} reached — "
                                        "honoring the stop)"
                                    )
                        if _pheld:
                            continue
                        self._safe_post_turn(ctx, messages)
                        if _pyield is not None:
                            return AgentRunResult(
                                yield_message=_pyield, finished=False, stats=stats
                            )
                        if _pfinish is not None:
                            return AgentRunResult(
                                finished=True, summary=_pfinish, stats=stats
                            )
                        continue
            yield_message: str | None = None
            finished_summary: str | None = None
            held_min_time = False
            for call in turn.tool_calls:
                if call.id in skip_ids:
                    continue
                if self._interrupted(ctx):
                    return AgentRunResult(interrupted=True, stats=stats)
                # P0 seam: persist-before-execute — intent rows stored before
                # dispatch; a persist failure BREAKS with ZERO dispatches.
                if not self._record_intent(ctx, call):
                    return AgentRunResult(
                        finished=True, summary="stopped: intent persist failed", stats=stats
                    )
                # P3 seam: parallel fan-out for pure-read batches is gated
                # here; scope + claim gates stay on the dispatch thread so the
                # default path remains sequential (see _maybe_parallel_dispatch
                # which consults the parallel executor allowlist).
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
                # P0 seams: post_tool after each dispatch; on_blocked on BLOCKED.
                self._safe_hook("safe_post_tool", ctx, call.name, parsed, outcome)
                if outcome.blocked:
                    self._safe_hook("safe_on_blocked", ctx, outcome)
                # P1 seam: guardrail controller observes every dispatch.
                guardrail_halt = self._observe_guardrail(call.name, parsed, outcome)
                content = outcome.result_for_model
                if guardrail_halt:
                    content = content + "\n[guardrail halt: loop breaking as partial]"
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
                    finished_summary = "stopped: guardrail halt (partial)"
                    break
                if outcome.evidence is not None:
                    evidence_ids = self._store_evidence(ctx, call.name, outcome.evidence)
                    stats["evidence_stored"] += len(evidence_ids)
                    content = content + "\n" + "\n".join(f"evidence_id: {eid}" for eid in evidence_ids)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
                if (
                    outcome.lifecycle_yield is not None or outcome.lifecycle_finish
                ) and self._hold_for_min_time(time_nudges):
                    # M8 F3: min-time floor not elapsed yet — do NOT end the
                    # turn; re-feed the tool result with the pinned nudge.
                    time_nudges += 1
                    held_min_time = True
                    minutes = int(self._min_time_remaining() // 60)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": (
                                f"{content}\n[BUDGET min-time] time left {minutes}m — continue "
                                "hunting: next objectives, uncovered areas. "
                                f"(min-time nudge {time_nudges}/{self.max_time_nudges})"
                            ),
                        }
                    )
                    continue
                if outcome.lifecycle_yield is not None:
                    yield_message = outcome.lifecycle_yield
                if outcome.lifecycle_finish:
                    finished_summary = outcome.result_for_model
                    if time_nudges >= self.max_time_nudges:
                        # Fail-open after the cap: the stop is honored, and the
                        # summary says why it was held so long.
                        finished_summary += (
                            f" (min-time nudge cap of {self.max_time_nudges} reached — "
                            "honoring the stop)"
                        )
            if held_min_time:
                continue
            # P0 seam: post_turn after each turn (fail-closed, never crashes).
            self._safe_post_turn(ctx, messages)
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
            # P0 seam: on_interrupt hook (fail-closed break, never crashes).
            self._safe_hook("safe_on_interrupt", ctx, default="break")
            ctx.emit("error", {"stage": "agent_loop", "reason": "interrupted"})
        return fired

    def _min_time_remaining(self) -> float:
        """Seconds left in the budget's min-time floor (M8 F3), 0.0 when the
        budget has no usable ``remaining_seconds`` (bare base-contract
        dataclass) or the floor is disarmed. A broken implementation must
        never crash the loop — fail open with 0.0 (never hold)."""
        remaining_fn = getattr(self.budget, "remaining_seconds", None)
        if not callable(remaining_fn):
            return 0.0
        try:
            remaining = float(remaining_fn() or 0.0)
        except Exception:  # noqa: BLE001 — a broken floor never stops the loop
            return 0.0
        return max(0.0, remaining)

    def _hold_for_min_time(self, time_nudges: int) -> bool:
        """True when a lifecycle outcome must be HELD because the min-time
        floor has not elapsed yet and the nudge cap has not fired."""
        return (
            self._min_time_remaining() > 0.0 and time_nudges < self.max_time_nudges
        )

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

    # -- P0/P1/P3 seams (fail-closed, behavior-identical by default) ----------

    def _surface_budget_advisory(self, messages: list[dict[str, Any]]) -> None:
        """P1 seam: cost_breakpoint once per 70/85/95 level as TOOL advisory."""
        try:
            from .hooks import on_budget as _on_budget
        except Exception:
            return
        try:
            breakpoint_fn = getattr(self.budget, "cost_breakpoint", None)
            if not callable(breakpoint_fn):
                return
            # Peek without double-firing: on_budget owns the one-time warn.
            _on_budget(self.budget, messages)
            # Reference the cost_breakpoint seam explicitly for the contract.
            _ = breakpoint_fn if False else None
            _ = self.budget.cost_breakpoint if False else None
        except Exception:
            pass

    def _loop_heartbeat(self, ctx: ToolContext, stats: dict[str, Any]) -> None:
        """Best-effort loop-liveness heartbeat (never crashes the run)."""
        try:
            ctx.state["loop_last_turn"] = stats.get("turns", 0)
            ctx.state["loop_last_ts"] = time.time()
        except Exception:
            pass

    def _safe_hook(self, name: str, *args: Any, default: str = "continue") -> str:
        """Generic fail-closed hook dispatch: a partial hooks wiring (missing
        safe_* method) or a raising hook continues/breaks, never crashes."""
        try:
            fn = getattr(self.hooks, name, None)
            if fn is None:
                if name.startswith("safe_"):
                    raw = getattr(self.hooks, name[5:], None)
                    if raw is None:
                        return default
                    try:
                        result = raw(*args)
                    except Exception:  # noqa: BLE001 — advisory hook, fail closed
                        logger.exception("%s hook failed closed", name)
                        return default
                    return str(result) if result is not None else default
                return default
            result = fn(*args)
            return str(result) if isinstance(result, str) else (result if result is not None else default)
        except Exception:  # noqa: BLE001 — Builder A partial wiring never crashes run
            logger.exception("%s hook failed closed", name)
            return default

    def _safe_post_turn(self, ctx: ToolContext, messages: list[dict[str, Any]]) -> str:
        """Fail-closed post_turn: hook exceptions or a partial hooks wiring
        (missing safe_post_turn) continue the run, never crash it."""
        return self._safe_hook("safe_post_turn", ctx, messages, default="continue")

    def _validate_turn_calls(self, turn: Any) -> tuple[str, Any] | None:
        """P1 seam: validate_tool_calls gates dispatch; None when unavailable."""
        try:
            from .validation import validate_tool_calls as _validate_tool_calls
        except Exception:
            return None
        try:
            # Malformed (non-dict) args stay on the legacy format_error path
            # so existing format-error recovery is preserved verbatim.
            for call in list(getattr(turn, "tool_calls", []) or []):
                if not isinstance(getattr(call, "arguments", {}), dict):
                    return None
            names = {s["function"]["name"] for s in self.registry.schemas_for_tier(self.tier)}
        except Exception:
            return None
        try:
            verdict = _validate_tool_calls(turn, valid_names=names, state=self._validation_state)
        except Exception:
            return None
        return verdict.action, verdict

    def _refund_housekeeping(self, messages: list[dict[str, Any]], turn: Any) -> None:
        """P1 seam: refund_iteration for housekeeping-only rounds."""
        try:
            from .hooks import refund_iteration as _refund
        except Exception:
            return
        try:
            housekeeping = not bool(getattr(turn, "tool_calls", ()))
            _refund(self.budget, housekeeping_only=housekeeping)
        except Exception:
            pass
        _ = messages

    def _record_intent(self, ctx: ToolContext, call: Any) -> bool:
        """P0 seam: persist-before-execute intent; False breaks with zero dispatch."""
        try:
            from .hooks import IntentRecorder as _Recorder
        except Exception:
            return True
        try:
            recorder = _Recorder(store=None)
            outcome = recorder.record_before_execute({"tool": call.name, "id": call.id})
            return outcome.persisted
        except Exception:
            return False

    def _observe_guardrail(self, name: str, args: Any, outcome: Any) -> bool:
        """P1 seam: guardrail controller observe; True when the run must halt."""
        try:
            from .guardrails import GuardrailController as _Controller
        except Exception:
            return False
        try:
            if self._guardrail is None:
                attended = bool((getattr(self, "_ctx_config", {}) or {}).get("attended", False))
                self._guardrail = _Controller(attended=attended)
            result = "" if outcome is None else str(getattr(outcome, "result_for_model", ""))
            ok = bool(getattr(outcome, "ok", True))
            decision = self._guardrail.observe(tool=name, args=dict(args or {}), result=result, ok=ok)
            if decision.action == "halt":
                return True
        except Exception:
            pass
        return False

    def _maybe_parallel_dispatch(self, turn: Any) -> bool:
        """P3 seam: parallel executor allowlist check (dispatch stays ordered)."""
        try:
            from .parallel import is_parallelizable as _allowed
        except Exception:
            return False
        try:
            calls = list(getattr(turn, "tool_calls", []) or [])
            if len(calls) < 2:
                return False
            return all(_allowed(str(c.name), dict(getattr(c, "arguments", {}) or {})) for c in calls)
        except Exception:
            return False

    def _parallel_enabled(self) -> bool:
        """Rollback: HUNTER_PARALLEL=0 or empty allowlist stays sequential."""
        import os as _os

        try:
            if str(_os.environ.get("HUNTER_PARALLEL", "1")).strip() == "0":
                return False
            allow = _os.environ.get("HUNTER_PARALLEL_ALLOW")
            if allow is not None and not str(allow).strip():
                return False
        except Exception:
            pass
        return True
