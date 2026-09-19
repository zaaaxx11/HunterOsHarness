"""Agent tool contracts — structural governance for the LLM brain.

Design laws (v0.2):
- T1  The LLM never touches the ledger, network, or filesystem directly.
      Every capability is a ToolSpec; every call is dispatched here.
- T2  Tier gating is STRUCTURAL: out-of-tier tools are absent from the
      schema list the model sees AND refused on direct dispatch.
- T3  Out-of-scope actions return a structured BLOCKED ToolOutcome — the
      model may read it and self-correct, but cannot bypass (scope gate is
      enforced again inside ScopedHttpClient; this is the early, readable one).
- T4  Unknown tool names are recoverable: a tool_not_found outcome goes
      back to the model (Strix ``tool_not_found_behavior="return_error_to_model"``).
- T5  A finding is a CLAIM: only ``create_finding_request`` may propose one,
      and its handler must machine-validate evidence against the ledger.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunter.engine.base import EmitFn
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import ScopeSet

TIER_ORDER: dict[str, int] = {"basic": 0, "advanced": 1}

@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema: {"type":"object","properties":{...},"required":[...]}
    handler: Callable[[dict[str, Any], ToolContext], ToolOutcome]
    min_tier: str = "basic"
    lifecycle: str | None = None  # None | "respond_to_user" | "finish_scan"
    danger: str = "none"  # "none" | "approval" — approval-danger tools run ONLY
    #  through a configured approval gate (v0.5 F1); without one, dispatch
    #  fails closed (approval.unavailable) — never a silent bypass.


@dataclass
class ToolContext:
    """Everything a tool may touch — and nothing else.

    v0.3: ``config`` may carry a ``"phase_machine"`` (a
    :class:`hunter.phases.PhaseState` mounted by the pipeline); tools fold
    their surface actions into the canonical phase machine through it
    (``hunter.agent.tools._observe_tool``). The field set above is unchanged.
    """

    run_id: str
    ledger: Ledger
    http: ScopedHttpClient
    scope: ScopeSet
    target_url: str
    emit: EmitFn
    config: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)  # run-scoped notes/coverage/threat model
    browser_session: Any | None = None
    browser_factory: Callable[[], Any] | None = None

    def ensure_browser(self, factory: Callable[[], Any] | None = None) -> Any:
        """Return the one lazy browser session owned by this run."""
        if self.browser_session is None:
            creator = self.browser_factory or factory
            if creator is None:
                raise RuntimeError("browser session factory is not configured")
            self.browser_session = creator()
        return self.browser_session

    def close_browser(self) -> None:
        """Close the run-owned browser session, safely and idempotently."""
        session = self.browser_session
        if session is None:
            return
        try:
            close = getattr(session, "close", None)
            if callable(close):
                with contextlib.suppress(Exception):
                    close()
        finally:
            self.browser_session = None


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    ok: bool = True
    result_for_model: str = ""  # bounded text the model reads (no secrets)
    evidence: dict[str, Any] | None = None  # {"kind": ..., "data": {...}} → pipeline stores
    blocked: bool = False  # true → outcome is a structured refusal
    code: str = ""  # stable machine code, e.g. "scope.target_out_of_scope"
    lifecycle_yield: str | None = None  # respond_to_user message
    lifecycle_finish: bool = False  # finish_scan requested


class ToolRegistry:
    """Registry of record for agent tools (governed pattern)."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._unavailable: dict[str, tuple[str, str]] = {}

    def register_unavailable(self, name: str, code: str, message: str) -> None:
        """Remember an optional capability without advertising a schema."""
        self._unavailable[name] = (code, message)

    def register(self, spec: ToolSpec, *, override: bool = False) -> None:
        if spec.name in self._specs and not override:
            raise ValueError(f"tool '{spec.name}' already registered")
        if spec.min_tier not in TIER_ORDER:
            raise ValueError(f"tool '{spec.name}' has unknown min_tier {spec.min_tier!r}")
        self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def specs_for_tier(self, tier: str) -> list[ToolSpec]:
        level = TIER_ORDER.get(tier)
        if level is None:
            raise ValueError(f"unknown tier {tier!r} (use basic|advanced)")
        return [s for s in self._specs.values() if TIER_ORDER[s.min_tier] <= level]

    def schemas_for_tier(self, tier: str) -> list[dict[str, Any]]:
        """OpenAI function-tool format; out-of-tier tools are structurally absent."""
        return [
            {
                "type": "function",
                "function": {
                    "name": s.name,
                    "description": s.description,
                    "parameters": s.parameters,
                },
            }
            for s in sorted(self.specs_for_tier(tier), key=lambda s: s.name)
        ]

    def dispatch(self, name: str, args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
        spec = self._specs.get(name)
        if spec is None:
            unavailable = self._unavailable.get(name)
            if unavailable is not None:
                code, message = unavailable
                return ToolOutcome(ok=False, blocked=True, code=code, result_for_model=message)
            return ToolOutcome(
                ok=False,
                blocked=False,
                code="tool.tool_not_found",
                result_for_model=(
                    f"unknown tool '{name}'. Available tools: "
                    + ", ".join(sorted(s.name for s in self.specs_for_tier("advanced")))
                ),
            )
        level = TIER_ORDER.get(ctx.config.get("tier", "basic"), 0)
        if TIER_ORDER[spec.min_tier] > level:
            return ToolOutcome(
                ok=False,
                blocked=True,
                code="tier.capability_locked",
                result_for_model=(
                    f"BLOCKED: tool '{name}' requires tier '{spec.min_tier}' "
                    f"(current tier '{ctx.config.get('tier', 'basic')}')."
                ),
            )
        if spec.danger == "approval":
            # Approval metadata is valid for exactly one dispatch. Never let a
            # prior approved shell call release a later direct/blocked call.
            ctx.config.pop("approval_id", None)
            ctx.config.pop("approval_class", None)
            gate = ctx.config.get("approval_gate")
            if gate is None:  # fail closed — no silent bypass on unaudited surfaces
                return ToolOutcome(
                    ok=False,
                    blocked=True,
                    code="approval.unavailable",
                    result_for_model=f"BLOCKED: tool '{name}' requires an approval gate; "
                    "none is configured on this surface.",
                )
            decision = gate(name, args, ctx)
            if decision is not None:
                return decision
        try:
            return spec.handler(args, ctx)
        except Exception as exc:  # tools must never crash the run
            from hunter.errors import build_error_surface  # noqa: PLC0415

            surface = build_error_surface(exc)
            return ToolOutcome(
                ok=False,
                code=surface["code"],
                result_for_model=f"[ERROR {surface['layer']}] {surface['message']}",
            )
