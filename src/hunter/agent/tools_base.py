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
    danger: str = "none"  # "none" | "approval" (approval floors land in v0.2 P1)


@dataclass
class ToolContext:
    """Everything a tool may touch — and nothing else."""

    run_id: str
    ledger: Ledger
    http: ScopedHttpClient
    scope: ScopeSet
    target_url: str
    emit: EmitFn
    config: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)  # run-scoped notes/coverage/threat model


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
    """Registry of record for agent tools (hermes pattern)."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}

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
