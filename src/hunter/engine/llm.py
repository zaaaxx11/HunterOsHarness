"""LLMEngine — the v0.2 pluggable brain, mounted on the agent loop.

The engine is a thin adapter: it converts the :class:`EngineDriver` seam
into a governed agent run.

- ``run`` builds a :class:`ToolContext` bound to the pipeline's ledger and
  run id (``ctx.ledger`` / ``ctx.run_id`` — additive EngineContext fields;
  ``run`` refuses to hunt without a ledger: ``engine.no_ledger``), aims the
  :class:`AgentLoop` at the target, and then runs the deterministic
  ``debunk_pass`` over every finding still CANDIDATE so RULE-E2 verification
  never depends on the model's word.
- Findings created by the agent are ALREADY in the ledger (the governance
  tool ``create_finding_request`` writes them through the claim gate).
  Therefore ``EngineResult.candidates`` is ALWAYS empty by design — the
  pipeline's collect phase finds zero new candidates, which is correct:
  persistence already happened under governance, and the pipeline's verify
  ladder is replaced by the debunk pass above.
- ``replay`` delegates to the deterministic probe recheck by key, exactly
  like :class:`DeterministicEngine`, so any candidate-shaped object can be
  re-verified by the pipeline if ever routed here.

No litellm import happens at module load: the dependency is optional (the
``[llm]`` extra) and lives behind the ChatProvider the caller supplies.
``LLMEngine()`` without a provider keeps the v0.1 ships-dark behavior
(``RuntimeError`` on run/replay) so the registry can always resolve the
"llm" name and the pipeline fails those runs gracefully.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from hunter.errors import HunterError
from hunter.kernel.findings import FindingStatus
from hunter.llm.base import ChatProvider, RunBudget

from .base import CandidateFinding, EngineContext, EngineResult, ScanPlan, TargetSpec

__all__ = ["LLMEngine"]

# NOTE: the agent layer (hunter.agent.*) is imported LAZILY inside the
# methods below. hunter.engine.__init__ eagerly imports this module, and the
# agent layer imports hunter.engine.base — a module-level import here would
# create a package-initialization cycle.

_LLM_NOT_READY = (
    "LLMEngine lands in v0.2 — the harness interface (EngineDriver) is ready; "
    "add litellm via the [llm] extra and a provider key."
)


class LLMEngine:
    """Agent-loop-backed brain implementing :class:`hunter.engine.base.EngineDriver`."""

    name = "llm"

    def __init__(
        self,
        provider: ChatProvider | None = None,
        *,
        tier: str = "basic",
        budget: RunBudget | None = None,
    ) -> None:
        self._provider = provider
        self.tier = tier
        self._budget = budget

    # -- EngineDriver ------------------------------------------------------------

    def plan(self, target: TargetSpec) -> ScanPlan:
        return ScanPlan(
            engine=self.name,
            phases=["brief", "audit", "finish"],
            notes={
                "brain": getattr(self._provider, "name", "none") if self._provider else "none",
                "tier": self.tier,
                "strategy": "governed-agent-loop",
            },
        )

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult:
        from hunter.agent.debunk import debunk_pass
        from hunter.agent.loop import AgentLoop
        from hunter.agent.prompts import build_goal
        from hunter.agent.tools import build_registry
        from hunter.agent.tools_base import ToolContext

        if self._provider is None:
            raise RuntimeError(_LLM_NOT_READY)
        if ctx.ledger is None:
            raise HunterError(
                code="engine.no_ledger",
                layer="engine",
                message=(
                    "LLMEngine requires a ledger-backed EngineContext "
                    "(ctx.ledger + ctx.run_id) so every finding is persisted under governance."
                ),
                hint="Run it through workflow.run_scan, which binds the ledger and run id.",
            )
        run_id = ctx.run_id or f"R-llm-{uuid.uuid4().hex[:12]}"
        browser_enabled = bool(ctx.config.get("browser_enabled", False))
        if "browser_enabled" not in ctx.config:
            provider_config = getattr(self._provider, "config", None)
            browser_enabled = bool(
                getattr(getattr(provider_config, "agent", None), "browser", False)
            )
        tool_ctx = ToolContext(
            run_id=run_id,
            ledger=ctx.ledger,
            http=ctx.http,
            scope=target.scope,
            target_url=target.url,
            emit=ctx.emit,
            config={
                **ctx.config,
                "tier": self.tier,
                "browser_enabled": browser_enabled,
                "hunt_permission": True,
            },
        )
        # M8 F1: daemon/hunter-mode hunts auto-allow approval-danger tools
        # (shell_exec) through the ledgered gate — the catastrophic denylist
        # still refuses first, in every mode. Without the flag the gate stays
        # unconfigured and dispatch fails closed (approval.unavailable).
        if ctx.config.get("approval_auto_allow"):
            from hunter.agent.approval import ApprovalStore, make_approval_gate
            from hunter.runtime_paths import RuntimePaths

            state_dir = ctx.config.get("state_dir")
            if state_dir:
                tool_ctx.config["approval_gate"] = make_approval_gate(
                    ApprovalStore(RuntimePaths.resolve(state=state_dir, migrate=False).approvals),
                    ledger=ctx.ledger,
                    run_id=run_id,
                    auto_allow=True,
                )
        try:
            goal = build_goal(target, self.tier)
            loop = AgentLoop(
                self._provider,
                build_registry(self.tier, browser_enabled=browser_enabled),
                tier=self.tier,
                budget=self._budget,
                interrupt_check=ctx.config.get("interrupt_check"),
            )
            agent_result = loop.run(tool_ctx, goal, stream_cb=ctx.config.get("stream_cb"))

            # Debunk: deterministic replay for every finding still CANDIDATE.
            # This — not the model — promotes findings to VERIFIED (RULE-E2).
            debunk_verified = 0
            for finding in list(ctx.ledger.findings(run_id)):
                if finding.status is FindingStatus.CANDIDATE and debunk_pass(finding, tool_ctx) == "verified":
                    debunk_verified += 1

            findings = ctx.ledger.findings(run_id)
            stats: dict[str, Any] = {
                **agent_result.stats,
                "findings": len(findings),
                "verified": sum(1 for f in findings if f.status is FindingStatus.VERIFIED),
                "ruled_out": sum(1 for f in findings if f.status is FindingStatus.RULED_OUT),
                "debunk_verified": debunk_verified,
                "yielded": agent_result.yield_message is not None,
                "stalled": agent_result.stalled,
                "interrupted": agent_result.interrupted,
            }
            ctx.emit(
                "engine_event",
                {
                    "stage": "agent_finished",
                    "run_id": run_id,
                    "findings": stats["findings"],
                    "verified": stats["verified"],
                    "turns": stats["turns"],
                    "cost_usd": round(stats["cost_usd"], 6),
                },
            )
            # candidates=[] BY DESIGN: agent findings are already in the ledger;
            # the pipeline's collect phase correctly finds zero new candidates.
            return EngineResult(candidates=[], stats=stats)
        finally:
            tool_ctx.close_browser()

    def replay(self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding) -> bool:
        from hunter.engine.deterministic.probes import RECHECKS

        if self._provider is None:
            raise RuntimeError(_LLM_NOT_READY)
        check_id = candidate.key.split("|", 1)[0]
        recheck = RECHECKS.get(check_id)
        if recheck is None:
            return False
        try:
            shim = EngineContext(http=ctx.http, emit=ctx.emit)
            return bool(recheck(shim, target.url.rstrip("/"), candidate))
        except httpx.HTTPError:
            return False
