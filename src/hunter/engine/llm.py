"""LLMEngine — the v0.2 pluggable brain (stub, ships dark).

The :class:`EngineDriver` interface is already everything an LLM hunter needs:
``plan`` declares the hunting strategy, ``run`` drives the same scope-gated
HTTP client and event stream the deterministic engine uses, and ``replay``
verifies candidates. That is the same mount point modern agent harnesses use
to plug a model in as the brain (the way hermes/Strix mount theirs) — the
harness stays in charge of scope, evidence and the ledger; the model only
ever speaks through the driver.

No litellm import happens at module load: the dependency is optional (the
``[llm]`` extra) and will be imported lazily inside ``run`` once v0.2 lands,
so this module is safe to import everywhere today.
"""

from __future__ import annotations

from .base import CandidateFinding, EngineContext, EngineResult, ScanPlan, TargetSpec

_LLM_NOT_READY = (
    "LLMEngine lands in v0.2 — the harness interface (EngineDriver) is ready; "
    "add litellm via the [llm] extra and a provider key."
)


class LLMEngine:
    """Reserved plug point for the LLM-backed brain. Not functional in v0.1."""

    name = "llm"

    def plan(self, target: TargetSpec) -> ScanPlan:
        return ScanPlan(
            engine=self.name,
            phases=["recon", "hunt", "verify"],
            notes={"brain": "litellm (lands in v0.2)"},
        )

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult:
        raise RuntimeError(_LLM_NOT_READY)

    def replay(self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding) -> bool:
        raise RuntimeError(_LLM_NOT_READY)
