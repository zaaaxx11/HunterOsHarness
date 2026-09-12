"""MockEngine — zero-network engine for tests, demos and pipeline wiring.

Returns one canned candidate without touching a socket, so the whole
pipeline (evidence binding, dedupe, ladder, reporting) can be exercised
before any real target — or any real brain — exists.
"""

from __future__ import annotations

from typing import Any

from hunter.kernel.findings import Severity

from .base import CandidateFinding, EngineContext, EngineResult, Evidence, ScanPlan, TargetSpec

MOCK_KEY = "mock|GET|/mock|-"

_CANNED = CandidateFinding(
    key=MOCK_KEY,
    title="Mock finding (canned)",
    severity=Severity.LOW,
    cwe="CWE-000",
    endpoint="/mock",
    method="GET",
    param=None,
    payload_used=None,
    description="Canned candidate from MockEngine — proves pipeline wiring with zero network I/O.",
    impact="None. This is a fixture, not a real vulnerability.",
    remediation="Nothing to fix; used for tests and offline demos.",
    evidence=(
        Evidence(
            kind="note",
            data={"note": "mock engine produced this candidate without touching the network"},
        ),
    ),
)


class MockEngine:
    """Implements :class:`hunter.engine.base.EngineDriver` offline."""

    name = "mock"

    def plan(self, target: TargetSpec) -> ScanPlan:
        return ScanPlan(engine=self.name, phases=["probe"], notes={"offline": True})

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult:
        ctx.emit("probe_started", {"check_id": "mock"})
        ctx.emit("probe_result", {"check_id": "mock", "candidates": 1, "hit": True})
        stats: dict[str, Any] = {
            "requests": 0,
            "blocked": 0,
            "errors": 0,
            "probes_run": 1,
            "elapsed_ms": 0.0,
        }
        return EngineResult(candidates=[_CANNED], stats=stats)

    def replay(self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding) -> bool:
        return candidate.key == MOCK_KEY
