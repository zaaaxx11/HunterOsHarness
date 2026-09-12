"""DeterministicEngine — the day-one brain. Zero LLM, zero flakiness.

Pipeline: recon (depth-1 same-origin crawl) -> probe (fixed, baseline-diffed
checks) -> collect (dedupe by key, first wins; sort severity desc then key).

Every request rides ``ctx.http`` (the scope gate — fail-closed before any
socket opens), every probe emits ``probe_started``/``probe_result`` events,
and replay re-executes ONLY the check that produced a candidate.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from hunter.kernel.findings import SEVERITY_ORDER

from ..base import CandidateFinding, EngineContext, EngineResult, ScanPlan, TargetSpec
from . import probes
from .recon import Recon, run_recon

__all__ = ["DeterministicEngine", "Recon"]


class DeterministicEngine:
    """Deterministic probe engine — implements :class:`hunter.engine.base.EngineDriver`."""

    name = "deterministic"

    def __init__(self, *, max_pages: int = 20) -> None:
        self.max_pages = max_pages

    def plan(self, target: TargetSpec) -> ScanPlan:
        return ScanPlan(
            engine=self.name,
            phases=["recon", "probe", "collect"],
            notes={"strategy": "deterministic-probes", "max_pages": self.max_pages},
        )

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult:
        base_url = target.url.rstrip("/")
        started = time.perf_counter()

        # -- recon -------------------------------------------------------------
        ctx.emit("phase_started", {"phase": "recon"})
        recon = run_recon(ctx.http, base_url, max_pages=self.max_pages)
        ctx.emit(
            "phase_ended",
            {
                "phase": "recon",
                "pages": len(recon.pages),
                "links": len(recon.links),
                "forms": len(recon.forms),
            },
        )

        # -- probe ---------------------------------------------------------------
        ctx.emit("phase_started", {"phase": "probe"})
        raw: list[CandidateFinding] = []
        for probe in probes.PROBES:
            raw.extend(probe.run(ctx, base_url, recon))
        ctx.emit("phase_ended", {"phase": "probe", "raw_candidates": len(raw)})

        # -- collect ---------------------------------------------------------------
        ctx.emit("phase_started", {"phase": "collect"})
        candidates = _dedupe(raw)
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        stats: dict[str, Any] = {
            **ctx.http.stats.summary(),
            "probes_run": len(probes.PROBES),
            "raw_candidates": len(raw),
            "candidates": len(candidates),
            "elapsed_ms": elapsed_ms,
        }
        ctx.emit(
            "phase_ended",
            {"phase": "collect", "findings": len(candidates), "elapsed_ms": elapsed_ms},
        )
        return EngineResult(candidates=candidates, stats=stats)

    def replay(self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding) -> bool:
        """Re-execute ONLY the check that produced ``candidate``.

        Dispatches on the check id (first segment of the dedupe key) and
        returns True when the signal reproduces. Emits nothing — evidence
        capture for replay belongs to the pipeline.
        """
        check_id = candidate.key.split("|", 1)[0]
        recheck = probes.RECHECKS.get(check_id)
        if recheck is None:
            return False
        for _attempt in (1, 2):  # one retry: replay must not flake on a lost packet
            try:
                return bool(recheck(ctx, target.url.rstrip("/"), candidate))
            except httpx.HTTPError:
                continue
        return False


def _dedupe(candidates: list[CandidateFinding]) -> list[CandidateFinding]:
    """Dedupe by key (first wins), sort by severity desc then key."""
    first_by_key: dict[str, CandidateFinding] = {}
    for candidate in candidates:
        first_by_key.setdefault(candidate.key, candidate)
    return sorted(
        first_by_key.values(),
        key=lambda c: (-SEVERITY_ORDER[c.severity.value], c.key),
    )
