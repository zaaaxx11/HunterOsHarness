"""EngineDriver contract — the plug point for brains.

An engine receives a scope-gated HTTP client and an emit callback; v0.1
engines never touch the ledger — they return ``CandidateFinding``s with
evidence and the pipeline binds evidence, dedupes, and promotes through the
ladder. v0.2 adds an opt-in ledger path for the LLM brain: the pipeline binds
``ledger`` and ``run_id`` onto :class:`EngineContext` (additive, default
``None``/""), and the agent persists findings ONLY through the governance
tool (``create_finding_request``), which re-validates evidence against the
ledger before ``Ledger.create_finding`` applies RULE-E1 again below it.
The claim gate is therefore never bypassed by either path.

Replay contract: ``replay`` re-executes ONLY the check that produced the
candidate and returns True when the signal reproduces. The pipeline uses it
for ladder verification (candidate -> verified, RULE-E2).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..kernel.events import canonical_json, sha256_hex
from ..kernel.findings import Severity
from ..tools.http_client import ScopedHttpClient
from ..tools.scope import ScopeSet

# emit(kind_name, payload) — kind_name is an EventKind value string
EmitFn = Callable[[str, dict[str, Any]], None]


@dataclass(frozen=True, slots=True)
class TargetSpec:
    url: str
    scope: ScopeSet
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evidence:
    """One bound piece of evidence for a candidate finding."""

    kind: str  # "http_exchange" | "file" | "note"
    data: dict[str, Any]

    def sha256(self) -> str:
        return sha256_hex(canonical_json(self.data))

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "data": self.data}


@dataclass(frozen=True, slots=True)
class CandidateFinding:
    key: str
    title: str
    severity: Severity
    cwe: str
    endpoint: str
    method: str = "GET"
    param: str | None = None
    payload_used: str | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)


@dataclass
class ScanPlan:
    engine: str
    phases: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngineResult:
    candidates: list[CandidateFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngineContext:
    http: ScopedHttpClient
    emit: EmitFn
    config: dict[str, Any] = field(default_factory=dict)
    # Additive v0.2 fields (defaults keep every v0.1 engine working unchanged):
    # the pipeline binds the run's Ledger and run id so ledger-backed engines
    # (the LLM agent) can persist findings through the claim gate. The
    # deterministic/mock engines ignore them; the pipeline still owns the run
    # lifecycle and re-applies the claim gate on anything returned as
    # candidates.
    ledger: Any = None
    run_id: str = ""


class EngineDriver(Protocol):
    name: str

    def plan(self, target: TargetSpec) -> ScanPlan: ...

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult: ...

    def replay(
        self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding
    ) -> bool: ...
