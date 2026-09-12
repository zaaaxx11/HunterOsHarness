"""EngineDriver contract — the plug point for brains.

An engine receives a scope-gated HTTP client and an emit callback; it NEVER
touches the ledger directly (the pipeline owns persistence and applies the
claim gate). Engines return ``CandidateFinding``s with evidence; the pipeline
binds evidence, dedupes, and promotes through the ladder.

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


class EngineDriver(Protocol):
    name: str

    def plan(self, target: TargetSpec) -> ScanPlan: ...

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult: ...

    def replay(
        self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding
    ) -> bool: ...
