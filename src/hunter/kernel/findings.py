"""Finding model — the kernel contract for what may be claimed.

A Finding is a *claim*. The ledger enforces that every claim carries evidence
(see ``ledger.create_finding`` and ``claimgate``): a finding without at least
one evidence artifact is structurally impossible to insert, not merely
discouraged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"  # probe observed a signal; single evidence bound
    VERIFIED = "verified"  # independent replay succeeded; second evidence bound
    RULED_OUT = "ruled_out"  # debunked; kept for the audit trail, never deleted


@dataclass(frozen=True, slots=True)
class Finding:
    id: str  # "F-0001"
    run_id: str
    key: str  # stable dedupe key, e.g. "reflected-xss|GET|/search|q"
    title: str
    severity: Severity
    cwe: str  # e.g. "CWE-79"
    endpoint: str
    method: str = "GET"
    param: str | None = None
    payload_used: str | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.CANDIDATE
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)


def dedupe_key(check_id: str, method: str, endpoint: str, param: str | None) -> str:
    """Stable identity for a finding within a run (used for dedupe)."""
    return f"{check_id}|{method.upper()}|{endpoint}|{param or '-'}"


def finding_id(n: int) -> str:
    return f"F-{n:04d}"
