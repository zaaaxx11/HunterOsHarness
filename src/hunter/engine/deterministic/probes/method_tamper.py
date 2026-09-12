"""method-tamper — state-changing HTTP methods accepted where they must not be.

OPTIONS returning 200 is normal (it is informational) and is never flagged;
PUT/DELETE/TRACE answering 2xx means the application never validated the
method. Well-behaved servers answer 405/501, so this probe is usually quiet.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "method-tamper"
ENDPOINT = "/"
STATE_CHANGING_METHODS = ("PUT", "DELETE", "TRACE")

SEVERITY = Severity.MEDIUM
CWE = "CWE-650"


def _signal(exchange) -> bool:
    return 200 <= exchange.status < 300


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []
    for method in STATE_CHANGING_METHODS:
        exchange = ctx.http.request(method, base_url + ENDPOINT)
        if not _signal(exchange):
            continue
        findings.append(
            _finding(
                check_id=CHECK_ID,
                title=f"State-changing method {method} accepted",
                severity=SEVERITY,
                cwe=CWE,
                method=method,
                endpoint=ENDPOINT,
                description=f"{method} {ENDPOINT} returned {exchange.status} instead of 405/501.",
                impact="Method-based access controls (if any) are bypassable; mutation endpoints leak.",
                remediation="Validate the HTTP method per route and answer 405 elsewhere.",
                exchanges=[exchange],
            )
        )
    return findings


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    method = candidate.method or "PUT"
    endpoint = candidate.endpoint or ENDPOINT
    return _signal(ctx.http.request(method, base_url + endpoint))
