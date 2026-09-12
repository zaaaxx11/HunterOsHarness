"""idor-heuristic — consecutive object ids all resolve with distinct content.

A heuristic on purpose: /invoice?id=1..3 all returning 200 with different
bodies suggests object references are unguarded. The vault (and any clean
target without such a route) answers 404, so the probe stays silent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "idor-heuristic"
ENDPOINT = "/invoice"
PARAM = "id"
IDS = ("1", "2", "3")

SEVERITY = Severity.HIGH
CWE = "CWE-639"


def _fetch_all(ctx: EngineContext, base_url: str, endpoint: str, param: str):
    return [
        ctx.http.get(f"{base_url}{endpoint}?{urlencode({param: value})}")
        for value in IDS
    ]


def _signal(exchanges) -> bool:
    bodies = [exchange.response_body for exchange in exchanges]
    all_ok = all(exchange.status == 200 for exchange in exchanges)
    distinct = len(set(bodies)) == len(bodies) and all(bodies)
    return all_ok and distinct


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    exchanges = _fetch_all(ctx, base_url, ENDPOINT, PARAM)
    if not _signal(exchanges):
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="Consecutive object ids accessible without authorization",
            severity=SEVERITY,
            cwe=CWE,
            method="GET",
            endpoint=ENDPOINT,
            param=PARAM,
            payload_used=",".join(IDS),
            description=(
                f"GET {ENDPOINT}?{PARAM}=1..3 all returned 200 with distinct bodies — "
                "references look directly enumerable."
            ),
            impact="Horizontal privilege escalation: users can read each other's objects.",
            remediation="Enforce object-level authorization (check ownership per request).",
            exchanges=exchanges,
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    param = candidate.param or PARAM
    return _signal(_fetch_all(ctx, base_url, endpoint, param))
