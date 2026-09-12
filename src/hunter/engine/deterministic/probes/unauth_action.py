"""unauth-action — state-changing POST succeeds with no credentials at all."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "unauth-action"
ENDPOINT = "/transfer"
FORM_BODY = "from=1&to=2&amount=100"
MARKER = "transfer complete"

SEVERITY = Severity.CRITICAL
CWE = "CWE-862"


def _signal(exchange) -> bool:
    return exchange.status == 200 and MARKER in exchange.response_body.lower()


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    # Baseline: the form page (no marker). The payload POST below is sent with
    # NO cookie or token of any kind — the exchange evidence shows it.
    baseline = ctx.http.get(base_url + ENDPOINT)
    payload = ctx.http.post(base_url + ENDPOINT, body=FORM_BODY)
    if not _signal(payload) or MARKER in baseline.response_body.lower():
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="Unauthenticated state-changing action",
            severity=SEVERITY,
            cwe=CWE,
            method="POST",
            endpoint=ENDPOINT,
            description=(
                f"POST {ENDPOINT} succeeds (200, {MARKER!r}) without any session cookie, "
                "token or credentials."
            ),
            impact="Anyone on the network can perform the sensitive action anonymously.",
            remediation="Enforce server-side authorization on every state-changing request.",
            exchanges=[baseline, payload],
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    return _signal(ctx.http.post(base_url + endpoint, body=FORM_BODY))
