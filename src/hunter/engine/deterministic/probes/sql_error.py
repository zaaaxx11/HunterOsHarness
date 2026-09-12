"""sql-error — SQL error disclosure triggered by a quote in a form field."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "sql-error"
ENDPOINT = "/login"
PARAM = "username"
PAYLOAD = "'"
BENIGN_USERNAME = "hunter"

# Signatures strong enough to call a 500 a SQL error disclosure.
SIGNATURES = (
    "sqlite",
    "mysql",
    "postgresql",
    "sql syntax",
    "syntax error",
    "unclosed quotation",
    "ora-",
)


def _signal(exchange) -> bool:
    body = exchange.response_body.lower()
    return exchange.status == 500 and any(sig in body for sig in SIGNATURES)


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    baseline = ctx.http.post(
        base_url + ENDPOINT,
        body=urlencode({PARAM: BENIGN_USERNAME, "password": BENIGN_USERNAME}),
    )
    payload = ctx.http.post(
        base_url + ENDPOINT,
        body=urlencode({PARAM: PAYLOAD, "password": BENIGN_USERNAME}),
    )
    if not _signal(payload) or _signal(baseline):
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="SQL error disclosure on login",
            severity=Severity.MEDIUM,
            cwe="CWE-653",
            method="POST",
            endpoint=ENDPOINT,
            param=PARAM,
            payload_used=PAYLOAD,
            description=(
                f"POST {ENDPOINT} with a quote in {PARAM} returns a 500 whose body leaks "
                "raw SQL error text (backend and query structure)."
            ),
            impact="Database technology and query structure leak, easing targeted injection.",
            remediation="Return a generic error page; log details server-side only.",
            exchanges=[baseline, payload],
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    param = candidate.param or PARAM
    exchange = ctx.http.post(
        base_url + endpoint,
        body=urlencode({param: PAYLOAD, "password": BENIGN_USERNAME}),
    )
    return _signal(exchange)
