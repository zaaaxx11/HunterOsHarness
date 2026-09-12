"""reflected-xss — canary reflected RAW (unescaped) into an HTML response."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "reflected-xss"
ENDPOINT = "/search"
PARAM = "q"
CANARY = "hun<x>ter<b>q9"


def _raw_echo(body: str) -> bool:
    """True when the canary's HTML tags survive unescaped in the body."""
    return "hun<x>ter" in body and "ter<b>q9" in body


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    baseline = ctx.http.get(base_url + ENDPOINT)
    url = f"{base_url}{ENDPOINT}?{urlencode({PARAM: CANARY})}"
    payload = ctx.http.get(url)
    if not _raw_echo(payload.response_body) or _raw_echo(baseline.response_body):
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="Reflected XSS in search parameter",
            severity=Severity.HIGH,
            cwe="CWE-79",
            method="GET",
            endpoint=ENDPOINT,
            param=PARAM,
            payload_used=CANARY,
            description=(
                f"GET {ENDPOINT}?{PARAM}=... echoes the canary {CANARY!r} back into the "
                "HTML body without escaping."
            ),
            impact="Attacker-controlled script can execute in victims' browsers.",
            remediation="HTML-encode reflected input and apply a CSP.",
            exchanges=[baseline, payload],
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    param = candidate.param or PARAM
    canary = candidate.payload_used or CANARY
    url = f"{base_url}{endpoint}?{urlencode({param: canary})}"
    exchange = ctx.http.get(url)
    return _raw_echo(exchange.response_body)
