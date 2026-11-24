"""cors-misconfig — CORS: reflecting Origin with Access-Control-Allow-Credentials.

Sends a GET with ``Origin: https://evil.example.com`` and signals when the
response echoes that origin back in ``Access-Control-Allow-Origin`` AND sets
``Access-Control-Allow-Credentials: true`` — the one-two punch that lets an
attacker's page steal authenticated responses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "cors-misconfig"
ORIGIN = "https://evil.example.com"


def _signal(exchange) -> bool:
    """Signal when CORS reflects the attacker origin AND allows credentials."""
    headers = exchange.response_headers
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    return acao == ORIGIN and acac == "true"


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    baseline = ctx.http.get(base_url + "/")
    if _signal(baseline):
        return []  # baseline already echoes — not a probe signal
    payload = ctx.http.get(
        base_url + "/",
        headers={"Origin": ORIGIN},
    )
    if not _signal(payload):
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="CORS misconfiguration — arbitrary origin reflection with credentials",
            severity=Severity.MEDIUM,
            cwe="CWE-942",
            method="GET",
            endpoint="/",
            param="Origin",
            payload_used=ORIGIN,
            description=(
                f"GET / with Origin: {ORIGIN} returns "
                "Access-Control-Allow-Origin: {ORIGIN} AND "
                "Access-Control-Allow-Credentials: true. Any site can make "
                "authenticated cross-origin requests and read the responses."
            ),
            impact=(
                "Cross-origin theft of authenticated data (session tokens, CSRF "
                "tokens, API keys) — a single visit to a malicious page is enough."
            ),
            remediation=(
                "If the endpoint must be CORS-enabled, use a strict allowlist "
                "(not the wildcard or reflection). Do NOT combine '*' with "
                "credentials. Verify the Origin against a known-good set server-side."
            ),
            exchanges=[baseline, payload],
        )
    ]


def run(
    ctx: EngineContext, base_url: str, recon: Recon,
) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    exchange = ctx.http.get(
        base_url + "/",
        headers={"Origin": ORIGIN},
    )
    return _signal(exchange)