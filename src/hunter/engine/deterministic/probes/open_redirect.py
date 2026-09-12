"""open-redirect — 3xx Location points at an attacker-controlled external URL.

Scope note: the probe never requests the external host. Only the in-scope
endpoint is fetched; the out-of-scope destination exists solely as the value
of the Location header we inspect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "open-redirect"
ENDPOINT = "/goto"
PARAM = "url"
PAYLOAD = "https://evil.example.com/"


def _signal(exchange) -> bool:
    return 300 <= exchange.status < 400 and exchange.response_headers.get("location") == PAYLOAD


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    baseline = ctx.http.get(base_url + ENDPOINT)
    if _signal(baseline):
        return []  # redirects externally even without our payload — different bug class
    url = f"{base_url}{ENDPOINT}?{urlencode({PARAM: PAYLOAD})}"
    payload = ctx.http.get(url)
    if not _signal(payload):
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="Open redirect via url parameter",
            severity=Severity.MEDIUM,
            cwe="CWE-601",
            method="GET",
            endpoint=ENDPOINT,
            param=PARAM,
            payload_used=PAYLOAD,
            description=(
                f"GET {ENDPOINT}?{PARAM}=<external> returns a 302 whose Location equals the "
                "attacker-supplied URL verbatim."
            ),
            impact="Phishing via trusted-domain redirects; OAuth/token flows can be hijacked.",
            remediation="Allowlist redirect destinations or use server-side opaque references.",
            exchanges=[baseline, payload],
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    param = candidate.param or PARAM
    url = f"{base_url}{endpoint}?{urlencode({param: PAYLOAD})}"
    return _signal(ctx.http.get(url))
