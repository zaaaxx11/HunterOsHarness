"""missing-headers — security response headers absent from responses."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "missing-headers"

REQUIRED_HEADERS = ("content-security-policy", "x-frame-options", "x-content-type-options")


def _missing(header_map: dict[str, str]) -> list[str]:
    return [name for name in REQUIRED_HEADERS if name not in header_map]


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    landing = ctx.http.get(base_url + "/")
    missing = _missing(landing.response_headers)
    if not missing:
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="Missing security response headers",
            severity=Severity.INFO,
            cwe="CWE-693",
            method="GET",
            endpoint="/",
            description=f"The landing page response does not send: {', '.join(missing)}.",
            impact="Browsers lose clickjacking, MIME-sniffing and script-injection mitigations.",
            remediation=(
                "Send Content-Security-Policy, X-Frame-Options and X-Content-Type-Options "
                "on every response."
            ),
            exchanges=[landing],
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    exchange = ctx.http.get(base_url + (candidate.endpoint or "/"))
    return bool(_missing(exchange.response_headers))
