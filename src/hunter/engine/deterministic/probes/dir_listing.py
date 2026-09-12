"""dir-listing — directory listing enabled under /static/."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "dir-listing"
TARGET_PATH = "/static/"

# Body markers that distinguish a real directory listing from any random HTML
# page that happens to contain an anchor (precision guard).
_LISTING_MARKERS = ("directory listing", "index of")


def _is_listing(response_body: str, response_headers: dict[str, str], status: int) -> bool:
    lowered = response_body.lower()
    content_type = response_headers.get("content-type", "")
    return (
        status == 200
        and "text/html" in content_type
        and "<a href" in lowered
        and any(marker in lowered for marker in _LISTING_MARKERS)
    )


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    exchange = ctx.http.get(base_url + TARGET_PATH)
    if not _is_listing(exchange.response_body, exchange.response_headers, exchange.status):
        return []
    return [
        _finding(
            check_id=CHECK_ID,
            title="Directory listing enabled",
            severity=Severity.LOW,
            cwe="CWE-548",
            method="GET",
            endpoint=TARGET_PATH,
            description=f"GET {TARGET_PATH} returns an HTML directory listing with links.",
            impact="Attackers can enumerate files that were not meant to be discoverable.",
            remediation="Disable autoindex/directory browsing for static roots.",
            exchanges=[exchange],
        )
    ]


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    path = candidate.endpoint or TARGET_PATH
    exchange = ctx.http.get(base_url + path)
    return _is_listing(exchange.response_body, exchange.response_headers, exchange.status)
