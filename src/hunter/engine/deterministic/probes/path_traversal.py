"""path-traversal — file parameter escaping the download root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "path-traversal"
ENDPOINT = "/download"
PARAM = "file"
MARKER = "root:x:0:0:"

# [0] is sent URL-encoded via urlencode; [1] is pre-encoded and appended raw so
# that servers handling %2f differently are both covered.
PAYLOADS = ("../../secret.txt", "..%2f..%2fsecret.txt")
LOGICAL_PAYLOAD = PAYLOADS[0]


def _payload_urls(base_url: str, endpoint: str, param: str) -> list[str]:
    return [
        f"{base_url}{endpoint}?{urlencode({param: PAYLOADS[0]})}",
        f"{base_url}{endpoint}?{param}={PAYLOADS[1]}",  # already encoded on purpose
    ]


def _signal(exchange) -> bool:
    return exchange.status == 200 and MARKER in exchange.response_body


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    baseline = ctx.http.get(base_url + ENDPOINT)
    if _signal(baseline):
        return []  # marker already present without a payload — not a traversal signal
    for url in _payload_urls(base_url, ENDPOINT, PARAM):
        payload = ctx.http.get(url)
        if _signal(payload):
            return [
                _finding(
                    check_id=CHECK_ID,
                    title="Path traversal in file download",
                    severity=Severity.HIGH,
                    cwe="CWE-22",
                    method="GET",
                    endpoint=ENDPOINT,
                    param=PARAM,
                    payload_used=LOGICAL_PAYLOAD,
                    description=(
                        f"GET {ENDPOINT}?{PARAM}=../../secret.txt returns 200 with the "
                        "content of a file outside the download root."
                    ),
                    impact="Arbitrary file read on the server (credentials, secrets, source).",
                    remediation="Resolve and allowlist the final path; reject any escape from the base dir.",
                    exchanges=[baseline, payload],
                )
            ]
    return []


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    param = candidate.param or PARAM
    return any(
        _signal(ctx.http.get(url))
        for url in _payload_urls(base_url, endpoint, param)
    )
