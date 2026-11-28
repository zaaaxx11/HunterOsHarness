"""Open-redirect verification helpers for debunk_pass.

The agent may file an open-redirect finding under a custom check_id (e.g.
"airvpn-001") whose slug is not in the deterministic RECHECKS registry.
These helpers independently replay the claim: they issue the request with
an attacker-controlled redirect payload and check for an immediate 3xx
Location or reflected evil host in a 200 body (no interstitial).

`_finalize_open_redirect` returns (outcome, poc_path) so the caller in
debunk.py can write coverage and set status with the PoC path attached.
"""

from __future__ import annotations

import httpx

from hunter.kernel.findings import Finding

from .tools_base import ToolContext

__all__ = [
    "_is_open_redirect_finding",
    "_verify_open_redirect",
]


def _is_open_redirect_finding(finding: Finding) -> bool:
    haystack = " ".join(
        str(getattr(finding, f, "") or "")
        for f in ("title", "description", "impact", "endpoint", "key")
    ).lower()
    if "open redirect" in haystack or "open-redirect" in haystack:
        return True
    endpoint = str(getattr(finding, "endpoint", "") or "")
    return bool("external_link" in endpoint or "url=" in endpoint or "redirect" in endpoint.lower())


def _verify_open_redirect(ctx: ToolContext, finding: Finding) -> bool | None:
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    endpoint = str(getattr(finding, "endpoint", "") or "").strip()
    if not endpoint:
        return False
    if "://" not in endpoint:
        base = str(getattr(ctx, "target_url", "") or "").rstrip("/")
        endpoint = f"{base}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
    try:
        p = urlparse(endpoint)
        qs = parse_qs(p.query, keep_blank_values=True)
        for key in ("url", "next", "redirect", "target", "to", "dest", "goto"):
            if key in qs or not qs:
                qs[key] = ["https://evil.com/"]
        attack = urlunparse(p._replace(query=urlencode(qs, doseq=True)))
    except Exception:  # noqa: BLE001
        attack = endpoint
    try:
        resp = ctx.http.get(attack)
    except httpx.HTTPError:
        return None
    loc = ""
    try:
        loc = str((resp.response_headers or {}).get("location", "") or "")
    except Exception:  # noqa: BLE001
        loc = ""
    status = int(getattr(resp, "status", 0) or 0)
    if 300 <= status < 400 and "evil.com" in loc:
        return True
    body = str(getattr(resp, "response_body", "") or "")
    return bool(status == 200 and "evil.com" in body and "whitelist" not in body.lower())
