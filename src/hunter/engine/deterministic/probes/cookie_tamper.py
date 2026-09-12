"""cookie_tamper — auth bypass via a forgeable plaintext role cookie.

Two candidate types can come out of this probe:

1. ``auth-bypass`` — an endpoint that denies anonymous access (401/403) but
   grants access once a plaintext ``role=admin`` cookie is set. The cookie is
   forgeable by construction: it is unsigned, and we authored it ourselves.
2. ``cookie-flags`` (extra, low) — a Set-Cookie observed while logging in that
   lacks HttpOnly and/or Secure. Deliberately NOT part of the vault answer
   key; it must never collide with one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "auth-bypass"
ENDPOINT = "/admin"
FORGED_COOKIE = "role=admin"
LOGIN_ENDPOINT = "/login"
LOGIN_BODY = urlencode({"username": "admin", "password": "admin123"})
DENIED_STATUSES = (401, 403)


def _auth_bypass_signal(baseline, tampered) -> bool:
    denied_without_cookie = baseline.status in DENIED_STATUSES
    allowed_with_forged_cookie = tampered.status == 200
    return denied_without_cookie and allowed_with_forged_cookie


def _cookie_flags_signal(exchange) -> bool:
    set_cookie = exchange.response_headers.get("set-cookie")
    if not set_cookie:
        return False
    lowered = set_cookie.lower()
    return "httponly" not in lowered or "secure" not in lowered


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []

    baseline = ctx.http.get(base_url + ENDPOINT)
    if baseline.status in DENIED_STATUSES:
        tampered = ctx.http.get(base_url + ENDPOINT, headers={"Cookie": FORGED_COOKIE})
        if _auth_bypass_signal(baseline, tampered):
            findings.append(
                _finding(
                    check_id=CHECK_ID,
                    title="Auth bypass via forgeable plaintext role cookie",
                    severity=Severity.HIGH,
                    cwe="CWE-807",
                    method="GET",
                    endpoint=ENDPOINT,
                    param="cookie.role",
                    payload_used=FORGED_COOKIE,
                    description=(
                        f"GET {ENDPOINT} denies anonymous access but returns 200 once the "
                        "unsigned cookie 'role=admin' is set. Authorization trusts a "
                        "client-controlled plaintext value."
                    ),
                    impact="Anyone can self-escalate to admin by setting one cookie.",
                    remediation="Store authorization server-side (signed session or opaque token).",
                    exchanges=[baseline, tampered],
                )
            )

    # The login POST is benign (same action as any user signing in) and is the
    # natural place to observe Set-Cookie hygiene.
    login = ctx.http.post(base_url + LOGIN_ENDPOINT, body=LOGIN_BODY)
    if _cookie_flags_signal(login):
        set_cookie = login.response_headers.get("set-cookie", "")
        missing = [f for f in ("HttpOnly", "Secure") if f.lower() not in set_cookie.lower()]
        findings.append(
            _finding(
                check_id="cookie-flags",
                title="Session cookie without HttpOnly/Secure flags",
                severity=Severity.LOW,
                cwe="CWE-1004",
                method="POST",
                endpoint=LOGIN_ENDPOINT,
                description=(
                    f"Set-Cookie from {LOGIN_ENDPOINT} lacks: {', '.join(missing)}. "
                    f"Cookie: {set_cookie}"
                ),
                impact="Cookie is readable by script and can travel over plaintext HTTP.",
                remediation="Set HttpOnly and Secure on session cookies.",
                exchanges=[login],
            )
        )

    return findings


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or ENDPOINT
    forged = candidate.payload_used or FORGED_COOKIE
    baseline = ctx.http.get(base_url + endpoint)
    tampered = ctx.http.get(base_url + endpoint, headers={"Cookie": forged})
    return _auth_bypass_signal(baseline, tampered)


def recheck_cookie_flags(ctx: EngineContext, base_url: str, candidate) -> bool:
    exchange = ctx.http.post(base_url + (candidate.endpoint or LOGIN_ENDPOINT), body=LOGIN_BODY)
    return _cookie_flags_signal(exchange)
