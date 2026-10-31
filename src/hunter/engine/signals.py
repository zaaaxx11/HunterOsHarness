"""Exchange-signal classifier for HTTP responses.

Classifies a single HTTP exchange (or a transport/crash outcome) into one of
eight signal classes so probes can distinguish a real signal from a WAF block,
soft-404, rate-limit, or transport failure.
"""

from __future__ import annotations

from enum import Enum, EnumMeta
from typing import Any


class _SignalClassMeta(EnumMeta):
    def __getitem__(cls, name):
        try:
            return super().__getitem__(name)
        except KeyError:
            return cls(name)


class SignalClass(str, Enum, metaclass=_SignalClassMeta):
    CLEAN = "clean"
    SIGNAL = "signal"
    AMBIGUOUS = "ambiguous"
    WAF = "waf"
    SOFT_404 = "soft-404"
    RATELIMIT = "ratelimit"
    TRANSPORT = "transport"
    CRASH = "crash"

    # Convenience aliases (same value -> not separate members).
    clean = "clean"
    signal = "signal"
    ambiguous = "ambiguous"
    waf = "waf"
    soft404 = "soft-404"
    soft_404 = "soft-404"
    SOFT404 = "soft-404"
    ratelimit = "ratelimit"
    rate_limit = "ratelimit"
    RATE_LIMIT = "ratelimit"
    transport = "transport"
    crash = "crash"


WAF_MARKERS: frozenset[str] = frozenset(
    {
        "access denied",
        "request blocked",
        "cloudflare",
        "incapsula",
        "akamai",
        "mod_security",
        "forbidden",
        "waf",
    }
)

RATELIMIT_MARKERS: frozenset[str] = frozenset(
    {"rate limit", "too many requests", "throttled", "slow down"}
)

SOFT404_MARKERS: frozenset[str] = frozenset({"page not found", "not found", "404"})


def _header(headers: Any, name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return "" if value is None else str(value)
    return ""


def _body_text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", "replace")
    return str(body)


def is_waf(status_code: Any, headers: Any, body: Any) -> bool:
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        code = 0
    text = _body_text(body).lower()
    server = _header(headers, "server").lower()
    has_marker = any(marker in text or marker in server for marker in WAF_MARKERS)
    if code in (403, 406) and has_marker:
        return True
    return code == 403 and len(_body_text(body).strip()) <= 120


def is_ratelimit(status_code: Any, headers: Any, body: Any) -> bool:
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        code = 0
    if code == 429:
        return True
    text = _body_text(body).lower()
    return any(marker in text for marker in RATELIMIT_MARKERS)


def is_soft_404(status_code: Any, headers: Any, body: Any) -> bool:
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        code = 0
    if code == 404:
        return True
    text = _body_text(body).lower()
    return any(marker in text for marker in SOFT404_MARKERS)


def classify(
    status_code,
    headers,
    body,
    *,
    baseline_status=None,
    baseline_body=None,
    baseline_len=None,
    canary=None,
    error=None,
) -> SignalClass:
    if error is not None:
        lowered = f"{type(error).__name__}: {error}".lower()
        if any(token in lowered for token in ("connect", "timeout", "read")):
            return SignalClass.TRANSPORT
        return SignalClass.CRASH

    text = _body_text(body)
    try:
        code = int(status_code) if status_code is not None else 0
    except (TypeError, ValueError):
        code = 0

    if is_waf(code, headers, text):
        return SignalClass.WAF
    if is_ratelimit(code, headers, text):
        return SignalClass.RATELIMIT
    if is_soft_404(code, headers, text) and (
        code == 404 or code == 200 or baseline_status is not None
    ):
        return SignalClass.SOFT_404

    if canary is not None and str(canary) in text:
        return SignalClass.SIGNAL
    if baseline_status is not None and code != baseline_status:
        return SignalClass.SIGNAL

    base_text = _body_text(baseline_body) if baseline_body is not None else None
    base_len = baseline_len
    if base_len is None and base_text is not None:
        base_len = len(base_text)

    if base_len is not None:
        diff = abs(len(text) - int(base_len))
        threshold = 0.1 * int(base_len)
        if diff > threshold and (base_text is None or text != base_text):
            return SignalClass.SIGNAL

    has_baseline = (
        baseline_status is not None or baseline_body is not None or baseline_len is not None
    )
    if has_baseline:
        status_matches = baseline_status is None or code == baseline_status
        if status_matches:
            if base_text is not None and text != base_text:
                if base_len is None:
                    return SignalClass.AMBIGUOUS
                diff = abs(len(text) - int(base_len))
                if diff <= 0.1 * int(base_len):
                    return SignalClass.AMBIGUOUS
            elif base_text is None and base_len is not None:
                diff = abs(len(text) - int(base_len))
                threshold = 0.1 * int(base_len)
                if 0 < diff <= threshold:
                    return SignalClass.AMBIGUOUS

    return SignalClass.CLEAN
