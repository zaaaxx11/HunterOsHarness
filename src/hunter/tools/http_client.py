"""Scope-gated HTTP client.

Every request passes ``ScopeSet.check_url`` before the socket opens —
fail-closed. Redirects are NOT followed automatically (open-redirect probes
need the raw 3xx), rate-limited by a minimum interval (RoE-friendly), and
every exchange is captured as a serializable dict for evidence binding.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from .scope import ScopeSet


@dataclass(frozen=True, slots=True)
class Exchange:
    """One HTTP request/response pair, evidence-ready."""

    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status: int
    response_headers: dict[str, str]
    response_body: str
    elapsed_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": dict(self.request_headers),
            "request_body": self.request_body,
            "status": self.status,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class ClientStats:
    requests: int = 0
    blocked: int = 0
    errors: int = 0

    def summary(self) -> dict[str, int]:
        return {"requests": self.requests, "blocked": self.blocked, "errors": self.errors}


class ScopedHttpClient:
    """The ONLY sanctioned way for engine/tools to touch the network."""

    def __init__(
        self,
        scope: ScopeSet,
        *,
        timeout: float = 10.0,
        min_interval: float = 0.05,
        max_body_chars: int = 40_000,
        user_agent: str = "HunterOsHarness/0.1",
        transport: httpx.BaseTransport | None = None,
        trust_env: bool = False,
    ) -> None:
        self.scope = scope
        self.stats = ClientStats()
        self._min_interval = min_interval
        self._max_body_chars = max_body_chars
        self._last_request_ts = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
            transport=transport,
            # Env proxies must never silently redirect scope-checked requests;
            # explicit proxy support lands later.
            trust_env=trust_env,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ScopedHttpClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _throttle(self) -> None:
        now = time.monotonic()
        wait = self._last_request_ts + self._min_interval - now
        if wait > 0:
            time.sleep(wait)
        self._last_request_ts = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> Exchange:
        self.scope.check_url(url)  # fail-closed BEFORE any I/O
        self._throttle()
        self.stats.requests += 1
        started = time.perf_counter()
        try:
            resp = self._client.request(
                method.upper(), url, headers=headers, content=body.encode("utf-8") if body else None
            )
            elapsed = (time.perf_counter() - started) * 1000.0
            return Exchange(
                method=method.upper(),
                url=url,
                request_headers={k.lower(): v for k, v in (headers or {}).items()},
                request_body=body or "",
                status=resp.status_code,
                response_headers={k.lower(): v for k, v in resp.headers.items()},
                response_body=resp.text[: self._max_body_chars],
                elapsed_ms=round(elapsed, 2),
            )
        except httpx.HTTPError:
            self.stats.errors += 1
            raise

    def get(self, url: str, **kw) -> Exchange:
        return self.request("GET", url, **kw)

    def post(self, url: str, *, body: str | None = None, **kw) -> Exchange:
        kw.setdefault("headers", {})
        kw["headers"].setdefault("Content-Type", "application/x-www-form-urlencoded")
        return self.request("POST", url, body=body, **kw)
