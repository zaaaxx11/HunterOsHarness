"""Fail-closed scope enforcement — structural, not prompt-based.

Every network-bearing operation MUST pass through :meth:`ScopeSet.check_url`
before execution. Localhost (127.0.0.1 / ::1 / localhost) is always allowed —
it is the demo and test surface and cannot constitute out-of-scope harm. Any
other host requires an explicit allowlist from a scope manifest.

Host matching is EXACT: the URL's parsed hostname (case-folded, userinfo and
brackets stripped by ``urlparse``) must equal a localhost literal or an
allowlist entry. The gate deliberately does NOT resolve DNS and does NOT
recognize loopback aliases (decimal ``2130706433``, hex ``0x7f000001``,
shorthand ``127.1``, IPv4-mapped IPv6, trailing-dot FQDNs): an alias that is
not an exact match is blocked. Fail-closed over convenience.

The gate lives in the HTTP client (and any future network tool), NOT in
prompts: a prompt injection cannot make the harness request an out-of-scope
host because the check happens in code before the socket opens.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


class ScopeViolation(PermissionError):
    """Raised when a request targets a host outside the authorized scope."""


def _normalize_host(host: str | None) -> str:
    if host is None:
        return ""
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):  # ipv6 literal
        host = host[1:-1]
    return host


@dataclass(frozen=True)
class ScopeSet:
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allow_subdomains: bool = False
    name: str = "default"

    def allows_host(self, host: str | None) -> bool:
        normalized = _normalize_host(host)
        if not normalized:
            return False
        if normalized in LOCAL_HOSTS:
            return True
        for allowed in self.allowed_hosts:
            if normalized == allowed:
                return True
            if self.allow_subdomains and normalized.endswith("." + allowed):
                return True
        return False

    def check_url(self, url: str) -> str:
        """Return the host when in scope; raise ScopeViolation otherwise.

        Fail-closed: missing scheme, missing host, unknown schemes, and URLs
        that cannot even be parsed (e.g. a malformed IPv6 literal, which makes
        ``urlparse`` raise ``ValueError``) are all violations — silence is not
        consent, and the failure type is always ScopeViolation.
        """
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            raise ScopeViolation(f"BLOCKED: URL could not be parsed ({url!r}): {exc}") from exc
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolation(f"BLOCKED: scheme '{parsed.scheme or '-'}' not allowed ({url!r})")
        host = _normalize_host(parsed.hostname)
        if not host:
            raise ScopeViolation(f"BLOCKED: URL has no host ({url!r})")
        if not self.allows_host(host):
            raise ScopeViolation(
                f"BLOCKED: host '{host}' is out of scope (scope={self.name!r}). "
                "Add it to the scope manifest to authorize."
            )
        return host

    def summary(self) -> dict:
        return {
            "name": self.name,
            "hosts": sorted(self.allowed_hosts),
            "allow_subdomains": self.allow_subdomains,
            "localhost": True,
        }


def localhost_scope() -> ScopeSet:
    """Scope for demo/tests: loopback only."""
    return ScopeSet(frozenset(), name="localhost-only")


def scope_from_manifest(path: str | Path) -> ScopeSet:
    """Load a scope manifest (JSON).

    Schema::

        {
          "name": "client-x",
          "hosts": ["example.com", "api.example.com"],
          "allow_subdomains": false
        }
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    hosts = raw.get("hosts", [])
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("scope manifest must contain a non-empty 'hosts' list")
    return ScopeSet(
        allowed_hosts=frozenset(str(h).strip().lower() for h in hosts),
        allow_subdomains=bool(raw.get("allow_subdomains", False)),
        name=str(raw.get("name", Path(path).stem)),
    )
