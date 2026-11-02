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
from urllib.parse import urljoin, urlparse

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

# ``0.0.0.0`` is the unspecified/all-interfaces address, not loopback: dialing
# it resolves differently across platforms (Linux frequently connects to
# localhost, Windows/other stacks do not). It is deliberately NOT implicitly
# authorized — a target using it needs an explicit scope manifest.
UNSPECIFIED_HOSTS = frozenset({"0.0.0.0", "::", "[::]"})


class ScopeViolation(PermissionError):
    """Raised when a request targets a host outside the authorized scope."""


def _normalize_host(host: str | None) -> str:
    if host is None:
        return ""
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):  # ipv6 literal
        host = host[1:-1]
    return host


# A model habitually glues the scheme onto the host when it drops the "://"
# ("rpc.example.com" + "https" -> "rpc.example.comhttps"). Detect that exact
# malformation so check_url can repair it instead of refusing on a nonsense
# host and wasting the rest of the run.
_GLUED_SCHEME_SUFFIXES = ("https", "http")


def _unglue_scheme(candidate: str) -> str | None:
    """Return the repaired URL when the scheme is glued onto the host.

    ``rpc.example.comhttps`` -> ``https://rpc.example.com``
    ``rpc.example.comhttps/v1`` -> ``https://rpc.example.com/v1``

    A glued scheme is ``<host><https>://<path>`` — the ``://`` comes FROM the
    scheme that is stuck to the host, so checking ``"://" in candidate`` and
    bailing BEFORE ungluing rejects the very malformation it was written to
    repair. One run recorded ``api.relay.linkhttps://v1/status`` producing a
    ScopeViolation at second 3588 — 156 evidence items and one finding lost
    because the last http_request hit a host the scope refused.

    Unglue first. THEN refuse already-valid URLs.
    """
    if not candidate or candidate.startswith("/"):
        return None
    head, sep, tail = candidate.partition("/")
    host_part = head.lower()
    for scheme in _GLUED_SCHEME_SUFFIXES:
        # Two shapes: <host><scheme>         (no ://) → api.relay.linkhttps
        #             <host><scheme>:        (:// split) → api.relay.linkhttps://v1
        #
        # In the second shape partition yields head="…https:", sep="/",
        # tail="/v1". Tail already starts with '/' so we never re-add sep;
        # adding it yields "https://api.relay.link//v1".
        if host_part.endswith(scheme) and len(host_part) > len(scheme):
            bare = head[: -len(scheme)]
            tail_sfx = sep + tail if sep else ""
        elif host_part.endswith(scheme + ":") and len(host_part) > len(scheme) + 1:
            bare = head[: -(len(scheme) + 1)]
            tail_sfx = tail  # already starts with '/'
        else:
            continue
        if bare.endswith(".") or "." not in bare:
            return None
        return f"{scheme}://{bare}" + tail_sfx
    if "://" in candidate:
        return None
    return None


@dataclass(frozen=True)
class ScopeSet:
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allow_subdomains: bool = False
    name: str = "default"
    local_roots: tuple[str, ...] = field(default_factory=tuple)

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

    def check_url(self, url: str, *, base_url: str = "") -> str:
        """Return the host when in scope; raise ScopeViolation otherwise.

        Fail-closed: missing host, unknown schemes, and URLs that cannot even
        be parsed (e.g. a malformed IPv6 literal, which makes ``urlparse``
        raise ``ValueError``) are all violations — silence is not consent, and
        the failure type is always ScopeViolation.

        Two convenience repairs, both of which STILL pass through the host
        allowlist below (a repair can never widen scope):

        * a scheme-less absolute reference (``rpc.example.com/path``) is
          retried as ``https://`` — models habitually drop the scheme, and the
          old path produced a nonsense host like ``rpc.example.comhttps``
          instead of a clear refusal;
        * a URL where the scheme got glued onto the host
          (``rpc.example.comhttps``) is un-glued first, so the run keeps going
          instead of dying on a typo;
        * a root-relative path (``/v1/status``) is joined onto ``base_url``.
        """
        candidate = (url or "").strip()
        if not candidate:
            raise ScopeViolation("BLOCKED: empty URL")

        unglued = _unglue_scheme(candidate)
        if unglued is not None:
            candidate = unglued

        parsed = self._parse(candidate)
        if not (parsed.scheme in ("http", "https") and parsed.hostname):
            if base_url and candidate.startswith("/"):
                joined = urljoin(base_url, candidate)
                parsed = self._parse(joined)
                candidate = joined
            elif not parsed.scheme and not candidate.startswith("/"):
                # Scheme-less absolute reference: assume https and re-parse.
                parsed = self._parse(f"https://{candidate}")
                candidate = f"https://{candidate}"

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

    @staticmethod
    def _parse(url: str):
        """``urlparse`` that turns a ValueError into a ScopeViolation."""
        try:
            return urlparse(url)
        except ValueError as exc:
            raise ScopeViolation(f"BLOCKED: URL could not be parsed ({url!r}): {exc}") from exc

    def allows_local_root(self, path: str | Path) -> bool:
        """True when ``path`` resolves inside one of the configured local roots."""
        try:
            resolved = Path(path).resolve()
        except (OSError, RuntimeError, ValueError):
            return False
        for root in self.local_roots:
            try:
                root_resolved = Path(root).resolve()
            except (OSError, RuntimeError, ValueError):
                continue
            try:
                resolved.relative_to(root_resolved)
                return True
            except ValueError:
                continue
        # Absent local_roots -> permissive (backward-compatible localhost behaviour).
        return bool(not self.local_roots)

    def summary(self) -> dict:
        return {
            "name": self.name,
            "hosts": sorted(self.allowed_hosts),
            "allow_subdomains": self.allow_subdomains,
            "localhost": True,
            "local_roots": list(self.local_roots),
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
    local_roots = raw.get("local_roots", [])
    if not isinstance(local_roots, list):
        raise ValueError("local_roots must be a list")
    if (not isinstance(hosts, list) or not hosts) and not local_roots:
        raise ValueError("scope manifest must contain hosts or local_roots")
    if not isinstance(hosts, list):
        hosts = []
    return ScopeSet(
        allowed_hosts=frozenset(str(h).strip().lower() for h in hosts),
        allow_subdomains=bool(raw.get("allow_subdomains", False)),
        name=str(raw.get("name", Path(path).stem)),
        local_roots=tuple(str(r) for r in local_roots),
    )
