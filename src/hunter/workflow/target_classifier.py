"""Target classifier and contract grouper.

Deterministic classification of hunt targets into ``api`` / ``web`` / ``repo`` /
``contract`` / ``bridge_path``, plus subdomain merging and Solidity contract
family grouping. Everything is fail-closed: unrecognized targets fall back to
a safe classification instead of raising.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# A bridge_path is a URL that looks like a deposit→mint flow entrypoint.
_BRIDGE_PATH_PATTERNS = [
    r"(?:^|/|\.)bridge(?:/|$|-)",
    r"(?:^|/|\.)deposit(?:/|$|-)",
    r"(?:^|/|\.)mint(?:/|$|-)",
    r"(?:^|/|\.)lock(?:/|$|-)",
    r"(?:^|/|\.)transfer(?:/|$|-)",
    r"(?:^|/|\.)send(?:/|$|-)",
    r"(?:^|/|\.)relay(?:/|$|-)",
]

# Hostnames that START with these keywords are bridge_path entrypoints
# regardless of path.  The `.` after the keyword anchors the subdomain boundary.
_BRIDGE_HOST_PREFIXES = ("bridge.", "deposit.", "mint.", "lock.")


def classify_target(target: str) -> str:
    """Return the classification for a single target string.

    Returns one of: ``api``, ``web``, ``repo``, ``contract``, ``bridge_path``,
    or ``unknown``.

    Classification rules (first match wins):

    * ``github.com/<owner>/<repo>`` → ``repo``
    * Local directory containing ``.sol`` files → ``contract``
    * ``https?://api.*`` → ``api``
    * ``https?://docs.*`` or ``*.link`` → ``web``
    * URL matching deposit/mint/bridge/transfer patterns → ``bridge_path``
    * Any other HTTP(S) URL → ``api`` (safe default)
    * Everything else → ``unknown``
    """
    token = (target or "").strip()
    if not token:
        return "unknown"

    # --- GitHub repo --------------------------------------------------------
    if _is_github_repo(token):
        return "repo"

    # --- Local contract directory -------------------------------------------
    path = Path(token).expanduser()
    try:
        if path.is_dir():
            sol_files = list(path.glob("*.sol"))
            if sol_files:
                return "contract"
    except OSError:
        pass

    # --- URL-based ----------------------------------------------------------
    parsed = urlparse(token)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()

    if scheme not in ("http", "https"):
        # Re-parse with https:// for scheme-less bare hosts (api.relay.link)
        if not host and "." in token and not token.startswith("/"):
            reparsed = urlparse(f"https://{token}")
            host = (reparsed.hostname or "").lower()
            scheme = reparsed.scheme.lower()
        if scheme not in ("http", "https"):
            if host:
                return _classify_by_host(host, token)
            return "unknown"

    if not host:
        return "unknown"

    # bridge_path patterns in path — must be checked BEFORE domain-based
    # rules because *.link domains may also carry bridge paths.
    path_part = (parsed.path or "").lower()
    if _matches_bridge(path_part) or host.startswith(_BRIDGE_HOST_PREFIXES):
        return "bridge_path"

    # api.* pattern
    if host.startswith("api.") or host.startswith("api-"):
        return "api"

    # docs.* or *.link pattern (shallow: at most 3 labels so
    # ``rpc.chain.relay.link`` stays ``api``, not ``web``).
    if host.startswith("docs.") or host.startswith("doc.") or _is_wildcard_link(host):
        return "web"

    # Default for HTTP(S): api
    return "api"


def _is_github_repo(token: str) -> bool:
    """Check if token is a GitHub repo URL or owner/repo shorthand."""
    parsed = urlparse(token)
    host = (parsed.hostname or "").lower()
    if host in ("github.com", "www.github.com"):
        path = (parsed.path or "").strip("/")
        parts = path.split("/")
        return len(parts) >= 2 and all(parts[:2])

    # owner/repo shorthand (no scheme)
    if not parsed.scheme:
        clean = token.strip().lstrip("/")
        parts = clean.split("/")
        if len(parts) == 2 and "/" not in parts[0].split(".") and "/" not in parts[1].split("."):
            # Heuristic: looks like owner/repo, not a domain/path
            if not _looks_like_domain(parts[0]):
                return True

    return False


def _looks_like_domain(s: str) -> bool:
    """Return True if string looks like a domain name."""
    return "." in s and not s.startswith("/") and len(s) > 3


def _classify_by_host(host: str, full: str) -> str:
    """Classify a URL that had no scheme (parsed as host-only)."""
    if host.startswith("api.") or host.startswith("api-"):
        return "api"
    if host.startswith("docs.") or host.startswith("doc.") or _is_wildcard_link(host):
        return "web"
    if _matches_bridge(full.lower()):
        return "bridge_path"
    return "api"


def _is_wildcard_link(host: str) -> bool:
    """True when ``host`` matches the ``*.link`` pattern (shallow: ≤ 3 labels)."""
    if not host.endswith(".link"):
        return False
    # ``relay.link`` (2 labels), ``docs.relay.link`` (3 labels) → web
    # ``rpc.chain.relay.link`` (4+ labels) → too deep for *.link wildcard
    return host.count(".") <= 2


def _matches_bridge(text: str) -> bool:
    """Check if text matches any bridge_path pattern."""
    text_lower = text.lower()
    for pat in _BRIDGE_PATH_PATTERNS:
        if re.search(pat, text_lower):
            return True
    return False


# ---------------------------------------------------------------------------
# Subdomain merge
# ---------------------------------------------------------------------------


def _extract_domain(host: str) -> str:
    """Return the registrable domain for a hostname.

    ``api.relay.link`` → ``relay.link``
    ``docs.relay.link`` → ``relay.link``
    ``relay.link`` → ``relay.link``
    """
    host = host.strip().lower()
    # Special TLDs: .link, .com, .org, .io, etc.
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Simple heuristic: last two parts
    return ".".join(parts[-2:])


def expand_targets(
    raw_targets: list[str],
    allow_subdomains: bool = False,
) -> list[dict]:
    """Expand and merge a list of raw target strings into task descriptors.

    Each task dict has:

    * ``target`` — the primary target string
    * ``kind`` — classification (api/web/repo/contract/bridge_path/unknown)
    * ``hosts`` — list of hostnames involved
    * ``subdomain_of`` — the root domain when subdomain merging is active

    When ``allow_subdomains`` is True, targets whose hostnames share the same
    registrable domain are merged into a single wildcard task
    (e.g. ``*.relay.link``).
    """
    if not raw_targets:
        return []

    tasks: list[dict[str, Any]] = []
    by_domain: dict[str, list[dict[str, Any]]] = {}

    for raw in raw_targets:
        kind = classify_target(raw)
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()

        # Re-parse bare hosts (api.relay.link) that urlparse puts in path
        if not host and "." in raw and not raw.startswith("/"):
            reparsed = urlparse(f"https://{raw}")
            host = (reparsed.hostname or "").lower()

        task: dict[str, Any] = {
            "target": raw,
            "kind": kind,
            "hosts": [host] if host else [],
        }

        if allow_subdomains and host:
            domain = _extract_domain(host)
            task["subdomain_of"] = domain
            by_domain.setdefault(domain, []).append(task)
        else:
            tasks.append(task)

    if allow_subdomains and by_domain:
        for domain, domain_tasks in by_domain.items():
            if len(domain_tasks) > 1:
                # Merge: create one wildcard task
                all_hosts: list[str] = []
                kinds: set[str] = set()
                for dt in domain_tasks:
                    all_hosts.extend(dt["hosts"])
                    kinds.add(dt["kind"])
                merged_kind = _merge_kinds(kinds)
                tasks.append({
                    "target": f"*.{domain}",
                    "kind": merged_kind,
                    "hosts": sorted(set(all_hosts)),
                    "subdomain_of": domain,
                    "merged": True,
                })
            else:
                tasks.append(domain_tasks[0])

    return tasks


def _merge_kinds(kinds: set[str]) -> str:
    """Pick the most specific kind from a set."""
    priority = ["bridge_path", "api", "web", "repo", "contract", "unknown"]
    for p in priority:
        if p in kinds:
            return p
    return "unknown"


# ---------------------------------------------------------------------------
# Contract families
# ---------------------------------------------------------------------------

# Family → set of root contract names (matching is prefix/substring-aware).
CONTRACT_FAMILIES: dict[str, set[str]] = {
    "hub": {"RelayHub", "HubBase", "ERC20View", "ERC20Permit"},
    "oracle": {"RelayOracleV2", "RelayOracleMultisig", "RelayOracleIdempotencyStore"},
    "depository": {"RelayDepository", "RelayExecutor", "RelayGatewayDepository"},
    "allocator": {"RelayAllocator", "WithdrawGasPayer"},
    "payload": {"PayloadBuilder", "GatewayVm", "GasPaid", "EmptyPayload"},
    "pricing": {"RelayPriceOracle", "RelayBpsFeeCalculator", "SignedPricingOracle"},
    "rate_limit": {"RelayUsdRateLimiter", "RelayAmountRateLimiter"},
    "mapping": {"RelayGenericMapping", "GenericMappingBase"},
    "funding": {"RelayFundingPool", "RelayFundingPoolFactory"},
}

# Reverse index: contract root name → family
_CONTRACT_TO_FAMILY: dict[str, str] = {}
for _family, _names in CONTRACT_FAMILIES.items():
    for _name in _names:
        _CONTRACT_TO_FAMILY[_name] = _family


def _classify_contract_name(filename: str) -> str | None:
    """Return the family for a contract filename, or None."""
    # Strip extension and path
    stem = Path(filename).stem
    for name, family in _CONTRACT_TO_FAMILY.items():
        if stem == name or stem.startswith(name):
            return family
    return None


def group_contracts(contract_dir: str) -> list[dict]:
    """Group ``.sol`` contracts in a directory into their families.

    Returns a list of dicts, each with:

    * ``family`` — one of the 9 families (hub, oracle, depository, ...)
    * ``contracts`` — list of relative contract filenames in that family
    * ``count`` — number of contracts in the group

    Contracts that don't match any family are placed in an ``unclassified``
    group (omitted when empty).
    """
    root = Path(contract_dir).expanduser().resolve()
    if not root.is_dir():
        return []

    families: dict[str, list[str]] = {}
    unmatched: list[str] = []

    for sol_file in sorted(root.rglob("*.sol")):
        rel = sol_file.relative_to(root).as_posix()
        family = _classify_contract_name(sol_file.name)
        if family:
            families.setdefault(family, []).append(rel)
        else:
            unmatched.append(rel)

    result: list[dict] = []
    for family_name in [
        "hub", "oracle", "depository", "allocator",
        "payload", "pricing", "rate_limit", "mapping", "funding",
    ]:
        if family_name in families:
            result.append({
                "family": family_name,
                "contracts": families[family_name],
                "count": len(families[family_name]),
            })

    if unmatched:
        result.append({
            "family": "unclassified",
            "contracts": unmatched,
            "count": len(unmatched),
        })

    return result