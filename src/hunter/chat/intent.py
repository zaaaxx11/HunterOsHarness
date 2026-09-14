"""Hunt-intent classification — PURE, never I/O.

:class:`IntentRouter` decides whether one free-text chat line is asking for a
governed hunt. The rule is deliberately dumb: a hunt keyword AND a target-like
token must co-occur in the same line. The regexes classify text; they never
execute, resolve, fetch, or stat a target.

Target table (mirrors Strix ``looksLikeTarget``):

1. URLs — ``https?://...`` (kind ``"url"``).
2. Validated IPv4 + ``localhost`` (kinds ``"ip"`` / ``"host"``).
3. Bare domains with file-extension / version-number exclusions (kind ``"host"``).
4. Windows + POSIX filesystem path shapes (kind ``"path"``, shape-only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["HuntIntent", "IntentRouter", "HUNT_KEYWORDS", "classify"]


@dataclass(frozen=True)
class HuntIntent:
    target: str | None  # leftmost target-like token, punctuation-stripped
    kind: str  # "url" | "host" | "ip" | "path" | "none"
    is_hunt: bool
    confidence: str  # "high" | "low" | "none"
    matched: list[str]  # every matched keyword phrase AND target token, text order


# Normative EN/ID keyword table (§2.2). Multi-word phrases match as
# case-insensitive substrings; single words match with word boundaries and the
# inflections in _STEM_INFLECTIONS.
HUNT_KEYWORDS: tuple[str, ...] = (
    "audit",
    "hunt",
    "scan",
    "pentest",
    "pen test",
    "pen-test",
    "find vulnerabilities",
    "find vulnerability",
    "security check",
    "security review",
    "break into",
    "attack surface",
    "vulnerability assessment",
    "cek keamanan",
    "cari celah",
    "keamanan",
    "tembus",
    "uji keamanan",
    "tes keamanan",
)

# Common file extensions in the TLD slot: prose files, never targets.
_NON_TARGET_TLDS = frozenset((
    "md", "txt", "py", "json", "yaml", "yml", "html", "htm", "css", "js", "ts",
    "csv", "log", "png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls",
    "xlsx", "zip", "tar", "gz", "cfg", "ini", "env", "lock", "sh", "bat", "ps1",
    "db", "sqlite", "toml",
))

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_LOCALHOST_RE = re.compile(r"\blocalhost(?::\d{1,5})?\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:/[^\s]*)?",
    re.IGNORECASE,
)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\s]+")
_POSIX_PATH_RE = re.compile(r"(?:~/|\./|\.\./|/)[^\s]+")

# Trailing sentence punctuation stripped from URL tokens.
_URL_TRAIL = ".,;:!?)\"'"

# Single-word stems and their inflections; every other single word matches
# with plain word boundaries.
_STEM_INFLECTIONS = {
    "audit": r"audit(?:s|ed|ing)?",
    "hunt": r"hunt(?:s|ed|ing)?",
    "scan": r"scan(?:s|ned|ning)?",
}


def _keyword_regex(keyword: str) -> re.Pattern[str]:
    """Compile one keyword entry: phrases are substrings, words are bounded."""
    if " " in keyword or "-" in keyword:
        return re.compile(re.escape(keyword), re.IGNORECASE)
    stem = _STEM_INFLECTIONS.get(keyword.lower())
    if stem is not None:
        return re.compile(rf"\b{stem}\b", re.IGNORECASE)
    return re.compile(rf"\b{re.escape(keyword)}\b", re.IGNORECASE)


def _valid_ipv4(token: str) -> bool:
    """Every octet must be ≤ 255 (validated, not just matched)."""
    host = token.split(":", 1)[0]
    try:
        return all(0 <= int(octet) <= 255 for octet in host.split("."))
    except ValueError:  # pragma: no cover — the regex only yields digits
        return False


def _domain_allowed(token: str) -> bool:
    """Reject file-extension lookalikes in the TLD slot."""
    host = token.split(":", 1)[0].split("/", 1)[0]
    if "." not in host:
        return False
    return host.rsplit(".", 1)[1].lower() not in _NON_TARGET_TLDS


class IntentRouter:
    """Pure classifier: keyword AND target co-occurrence means hunt."""

    def __init__(self, *, keywords: tuple[str, ...] = HUNT_KEYWORDS) -> None:
        self.keywords = keywords
        self._patterns = [(keyword, _keyword_regex(keyword)) for keyword in keywords]

    def classify(self, text: str) -> HuntIntent:
        text = text or ""
        # (start, token, kind, is_target) in text order — keywords and targets
        # share one timeline so `matched` reads left to right.
        hits: list[tuple[int, str, str | None]] = []
        targets: list[tuple[int, str, str]] = []

        for start, _end, token, kind in self._find_targets(text):
            targets.append((start, token, kind))
            hits.append((start, token, kind))

        for _keyword, pattern in self._patterns:
            for match in pattern.finditer(text):
                hits.append((match.start(), match.group(0), None))

        hits.sort(key=lambda hit: hit[0])
        matched = [token for _, token, _ in hits]

        has_keyword = any(kind is None for _, _, kind in hits)
        if targets and has_keyword:
            start, token, kind = targets[0]
            return HuntIntent(target=token, kind=kind, is_hunt=True,
                              confidence="high", matched=matched)
        if targets or has_keyword:
            target, kind = (targets[0][1], targets[0][2]) if targets else (None, "none")
            return HuntIntent(target=target, kind=kind, is_hunt=False,
                              confidence="low", matched=matched)
        return HuntIntent(target=None, kind="none", is_hunt=False,
                          confidence="none", matched=[])

    def _find_targets(self, text: str) -> list[tuple[int, int, str, str]]:
        """Target spans in text order. Each pattern runs on text with the
        earlier patterns' spans blanked out (no double-counting)."""
        found: list[tuple[int, int, str, str]] = []
        work = text

        def _claim(pattern: re.Pattern[str], kind: str,
                   accept=None) -> None:
            nonlocal work
            for match in pattern.finditer(work):
                raw = match.group(0)
                token = raw.rstrip(_URL_TRAIL) if kind == "url" else raw
                if accept is not None and not accept(token):
                    continue
                start = match.start()
                found.append((start, match.end(), token, kind))
                work = work[:start] + " " * (match.end() - start) + work[match.end():]

        _claim(_URL_RE, "url")
        _claim(_LOCALHOST_RE, "host")
        _claim(_IPV4_RE, "ip", accept=_valid_ipv4)
        _claim(_DOMAIN_RE, "host", accept=_domain_allowed)
        _claim(_WIN_PATH_RE, "path")
        _claim(_POSIX_PATH_RE, "path")
        found.sort(key=lambda span: span[0])
        return found


def classify(text: str) -> HuntIntent:
    """Convenience: ``IntentRouter().classify(text)`` with the default table."""
    return IntentRouter().classify(text)
