"""SOUL.md — the operating character, loaded and sanitized.

Model: ``SOUL.md`` is a HunterOS product file and it is USER-EDITABLE —
after installing, the user may change it freely (open source). What the
user cannot change is the CORE IDENTITY below: the engine always prepends
it before the file content reaches a prompt. The harness is HunterOS,
built by zaaaxx — that line comes from code, never from a file.

Load order (first readable file wins, then stop):

1. ``$HUNTER_SOUL_FILE`` (or ``$HUNTEROS_SOUL``) — explicit env pin.
2. ``~/.hunter/SOUL.md`` — the unified home copy (trusted).
3. ``<cwd>/.hunter/soul.md`` — project-local UNTRUSTED, always sanitized
   and stamped; ``./SOUL.md`` at the cwd root is never loaded.
4. the bundled character at ``hunter/_data/prompts/soul.md`` (kept
   byte-equal to the tracked root ``SOUL.md``; a static test guards the
   divergence).
5. ``""`` — no persona; the core identity still renders.

Sanitize-not-refuse: a user edit must never brick chat startup, so
injection-shaped markers in the file are NEUTRALIZED (each occurrence is
replaced with ``[removed injection marker]``) instead of raising, and the
result is capped at :data:`SOUL_MAX_CHARS` so an oversized file cannot flood
every prompt.
"""

from __future__ import annotations

import base64
import os
import re
from importlib import resources
from pathlib import Path
from typing import Any

__all__ = [
    "CORE_IDENTITY",
    "INJECTION_MARKERS",
    "SOUL_FILE_NAME",
    "SOUL_MAX_CHARS",
    "SOUL_TRUNCATION_MARKER",
    "load_soul",
    "sanitize_soul",
    "soul_block",
]

# The core identity. Hardcoded in the engine — not read from any file, so no
# user edit, prompt injection, or override can rename the harness or its
# builder. Always prepended before the persona text.
CORE_IDENTITY = "You are Hunter, the HunterOS audit agent built by zaaaxx."

SOUL_FILE_NAME = "SOUL.md"
SOUL_MAX_CHARS = 8000
SOUL_TRUNCATION_MARKER = "...[soul truncated]"

# Injection-shaped markers are neutralized, never executed and never refused:
# a broken user edit must not take chat down with it (fail-open to the
# bundled character, fail-closed to injection).
INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous",
    "disregard all previous",
    "system:",
    "<system>",
    "[system]",
    "assistant:",
    "</system>",
)

SOUL_HEADER = "OPERATING CHARACTER (soul) — binds every turn:\n"
_REMOVED = "[removed injection marker]"
_BUNDLED_RESOURCE = "_data/prompts/soul.md"

# Opsi B: whitespace-tolerant injection patterns (spasi-ganda/newline safe).
_INJECTION_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+previous", re.IGNORECASE),
    re.compile(r"disregard\s+all\s+previous", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
    re.compile(r"assistant\s*:", re.IGNORECASE),
    re.compile(r"<\s*/\s*system\s*>", re.IGNORECASE),
)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _neutralize_base64_payloads(text: str) -> str:
    """Decode base64 tokens and neutralize those hiding injections (Opsi B)."""

    def _repl(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            for pattern in _INJECTION_RES:
                if pattern.search(decoded):
                    return _REMOVED
        except Exception:  # noqa: BLE001 — undecodable stays verbatim
            pass
        return token

    try:
        return _B64_RE.sub(_repl, text)
    except Exception:  # noqa: BLE001 — sanitize never raises
        return text

# Sentinel for the loader-default: a BARE ``soul_block()`` call loads the
# active soul (.hunter/soul.md → bundled) so chat wiring can render it
# without knowing the chain; an EXPLICIT ``None`` or ``""`` means "no soul"
# and renders "" (pinned by tests on both behaviors).
_UNSET: Any = object()


def _read_persona_file(path: Path) -> str | None:
    """Read one persona file; missing/unreadable entries are skipped, never raised."""
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _bundled_soul() -> str:
    """The shipped character (same importlib.resources pattern as prompts)."""
    try:  # pragma: no cover - exercised implicitly on installed packages
        return resources.files("hunter").joinpath(_BUNDLED_RESOURCE).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError, UnicodeDecodeError):
        return ""


def sanitize_soul(text: str) -> str:
    """Neutralize injection markers and cap the length.

    Every occurrence of every :data:`INJECTION_MARKERS` entry (case-insensitive,
    whitespace-tolerant via ``\\s+``) becomes ``[removed injection marker]``;
    base64 tokens decoding to an injection are neutralized the same way; text
    past :data:`SOUL_MAX_CHARS` chars is cut at a line boundary and stamped
    with ``...[soul truncated]``. The cut prefers the last ``"\\n## "``
    heading boundary inside the window, else the last ``"\\n"`` — but when
    that boundary sits more than 500 chars before the cap the cut falls back
    to the cap itself so a pathological header cannot eat the body.
    Never raises.
    """
    cleaned = _neutralize_base64_payloads(str(text or ""))
    for pattern in _INJECTION_RES:
        cleaned = pattern.sub(_REMOVED, cleaned)
    if len(cleaned) > SOUL_MAX_CHARS:
        window = cleaned[:SOUL_MAX_CHARS]
        cut: int | None = None
        heading_at = window.rfind("\n## ")
        if heading_at != -1 and SOUL_MAX_CHARS - heading_at <= 500:
            cut = heading_at + 1
        else:
            newline_at = window.rfind("\n")
            if newline_at != -1 and SOUL_MAX_CHARS - newline_at <= 500:
                cut = newline_at + 1
        if cut is None:
            cut = SOUL_MAX_CHARS
        cleaned = cleaned[:cut] + SOUL_TRUNCATION_MARKER
    return cleaned


def _default_home_soul() -> Path:
    """``~/.hunter/SOUL.md`` via the unified home when available."""
    try:
        from hunter.home import hunter_home as _hunter_home

        return _hunter_home() / SOUL_FILE_NAME
    except Exception:  # noqa: BLE001 — fall back to a plain home-derived path
        return Path.home() / ".hunter" / SOUL_FILE_NAME


def load_soul(*, repo_root: Path | None = None) -> str:
    """Load the user-editable persona, first readable file wins then stop.

    Trust priority (highest first):

    1. ``$HUNTER_SOUL_FILE`` (or ``$HUNTEROS_SOUL``) — explicit env pin,
       returned verbatim.
    2. ``~/.hunter/SOUL.md`` — the unified home copy, returned verbatim.
    3. ``<cwd>/.hunter/soul.md`` — project-local UNTRUSTED: always
       sanitized with :func:`sanitize_soul` and stamped ``[UNTRUSTED]`` so
       a hostile checkout can never inject prompts; ``./SOUL.md`` at the
       cwd root is never loaded. Mounted as user-block, never system
       verbatim.
    4. the bundled character — returned verbatim.
    5. ``""`` — no persona; the core identity still renders.

    Never raises; unreadable files (including a directory where the file
    should be) are skipped and the next candidate is tried.
    """
    repo_root = Path.cwd() if repo_root is None else Path(repo_root)
    env_pinned = os.getenv("HUNTER_SOUL_FILE") or os.getenv("HUNTEROS_SOUL")
    if env_pinned:
        text = _read_persona_file(Path(env_pinned))
        if text is not None:
            return text
    text = _read_persona_file(_default_home_soul())
    if text is not None:
        return text
    for candidate in (repo_root / ".hunter" / "soul.md", repo_root / ".hunter" / "SOUL.md"):
        text = _read_persona_file(candidate)
        if text is not None:
            return "[UNTRUSTED] project soul - sanitized\n" + sanitize_soul(text)
    return _bundled_soul()


def soul_block(text: str | None = _UNSET) -> str:
    """Render the prompt block: core identity + persona, sanitized.

    - ``soul_block()`` — load the active soul (:func:`load_soul`), sanitize
      it, and wrap it under the core identity header.
    - ``soul_block(some_text)`` — wrap the given text the same way.
    - ``soul_block(None)`` / ``soul_block("")`` — ``""``: no soul, no section.
    """
    if text is _UNSET:
        return soul_block(load_soul())
    if not text:
        return ""
    return SOUL_HEADER + CORE_IDENTITY + "\n" + sanitize_soul(text)
