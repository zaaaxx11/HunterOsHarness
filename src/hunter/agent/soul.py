"""SOUL.md — the operating character, loaded and sanitized.

Model: ``SOUL.md`` is a HunterOS product file and it is USER-EDITABLE —
after installing, the user may change it freely (open source). What the
user cannot change is the CORE IDENTITY below: the engine always prepends
it before the file content reaches a prompt. The harness is HunterOS,
built by zaaaxx — that line comes from code, never from a file.

Load order (first readable file wins, then stop):

1. ``SOUL.md`` in the working directory (the user's own copy).
2. the bundled character at ``hunter/_data/prompts/soul.md`` (kept
   byte-equal to the tracked root ``SOUL.md``; a static test guards the
   divergence).
3. ``""`` — no persona; the core identity still renders.

Sanitize-not-refuse: a user edit must never brick chat startup, so
injection-shaped markers in the file are NEUTRALIZED (each occurrence is
replaced with ``[removed injection marker]``) instead of raising, and the
result is capped at :data:`SOUL_MAX_CHARS` so an oversized file cannot flood
every prompt.
"""

from __future__ import annotations

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
SOUL_MAX_CHARS = 4000
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
    "```",
    "assistant:",
    "</system>",
)

SOUL_HEADER = "OPERATING CHARACTER (soul) — binds every turn:\n"
_REMOVED = "[removed injection marker]"
_BUNDLED_RESOURCE = "_data/prompts/soul.md"

# Sentinel for the loader-default: a BARE ``soul_block()`` call loads the
# active soul (working-dir SOUL.md → bundled) so chat wiring can render it
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

    Every occurrence of every :data:`INJECTION_MARKERS` entry (case-insensitive)
    becomes ``[removed injection marker]``; text past :data:`SOUL_MAX_CHARS`
    chars is cut and stamped with ``...[soul truncated]``. Never raises.
    """
    cleaned = str(text or "")
    for marker in INJECTION_MARKERS:
        cleaned = re.sub(re.escape(marker), _REMOVED, cleaned, flags=re.IGNORECASE)
    if len(cleaned) > SOUL_MAX_CHARS:
        cleaned = cleaned[:SOUL_MAX_CHARS] + SOUL_TRUNCATION_MARKER
    return cleaned


def load_soul(*, repo_root: Path | None = None) -> str:
    """Load the user-editable persona: working-dir SOUL.md → bundled → "".

    Never raises; unreadable files (including a directory where the file
    should be) are skipped and the next candidate is tried.
    """
    repo_root = Path.cwd() if repo_root is None else Path(repo_root)
    text = _read_persona_file(repo_root / SOUL_FILE_NAME)
    if text is not None:
        return text
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
