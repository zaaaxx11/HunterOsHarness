"""SOUL.md — the operating character, loaded and sanitized.

Precedence (first readable file wins, then stop):

1. ``~/.hunteros/SOUL.local.md`` — the owner's private persona. It is
   gitignored BY DESIGN: it never leaves the machine.
2. ``SOUL.local.md`` in the working directory (repo override).
3. the bundled general character at ``hunter/_data/prompts/soul.md``
   (kept byte-equal to the tracked root ``SOUL.md``; a static test
   guards the divergence).
4. ``""`` — no soul; every prompt renders unchanged.

Sanitize-not-refuse: a personal override must never brick chat startup, so
injection-shaped markers in an override are NEUTRALIZED (each occurrence is
replaced with ``[removed injection marker]``) instead of raising, and the
result is capped at :data:`SOUL_MAX_CHARS` so an oversized file cannot flood
every prompt. The bundled soul is trusted content, but it goes through the
same sanitizer for one invariant: what reaches a prompt is always
post-sanitize text.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

__all__ = [
    "INJECTION_MARKERS",
    "SOUL_LOCAL_HOME",
    "SOUL_LOCAL_REPO",
    "SOUL_MAX_CHARS",
    "SOUL_TRUNCATION_MARKER",
    "load_soul",
    "sanitize_soul",
    "soul_block",
]

# The owner's private persona: HOME-relative (gitignored at both spellings).
SOUL_LOCAL_HOME = Path("~/.hunteros/SOUL.local.md")
SOUL_LOCAL_REPO = Path("SOUL.local.md")  # cwd-relative repo override
SOUL_MAX_CHARS = 4000
SOUL_TRUNCATION_MARKER = "...[soul truncated]"

# Injection-shaped markers are neutralized, never executed and never refused:
# a broken override must not take chat down with it (fail-open to the bundled
# character, fail-closed to injection).
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
# active soul (home → repo → bundled) so chat wiring can render it without
# knowing the precedence chain; an EXPLICIT ``None`` or ``""`` means "no
# soul" and renders "" (pinned by tests on both behaviors).
_UNSET: Any = object()


def _local_home_path(home: Path | None) -> Path:
    """Resolve the HOME persona path (``~/.hunteros/SOUL.local.md`` shape)."""
    if home is None:
        return SOUL_LOCAL_HOME.expanduser()
    return Path(home) / SOUL_LOCAL_HOME.parent.name / SOUL_LOCAL_HOME.name


def _read_persona_file(path: Path) -> str | None:
    """Read one persona file; missing/unreadable entries are skipped, never raised."""
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _bundled_soul() -> str:
    """The shipped general character (same importlib.resources pattern as prompts)."""
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


def load_soul(*, home: Path | None = None, repo_root: Path | None = None) -> str:
    """Load the operating character: HOME persona → repo persona → bundled → "".

    Never raises; unreadable files (including a directory where the file should
    be) are skipped and the next candidate is tried.
    """
    repo_root = Path.cwd() if repo_root is None else Path(repo_root)
    for path in (_local_home_path(home), repo_root / SOUL_LOCAL_REPO):
        text = _read_persona_file(path)
        if text is not None:
            return text
    return _bundled_soul()


def soul_block(text: str | None = _UNSET) -> str:
    """Render the prompt block for the operating character.

    - ``soul_block()`` — load the active soul (:func:`load_soul` precedence),
      sanitize it, and wrap it in the header.
    - ``soul_block(some_text)`` — wrap the given text in the header.
    - ``soul_block(None)`` / ``soul_block("")`` — ``""``: no soul, no section.
    """
    if text is _UNSET:
        return soul_block(load_soul())
    if not text:
        return ""
    return SOUL_HEADER + sanitize_soul(text)
