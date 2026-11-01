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


# -- per-role souls --------------------------------------------------------------
#
# One soul per worker role, so a delegated sub-agent opens with the character of
# its specialty instead of the orchestrator's. Resolution order (highest first):
#
# 1. ``~/.hunter/souls/<role>.md`` — operator override, trusted, verbatim.
# 2. ``$HUNTER_SOULS_DIR/<role>.md`` — explicit dir pin, trusted, verbatim.
# 3. bundled ``_data/prompts/souls/<role>.md`` — ships with the harness.
# 4. the shared soul (:func:`load_soul`) — a role without a card still gets an
#    identity rather than an empty system prompt.
#
# A role is part of the path, so it is validated as a strict identifier: a
# crafted role like ``../../etc/passwd`` must never reach the filesystem.

_ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

# Per-role soul budget. A worker's character is worth its context, but not more
# than this: the cap keeps a bloated card from crowding out the tools, skills and
# evidence the worker actually needs. Enforced on the rendered block.
#
# Deliberately generous — a well-written card runs 300-400 tokens, so 5000 is
# pure headroom for a verbose operator override rather than a working limit.
# It exists only to stop a runaway file from eating the whole context window.
ROLE_SOUL_MAX_TOKENS = 5000


def _valid_role(role: str) -> str:
    clean = (role or "").strip().lower()
    if not _ROLE_RE.match(clean):
        raise ValueError(f"invalid role name: {role!r}")
    return clean


def _role_soul_candidates(role: str) -> list[Path]:
    out: list[Path] = []
    env_dir = os.getenv("HUNTER_SOULS_DIR") or os.getenv("HUNTEROS_SOULS_DIR")
    if env_dir:
        out.append(Path(env_dir) / f"{role}.md")
    try:
        from hunter.home import hunter_home as _hunter_home

        out.append(_hunter_home() / "souls" / f"{role}.md")
    except Exception:  # noqa: BLE001
        out.append(Path.home() / ".hunter" / "souls" / f"{role}.md")
    bundled_dir = Path(__file__).resolve().parent.parent / "_data" / "prompts" / "souls"
    out.append(bundled_dir / f"{role}.md")
    return out


def load_role_soul(role: str, *, fallback_to_shared: bool = True) -> str:
    """Persona text for one worker role. Never raises."""
    try:
        role = _valid_role(role)
    except ValueError:
        role = "redteam"
    for candidate in _role_soul_candidates(role):
        text = _read_persona_file(candidate)
        if text is not None:
            return text
    if fallback_to_shared:
        try:
            return load_soul()
        except Exception:  # noqa: BLE001
            return ""
    return ""


def role_soul_block(role: str, *, max_tokens: int = ROLE_SOUL_MAX_TOKENS) -> str:
    """Full prompt block (headers + identity + card) for a worker role.

    Hard-capped at ``max_tokens``: a bloated card is trimmed at a line boundary
    rather than silently eating the child's context budget. The cap is enforced
    on the RENDERED block, not just the card file, because the headers and core
    identity are part of what the child actually pays for.
    """
    text = load_role_soul(role)
    if not text:
        return ""
    header = (
        "# SOUL — role-scoped\n\n"
        f"You are running as the **{role}** worker. The card below is your\n"
        "character for this task; the core identity still applies.\n\n"
    )
    block = header + CORE_IDENTITY + "\n" + sanitize_soul(text)
    return _cap_tokens(block, max_tokens)


def _count_tokens(text: str) -> int:
    """Token count for a prompt fragment, with a cheap fallback.

    Prefers the real BPE tokenizer when it is installed; otherwise falls back to
    a conservative chars/4 estimate, which over-counts for prose and therefore
    errs on the safe side of the cap.
    """
    try:
        import tiktoken  # type: ignore

        return len(tiktoken.get_encoding("cl100k_base").encode(text))
    except Exception:  # noqa: BLE001
        return (len(text) + 3) // 4


def _cap_tokens(block: str, max_tokens: int) -> str:
    """Trim ``block`` at a line boundary until it fits within ``max_tokens``."""
    if max_tokens <= 0:
        return block
    if _count_tokens(block) <= max_tokens:
        return block
    lines = block.splitlines()
    kept: list[str] = []
    for line in lines:
        candidate = "\n".join(kept + [line])
        if _count_tokens(candidate) > max_tokens:
            break
        kept.append(line)
    trimmed = "\n".join(kept).rstrip()
    note = f"\n\n[TRUNCATED at {max_tokens} tokens]"
    return trimmed + note


def available_roles() -> list[str]:
    """Every role that has a resolvable soul card on disk."""
    roles: set[str] = set()
    for candidate in _role_soul_candidates("__probe__"):
        directory = candidate.parent
        try:
            for entry in directory.iterdir():
                if entry.suffix == ".md" and _ROLE_RE.match(entry.stem):
                    roles.add(entry.stem)
        except OSError:
            continue
    return sorted(roles)
