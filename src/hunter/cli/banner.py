"""HUNT startup banner renderer.

The banner artwork is precomputed text (``/home/simon/hunt_banner.txt``);
this module only *colours* it, so there is no dependency on ``pyfiglet`` or
any other font renderer.

Colour contract
---------------
============================  ==================
glyph class                   theme role
============================  ==================
box drawing ``╔ ╗ ╚ ╝ ║ ═``  ``primary_deep``
blocks ``█ ▀ ▄``              ``primary``
face glyphs ``* % # @``       ``primary``
structures ``+ = — -``        ``primary_dim``
shading ``. : , '``           ``primary_deep``
``Autonomous Security Hunt``  ``primary`` (whole line)
``hunter →``                  ``primary_dim`` (whole line)
``Type /help``                ``text_dim`` (whole line)
============================  ==================

Any other non-whitespace glyph keeps the default ``text`` role; whitespace is
never wrapped in escape codes, and adjacent glyphs sharing a role are emitted
as a single escape run.
"""

from __future__ import annotations

import os

try:  # pragma: no cover - import shim for script / sys.path usage
    from theme import paint
except ImportError:  # pragma: no cover - package usage
    from .theme import paint

__all__ = ["BANNER_FILE", "FALLBACK_BANNER", "banner_path", "load_banner", "render_banner"]

#: Default artwork location; override with ``HUNT_BANNER_FILE``.
BANNER_FILE = "/home/simon/hunt_banner.txt"

#: Careful, small banner used when the artwork file cannot be read.
FALLBACK_BANNER = "\n".join(
    (
        "╔══════════════════════════════════════╗",
        "║  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ ║",
        "║  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝ ║",
        "║  ███████║██║   ██║██╔██╗ ██║   ██║    ║",
        "║  ██╔══██║██║   ██║██║╚██╗██║   ██║    ║",
        "║  ██║  ██║╚██████╔╝██║ ╚████║   ██║    ║",
        "║  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ║",
        "║  Autonomous Security Hunt  ·  v3.0   ║",
        "║  hunter → verifier → chainer → loop  ║",
        "║  Type /help for commands             ║",
        "╚══════════════════════════════════════╝",
    )
)

_BOX = frozenset("╔╗╚╝║═╠╣╦╩╬")
_BLOCK = frozenset("█▀▄▌▐░▒▓")
_FACE = frozenset("*%#@")
_STRUCTURE = frozenset("+=—-")          # includes U+2014 em dash
_SHADING = frozenset(".:,'`")

# Whole-line rules, evaluated in order; first substring match wins.
_LINE_RULES: tuple[tuple[str, str], ...] = (
    ("Autonomous Security Hunt", "primary"),
    ("hunter →", "primary_dim"),
    ("Type /help", "text_dim"),
)


def _candidate_paths(path: str | None = None) -> tuple[str, ...]:
    if path:
        return (path,)
    candidates = [
        os.environ.get("HUNT_BANNER_FILE", ""),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "hunt_banner.txt"),
        BANNER_FILE,
        os.path.join(os.path.expanduser("~"), "hunt_banner.txt"),
    ]
    seen: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.append(candidate)
    return tuple(seen)


def banner_path(path: str | None = None) -> str | None:
    """Return the banner file that will be / was read, or ``None``."""
    for candidate in _candidate_paths(path):
        if os.path.isfile(candidate):
            return candidate
    return None


def load_banner(path: str | None = None) -> str:
    """Read the banner artwork (UTF-8), falling back to a small banner."""
    for candidate in _candidate_paths(path):
        try:
            with open(candidate, encoding="utf-8") as handle:
                text = handle.read()
        except (OSError, UnicodeDecodeError):
            continue
        if text.strip():
            return text
    return FALLBACK_BANNER


def _char_role(char: str) -> str | None:
    """Theme role for one glyph, or ``None`` to leave it uncoloured."""
    if char.isspace():
        return None
    if char in _BOX:
        return "primary_deep"
    if char in _BLOCK:
        return "primary"
    if char in _FACE:
        return "primary"
    if char in _STRUCTURE:
        return "primary_dim"
    if char in _SHADING:
        return "primary_deep"
    return "text"


def _paint_run(chars: list[str], role: str | None, force: bool | None) -> str:
    if not chars:
        return ""
    text = "".join(chars)
    if role is None:
        return text
    return paint(text, role, force=force)


def _render_line(line: str, force: bool | None) -> str:
    if not line:
        return ""
    for needle, role in _LINE_RULES:
        if needle in line:
            return paint(line, role, force=force)

    out: list[str] = []
    run: list[str] = []
    run_role: str | None = None
    for char in line:
        role = _char_role(char)
        if role == run_role:
            run.append(char)
            continue
        out.append(_paint_run(run, run_role, force))
        run = [char]
        run_role = role
    out.append(_paint_run(run, run_role, force))
    return "".join(out)


def render_banner(*, color: bool | None = None, path: str | None = None) -> str:
    """Return the banner, coloured for the terminal.

    ``color`` forces colour on (``True``) or off (``False``); the default
    ``None`` auto-detects: piped or redirected output stays plain so no
    escape codes leak into logs.  ``path`` overrides the artwork location.
    """
    text = load_banner(path)
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    rendered = [line.rstrip("\r") for line in lines]
    return "\n".join(_render_line(line, color) for line in rendered)
