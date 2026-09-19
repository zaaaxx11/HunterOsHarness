"""Shared HunterOs terminal palette and presentation helpers.

The branding module is deliberately independent from the CLI, chat, and TUI
surfaces.  It owns colors only; content and command behavior remain in their
respective modules.  Rich is imported lazily so importing HunterOs data and
machine-facing commands does not require a terminal renderer.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any

from hunter.palette import SKINS  # noqa: E402 — single source, identity-preserved

# Keep this mapping small and immutable-by-convention: every renderer consumes
# the same seven values rather than inventing a nearby shade.
PALETTE: dict[str, str] = {
    "base": "#00FFE5",
    "bright1": "#4DFFF0",
    "bright2": "#80FFF6",
    "bright3": "#B3FFFC",
    "bright4": "#E6FFFE",
    "deep": "#00B59E",
    "dim": "#007A70",
}

# Nearest xterm-256 colors, calculated from PALETTE's RGB values.  Keeping the
# mapping explicit makes fallback output deterministic on every platform.
ANSI256: dict[str, int] = {
    "base": 50,
    "bright1": 87,
    "bright2": 123,
    "bright3": 159,
    "bright4": 195,
    "deep": 37,
    "dim": 29,
}

# Conventional SGR fallback remains available for simple terminals.  The
# explicit fallback is intentionally separate from Rich's truecolor path.
ANSI_FALLBACK: dict[str, str] = {
    "base": "\x1b[96m",
    "bright1": "\x1b[96m",
    "bright2": "\x1b[96m",
    "bright3": "\x1b[97m",
    "bright4": "\x1b[97m",
    "deep": "\x1b[36m",
    "dim": "\x1b[2;36m",
}
ANSI_RESET = "\x1b[0m"

# Semantic roles deliberately resolve back to PALETTE.  A severity or status
# label therefore cannot introduce a second color family while remaining
# readable on a black terminal.
_ROLE_ALIASES: dict[str, str] = {
    "heading": "bright3",
    "success": "bright3",
    "warning": "bright2",
    "error": "bright4",
    "critical": "bright4",
    "high": "bright2",
    "medium": "bright1",
    "low": "base",
    "info": "base",
    "status": "deep",
    "muted": "dim",
    "prompt": "base",
}


def _palette_role(role: str) -> str:
    """Return the canonical palette key or raise a useful ``KeyError``."""
    if not isinstance(role, str):
        raise KeyError(f"unknown HunterOs palette role: {role!r}")
    canonical = _ROLE_ALIASES.get(role, role)
    if canonical not in PALETTE:
        known = ", ".join((*PALETTE, *_ROLE_ALIASES))
        raise KeyError(f"unknown HunterOs palette role {role!r}; expected one of: {known}")
    return canonical


def rich_style(role: str, *, bold: bool = False, dim: bool = False, italic: bool = False) -> Any:
    """Return a Rich ``Style`` for a palette or semantic role.

    Rich is optional at import time.  In a minimal installation this function
    returns the validated hex color, which is still accepted by APIs that
    accept Rich color strings.  Unknown roles fail closed with ``KeyError``.
    """
    canonical = _palette_role(role)
    color = PALETTE[canonical]
    try:
        from rich.style import Style
    except ImportError:  # pragma: no cover - exercised only without rich
        return color
    return Style(color=color, bold=bold, dim=dim, italic=italic)


def palette_style(role: str, *, ansi: bool = False) -> str:
    """Return a truecolor value or deterministic ANSI prefix for ``role``."""
    canonical = _palette_role(role)
    return ANSI_FALLBACK[canonical] if ansi else PALETTE[canonical]


def colorize(text: str, role: str = "base", *, ansi: bool | None = None) -> str:
    """Colorize terminal text only when explicitly requested or on a TTY.

    ``ansi=None`` is intentionally conservative: pipes and test captures stay
    byte-for-byte plain, while an interactive terminal gets the common SGR
    fallback.  Machine-readable callers should pass ``ansi=False``.
    """
    prefix = palette_style(role, ansi=True)
    if ansi is None:
        try:
            ansi = bool(sys.stdout.isatty())
        except (AttributeError, OSError):
            ansi = False
    if not ansi:
        return text
    return f"{prefix}{text}{ANSI_RESET}"


def make_theme() -> Any:
    """Build the shared Rich theme, importing Rich only when requested."""
    from rich.theme import Theme

    styles = {f"hunter.{role}": color for role, color in PALETTE.items()}
    styles.update({f"hunter.{role}": PALETTE[canonical] for role, canonical in _ROLE_ALIASES.items()})
    return Theme(styles)


def make_console(*, stderr: bool = False, **kwargs: Any) -> Any:
    """Construct a Rich console using the shared HunterOs theme."""
    from rich.console import Console

    return Console(stderr=stderr, theme=make_theme(), **kwargs)


def palette_css(palette: Mapping[str, str] | None = None) -> str:
    """Return Textual variable declarations derived from a shared palette."""
    source = PALETTE if palette is None else palette
    return "\n".join(f"$hunter-{role}: {value};" for role, value in source.items()) + "\n"


def ansi256(role: str) -> int:
    """Return the deterministic xterm-256 fallback index for ``role``."""
    return ANSI256[_palette_role(role)]


__all__ = [
    "ANSI256",
    "ANSI_FALLBACK",
    "ANSI_RESET",
    "PALETTE",
    "SKINS",
    "ansi256",
    "colorize",
    "make_console",
    "make_theme",
    "palette_css",
    "palette_style",
    "rich_style",
]
