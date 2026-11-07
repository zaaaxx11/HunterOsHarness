"""HUNT terminal theme -- the canonical tosca palette plus ANSI helpers.

The module is dependency-free (standard library only) and is safe to import
from anywhere: :mod:`banner`, :mod:`repl`, ``__main__`` and tests all share
it as the single source of colour truth.  There is deliberately no ``rich``
import here so the palette can be used in a bare interpreter.

Graceful degradation
--------------------
:func:`paint` never emits escape codes when the target stream is not a TTY
(a pipe, a CI log, a captured file, a test harness) unless explicitly forced
with ``force=True``.  ``NO_COLOR`` is honoured, and ``HUNT_FORCE_COLOR``
overrides TTY detection for demos and screenshots.

Public surface
--------------
``THEME``        role name -> ``#RRGGBB`` hex
``XTERM256``     role name -> xterm-256 palette index (exact nearest match)
``ansi(name)``   truecolor SGR escape for a role
``ansi_256()``   xterm-256 SGR escape for a role
``paint(t, n)``  wrap text in the SGR escape + reset (TTY-aware)
``color_enabled()`` predicate used by every colouring helper
"""

from __future__ import annotations

import os
import sys
from typing import Iterable

__all__ = [
    "ALIASES",
    "BOLD",
    "DIM",
    "RESET",
    "THEME",
    "UNDERLINE",
    "XTERM256",
    "ansi",
    "ansi_256",
    "color_enabled",
    "hex_to_rgb",
    "paint",
    "paint_all",
    "rgb_to_xterm256",
    "strip_ansi",
    "supports_truecolor",
]

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------

THEME: dict[str, str] = {
    "primary": "#00FFE5",
    "primary_dim": "#00B4A0",
    "primary_deep": "#006E64",
    "accent": "#00FFC8",
    "text": "#FFFFFF",
    "text_dim": "#969696",
    "error": "#FF5555",
    "warn": "#FFC850",
    "success": "#00DC82",
    "info": "#64B4FF",
}

#: Human-friendly spellings resolved before a role is looked up.
ALIASES: dict[str, str] = {
    "base": "primary",
    "brand": "primary",
    "prompt": "primary",
    "dim": "primary_dim",
    "deep": "primary_deep",
    "muted": "text_dim",
    "default": "text",
    "warning": "warn",
    "critical": "error",
    "danger": "error",
    "ok": "success",
    "hint": "text_dim",
}

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
UNDERLINE = "\x1b[4m"

# --------------------------------------------------------------------------
# xterm-256 approximation
# --------------------------------------------------------------------------

def _build_xterm_palette() -> list[tuple[int, int, int]]:
    """Return the RGB value of every xterm-256 palette slot (0..255)."""
    base = [
        (0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0),
        (0, 0, 128), (128, 0, 128), (0, 128, 128), (192, 192, 192),
        (128, 128, 128), (255, 0, 0), (0, 255, 0), (255, 255, 0),
        (0, 0, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255),
    ]
    levels = (0, 95, 135, 175, 215, 255)
    cube = [(r, g, b) for r in levels for g in levels for b in levels]
    grey = [(8 + 10 * i,) * 3 for i in range(24)]
    return base + cube + grey


_XTERM_PALETTE: list[tuple[int, int, int]] = _build_xterm_palette()


def hex_to_rgb(value: str) -> tuple[int, int, int]:
    """``'#00FFE5'`` / ``'00ffe5'`` / ``'0FE'`` -> ``(0, 255, 229)``."""
    text = value.strip().lstrip("#")
    if len(text) == 3:
        text = "".join(ch * 2 for ch in text)
    if len(text) != 6:
        raise ValueError(f"not a hex colour: {value!r}")
    try:
        return int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"not a hex colour: {value!r}") from exc


def rgb_to_xterm256(red: int, green: int, blue: int) -> int:
    """Nearest xterm-256 index for an RGB triple (squared-distance match)."""
    best_index = 0
    best_distance = None
    for index, (r, g, b) in enumerate(_XTERM_PALETTE):
        distance = (r - red) ** 2 + (g - green) ** 2 + (b - blue) ** 2
        if best_distance is None or distance < best_distance:
            best_index, best_distance = index, distance
            if distance == 0:
                break
    return best_index


#: ``role -> xterm-256 index`` for the canonical palette.
XTERM256: dict[str, int] = {
    role: rgb_to_xterm256(*hex_to_rgb(value)) for role, value in THEME.items()
}


def _role(name: str) -> str:
    """Resolve a role name (following aliases) or raise ``KeyError``."""
    canonical = ALIASES.get(name, name)
    if canonical not in THEME:
        known = ", ".join(sorted(THEME))
        raise KeyError(f"unknown theme role {name!r} (known: {known})")
    return canonical


# --------------------------------------------------------------------------
# Escape sequences
# --------------------------------------------------------------------------

def ansi(name: str) -> str:
    """24-bit SGR escape for a role, e.g. ``'\\x1b[38;2;0;255;229m'``."""
    red, green, blue = hex_to_rgb(THEME[_role(name)])
    return f"\x1b[38;2;{red};{green};{blue}m"


def ansi_256(name: str) -> str:
    """xterm-256 SGR escape for a role, e.g. ``'\\x1b[38;5;50m'``."""
    return f"\x1b[38;5;{XTERM256[_role(name)]}m"


_ANSI_RE = None


def strip_ansi(text: str) -> str:
    """Remove SGR/CSI escape sequences from *text*."""
    global _ANSI_RE
    if _ANSI_RE is None:
        import re

        _ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
    return _ANSI_RE.sub("", text)


# --------------------------------------------------------------------------
# Environment / capability detection
# --------------------------------------------------------------------------

def _env_present(*names: str) -> bool:
    return any(os.environ.get(name, "") != "" for name in names)


def supports_truecolor() -> bool:
    """True when the environment advertises 24-bit colour support."""
    if _env_present("HUNT_256COLOR", "HUNT_NO_TRUECOLOR"):
        return False
    if _env_present("HUNT_TRUECOLOR", "HUNT_FORCE_TRUECOLOR"):
        return True
    colorterm = os.environ.get("COLORTERM", "").lower()
    if "truecolor" in colorterm or "24bit" in colorterm:
        return True
    if os.environ.get("TERM", "").lower().endswith("direct"):
        return True
    return True


def color_enabled(force: bool | None = None, stream=None) -> bool:
    """Decide whether escape codes may be emitted for *stream*.

    ``force=True`` always allows colour, ``force=False`` never does, and
    ``None`` (the default) auto-detects: ``NO_COLOR``/``HUNT_NO_COLOR``
    disable, ``HUNT_FORCE_COLOR``/``CLICOLOR_FORCE`` enable, otherwise the
    stream must be a TTY.
    """
    if force is not None:
        return bool(force)
    if _env_present("NO_COLOR", "HUNT_NO_COLOR"):
        return False
    if _env_present("HUNT_FORCE_COLOR", "CLICOLOR_FORCE"):
        return True
    target = sys.stdout if stream is None else stream
    try:
        return bool(target.isatty())
    except (AttributeError, ValueError, OSError):  # closed / fake stream
        return False


# --------------------------------------------------------------------------
# Painting
# --------------------------------------------------------------------------

def paint(text: str, name: str, *, force: bool | None = None,
          truecolor: bool | None = None, stream=None) -> str:
    """Wrap *text* in the escape code for role *name* plus a reset.

    Returns *text* unchanged when colour is disabled (non-TTY stdout, no
    ``NO_COLOR`` override), so captured output never contains escape codes.
    """
    if not text:
        return text
    if not color_enabled(force, stream):
        return text
    use_truecolor = supports_truecolor() if truecolor is None else bool(truecolor)
    code = ansi(name) if use_truecolor else ansi_256(name)
    return f"{code}{text}{RESET}"


def paint_all(parts: Iterable[tuple[str, str]], **kwargs) -> str:
    """Paint a sequence of ``(text, role)`` pairs and join them."""
    return "".join(paint(text, role, **kwargs) for text, role in parts)
