"""Canonical HunterOS terminal palette and Rich/ANSI helpers."""
from __future__ import annotations

import sys
from typing import Any

PALETTE: dict[str, str] = {
    "base": "#00FFE5",
    "highlight": "#4DFFF0",
    "highlight_soft": "#80FFF6",
    "highlight_pale": "#B3FFFC",
    "highlight_faint": "#E6FFFE",
    "deep": "#00B59E",
    "dim": "#007A70",
}
ANSI_FALLBACK = {
    "base": "\x1b[96m",
    "highlight": "\x1b[96m",
    "highlight_soft": "\x1b[96m",
    "highlight_pale": "\x1b[97m",
    "highlight_faint": "\x1b[97m",
    "deep": "\x1b[36m",
    "dim": "\x1b[2;36m",
}
ANSI_RESET = "\x1b[0m"
ANSI256 = {"base": 50, "highlight": 87, "highlight_soft": 123,
           "highlight_pale": 159, "highlight_faint": 195, "deep": 37, "dim": 29}
_ALIASES = {
    "bright1": "highlight", "bright2": "highlight_soft", "bright3": "highlight_pale",
    "bright4": "highlight_faint", "heading": "highlight_pale", "success": "highlight_pale",
    "warning": "highlight_soft", "error": "highlight_faint", "critical": "highlight_faint",
    "high": "highlight_soft", "medium": "highlight", "low": "base", "info": "base",
    "status": "deep", "muted": "dim", "prompt": "base",
}


def _role(role: str) -> str:
    canonical = _ALIASES.get(role, role)
    if canonical not in PALETTE:
        raise KeyError(f"unknown HunterOS palette role: {role!r}")
    return canonical


def rich_style(role: str, *, bold: bool = False, dim: bool = False, italic: bool = False) -> Any:
    from rich.style import Style
    return Style(color=PALETTE[_role(role)], bold=bold, dim=dim, italic=italic)


def make_theme() -> Any:
    from rich.theme import Theme
    styles = {f"hunter.{name}": value for name, value in PALETTE.items()}
    styles.update({f"hunter.{name}": PALETTE[target] for name, target in _ALIASES.items()})
    return Theme(styles)


def make_console(*, stderr: bool = False, **kwargs: Any) -> Any:
    from rich.console import Console
    theme = make_theme()
    console = Console(stderr=stderr, theme=theme, **kwargs)
    # Rich 15 does not expose Console.theme publicly; retain a stable
    # inspection seam for integrations and palette tests.
    if not hasattr(console, "theme"):
        console.theme = theme
    return console


def palette_style(role: str, *, ansi: bool = False) -> str:
    canonical = _role(role)
    return ANSI_FALLBACK[canonical] if ansi else PALETTE[canonical]


def colorize(text: str, role: str = "base", *, ansi: bool | None = None) -> str:
    if ansi is None:
        try:
            ansi = bool(sys.stdout.isatty())
        except (AttributeError, OSError):
            ansi = False
    if not ansi:
        return text
    return f"{palette_style(role, ansi=True)}{text}{ANSI_RESET}"


def palette_css() -> str:
    return "\n".join(f"$hunter-{role}: {color};" for role, color in PALETTE.items()) + "\n"


__all__ = ["ANSI256", "ANSI_FALLBACK", "ANSI_RESET", "PALETTE", "colorize", "make_console",
           "make_theme", "palette_css", "palette_style", "rich_style"]
