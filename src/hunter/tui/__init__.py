"""TUI surface (Textual). UX layer only — every core function must also work via plain CLI.

``HunterTui`` is exported lazily so ``import hunter.tui`` stays cheap for the
plain CLI; use ``from hunter.tui.app import HunterTui`` or
``from hunter.tui import HunterTui``.
"""

from typing import Any

__all__ = ["HunterTui"]


def __getattr__(name: str) -> Any:
    if name == "HunterTui":
        from .app import HunterTui

        return HunterTui
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
