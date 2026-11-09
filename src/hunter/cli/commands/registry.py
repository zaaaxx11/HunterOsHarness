"""Slash-command registry for the HUNT terminal CLI.

One registry, one dispatch path, one help renderer — the REPL hands any line
that starts with ``/`` to :func:`dispatch`, so every surface (interactive REPL,
piped stdin, a future webhook) resolves commands identically.

Public surface
--------------
``@command(...)``   decorator that registers a handler in :data:`REGISTRY`
``resolve(line)``   ``"/hunt https://x 6h"`` -> ``("hunt", "https://x 6h", [...])``
``dispatch(line, session)``  run a handler, never raise into the REPL
``help_text()``     grouped help, ordered by :data:`CATEGORY_ORDER`
``suggest(prefix)`` command names for tab-completion

A handler is ``fn(args: str, session) -> str``. The session is duck-typed and
never imported here: the registry only forwards it. Anything a handler needs
must be pulled with ``getattr(session, name, default)`` so a partially-built
session degrades to a helpful message instead of an ``AttributeError``.

Stdlib only, so this module stays importable from anywhere.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any, Callable

__all__ = [
    "CATEGORY_ORDER",
    "Command",
    "REGISTRY",
    "command",
    "resolve",
    "dispatch",
    "help_text",
    "suggest",
    "ensure_core",
]

# The canonical display order. help_text() emits these sections in this order
# so the command list is stable across releases; unknown categories append
# after the known ones rather than disappearing.
CATEGORY_ORDER: tuple[str, ...] = (
    "Session",
    "Hunt",
    "Findings",
    "Model & Config",
    "Tools & Skills",
    "Chat",
    "Debug",
)


@dataclass(frozen=True)
class Command:
    """One slash command.

    ``name`` is canonical and carries no slash. ``handler`` takes
    ``(args_str, session)`` and returns the text the chat prints.
    """

    name: str
    description: str
    arg_hint: str = ""
    category: str = "Chat"
    handler: Callable[[str, Any], str] | None = None
    aliases: tuple[str, ...] = ()
    manual: str = ""

    @property
    def usage(self) -> str:
        """``/name <args>`` for help and error lines."""
        return f"/{self.name}" + (f" {self.arg_hint}" if self.arg_hint else "")


REGISTRY: dict[str, Command] = {}
_ALIASES: dict[str, str] = {}


def command(
    name: str,
    description: str,
    arg_hint: str = "",
    category: str = "Chat",
    aliases: tuple[str, ...] = (),
    manual: str = "",
) -> Callable[[Callable[[str, Any], str]], Callable[[str, Any], str]]:
    """Register a handler.

    ``@command("hunt", "Start a hunt", "<target> [goal] [time]", "Hunt")``

    Re-registering a name replaces the entry, which keeps ``importlib.reload``
    and the test seam honest. Aliases resolve to the canonical name in
    :func:`resolve` and are listed by :func:`suggest`.
    """

    def decorator(fn: Callable[[str, Any], str]) -> Callable[[str, Any], str]:
        canonical = name.strip().lstrip("/").lower()
        clean_aliases = tuple(a.strip().lstrip("/").lower() for a in aliases if a.strip())
        cmd = Command(
            name=canonical,
            description=description,
            arg_hint=arg_hint.strip(),
            category=category,
            handler=fn,
            manual=manual,
            aliases=clean_aliases,
        )
        REGISTRY[canonical] = cmd
        for alias in clean_aliases:
            _ALIASES[alias] = canonical
        return fn

    return decorator



def _builtin_help_command() -> Command:
    return Command(
        name="help",
        description="Show all commands or detail for one",
        arg_hint="[command]",
        category="Chat",
        handler=_help_handler,
        manual="Show the full command list grouped by category, or detailed help for one command. /help hunt shows /hunt with its manual, usage, and examples.",
        aliases=("?",),
    )


