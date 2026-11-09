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


def ensure_core() -> None:
    """Import :mod:`core` once so its decorators populate the registry.

    Kept lazy and tolerant: the registry must be importable on its own (a
    ``/help`` from a stripped build still works), and a broken core import
    must not take the whole REPL down.
    """
    if REGISTRY:
        # Built-in help is always available, even before core import
        if "help" not in REGISTRY:
            from hunter.cli.commands.registry import help_text, help_detail
            REGISTRY["help"] = Command(
                name="help",
                description="Show all commands or detail for one",
                arg_hint="[command]",
                category="Chat",
                handler=lambda args, s: help_detail(args.strip().lstrip("/").split(" ")[0].lower()) if args.strip() else help_text(),
                manual="Show full command list grouped by category, or detail for one. /help hunt shows /hunt with manual, usage, and examples.",
                aliases=("?","h"),
            )
        return
    try:  # package layout (cli/commands/) or flat dir (selftest)
        from . import core  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        try:
            import core  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:
            return


def _normalize_name(token: str) -> str:
    """Strip the slash and a Telegram-style ``@bot`` suffix."""
    name = token.strip().lstrip("/").lower()
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def resolve(line: str) -> tuple[str, str, list[str]]:
    """Parse ``"/name args"`` into ``(name, args_str, args_list)``.

    Quoted arguments survive via :func:`shlex.split`; an unbalanced quote
    degrades to whitespace splitting instead of raising, because a half-typed
    command at a prompt must never crash the REPL.

    Returns ``("", "", [])`` for a blank line or one that is not a slash
    command. Aliases resolve to their canonical name.
    """
    if not isinstance(line, str):
        return ("", "", [])
    stripped = line.strip()
    if not stripped.startswith("/"):
        return ("", "", [])
    body = stripped[1:].strip()
    if not body:
        return ("", "", [])
    head, _, rest = body.partition(" ")
    name = _normalize_name(head)
    if not name:
        return ("", "", [])
    args_str = rest.strip()
    if args_str:
        try:
            args_list = shlex.split(args_str)
        except ValueError:
            # Unbalanced quote / trailing backslash: keep the words.
            args_list = args_str.split()
    else:
        args_list = []
    return (_ALIASES.get(name, name), args_str, args_list)


def _nearest(name: str) -> str:
    """Best-effort did-you-mean: shortest edit distance within 2 edits."""
    best, best_dist = "", 99
    for candidate in REGISTRY:
        dist = _edit_distance(name, candidate)
        if dist < best_dist:
            best, best_dist = candidate, dist
    return best if best_dist <= 2 else ""


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance, two-row form (tiny inputs, no dependency)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def dispatch(line: str, session: Any) -> str:
    """Run the handler for ``line`` and return printable text.

    Every failure mode becomes a message, never a traceback: unknown command,
    a handler that raises, or a handler that forgets to return a string. One
    broken command must not end the hunt.
    """
    ensure_core()
    name, args_str, _args_list = resolve(line)
    if not name:
        return "not a slash command — type /help for the command list"
    cmd = REGISTRY.get(name)
    if cmd is None:
        near = _nearest(name)
        hint = f" — did you mean /{near}?" if near else " — type /help for the command list"
        return f"unknown command /{name}{hint}"
    handler = cmd.handler
    if handler is None:
        return f"/{name} has no handler registered"
    try:
        result = handler(args_str, session)
    except Exception as exc:  # noqa: BLE001 — the REPL gets an answer, always
        return f"/{name} failed: {type(exc).__name__}: {exc}"
    if result is None:
        return f"/{name} did nothing (handler returned None)"
    return result if isinstance(result, str) else str(result)


def _grouped() -> list[tuple[str, list[Command]]]:
    """Commands bucketed by category in canonical order."""
    groups: dict[str, list[Command]] = {}
    for cmd in REGISTRY.values():
        groups.setdefault(cmd.category, []).append(cmd)
    ordered: list[tuple[str, list[Command]]] = []
    for category in CATEGORY_ORDER:
        if category in groups:
            ordered.append((category, sorted(groups[category], key=lambda c: c.name)))
    for category in sorted(groups):
        if category not in CATEGORY_ORDER:
            ordered.append((category, sorted(groups[category], key=lambda c: c.name)))
    return ordered


def _list_signature(cmd: Command) -> str:
    """The list-view signature: the name plus a short argument hint.

    The full usage made the description start at a different offset on every row
    (long hints overflowed the padded column), which is what made /help a ragged
    wall. The complete signature still lives in /help <command>.
    """
    hint = (cmd.arg_hint or "").strip()
    if not hint:
        return f"/{cmd.name}"
    candidate = f"/{cmd.name} {hint.split()[0]}"
    return candidate if len(candidate) <= 20 else f"/{cmd.name} <args>"


def help_text(prefix: str = "", name: str = "") -> str:
    """Render grouped help, optionally filtered to commands starting with ``prefix``.

    One line per command: a monospace name, then a one-line description. Aligned
    in a padded code block, descriptions wrap on narrow clients instead of being
    truncated, so the layout survives a phone screen.
    """
    ensure_core()
    name = (name or prefix).strip().lstrip("/")
    if name and "/" not in name and " " not in name:
        return help_detail(name)
    want = prefix.strip().lstrip("/").lower()
    lines: list[str] = [
        f"**HUNT commands** — {len(REGISTRY)} total · `/help <name>` explains one",
        "",
    ]
    shown = 0
    for category, commands in _grouped():
        rows = [c for c in commands if not want or c.name.startswith(want)]
        if not rows:
            continue
        lines.append(f"**{category}**")
        width = max(len(_list_signature(c)) for c in rows)
        for cmd in rows:
            alias = f"  ({', '.join('/' + a for a in cmd.aliases)})" if cmd.aliases else ""
            lines.append(f"`{_list_signature(cmd):<{width}}` — {cmd.description}{alias}")
        lines.append("")
        shown += len(rows)
    if shown == 0:
        return f"no commands match '{want}' — /help lists all {len(REGISTRY)} commands"
    lines.append(f"**{shown}** shown · Tab completes · `/help <name>` explains one.")
    return "\n".join(lines).rstrip()


def help_detail(name: str) -> str:
    """Detailed help for one command, including its manual."""
    ensure_core()
    cmd = REGISTRY.get(name.lstrip("/").lower())
    if cmd is None:
        return f"no command '{name}' — /help lists all commands"
    lines = [f"/{cmd.name} — {cmd.description}"]
    if cmd.manual:
        lines.append("")
        lines.append(cmd.manual)
    lines.append("")
    lines.append(f"usage: {cmd.usage}")
    lines.append(f"category: {cmd.category}")
    if cmd.aliases:
        lines.append("aliases: " + ", ".join("/" + a for a in cmd.aliases))
    return "\n".join(lines)



def suggest(prefix: str) -> list[str]:
    """Command names matching ``prefix``, for tab-completion.

    Accepts a bare prefix or one with a leading ``/``. Canonical names come
    first sorted, then aliases, so a completion menu is deterministic.
    """
    ensure_core()
    name = (name or prefix).strip().lstrip("/")
    if name and "/" not in name and " " not in name:
        return help_detail(name)
    want = prefix.strip().lstrip("/").lower()
    canonical = sorted(name for name in REGISTRY if name.startswith(want))
    aliases = sorted(alias for alias in _ALIASES if alias.startswith(want))
    out = canonical + [a for a in aliases if a not in canonical]
    return out