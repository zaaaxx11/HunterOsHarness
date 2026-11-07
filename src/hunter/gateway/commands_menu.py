"""Publish the slash-command menu to Telegram's client UI.

Telegram shows the blue "/" autocomplete from ``setMyCommands`` — a per-bot (or
per-scope) list of ``{command, description}``. Without this the client shows
whatever was configured last, which is why the bot advertised stale commands.

The list is derived from the same registry the shell dispatches, so the menu can
never drift from what the bot actually understands.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

__all__ = ["build_bot_commands", "sync_telegram_commands", "TELEGRAM_MAX_COMMANDS"]

TELEGRAM_MAX_COMMANDS = 100
_COMMAND_MAX = 32
_DESCRIPTION_MAX = 256
_DESCRIPTION_MIN = 3


def _sanitize_name(name: str) -> str:
    """Telegram command names: lowercase a-z, 0-9 and underscore, <= 32 chars."""
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in str(name).lower())
    return out[:_COMMAND_MAX].strip("_")


def build_bot_commands(limit: int = TELEGRAM_MAX_COMMANDS) -> list[dict[str, str]]:
    """The ``setMyCommands`` payload, built from the live command registry."""
    from hunter.cli.commands import core as _core  # noqa: F401 - registers
    from hunter.cli.commands import registry as _registry

    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in sorted(_registry.REGISTRY):
        entry = _registry.REGISTRY[name]
        if isinstance(entry, dict):
            description = entry.get("description") or ""
            hint = entry.get("arg_hint") or ""
        else:
            description = getattr(entry, "description", "") or ""
            hint = getattr(entry, "arg_hint", "") or ""
        cmd = _sanitize_name(name)
        if not cmd or cmd in seen:
            continue
        text = " ".join(str(description).split())
        if hint:
            text = f"{text} {str(hint).strip()}".strip()
        if len(text) < _DESCRIPTION_MIN:
            text = f"{cmd} command"
        seen.add(cmd)
        rows.append({"command": cmd, "description": text[:_DESCRIPTION_MAX]})
        if len(rows) >= limit:
            break
    return rows


def _call(token: str, method: str, payload: dict[str, Any] | None = None,
          timeout: float = 25.0) -> dict[str, Any]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:  # noqa: PERF203
        return {"ok": False, "error": f"HTTP {exc.code}", "detail": exc.read().decode()[:200]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}


def sync_telegram_commands(token: str, commands: list[dict[str, str]] | None = None,
                           *, quiet: bool = False) -> int:
    """Publish the menu. Returns the number of commands registered (0 on failure).

    ``setMyCommands`` replaces the whole list, so a stale entry cannot survive.
    ``setChatMenuButton`` flips the client's menu button to the command list.
    """
    if not token:
        return 0
    rows = list(commands) if commands is not None else build_bot_commands()
    if not rows:
        return 0
    result = _call(token, "setMyCommands", {"commands": rows})
    if not result.get("ok"):
        if not quiet:
            print(f"[hunt] telegram setMyCommands failed: {result}", file=sys.stderr)
        return 0
    # The menu button defaults to "commands" for private chats; set it explicitly
    # so the client shows the list instead of an empty default button.
    _call(token, "setChatMenuButton", {"menu_button": {"type": "commands"}})
    if not quiet:
        print(f"[hunt] telegram menu: {len(rows)} commands published", file=sys.stderr)
    return len(rows)
