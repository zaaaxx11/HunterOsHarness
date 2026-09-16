"""HunterOs hospitality — pinned UX copy and the 💡 hint module (M11).

Plain-strings-only module (the ``branding.py`` doctrine): surfaces render,
this module authors. Every string below is a byte-exact contract pinned by
tests (`tests/test_m11_hospitality.py`, `tests/test_m11_chat_oneshot.py`,
`tests/test_docs_m11.py`) — copy is a contract, not a suggestion.

Emoji state language (📋 ✅ ⚠️ 💡 ⏸️) applies to NEW M11 surfaces and the
``handle_cli_error`` backstop only; ``HunterError.user_message()`` is not
retro-fitted (Q7) and ``[BLOCKED]`` lines stay emoji-free.
"""

from __future__ import annotations

import time

from hunter.errors import (
    EXIT_AUTH,
    EXIT_CONFIG,
    EXIT_ERROR,
    EXIT_LEDGER,
    EXIT_RATE_LIMIT,
    HunterError,
)

__all__ = [
    "EXIT_HINTS",
    "cancelled_line",
    "exit_hint",
    "hint_line",
    "key_saved_line",
    "no_provider_message",
    "paused_message",
    "probe_unverified_line",
    "probe_verified_line",
    "resume_message",
    "short_no_provider_line",
    "unknown_session_message",
]


def hint_line(command: str, why: str = "") -> str:
    """The exact-next-command trailer: ``💡 Try: {command}`` (plus `` — {why}``
    when a reason is given)."""
    line = f"💡 Try: {command}"
    if why:
        line = f"{line} — {why}"
    return line


def no_provider_message(error: HunterError | None = None) -> str:
    """The ONE setup panel (M3). When ``error`` is given, its
    ``user_message()`` first line replaces the ``[ERROR config]`` line; the
    💡 block is identical."""
    if error is not None:
        first_line = error.user_message().splitlines()[0]
    else:
        first_line = "[ERROR config] no provider configured — chat needs a brain"
    return "\n".join(
        [
            first_line,
            "💡 Fix it in under a minute:",
            "   hunter init                  — the guided wizard (recommended)",
            "   hunter model                 — pick a provider + model (key already set?)",
            "   hunter config provider add custom --base-url https://your-endpoint/v1",
            "   hunter config key set CUSTOM_API_KEY",
        ]
    )


def short_no_provider_line() -> str:
    """The per-line follow-up after the panel has shown once (kills the
    no-provider spam on REPL/gateway surfaces)."""
    return "💡 no brain configured — run hunter init (the setup panel is above)"


def unknown_session_message(session_id: str, sessions: list[dict]) -> str:
    """M3 — the friendly unknown-`--resume` message listing recent sessions."""
    lines = [f"no session '{session_id}'.", "sessions:"]
    if sessions:
        for session in sessions:
            sid = str(session.get("session_id", ""))
            title = str(session.get("title") or "") or "(untitled)"
            lines.append(f"  {sid}  {title}  ({_relative_age(session.get('last_active_at'))})")
    else:
        lines.append("  (none yet)")
    lines.append(
        f"💡 resume one: hunter chat --resume {session_id} — or start fresh: hunter chat"
    )
    return "\n".join(lines)


def _relative_age(ts) -> str:
    """Human age for a session's ``last_active_at`` epoch (best-effort)."""
    try:
        seconds = max(0.0, time.time() - float(ts or 0.0))
    except (TypeError, ValueError):
        return "a while ago"
    if float(ts or 0.0) <= 0.0:
        return "a while ago"
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def paused_message() -> str:
    """The pause ESTOP confirmation (in-flight work is NEVER killed)."""
    return (
        "⏸️ Hunter is paused. New work is on hold; run `hunter resume` to pick things back up."
    )


def resume_message(pending: int) -> str:
    """The resume confirmation with the live queue count."""
    return f"✅ Resumed — {pending} task(s) waiting in the queue."


# The backstop trailer table (M8 wiring in cli/handle.py): used ONLY when the
# error carries no hint of its own and is not a blocked layer. Blocked layers
# (scope/claim/approval) never suggest a fix that widens scope; usage and
# interrupt lines speak for themselves.
EXIT_HINTS: dict[int, str] = {
    EXIT_CONFIG: "hunter config check",
    EXIT_AUTH: "hunter config key list — then hunter config key set <VAR>",
    EXIT_LEDGER: "hunter verify",
    EXIT_RATE_LIMIT: "retry later — or add a fallback: hunter config provider add",
    EXIT_ERROR: "hunter doctor",
}


def exit_hint(exit_code: int, *, blocked: bool = False) -> str | None:
    """Backstop trailer (M8): ``None`` for blocked layers / codes without a
    map; else the mapped ``💡 Try: ...`` line."""
    if blocked:
        return None
    command = EXIT_HINTS.get(int(exit_code))
    if command is None:
        return None
    return hint_line(command)


def probe_verified_line(url: str, count: int) -> str:
    """Advisory probe success copy (M4)."""
    return f"✅ Verified endpoint via {url} ({count} model(s) visible)"


def probe_unverified_line(url: str) -> str:
    """Advisory probe failure copy — still saves the provider (M4)."""
    return f"⚠️ Warning: could not verify this endpoint via {url}. Hunter will still save it."


def key_saved_line(var: str) -> str:
    """Masked key-capture confirmation (M4): names the VAR, never a value."""
    return f"✅ API key saved to keys.env as {var}"


def cancelled_line(*, wrote_config: bool) -> str:
    """The wizard Ctrl+C copy: honest about what landed before the cancel."""
    if wrote_config:
        return "⏸️ cancelled — the config was written; run `hunter doctor` to verify."
    return "⏸️ cancelled — nothing was changed."
