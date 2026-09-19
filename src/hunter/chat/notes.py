"""R2-C /note queue — parked notes while an audit is active.

Rename note: ``/note`` stays ``/note`` (no silent rename drift). If a future
surface renames it (e.g. ``/note`` -> ``/memo``), the old name remains an
alias and this module documents the rename path — see RENAME_NOTE.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

NOTE_CAP = 20

RENAME_NOTE = (
    "rename: /note keeps its name; any future rename (e.g. /note -> /memo) "
    "must keep /note as an alias and document the rename here — "
    "no silent /note drift."
)

_EVIDENCE_ID_RE = re.compile(r"\b(?:EV-[0-9a-fA-F]+|R-[0-9a-f]{12})\b")

__all__ = ["NOTE_CAP", "RENAME_NOTE", "flush_notes", "park_note"]


def _is_note_row(message: dict[str, Any]) -> bool:
    try:
        return str(message.get("content", "")).startswith("note:")
    except Exception:
        return False


def _resolve_store_sid(engine: Any) -> tuple[Any, str | None]:
    store = getattr(engine, "store", None)
    sid = getattr(engine, "session_id", None)
    if sid is None and isinstance(getattr(engine, "options", None), dict):
        sid = engine.options.get("session_id")
    if store is None and hasattr(engine, "append_message") and hasattr(engine, "messages"):
        # Allow direct (store, sid) style: engine may itself be a store.
        return engine, None
    return store, sid


def _count_notes(store: Any, sid: str) -> int:
    try:
        rows = store.messages(sid)
    except Exception:
        return 0
    return sum(1 for m in rows if _is_note_row(m))


def park_note(engine: Any, text: str) -> Any:
    """Park one chat-only note (run_id None, never drives _audit_turn).

    Appends exactly one chat.db row (``note: <text>``) with run_id None.
    Enforces NOTE_CAP (20); the 21st park raises. Never calls
    engine._audit_turn (free text must never smuggle writes into an armed
    run).
    """
    store, sid = _resolve_store_sid(engine)
    if store is None or not sid:
        raise ValueError("no active session — park_note needs a session")
    if _count_notes(store, sid) >= NOTE_CAP:
        raise ValueError(f"note queue full ({NOTE_CAP}) — flush with /audit finish first")
    content = f"note: {str(text or '').strip()}"
    row = store.append_message(sid, "user", content, run_id=None)
    seq = row.get("seq") if isinstance(row, dict) else None
    return SimpleNamespace(run_id=None, seq=seq, content=content)


def flush_notes(store: Any, sid: str) -> str:
    """Flush queued notes on /audit finish: announce N, ledger untouched.

    Read-only over chat.db (counts ``note:`` rows); never writes ledger.db
    runs. Sweeps EV/R ids into the returned view so nothing parked is lost.
    """
    try:
        rows = store.messages(sid)
    except Exception:
        return "flushed 0 note(s) — no session"
    notes = [m for m in rows if _is_note_row(m)]
    count = len(notes)
    blob = "\n".join(str(m.get("content", "")) for m in notes)
    ids = sorted(set(_EVIDENCE_ID_RE.findall(blob)))
    sweep = f" — ids: {', '.join(ids)}" if ids else ""
    if count == 0:
        return "flushed 0 note(s) — queue empty"
    return f"flushed {count} note(s){sweep} (ledger unchanged)"
