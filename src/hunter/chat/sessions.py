"""ChatStore — hash-chained chat sessions over SQLite.

The chat transcript is treated with the same discipline as the audit ledger:

- **Append-only.** No UPDATE or DELETE path exists; anti-tamper triggers
  reject direct SQL mutations of ``chat_messages`` outright, and
  ``chat_sessions`` may only ever move ``title`` / ``last_active_at`` /
  ``model`` / ``provider`` (identity columns are frozen).
- **Hash-chained.** Every message row stores ``self_hash = sha256`` over
  ``canonical_json({seq, session_id, role, content, tool_calls_json,
  run_id, prev_hash})`` where ``prev_hash`` is the previous row's
  ``self_hash`` for that session (GENESIS_HASH for the first).
  ``verify_chain`` recomputes every digest and reports the first break —
  the same tamper-evidence contract as ``hunter.kernel.ledger``.
- **Tombstone undo.** ``undo`` never deletes: it APPENDS a
  ``role="tombstone"`` row recording the hidden range
  (``canonical_json({"kind": "undo", "from_seq": .., "to_seq": ..,
  "hidden": ..})``). ``messages()`` returns only rows appended AFTER the
  most recent tombstone, so undone turns vanish from every view while the
  chain — tombstones included — keeps verifying end to end. Export skips
  post-tombstone rows as well, so nothing hidden can leak into a report.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from hunter.kernel.events import GENESIS_HASH, canonical_json, sha256_hex

__all__ = ["ChatStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id     TEXT PRIMARY KEY,
    title          TEXT,
    created_at     REAL,
    last_active_at REAL,
    model          TEXT,
    provider       TEXT
);

CREATE TABLE IF NOT EXISTS chat_messages (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT,
    role           TEXT,
    content        TEXT,
    tool_calls_json TEXT,
    turn_id        TEXT,
    run_id         TEXT,
    cost_usd       REAL,
    created_at     REAL,
    prev_hash      TEXT,
    self_hash      TEXT UNIQUE
);

-- Append-only discipline (mirrors hunter/kernel/ledger.py): chat_messages
-- must never be rewritten. Direct UPDATE/DELETE fail loudly at the schema.
CREATE TRIGGER IF NOT EXISTS chat_messages_no_update
BEFORE UPDATE ON chat_messages
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS chat_messages_no_delete
BEFORE DELETE ON chat_messages
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

-- INSERT OR REPLACE deletes the conflicting row without firing delete
-- triggers — close the rewrite hole at the schema level.
CREATE TRIGGER IF NOT EXISTS chat_messages_no_replace
BEFORE INSERT ON chat_messages
WHEN EXISTS (SELECT 1 FROM chat_messages WHERE seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

-- Session metadata is mutable ONLY in the UX columns; identity is frozen.
CREATE TRIGGER IF NOT EXISTS chat_sessions_protected_columns
BEFORE UPDATE ON chat_sessions
WHEN OLD.session_id IS NOT NEW.session_id
    OR OLD.created_at IS NOT NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: identity columns are frozen');
END;
"""

_TOMBSTONE_ROLE = "tombstone"
_LIVE_ROLES = ("user", "assistant", "tool")


class ChatStore:
    """Append-only, hash-chained chat transcript store. All writes flow here."""

    def __init__(self, path: str | Path | None = None) -> None:
        db_path = self._resolve_path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA recursive_triggers=ON")
        self._conn.executescript(_SCHEMA)

    @staticmethod
    def _resolve_path(path: str | Path | None) -> Path:
        if path is not None:
            return Path(path)
        from_env = (os.environ.get("HUNTEROS_CHAT_DB") or "").strip()
        if from_env:
            return Path(from_env)
        from hunter.home import hunter_home  # deferred: home.py is stdlib-only

        return hunter_home() / "chat.db"

    @property
    def path(self) -> Path:
        """Filesystem path of the backing database file."""
        return self._path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- sessions -----------------------------------------------------------

    def create_session(self, title: str = "") -> str:
        sid = f"S-{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO chat_sessions (session_id, title, created_at, last_active_at,"
                " model, provider) VALUES (?, ?, ?, ?, '', '')",
                (sid, title, now, now),
            )
        return sid

    def list_sessions(self) -> list[dict[str, Any]]:
        """All sessions, most recently active first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT session_id, title, created_at, last_active_at, model, provider"
                " FROM chat_sessions ORDER BY last_active_at DESC, session_id DESC"
            ).fetchall()
        return [self._session_row(r) for r in rows]

    def get_session(self, sid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT session_id, title, created_at, last_active_at, model, provider"
                " FROM chat_sessions WHERE session_id = ?",
                (sid,),
            ).fetchone()
        return self._session_row(row) if row is not None else None

    def set_title(self, sid: str, title: str) -> None:
        if self.get_session(sid) is None:
            raise KeyError(f"session '{sid}' not found")
        with self._lock:
            self._conn.execute(
                "UPDATE chat_sessions SET title = ?, last_active_at = ? WHERE session_id = ?",
                (title, time.time(), sid),
            )

    @staticmethod
    def _session_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "session_id": row[0],
            "title": row[1] or "",
            "created_at": row[2],
            "last_active_at": row[3],
            "model": row[4] or "",
            "provider": row[5] or "",
        }

    # -- messages -----------------------------------------------------------

    def append_message(
        self,
        sid: str,
        role: str,
        content: str,
        *,
        tool_calls: list[dict[str, Any]] | None = None,
        run_id: str | None = None,
        cost_usd: float = 0.0,
    ) -> dict[str, Any]:
        """Append one message and chain it onto the session's hash chain."""
        if self.get_session(sid) is None:
            raise KeyError(f"session '{sid}' not found")
        now = time.time()
        with self._lock:
            prev = self._conn.execute(
                "SELECT self_hash FROM chat_messages WHERE session_id = ?"
                " ORDER BY seq DESC LIMIT 1",
                (sid,),
            ).fetchone()
            prev_hash = prev[0] if prev is not None else GENESIS_HASH
            # seq is computed explicitly (max+1, exactly like the ledger) so
            # the chain digest is known BEFORE insert — no self-UPDATE, the
            # append-only triggers stay inviolate.
            seq = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM chat_messages"
                ).fetchone()[0]
            )
            calls = tool_calls or []
            digest = self._message_hash(seq, sid, role, content, calls, run_id, prev_hash)
            self._conn.execute(
                "INSERT INTO chat_messages (seq, session_id, role, content, tool_calls_json,"
                " turn_id, run_id, cost_usd, created_at, prev_hash, self_hash)"
                " VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
                (
                    seq,
                    sid,
                    role,
                    content,
                    canonical_json(calls),
                    run_id,
                    float(cost_usd),
                    now,
                    prev_hash,
                    digest,
                ),
            )
            self._conn.execute(
                "UPDATE chat_sessions SET last_active_at = ? WHERE session_id = ?",
                (now, sid),
            )
        return {
            "seq": seq,
            "session_id": sid,
            "role": role,
            "content": content,
            "tool_calls": tool_calls or [],
            "run_id": run_id,
            "cost_usd": float(cost_usd),
            "created_at": now,
            "prev_hash": prev_hash,
            "self_hash": digest,
        }

    @staticmethod
    def _message_hash(
        seq: int,
        sid: str,
        role: str,
        content: str,
        tool_calls: list[dict[str, Any]],
        run_id: str | None,
        prev_hash: str,
    ) -> str:
        """sha256 over the canonical row material — the chain link."""
        return sha256_hex(
            canonical_json(
                {
                    "seq": seq,
                    "session_id": sid,
                    "role": role,
                    "content": content,
                    "tool_calls_json": canonical_json(tool_calls),
                    "run_id": run_id,
                    "prev_hash": prev_hash,
                }
            )
        )

    def messages(self, sid: str) -> list[dict[str, Any]]:
        """Live (non-hidden, non-tombstone) messages in append order.

        Rows inside any tombstone's recorded range are hidden — the undo
        mechanism — and never returned here, by export(), or by the
        conversation history builder.
        """
        return self._live_rows(sid)

    def _live_rows(self, sid: str) -> list[dict[str, Any]]:
        with self._lock:
            all_rows = self._conn.execute(
                "SELECT seq, role, content, tool_calls_json, run_id, cost_usd, created_at,"
                " prev_hash, self_hash FROM chat_messages"
                " WHERE session_id = ? AND role != ?"
                " ORDER BY seq",
                (sid, _TOMBSTONE_ROLE),
            ).fetchall()
            tombstones = self._conn.execute(
                "SELECT content FROM chat_messages"
                " WHERE session_id = ? AND role = ? ORDER BY seq",
                (sid, _TOMBSTONE_ROLE),
            ).fetchall()
        hidden: set[int] = set()
        for (raw,) in tombstones:
            try:
                payload = json.loads(raw)
                hidden.update(range(int(payload["from_seq"]), int(payload["to_seq"]) + 1))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue  # a corrupt tombstone hides nothing
        return [self._message_row(r) for r in all_rows if r[0] not in hidden]

    @staticmethod
    def _message_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "seq": row[0],
            "role": row[1],
            "content": row[2],
            "tool_calls": json.loads(row[3]) if row[3] else [],
            "run_id": row[4],
            "cost_usd": row[5] or 0.0,
            "created_at": row[6],
            "prev_hash": row[7],
            "self_hash": row[8],
        }

    def undo(self, sid: str, n_user_turns: int = 1) -> int:
        """Hide the last ``n_user_turns`` user turns (and their replies).

        Tombstone pattern: nothing is deleted. A ``role="tombstone"`` row is
        APPENDED whose content records the hidden range; ``messages()`` and
        ``export()`` skip everything at or before it. The hash chain —
        tombstones included — keeps verifying. Returns the number of hidden
        rows (0 when there is nothing to undo).
        """
        live = self._live_rows(sid)
        if not live:
            return 0
        n_user_turns = max(1, int(n_user_turns))
        seen_users = 0
        cut_index = 0
        for index in range(len(live) - 1, -1, -1):
            if live[index]["role"] == "user":
                seen_users += 1
                if seen_users == n_user_turns:
                    cut_index = index
                    break
        # Fewer user turns than requested → hide the whole live range.
        hidden = len(live) - cut_index
        payload = canonical_json(
            {
                "kind": "undo",
                "from_seq": live[cut_index]["seq"],
                "to_seq": live[-1]["seq"],
                "hidden": hidden,
                "reason": "user undo",
            }
        )
        # The tombstone is a normal chained row (role="tombstone").
        now = time.time()
        with self._lock:
            prev = self._conn.execute(
                "SELECT self_hash FROM chat_messages WHERE session_id = ?"
                " ORDER BY seq DESC LIMIT 1",
                (sid,),
            ).fetchone()
            prev_hash = prev[0] if prev is not None else GENESIS_HASH
            seq = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM chat_messages"
                ).fetchone()[0]
            )
            digest = self._message_hash(seq, sid, _TOMBSTONE_ROLE, payload, [], None, prev_hash)
            self._conn.execute(
                "INSERT INTO chat_messages (seq, session_id, role, content, tool_calls_json,"
                " turn_id, run_id, cost_usd, created_at, prev_hash, self_hash)"
                " VALUES (?, ?, ?, ?, '[]', NULL, NULL, 0.0, ?, ?, ?)",
                (seq, sid, _TOMBSTONE_ROLE, payload, now, prev_hash, digest),
            )
            self._conn.execute(
                "UPDATE chat_sessions SET last_active_at = ? WHERE session_id = ?", (now, sid)
            )
        return hidden

    def verify_chain(self, sid: str) -> tuple[bool, int, int | None]:
        """Recompute every stored hash for the session (tombstones included).

        Returns ``(ok, checked, broken_at)`` where ``broken_at`` is the seq of
        the first failing row or None. A row whose stored ``self_hash`` does
        not match its recomputed content hash, or whose ``prev_hash`` does not
        match the preceding row, marks the chain broken.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, role, content, tool_calls_json, run_id, prev_hash, self_hash"
                " FROM chat_messages WHERE session_id = ? ORDER BY seq",
                (sid,),
            ).fetchall()
        ok = True
        broken_at: int | None = None
        expected_prev = GENESIS_HASH
        for index, (seq, role, content, tool_calls_json, run_id, prev_hash, digest) in enumerate(rows):
            try:
                tool_calls = json.loads(tool_calls_json) if tool_calls_json else []
            except json.JSONDecodeError:
                tool_calls = None  # corrupt stored material is itself tampering
            recomputed = (
                self._message_hash(seq, sid, role, content, tool_calls, run_id, prev_hash)
                if isinstance(tool_calls, list)
                else None
            )
            problems = []
            if recomputed is None or digest != recomputed:
                problems.append(f"seq {seq}: stored hash does not match recomputed content hash")
            if index == 0:
                if prev_hash != GENESIS_HASH:
                    problems.append(f"seq {seq}: first row does not chain from GENESIS_HASH")
            elif prev_hash != expected_prev:
                problems.append(
                    f"seq {seq}: prev_hash does not match hash of the preceding row"
                )
            expected_prev = digest
            if problems:
                ok = False
                if broken_at is None:
                    broken_at = seq
        return ok, len(rows), broken_at

    # -- export -------------------------------------------------------------

    def export(self, sid: str, fmt: str = "jsonl") -> str:
        """Export the LIVE transcript (post-tombstone rows only).

        ``fmt="jsonl"``   one JSON object per message.
        ``fmt="markdown"`` a readable transcript with role headers.
        Anything else raises ValueError.
        """
        session = self.get_session(sid)
        if session is None:
            raise KeyError(f"session '{sid}' not found")
        rows = self.messages(sid)
        if fmt == "jsonl":
            lines = []
            for m in rows:
                lines.append(
                    json.dumps(
                        {
                            "seq": m["seq"],
                            "role": m["role"],
                            "content": m["content"],
                            "tool_calls": m["tool_calls"],
                            "run_id": m["run_id"],
                            "cost_usd": m["cost_usd"],
                            "created_at": m["created_at"],
                        },
                        ensure_ascii=False,
                    )
                )
            return "\n".join(lines) + ("\n" if lines else "")
        if fmt == "markdown":
            title = session["title"] or "(untitled)"
            lines = [f"# HunterOs chat transcript — {title}", "", f"session: `{sid}`", ""]
            for m in rows:
                lines += [f"## {m['role']}", "", m["content"], ""]
            return "\n".join(lines)
        raise ValueError(f"unknown export format {fmt!r} (use jsonl | markdown)")
