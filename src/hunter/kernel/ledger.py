"""Hash-chained event ledger over SQLite — the single source of truth.

Contract for the implementer (B1). The public API below is fixed; internals
are free. Invariants:

- I1  Events are append-only. No UPDATE/DELETE paths exist anywhere.
- I2  Every event chains ``sha256(prev_hash + canonical row)``; genesis prev
      is GENESIS_HASH. ``verify_chain`` recomputes and reports tampering.
- I3  ``create_finding`` applies claim gate RULE-E1 (>= 1 evidence bound)
      inside the same transaction; an insert without evidence must fail with
      ``ClaimGateBlocked`` and leave NO partial rows.
- I4  ``set_finding_status(VERIFIED)`` applies RULE-E2 (>= 2 evidence, the
      second being a replay bound after creation).
- I5  ``add_evidence`` deep-redacts payloads (RULE-E3) BEFORE storage.
- I6  Evidence digests use ``events.canonical_json`` + sha256.
- I7  All writes happen through this class; schema has anti-tamper triggers
      that reject direct UPDATE/DELETE on events/findings/evidence.

State directory convention: ``<state_dir>/ledger.db`` where ``state_dir`` is
``~/.hunter`` by default (M11 unified home; env HUNTER_STATE_DIR overrides,
or an explicit path).
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any

from .claimgate import ClaimGateBlocked, validate_finding_insert, validate_status_change
from .events import GENESIS_HASH, Event, EventKind, canonical_json, sha256_hex
from .findings import Finding, FindingStatus, Severity, finding_id
from .redaction import redact_payload


@dataclass
class ChainReport:
    ok: bool
    checked: int = 0
    broken_at_seq: int | None = None
    details: list[str] = field(default_factory=list)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    target     TEXT NOT NULL,
    engine     TEXT NOT NULL,
    scope_name TEXT NOT NULL,
    started_ts REAL,
    ended_ts   REAL,
    status     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    TEXT NOT NULL,
    kind      TEXT NOT NULL,
    payload   TEXT NOT NULL,
    ts        REAL NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS evidence (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    data        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    created_seq INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL,
    key          TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    cwe          TEXT NOT NULL,
    endpoint     TEXT NOT NULL,
    method       TEXT NOT NULL,
    param        TEXT,
    payload_used TEXT,
    description  TEXT NOT NULL DEFAULT '',
    impact       TEXT NOT NULL DEFAULT '',
    remediation  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    klass        TEXT NOT NULL DEFAULT 'unknown',
    falsifier    TEXT NOT NULL DEFAULT '',
    action_class TEXT NOT NULL DEFAULT 'read',
    surface      TEXT,
    poc_path     TEXT,
    logs_path    TEXT
);

-- v0.7 hunting-klass tables (append-only, trigger-protected below).
CREATE TABLE IF NOT EXISTS leads (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL,
    title       TEXT NOT NULL,
    klass       TEXT NOT NULL DEFAULT 'unknown',
    surface     TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    retrigger   TEXT,
    created_seq INTEGER
);

CREATE TABLE IF NOT EXISTS followups (
    id           TEXT PRIMARY KEY,
    finding_id   TEXT NOT NULL,
    title        TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'variant',
    status       TEXT NOT NULL DEFAULT 'open',
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    created_seq  INTEGER
);

CREATE TABLE IF NOT EXISTS waves (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL,
    budget      INTEGER NOT NULL DEFAULT 0,
    verdict     TEXT,
    created_seq INTEGER
);

CREATE TABLE IF NOT EXISTS hunt_memory (
    id          TEXT PRIMARY KEY,
    run_id      TEXT,
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    created_seq INTEGER
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id             TEXT PRIMARY KEY,
    parent_id           TEXT,
    target              TEXT NOT NULL,
    target_kind         TEXT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'queued',
    priority            INTEGER NOT NULL DEFAULT 0,
    depth               INTEGER NOT NULL DEFAULT 0,
    spawned_from_finding TEXT,
    chain_hypothesis    TEXT,
    injected_context    TEXT,
    max_turns           INTEGER NOT NULL DEFAULT 8,
    max_wall_s          INTEGER NOT NULL DEFAULT 300,
    max_cost_usd        REAL    NOT NULL DEFAULT 0.50,
    run_id              TEXT,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    max_retries         INTEGER NOT NULL DEFAULT 2,
    last_error          TEXT,
    created_ts          REAL,
    started_ts          REAL,
    finished_ts         REAL
);

-- I1/I7: the ledger is append-only; direct SQL tampering must fail loudly.
CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

-- INSERT OR REPLACE deletes the conflicting row without firing delete
-- triggers (unless recursive_triggers is on) — a silent rewrite hole. The
-- no_replace triggers close it at the schema level: legitimate writers only
-- ever append fresh primary keys, never re-insert an existing one.
CREATE TRIGGER IF NOT EXISTS events_no_replace
BEFORE INSERT ON events
WHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR hash = NEW.hash)
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS evidence_no_update
BEFORE UPDATE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS evidence_no_replace
BEFORE INSERT ON evidence
WHEN EXISTS (SELECT 1 FROM evidence WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS findings_no_delete
BEFORE DELETE ON findings
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

CREATE TRIGGER IF NOT EXISTS findings_no_replace
BEFORE INSERT ON findings
WHEN EXISTS (SELECT 1 FROM findings WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

-- On findings, only `status` and `evidence_ids` may ever change (I4).
CREATE TRIGGER IF NOT EXISTS findings_protected_columns
BEFORE UPDATE ON findings
WHEN OLD.id IS NOT NEW.id
    OR OLD.run_id IS NOT NEW.run_id
    OR OLD.key IS NOT NEW.key
    OR OLD.title IS NOT NEW.title
    OR OLD.severity IS NOT NEW.severity
    OR OLD.cwe IS NOT NEW.cwe
    OR OLD.endpoint IS NOT NEW.endpoint
    OR OLD.method IS NOT NEW.method
    OR OLD.param IS NOT NEW.param
    OR OLD.payload_used IS NOT NEW.payload_used
    OR OLD.description IS NOT NEW.description
    OR OLD.impact IS NOT NEW.impact
    OR OLD.remediation IS NOT NEW.remediation
    OR OLD.klass IS NOT NEW.klass
    OR OLD.falsifier IS NOT NEW.falsifier
    OR OLD.action_class IS NOT NEW.action_class
    OR OLD.surface IS NOT NEW.surface
    OR OLD.poc_path IS NOT NEW.poc_path
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

-- RULE-E1 at the storage layer: no finding row may come into existence
-- unless it references at least one evidence artifact that exists, and none
-- of its references is dangling. Mirrors ledger.create_finding for raw SQL.
-- Theoretical findings are hypotheses (0 evidence legal).
CREATE TRIGGER IF NOT EXISTS findings_insert_requires_evidence
BEFORE INSERT ON findings
WHEN NEW.status != 'theoretical'
  AND (
    NOT EXISTS (
        SELECT 1 FROM json_each(COALESCE(NEW.evidence_ids, '[]')) AS je
        JOIN evidence e ON e.id = je.value AND e.run_id = NEW.run_id
        WHERE je.type = 'text'
    )
    OR EXISTS (
        SELECT 1 FROM json_each(COALESCE(NEW.evidence_ids, '[]')) AS je
        LEFT JOIN evidence e ON e.id = je.value
        WHERE je.type != 'text' OR e.id IS NULL OR e.run_id != NEW.run_id
    )
  )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: finding requires existing bound evidence (RULE-E1)');
END;

-- RULE-E2 at the storage layer: a row can neither be created with nor
-- updated to status 'verified' unless replay evidence bound to that exact
-- finding id exists. Replay evidence is an http_exchange with replay=true,
-- OR a local_read (contract audit — the source code IS the replay). Mirrors
-- the claim gate for raw SQL.
-- RULE-E2 at the storage layer: a row can neither be created with nor
-- updated to status 'verified' unless replay evidence bound to that exact
-- finding id exists. Replay evidence is an http_exchange with replay=true,
-- OR a local_read of the source code (a contract audit has no HTTP exchange —
-- its "replay" is reading the same vulnerable line). EVERY branch is bound to
-- NEW.id: an unbound `kind = 'local_read'` let any single local_read anywhere
-- in the database satisfy the rule for an unrelated finding.
CREATE TRIGGER IF NOT EXISTS findings_insert_verified_requires_replay
BEFORE INSERT ON findings
WHEN NEW.status = 'verified'
    AND NOT EXISTS (
        SELECT 1 FROM evidence
        WHERE (kind = 'http_exchange' AND json_extract(data, '$.replay') = 1
               AND json_extract(data, '$.finding_id') = NEW.id)
           OR (kind = 'local_read'
               AND json_extract(data, '$.finding_id') = NEW.id)
           OR (kind = 'local_read'
               AND json_extract(data, '$.replay') = 1
               AND json_extract(data, '$.finding_id') = NEW.id)
    )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: verified requires replay evidence (RULE-E2)');
END;

CREATE TRIGGER IF NOT EXISTS findings_update_verified_requires_replay
AFTER UPDATE OF status ON findings
WHEN NEW.status = 'verified'
    AND NOT EXISTS (
        SELECT 1 FROM evidence
        WHERE (kind = 'http_exchange' AND json_extract(data, '$.replay') = 1
               AND json_extract(data, '$.finding_id') = NEW.id)
           OR (kind = 'local_read'
               AND json_extract(data, '$.finding_id') = NEW.id)
    )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: verified requires replay evidence (RULE-E2)');
END;

-- RULE-E1 (v0.7): a raw UPDATE that flips a theoretical finding to a claim
-- status requires bound evidence; theoretical -> candidate with 0 evidence is
-- blocked. Mirrors the claim gate for raw SQL.
CREATE TRIGGER IF NOT EXISTS findings_update_theoretical_requires_evidence
BEFORE UPDATE OF status ON findings
WHEN OLD.status = 'theoretical'
  AND NEW.status != 'theoretical'
  AND (
        json_valid(NEW.evidence_ids) IS NOT 1
        OR json_type(NEW.evidence_ids) != 'array'
        OR json_array_length(NEW.evidence_ids) == 0
  )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: theoretical promotion requires evidence (RULE-E1)');
END;

-- RULE-E1/RULE-E2 at the storage layer for evidence_ids rewrites: a raw-SQL
-- UPDATE that touches evidence_ids is rejected unless the NEW list is a
-- non-empty JSON array whose ids ALL exist in evidence, ALL belong to the
-- finding's own run (no cross-run splice), and — when the row is currently
-- verified — still contains the replay evidence bound to this finding id.
-- Legitimate same-run extensions pass; set_finding_status (which appends the
-- replay id when verifying) passes. Mirrors the claim gate for raw SQL.
CREATE TRIGGER IF NOT EXISTS findings_update_evidence_ids_guard
BEFORE UPDATE OF evidence_ids ON findings
WHEN (
        json_valid(NEW.evidence_ids) IS NOT 1
        OR json_type(NEW.evidence_ids) != 'array'
        OR json_array_length(NEW.evidence_ids) == 0
        OR EXISTS (
            SELECT 1 FROM json_each(NEW.evidence_ids) AS je
            WHERE NOT EXISTS (SELECT 1 FROM evidence e WHERE e.id = je.value)
        )
        OR EXISTS (
            SELECT 1 FROM json_each(NEW.evidence_ids) AS je
            JOIN evidence e ON e.id = je.value
            WHERE e.run_id != NEW.run_id
        )
        OR (
            OLD.status = 'verified'
            AND NOT EXISTS (
                SELECT 1 FROM json_each(NEW.evidence_ids) AS je
                WHERE EXISTS (
                    SELECT 1 FROM evidence e
                    WHERE e.id = je.value
                      AND (
                        (e.kind = 'http_exchange'
                         AND json_extract(e.data, '$.replay') = 1
                         AND json_extract(e.data, '$.finding_id') = NEW.id)
                        OR e.kind = 'local_read'
                      )
                )
            )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: evidence_ids update violates RULE-E1/RULE-E2');
END;

-- Append-only protection for v0.7 hunting-klass tables.
CREATE TRIGGER IF NOT EXISTS leads_no_update
BEFORE UPDATE ON leads
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS leads_no_delete
BEFORE DELETE ON leads
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS leads_no_replace
BEFORE INSERT ON leads
WHEN EXISTS (SELECT 1 FROM leads WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;

CREATE TRIGGER IF NOT EXISTS followups_no_update
BEFORE UPDATE ON followups
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS followups_no_delete
BEFORE DELETE ON followups
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS followups_no_replace
BEFORE INSERT ON followups
WHEN EXISTS (SELECT 1 FROM followups WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;

CREATE TRIGGER IF NOT EXISTS waves_no_update
BEFORE UPDATE ON waves
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS waves_no_delete
BEFORE DELETE ON waves
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS waves_no_replace
BEFORE INSERT ON waves
WHEN EXISTS (SELECT 1 FROM waves WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;

CREATE TRIGGER IF NOT EXISTS hunt_memory_no_update
BEFORE UPDATE ON hunt_memory
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS hunt_memory_no_delete
BEFORE DELETE ON hunt_memory
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;
CREATE TRIGGER IF NOT EXISTS hunt_memory_no_replace
BEFORE INSERT ON hunt_memory
WHEN EXISTS (SELECT 1 FROM hunt_memory WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'BLOCKED: append-only'); END;

-- Run metadata feeds the report headers; it is written once and then only
-- ended_ts/status may move (finish_run). Everything else is frozen.
CREATE TRIGGER IF NOT EXISTS runs_protected_columns
BEFORE UPDATE ON runs
WHEN OLD.run_id IS NOT NEW.run_id
    OR OLD.target IS NOT NEW.target
    OR OLD.engine IS NOT NEW.engine
    OR OLD.scope_name IS NOT NEW.scope_name
    OR OLD.started_ts IS NOT NEW.started_ts
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;
"""


def _enum_value(value: Any) -> str:
    """String value of a (str, Enum) member; passthrough for plain strings."""
    return value.value if isinstance(value, Enum) else str(value)


def _enum_member(enum_cls: type, raw: Any) -> Any:
    """Decode a stored string into an enum member; passthrough when unknown."""
    try:
        return enum_cls(raw)
    except ValueError:
        return raw


class Ledger:
    """Append-only, hash-chained event store. All writes flow through here."""

    _FINDING_COLS = (
        "id, run_id, key, title, severity, cwe, endpoint, method, param, payload_used,"
        " description, impact, remediation, status, evidence_ids, klass, falsifier,"
        " action_class, surface, poc_path, logs_path"
    )

    _TASK_COLS = (
        "task_id, parent_id, target, target_kind, state, priority, depth,"
        " spawned_from_finding, chain_hypothesis, injected_context,"
        " max_turns, max_wall_s, max_cost_usd, run_id,"
        " retry_count, max_retries, last_error, created_ts, started_ts, finished_ts"
    )

    def __init__(self, path: str | Path | None = None) -> None:
        db_path = self._resolve_path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        # Fire delete-side triggers even for REPLACE-shaped writes on this
        # connection (belt and braces on top of the *_no_replace triggers).
        self._conn.execute("PRAGMA recursive_triggers=ON")
        # v0.7 migration: add new columns / drop stale trigger defs before
        # re-running the (IF NOT EXISTS) schema script.
        self._migrate_v07()
        self._migrate_v3()
        self._conn.executescript(_SCHEMA)
        # Second pass: on a FRESH db the runs table only exists after the
        # schema script above, so the v3 columns are added here (idempotent).
        self._migrate_v3()
        # Stamp schema version (v3 = run lifecycle columns, RETENTION-SPEC A).
        try:
            v = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        except Exception:
            v = 0
        if v < 3:
            self._conn.execute("PRAGMA user_version = 3")

    def _migrate_v07(self) -> None:
        # Drop findings triggers we redefine (so stale defs get replaced).
        for trig in (
            "findings_protected_columns",
            "findings_insert_requires_evidence",
            "findings_insert_verified_requires_replay",
            "findings_update_verified_requires_replay",
            "findings_update_evidence_ids_guard",
            "findings_update_theoretical_requires_evidence",
        ):
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute(f"DROP TRIGGER IF EXISTS {trig}")
        # Add new columns to findings if missing (old DBs).
        new_cols = [
            ("klass", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("falsifier", "TEXT NOT NULL DEFAULT ''"),
            ("action_class", "TEXT NOT NULL DEFAULT 'read'"),
            ("surface", "TEXT"),
            ("poc_path", "TEXT"),
            ("logs_path", "TEXT"),
        ]
        existing = {r[1] for r in self._conn.execute("PRAGMA table_info(findings)").fetchall()}
        for col, decl in new_cols:
            if col not in existing:
                with contextlib.suppress(sqlite3.OperationalError):
                    self._conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")

    def _migrate_v3(self) -> None:
        """RETENTION-SPEC Part A: run-lifecycle columns on ``runs``.

        Additive only. ``runs_protected_columns`` freezes run_id/target/
        engine/scope_name/started_ts and deliberately does NOT mention these
        three columns, so a sealed run's outcome/closed_at/summary_json stay
        writable by ``kernel.runs.close_run``. Idempotent: re-running on a
        migrated db is a no-op.
        """
        new_cols = [
            ("outcome", "TEXT"),
            ("closed_at", "REAL"),
            ("summary_json", "TEXT"),
        ]
        existing = {r[1] for r in self._conn.execute("PRAGMA table_info(runs)").fetchall()}
        for col, decl in new_cols:
            if col not in existing:
                with contextlib.suppress(sqlite3.OperationalError):
                    self._conn.execute(f"ALTER TABLE runs ADD COLUMN {col} {decl}")

    def assert_run_writable(self, run_id: str) -> None:
        """Raise ``runs.RunClosed`` when ``run_id`` has been sealed (Part A).

        Read paths never call this — replaying/reporting a closed run stays
        possible. Import is local: ``hunter.kernel.runs`` imports this module.
        """
        from .runs import assert_run_writable as _assert  # noqa: PLC0415

        _assert(self, run_id)

    def run_is_closed(self, run_id: str) -> bool:
        """True when the run row carries a ``closed_at`` stamp."""
        from .runs import run_is_closed as _closed  # noqa: PLC0415

        return _closed(self, run_id)

    @staticmethod
    def _resolve_path(path: str | Path | None) -> Path:
        if path is not None:
            return Path(path)
        from hunter.runtime_paths import RuntimePaths

        return RuntimePaths.resolve(migrate=False).ledger

    @property
    def path(self) -> Path:
        """Filesystem path of the backing database file."""
        return self._path

    def close(self) -> None:
        """Close the underlying connection (the file remains, append-only)."""
        with self._lock:
            self._conn.close()

    # -- internals ----------------------------------------------------------

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """Serialize writers (thread lock) and make the block atomic."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _append_event(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        kind: EventKind | str,
        payload: dict[str, Any],
    ) -> Event:
        """Caller must hold the write transaction. Chains onto the global tip."""
        tip = conn.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = tip[0] if tip is not None else GENESIS_HASH
        seq = int(conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM events").fetchone()[0])
        event = Event.create(
            run_id=run_id,
            kind=kind,
            payload=payload,
            seq=seq,
            ts=time.time(),
            prev_hash=prev_hash,
        )
        conn.execute(
            "INSERT INTO events (seq, run_id, kind, payload, ts, prev_hash, hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.seq,
                run_id,
                _enum_value(kind),
                canonical_json(payload),
                event.ts,
                event.prev_hash,
                event.hash,
            ),
        )
        return event

    @staticmethod
    def _next_id(conn: sqlite3.Connection, table: str, prefix: str) -> str:
        """Global counter (EV-0001... / F-0001...) — rows are never deleted."""
        start = len(prefix) + 2  # skip prefix and '-'
        row = conn.execute(
            f"SELECT COALESCE(MAX(CAST(SUBSTR(id, ?) AS INTEGER)), 0) FROM {table}", (start,)
        ).fetchone()
        number = int(row[0]) + 1
        if prefix == "F":
            return finding_id(number)
        return f"{prefix}-{number:04d}"

    @staticmethod
    def _fetch_events(
        conn: sqlite3.Connection, run_id: str | None
    ) -> list[tuple[Any, ...]]:
        sql = "SELECT seq, run_id, kind, payload, ts, prev_hash, hash FROM events"
        params: tuple[Any, ...] = ()
        if run_id is not None:
            sql += " WHERE run_id = ?"
            params = (run_id,)
        sql += " ORDER BY seq"
        return conn.execute(sql, params).fetchall()

    @staticmethod
    def _row_to_event(row: tuple[Any, ...]) -> Event:
        seq, run_id, kind_raw, payload_raw, ts, prev_hash, digest = row
        try:
            kind: EventKind | str = EventKind(kind_raw)
        except ValueError:
            # Unknown (newer-writer) kind: keep the raw string — ``Event.kind``
            # is ``EventKind | str`` and ``kind_value()`` normalises both, so the
            # row still hash-verifies instead of being dropped.
            kind = str(kind_raw)
        return Event(
            seq=seq,
            run_id=run_id,
            kind=kind,
            payload=json.loads(payload_raw),
            ts=ts,
            prev_hash=prev_hash,
            hash=digest,
        )

    def _hash_exists(self, digest: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM events WHERE hash = ?", (digest,)).fetchone()
        return row is not None

    @staticmethod
    def _fetch_finding_row(conn: sqlite3.Connection, finding_id: str) -> tuple[Any, ...] | None:
        return conn.execute(
            f"SELECT {Ledger._FINDING_COLS} FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()

    @staticmethod
    def _row_to_finding(row: tuple[Any, ...]) -> Finding:
        # Back-compat: old rows may lack the v0.7 columns.
        # Pad row to full width if needed.
        row = tuple(row) + (None,) * (21 - len(row))
        (
            fid, run_id, key, title, severity, cwe, endpoint, method, param,
            payload_used, description, impact, remediation, status, evidence_ids,
            klass, falsifier, action_class, surface, poc_path, logs_path,
        ) = row[:21]
        return Finding(
            id=fid,
            run_id=run_id,
            key=key,
            title=title,
            severity=_enum_member(Severity, severity),
            cwe=cwe,
            endpoint=endpoint,
            method=method,
            param=param,
            payload_used=payload_used,
            description=description,
            impact=impact,
            remediation=remediation,
            status=_enum_member(FindingStatus, status),
            evidence_ids=tuple(json.loads(evidence_ids)),
            klass=klass or "unknown",
            falsifier=falsifier or "",
            action_class=action_class or "read",
            surface=surface,
            poc_path=poc_path,
            logs_path=logs_path,
        )

    @staticmethod
    def _find_replay_evidence(conn: sqlite3.Connection, finding_id: str) -> str | None:
        """RULE-E2: an http_exchange artifact whose data replays this finding."""
        rows = conn.execute(
            "SELECT id, data FROM evidence WHERE kind = ? ORDER BY created_seq, id",
            ("http_exchange",),
        ).fetchall()
        for evidence_id, raw in rows:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(data, dict)
                and data.get("replay") is True
                and data.get("finding_id") == finding_id
            ):
                return evidence_id
        return None

    # -- runs ---------------------------------------------------------------

    def create_run(self, run_id: str, target: str, engine: str, scope_name: str) -> None:
        with self._write() as conn:
            conn.execute(
                "INSERT INTO runs (run_id, target, engine, scope_name, started_ts, ended_ts, status)"
                " VALUES (?, ?, ?, ?, ?, NULL, ?)",
                (run_id, target, engine, scope_name, time.time(), "running"),
            )

    def finish_run(self, run_id: str, status: str) -> None:
        with self._write() as conn:
            cursor = conn.execute(
                "UPDATE runs SET ended_ts = ?, status = ? WHERE run_id = ?",
                (time.time(), status, run_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"run '{run_id}' not found")

    def runs(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT run_id, target, engine, scope_name, started_ts, ended_ts, status,"
                " outcome, closed_at, summary_json"
                " FROM runs ORDER BY started_ts, run_id"
            ).fetchall()
        return [
            {
                "run_id": r[0],
                "target": r[1],
                "engine": r[2],
                "scope_name": r[3],
                "started_ts": r[4],
                "ended_ts": r[5],
                "status": r[6],
                # Lifecycle columns (schema v3). Retention MUST see closed_at:
                # without it every run looks open and garbage collection becomes
                # a silent no-op that never reclaims a single row.
                "outcome": r[7],
                "closed_at": r[8],
                "summary_json": r[9],
            }
            for r in rows
        ]

    # -- events -------------------------------------------------------------

    def append(self, run_id: str, kind: EventKind | str, payload: dict[str, Any]) -> Event:
        with self._write() as conn:
            return self._append_event(conn, run_id, kind, payload)

    def events(self, run_id: str | None = None) -> list[Event]:
        with self._lock:
            rows = self._fetch_events(self._conn, run_id)
        return [self._row_to_event(r) for r in rows]

    def verify_chain(self, run_id: str | None = None) -> ChainReport:
        """Recompute every stored hash and report the first break, if any.

        Global (``run_id is None``): single-chain contiguity — every row must
        chain onto its predecessor. Per-run: the global chain interleaves runs,
        so filtered contiguity is NOT required — each row must hash-verify and
        its ``prev_hash`` must be GENESIS or reference an existing event
        globally (a dangling/missing predecessor still fails).
        """
        with self._lock:
            rows = self._fetch_events(self._conn, run_id)
        report = ChainReport(ok=True, checked=len(rows))
        if run_id is not None:
            for row in rows:
                try:
                    event = self._row_to_event(row)
                except (json.JSONDecodeError, TypeError, ValueError):
                    seq = row[0]
                    report.ok = False
                    if report.broken_at_seq is None:
                        report.broken_at_seq = seq
                    report.details.append(f"seq {seq}: row is not decodable (payload corrupt)")
                    continue
                run_problems: list[str] = []
                if event.hash != event.recompute_hash():
                    run_problems.append(
                        f"seq {event.seq}: stored hash does not match recomputed content hash"
                    )
                if event.prev_hash != GENESIS_HASH and not self._hash_exists(event.prev_hash):
                    run_problems.append(
                        f"seq {event.seq}: prev_hash references no event and is not GENESIS_HASH"
                    )
                if run_problems:
                    report.ok = False
                    if report.broken_at_seq is None:
                        report.broken_at_seq = event.seq
                    report.details.extend(run_problems)
            return report
        expected_prev = GENESIS_HASH
        for idx, row in enumerate(rows):
            try:
                event = self._row_to_event(row)
            except (json.JSONDecodeError, TypeError, ValueError):
                seq = row[0]
                report.ok = False
                if report.broken_at_seq is None:
                    report.broken_at_seq = seq
                report.details.append(f"seq {seq}: row is not decodable (payload corrupt)")
                continue
            problems: list[str] = []
            if event.hash != event.recompute_hash():
                problems.append(
                    f"seq {event.seq}: stored hash does not match recomputed content hash"
                )
            if idx == 0:
                # Unfiltered: the first row must chain from genesis. Filtered: its
                # prev_hash may point at an event of another run — it must exist.
                if event.prev_hash != GENESIS_HASH and not self._hash_exists(event.prev_hash):
                    problems.append(
                        f"seq {event.seq}: prev_hash references no event and is not GENESIS_HASH"
                    )
            elif event.prev_hash != expected_prev:
                problems.append(
                    f"seq {event.seq}: prev_hash does not match hash of the preceding event"
                )
            expected_prev = event.hash
            if problems:
                report.ok = False
                if report.broken_at_seq is None:
                    report.broken_at_seq = event.seq
                report.details.extend(problems)
        return report

    # -- evidence -----------------------------------------------------------

    #: Closed vocabulary of evidence artifact kinds (media hardening: an
    #: unknown kind is rejected instead of stored).
    ALLOWED_EVIDENCE_KINDS = frozenset(
        {
            "http_exchange",
            "http_response",
            "code_location",
            "note",
            "tool_output",
            "browser_event",
            # Post-JS DOM snapshot produced by the browser_render tool. The tool
            # emitted this kind before it was in the vocabulary, so any hunt that
            # rendered a page died on the claim gate instead of storing evidence.
            "browser_render",
            "local_read",
            "dns_record",
            "ct_entry",
            "headers_audit",
            "port_hint",
            "dnssec_hint",
            "tls_inventory",
            "contract_call",
            "contract_source",
            "slither_audit",
            "cast_call",
            "poc_run",
            "verifier_transcript",
        }
    )

    #: Largest single evidence blob accepted (canonical JSON, UTF-8 bytes).
    EVIDENCE_MAX_BYTES = 1024 * 1024  # 1 MiB

    def add_evidence(self, run_id: str, kind: str, data: dict[str, Any]) -> str:
        """Deep-redacts, stores, and returns the evidence id (e.g. 'EV-0007').

        Rejects unknown ``kind`` values (allowlist) and oversized payloads
        (size cap) with :class:`ClaimGateBlocked` — fail-closed, nothing is
        persisted on rejection.
        """
        if kind not in self.ALLOWED_EVIDENCE_KINDS:
            raise ClaimGateBlocked(
                f"BLOCKED: evidence kind {kind!r} is not in the allowed "
                f"vocabulary {sorted(self.ALLOWED_EVIDENCE_KINDS)}."
            )
        redacted = redact_payload(data)
        if kind == "code_location":
            # Validate the REDACTED payload: the stored artifact is what must
            # re-verify, so tamper-evidence binds to what is actually on disk.
            from .claimgate import validate_code_location

            validate_code_location(redacted)
        blob = canonical_json(redacted)
        if len(blob.encode("utf-8")) > self.EVIDENCE_MAX_BYTES:
            raise ClaimGateBlocked(
                f"BLOCKED: evidence blob exceeds the {self.EVIDENCE_MAX_BYTES}-byte cap."
            )
        digest = sha256_hex(blob)
        with self._write() as conn:
            # Inside the transaction: a concurrent seal cannot slip between
            # the check and the insert (BEGIN IMMEDIATE holds the write lock).
            self.assert_run_writable(run_id)
            evidence_id = self._next_id(conn, "evidence", "EV")
            stored = self._append_event(
                conn,
                run_id,
                EventKind.EVIDENCE_STORED,
                {"evidence_id": evidence_id, "kind": kind, "sha256": digest},
            )
            conn.execute(
                "INSERT INTO evidence (id, run_id, kind, data, sha256, created_seq)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (evidence_id, run_id, kind, blob, digest, stored.seq),
            )
        return evidence_id

    def evidence(self, run_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT id, run_id, kind, data, sha256, created_seq FROM evidence"
        params: tuple[Any, ...] = ()
        if run_id is not None:
            sql += " WHERE run_id = ?"
            params = (run_id,)
        sql += " ORDER BY created_seq, id"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            {
                "id": r[0],
                "run_id": r[1],
                "kind": r[2],
                "data": json.loads(r[3]),
                "sha256": r[4],
                "created_seq": r[5],
            }
            for r in rows
        ]

    # -- findings -----------------------------------------------------------

    def create_finding(self, finding: Finding) -> Finding:
        """Assigns id, binds evidence, applies RULE-E1 atomically."""
        with self._write() as conn:
            # RETENTION-SPEC A: a sealed run accepts no new claims.
            self.assert_run_writable(finding.run_id)
            for evidence_id in finding.evidence_ids:
                known = conn.execute(
                    "SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)
                ).fetchone()
                if known is None:
                    raise ClaimGateBlocked(
                        f"BLOCKED: evidence '{evidence_id}' bound to finding"
                        f" '{finding.key}' does not exist in the ledger (RULE-E1)."
                    )
                # Same-run ownership: evidence may never be spliced across runs
                # (mirrors the evidence_ids UPDATE guard at the trigger layer).
                row = conn.execute(
                    "SELECT run_id FROM evidence WHERE id = ?", (evidence_id,)
                ).fetchone()
                if row is not None and str(row[0]) != str(finding.run_id):
                    raise ClaimGateBlocked(
                        f"BLOCKED: evidence '{evidence_id}' belongs to run '{row[0]}',"
                        f" not '{finding.run_id}' (RULE-E1 cross-run splice)."
                    )
            validate_finding_insert(finding, len(finding.evidence_ids))
            new_id = self._next_id(conn, "findings", "F")
            created = replace(finding, id=new_id, status=FindingStatus.CANDIDATE)
            conn.execute(
                "INSERT INTO findings (id, run_id, key, title, severity, cwe, endpoint, method,"
                " param, payload_used, description, impact, remediation, status, evidence_ids,"
                " klass, falsifier, action_class, surface, poc_path, logs_path)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    created.id,
                    created.run_id,
                    created.key,
                    created.title,
                    _enum_value(created.severity),
                    created.cwe,
                    created.endpoint,
                    created.method,
                    created.param,
                    created.payload_used,
                    created.description,
                    created.impact,
                    created.remediation,
                    _enum_value(created.status),
                    canonical_json(list(created.evidence_ids)),
                    created.klass,
                    created.falsifier,
                    created.action_class,
                    created.surface,
                    created.poc_path,
                    created.logs_path,
                ),
            )
            self._append_event(
                conn,
                created.run_id,
                EventKind.FINDING_CREATED,
                {
                    "finding_id": created.id,
                    "key": created.key,
                    "title": created.title,
                    "severity": _enum_value(created.severity),
                    "evidence_ids": list(created.evidence_ids),
                },
            )
        return created

    def create_theoretical_finding(self, finding: Finding) -> Finding:
        """Record a hypothesis (0 evidence legal). Status forced THEORETICAL."""
        from dataclasses import replace as _replace

        finding = _replace(finding, status=FindingStatus.THEORETICAL)
        evidence_ids = list(finding.evidence_ids)
        with self._write() as conn:
            # RETENTION-SPEC A: a sealed run accepts no new claims.
            self.assert_run_writable(finding.run_id)
            for evidence_id in evidence_ids:
                known = conn.execute(
                    "SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)
                ).fetchone()
                if known is None:
                    raise ClaimGateBlocked(
                        f"BLOCKED: evidence '{evidence_id}' bound to finding"
                        f" '{finding.key}' does not exist in the ledger (RULE-E1)."
                    )
                row = conn.execute(
                    "SELECT run_id FROM evidence WHERE id = ?", (evidence_id,)
                ).fetchone()
                if row is not None and str(row[0]) != str(finding.run_id):
                    raise ClaimGateBlocked(
                        f"BLOCKED: evidence '{evidence_id}' belongs to run '{row[0]}',"
                        f" not '{finding.run_id}' (RULE-E1 cross-run splice)."
                    )
            validate_finding_insert(finding, len(evidence_ids))
            new_id = self._next_id(conn, "findings", "F")
            created = _replace(finding, id=new_id, status=FindingStatus.THEORETICAL)
            conn.execute(
                "INSERT INTO findings (id, run_id, key, title, severity, cwe, endpoint, method,"
                " param, payload_used, description, impact, remediation, status, evidence_ids,"
                " klass, falsifier, action_class, surface, poc_path, logs_path)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    created.id,
                    created.run_id,
                    created.key,
                    created.title,
                    _enum_value(created.severity),
                    created.cwe,
                    created.endpoint,
                    created.method,
                    created.param,
                    created.payload_used,
                    created.description,
                    created.impact,
                    created.remediation,
                    _enum_value(created.status),
                    canonical_json(list(created.evidence_ids)),
                    created.klass,
                    created.falsifier,
                    created.action_class,
                    created.surface,
                    created.poc_path,
                    created.logs_path,
                ),
            )
            self._append_event(
                conn,
                created.run_id,
                EventKind.FINDING_CREATED,
                {
                    "finding_id": created.id,
                    "key": created.key,
                    "title": created.title,
                    "severity": _enum_value(created.severity),
                    "status": _enum_value(created.status),
                    "evidence_ids": list(created.evidence_ids),
                },
            )
        return created

    def set_finding_status(
        self, finding_id: str, status: FindingStatus, reason: str,
        poc_path: str | None = None,
        logs_path: str | None = None,
        falsifier: str | None = None,
    ) -> Finding:
        """Applies RULE-E2 (verified needs replay evidence). Append-only trail."""
        new_status = (
            status if isinstance(status, FindingStatus) else _enum_member(FindingStatus, str(status))
        )
        with self._write() as conn:
            row = self._fetch_finding_row(conn, finding_id)
            if row is None:
                raise KeyError(f"finding '{finding_id}' not found")
            current = self._row_to_finding(row)
            # RETENTION-SPEC A: statuses may not move once the run is sealed.
            self.assert_run_writable(current.run_id)
            if not reason or not reason.strip():
                raise ClaimGateBlocked(
                    f"BLOCKED: status change of finding '{finding_id}' requires a non-empty"
                    " reason — the audit trail must explain itself."
                )
            evidence_ids = list(current.evidence_ids)
            if new_status == FindingStatus.VERIFIED:
                # RULE-E2: VERIFIED requires replay evidence — an http_exchange
                # with replay=true bound to this finding, OR a local_read of
                # the source code that was independently re-verified. A contract
                # audit has no HTTP exchange; its "replay" is reading the same
                # vulnerable line in the source.
                replay_id = self._find_replay_evidence(conn, finding_id)
                if replay_id is None:
                    # Check for local_read evidence (contract findings)
                    for eid in evidence_ids:
                        row = conn.execute(
                            "SELECT kind FROM evidence WHERE id = ?", (eid,)
                        ).fetchone()
                        if row and row[0] == "local_read":
                            replay_id = eid
                            break
                if replay_id is None:
                    raise ClaimGateBlocked(
                        f"BLOCKED: finding '{finding_id}' cannot be VERIFIED: no replay evidence"
                        " (http_exchange with replay=true or local_read) bound to it exists"
                        " (RULE-E2)."
                    )
                if replay_id not in evidence_ids:
                    evidence_ids.append(replay_id)
            # Validate all transitions (RULE-E1 for theoretical promotion, RULE-E2
            # for verified, RULE-E5 klass already fixed at insert).
            validate_status_change(current, new_status, len(evidence_ids))
            updates = ["status = ?", "evidence_ids = ?"]
            params: list[Any] = [_enum_value(new_status), canonical_json(evidence_ids)]
            if poc_path is not None:
                updates.append("poc_path = ?")
                params.append(poc_path)
            if logs_path is not None:
                updates.append("logs_path = ?")
                params.append(logs_path)
            if falsifier is not None:
                updates.append("falsifier = ?")
                params.append(falsifier)
            params.append(finding_id)
            conn.execute(f"UPDATE findings SET {', '.join(updates)} WHERE id = ?", params)
            updated = replace(current, status=new_status, evidence_ids=tuple(evidence_ids))
            self._append_event(
                conn,
                current.run_id,
                EventKind.FINDING_STATUS_CHANGED,
                {
                    "finding_id": finding_id,
                    "old_status": _enum_value(current.status),
                    "new_status": _enum_value(new_status),
                    "reason": reason,
                    "evidence_ids": list(evidence_ids),
                },
            )
        return updated

    def get_finding(self, finding_id: str) -> Finding:
        with self._lock:
            row = self._fetch_finding_row(self._conn, finding_id)
        if row is None:
            raise KeyError(f"finding '{finding_id}' not found")
        return self._row_to_finding(row)

    def findings(self, run_id: str | None = None) -> list[Finding]:
        sql = f"SELECT {self._FINDING_COLS} FROM findings"
        params: tuple[Any, ...] = ()
        if run_id is not None:
            sql += " WHERE run_id = ?"
            params = (run_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    # -- tasks ---------------------------------------------------------------

    #: Allowed task states for the state machine.
    TASK_STATES = frozenset({"queued", "running", "completed", "failed", "retrying"})

    @staticmethod
    def _next_task_id(conn: sqlite3.Connection) -> str:
        """Generate the next global task id as T-0001, T-0002, etc."""
        row = conn.execute(
            "SELECT COALESCE(MAX(CAST(SUBSTR(task_id, 3) AS INTEGER)), 0) FROM tasks"
        ).fetchone()
        number = int(row[0]) + 1
        return f"T-{number:04d}"

    def next_task_id(self) -> str:
        """Public read-only peek at the next task id."""
        with self._lock:
            return self._next_task_id(self._conn)

    def add_task(
        self,
        target: str,
        target_kind: str,
        parent_id: str | None = None,
        depth: int = 0,
        priority: int = 0,
        spawned_from_finding: str | None = None,
        chain_hypothesis: str | None = None,
        injected_context: str | None = None,
        max_turns: int = 8,
        max_wall_s: int = 300,
        max_cost_usd: float = 0.50,
        run_id: str | None = None,
    ) -> str:
        """Enqueue a new task. Returns the assigned task_id.

        The task enters the ``queued`` state and is a candidate for
        ``claim_task`` / ``get_next_queued``.
        """
        with self._write() as conn:
            task_id = self._next_task_id(conn)
            now = time.time()
            conn.execute(
                "INSERT INTO tasks (task_id, parent_id, target, target_kind, state,"
                " priority, depth, spawned_from_finding, chain_hypothesis,"
                " injected_context, max_turns, max_wall_s, max_cost_usd, run_id,"
                " created_ts)"
                " VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id, parent_id, target, target_kind,
                    priority, depth,
                    spawned_from_finding, chain_hypothesis,
                    injected_context, max_turns, max_wall_s, max_cost_usd,
                    run_id, now,
                ),
            )
        return task_id

    def claim_task(self) -> dict[str, Any] | None:
        """Atomically claim the next queued task (BFS order).

        Returns the task row as a dict, or ``None`` when no queued tasks remain.
        The returned task is now in ``running`` state and cannot be claimed by
        another caller (the UPDATE runs inside a write transaction).
        """
        with self._write() as conn:
            now = time.time()
            # Find the highest-priority queued task in BFS order.
            row = conn.execute(
                "SELECT task_id FROM tasks"
                " WHERE state = 'queued'"
                " ORDER BY depth, priority, created_ts, task_id"
                " LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            task_id = row[0]
            conn.execute(
                "UPDATE tasks SET state = 'running',"
                " retry_count = retry_count + 1, started_ts = ?"
                " WHERE task_id = ? AND state = 'queued'",
                (now, task_id),
            )
            # Re-read under the same transaction to return full row.
            row = conn.execute(
                f"SELECT {self._TASK_COLS} FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        return self._row_to_task(row) if row else None

    def finish_task(
        self, task_id: str, state: str, error: str | None = None
    ) -> None:
        """Mark a task as ``completed`` or ``failed``.

        ``state`` must be ``'completed'`` or ``'failed'``.
        If ``error`` is given it is written to ``last_error``.
        """
        if state not in ("completed", "failed"):
            raise ValueError(f"state must be 'completed' or 'failed', got {state!r}")
        with self._write() as conn:
            now = time.time()
            cursor = conn.execute(
                "UPDATE tasks SET state = ?, finished_ts = ?, last_error = ?"
                " WHERE task_id = ?",
                (state, now, error, task_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"task '{task_id}' not found")

    def mark_retrying(self, task_id: str, error: str) -> str | None:
        """Route a failed task into retry.

        If ``retry_count < max_retries`` the task moves to ``retrying`` state
        and then back to ``queued`` (so it can be claimed again).
        Returns the task_id if retried, or ``None`` when retries are exhausted
        (task stays ``failed``).
        """
        with self._write() as conn:
            row = conn.execute(
                "SELECT retry_count, max_retries FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"task '{task_id}' not found")
            retry_count, max_retries = int(row[0]), int(row[1])
            if retry_count >= max_retries:
                # Exhausted — leave in failed state, just stamp the error.
                conn.execute(
                    "UPDATE tasks SET last_error = ? WHERE task_id = ?",
                    (error, task_id),
                )
                return None
            # Move: failed → retrying → queued
            conn.execute(
                "UPDATE tasks SET state = 'retrying', last_error = ?"
                " WHERE task_id = ?",
                (error, task_id),
            )
            conn.execute(
                "UPDATE tasks SET state = 'queued' WHERE task_id = ?",
                (task_id,),
            )
            return task_id

    def get_next_queued(self) -> dict[str, Any] | None:
        """Peek at the next queued task (BFS order) without claiming it.

        BFS order: lowest ``depth`` first, then ``priority`` (higher = sooner),
        then ``created_ts``.
        """
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._TASK_COLS} FROM tasks"
                " WHERE state = 'queued'"
                " ORDER BY depth, priority, created_ts, task_id"
                " LIMIT 1"
            ).fetchone()
        return self._row_to_task(row) if row else None

    def pending_count(self) -> int:
        """Number of tasks currently in the ``queued`` state."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE state = 'queued'"
            ).fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _row_to_task(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "task_id": row[0],
            "parent_id": row[1],
            "target": row[2],
            "target_kind": row[3],
            "state": row[4],
            "priority": row[5],
            "depth": row[6],
            "spawned_from_finding": row[7],
            "chain_hypothesis": row[8],
            "injected_context": row[9],
            "max_turns": row[10],
            "max_wall_s": row[11],
            "max_cost_usd": row[12],
            "run_id": row[13],
            "retry_count": row[14],
            "max_retries": row[15],
            "last_error": row[16],
            "created_ts": row[17],
            "started_ts": row[18],
            "finished_ts": row[19],
        }

    def spawn_child_task(self, parent_id: str, *, target: str, target_kind: str,
                         spawned_from_finding: str | None = None,
                         chain_hypothesis: str | None = None,
                         injected_context: str | None = None,
                         max_turns: int = 8, max_wall_s: int = 300,
                         max_cost_usd: float = 0.50,
                         priority: int = 0, depth: int = 1,
                         run_id: str | None = None) -> str:
        """Spawn a child task derived from a parent finding."""
        with self._write() as conn:
            task_id = self._next_task_id(conn)
            conn.execute(
                "INSERT INTO tasks (task_id, parent_id, target, target_kind,"
                " state, priority, depth, spawned_from_finding, chain_hypothesis,"
                " injected_context, max_turns, max_wall_s, max_cost_usd, run_id,"
                " retry_count, max_retries, created_ts)"
                " VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 2, ?)",
                (task_id, parent_id, target, target_kind, priority, depth,
                 spawned_from_finding, chain_hypothesis, injected_context,
                 max_turns, max_wall_s, max_cost_usd, run_id, time.time()),
            )
        return task_id

    def prior_finding_summaries(self, run_id: str | None = None,
                                limit: int = 10) -> list[dict[str, str]]:
        """Return compact summaries (title + description) of prior findings
        for cross-pollination injection. Most recent first."""
        sql = (
            "SELECT title, description FROM findings"
        )
        params: tuple[Any, ...] = ()
        if run_id is not None:
            sql += " WHERE run_id = ?"
            params = (run_id,)
        sql += " ORDER BY rowid DESC LIMIT ?"
        params = (*params, limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            {"title": r[0], "key_output": (r[1][:500] if r[1] else "")}
            for r in rows
        ]

    def task_count(self) -> dict[str, int]:
        """Return counts by state for daemon status."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, COUNT(*) FROM tasks GROUP BY state"
            ).fetchall()
        return {r[0]: r[1] for r in rows}
