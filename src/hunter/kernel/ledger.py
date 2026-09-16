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
    evidence_ids TEXT NOT NULL DEFAULT '[]'
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
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: append-only');
END;

-- RULE-E1 at the storage layer: no finding row may come into existence
-- unless it references at least one evidence artifact that exists, and none
-- of its references is dangling. Mirrors ledger.create_finding for raw SQL.
CREATE TRIGGER IF NOT EXISTS findings_insert_requires_evidence
BEFORE INSERT ON findings
WHEN NOT EXISTS (
        SELECT 1 FROM json_each(COALESCE(NEW.evidence_ids, '[]')) AS je
        WHERE je.type = 'text'
          AND EXISTS (SELECT 1 FROM evidence e WHERE e.id = je.value)
    )
    OR EXISTS (
        SELECT 1 FROM json_each(COALESCE(NEW.evidence_ids, '[]')) AS je
        WHERE NOT EXISTS (SELECT 1 FROM evidence e WHERE e.id = je.value)
    )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: finding requires existing bound evidence (RULE-E1)');
END;

-- RULE-E2 at the storage layer: a row can neither be created with nor
-- updated to status 'verified' unless replay evidence bound to that exact
-- finding id exists. Mirrors the claim gate for raw SQL.
CREATE TRIGGER IF NOT EXISTS findings_insert_verified_requires_replay
BEFORE INSERT ON findings
WHEN NEW.status = 'verified'
    AND NOT EXISTS (
        SELECT 1 FROM evidence
        WHERE kind = 'http_exchange'
          AND json_extract(data, '$.replay') = 1
          AND json_extract(data, '$.finding_id') = NEW.id
    )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: verified requires replay evidence (RULE-E2)');
END;

CREATE TRIGGER IF NOT EXISTS findings_update_verified_requires_replay
AFTER UPDATE OF status ON findings
WHEN NEW.status = 'verified'
    AND NOT EXISTS (
        SELECT 1 FROM evidence
        WHERE kind = 'http_exchange'
          AND json_extract(data, '$.replay') = 1
          AND json_extract(data, '$.finding_id') = NEW.id
    )
BEGIN
    SELECT RAISE(ABORT, 'BLOCKED: verified requires replay evidence (RULE-E2)');
END;

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
        " description, impact, remediation, status, evidence_ids"
    )

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
        # Fire delete-side triggers even for REPLACE-shaped writes on this
        # connection (belt and braces on top of the *_no_replace triggers).
        self._conn.execute("PRAGMA recursive_triggers=ON")
        self._conn.executescript(_SCHEMA)

    @staticmethod
    def _resolve_path(path: str | Path | None) -> Path:
        if path is not None:
            return Path(path)
        from hunter.home import state_dir  # deferred: home.py is stdlib-only

        return state_dir() / "ledger.db"

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
            kind = kind_raw
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
        (
            fid, run_id, key, title, severity, cwe, endpoint, method, param,
            payload_used, description, impact, remediation, status, evidence_ids,
        ) = row
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
                "SELECT run_id, target, engine, scope_name, started_ts, ended_ts, status"
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
        """Recompute every stored hash and report the first break, if any."""
        with self._lock:
            rows = self._fetch_events(self._conn, run_id)
        report = ChainReport(ok=True, checked=len(rows))
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

    def add_evidence(self, run_id: str, kind: str, data: dict[str, Any]) -> str:
        """Deep-redacts, stores, and returns the evidence id (e.g. 'EV-0007')."""
        redacted = redact_payload(data)
        digest = sha256_hex(canonical_json(redacted))
        with self._write() as conn:
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
                (evidence_id, run_id, kind, canonical_json(redacted), digest, stored.seq),
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
            for evidence_id in finding.evidence_ids:
                known = conn.execute(
                    "SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)
                ).fetchone()
                if known is None:
                    raise ClaimGateBlocked(
                        f"BLOCKED: evidence '{evidence_id}' bound to finding"
                        f" '{finding.key}' does not exist in the ledger (RULE-E1)."
                    )
            validate_finding_insert(finding, len(finding.evidence_ids))
            new_id = self._next_id(conn, "findings", "F")
            created = replace(finding, id=new_id, status=FindingStatus.CANDIDATE)
            conn.execute(
                "INSERT INTO findings (id, run_id, key, title, severity, cwe, endpoint, method,"
                " param, payload_used, description, impact, remediation, status, evidence_ids)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    def set_finding_status(
        self, finding_id: str, status: FindingStatus, reason: str
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
            if not reason or not reason.strip():
                raise ClaimGateBlocked(
                    f"BLOCKED: status change of finding '{finding_id}' requires a non-empty"
                    " reason — the audit trail must explain itself."
                )
            evidence_ids = list(current.evidence_ids)
            if new_status == FindingStatus.VERIFIED:
                replay_id = self._find_replay_evidence(conn, finding_id)
                if replay_id is None:
                    raise ClaimGateBlocked(
                        f"BLOCKED: finding '{finding_id}' cannot be VERIFIED: no http_exchange"
                        " evidence with replay=true bound to it exists (RULE-E2)."
                    )
                if replay_id not in evidence_ids:
                    evidence_ids.append(replay_id)
                validate_status_change(current, new_status, len(evidence_ids))
            conn.execute(
                "UPDATE findings SET status = ?, evidence_ids = ? WHERE id = ?",
                (_enum_value(new_status), canonical_json(evidence_ids), finding_id),
            )
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
