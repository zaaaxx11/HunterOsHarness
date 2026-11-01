"""Part B of docs/RETENTION-SPEC.md — `hunter gc` retention.

Covers:
- archive_run / verify_archive / purge_run
- gc_chat (7-day chat retention)
- gc_runs orchestration (closed-run retention)
- `hunter gc` CLI
- cron wrapper

Invariants proven here:
  1. Closed runs are archived to `<archive_dir>/<run_id>.db`.
  2. Archive verification recomputes hash chains and compares row counts.
  3. Purge drops append-only triggers, deletes, recreates triggers inside
     BEGIN IMMEDIATE; any verification failure rolls back and leaves the
     live database byte-identical in row counts.
  4. Open runs are NEVER archived or purged.
  5. gc_chat removes only chat rows older than 7 days.
  6. `hunter gc` is a registered CLI command; `--json` emits pure JSON.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hunter.kernel.ledger import Ledger
from hunter.kernel.runs import run_is_closed

if TYPE_CHECKING:
    from hunter.chat.sessions import ChatStore

__all__ = [
    "archive_run",
    "gc_chat",
    "gc_runs",
    "purge_run",
    "verify_archive",
]


# -- helpers ------------------------------------------------------------------


def _trigger_names(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def _drop_triggers(conn: sqlite3.Connection) -> None:
    for name in _trigger_names(conn):
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")


def _recreate_triggers(conn: sqlite3.Connection, schema_sql: str) -> None:
    conn.executescript(schema_sql)


def _row_count(conn: sqlite3.Connection, table: str, run_id: str) -> int:
    column = {
        "events": "run_id",
        "evidence": "run_id",
        "findings": "run_id",
        "runs": "run_id",
        "hunt_memory": "run_id",
        "waves": "run_id",
    }.get(table, "run_id")
    return int(
        conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", (run_id,)).fetchone()[0]
    )


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Minimal archive schema: run data tables.
_ARCHIVE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    engine TEXT NOT NULL,
    scope_name TEXT NOT NULL,
    started_ts REAL,
    ended_ts REAL,
    status TEXT NOT NULL,
    outcome TEXT,
    closed_at REAL,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    ts REAL NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    key TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cwe TEXT,
    endpoint TEXT,
    method TEXT,
    param TEXT,
    payload_used TEXT,
    description TEXT,
    impact TEXT,
    remediation TEXT,
    status TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    klass TEXT,
    falsifier TEXT,
    action_class TEXT,
    surface TEXT,
    poc_path TEXT
);
"""


def _archive_schema(conn: sqlite3.Connection, run_id: str) -> None:
    """Ensure archive tables exist and copy rows for ``run_id``.

    The archive inherits the live DB's append-only triggers through
    ``backup()``. Those guards must be lifted *just long enough* to copy the
    rows and then put back verbatim: the archive is the only surviving copy of
    a purged run, so leaving it unguarded would make the evidence trivially
    destroyable — the exact property the ledger is built to prevent.
    """
    conn.executescript(_ARCHIVE_SCHEMA_SQL)
    # Capture the guards BEFORE dropping them so they can be restored exactly.
    guards = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND sql IS NOT NULL"
    ).fetchall()
    for name in _trigger_names(conn):
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")
    conn.execute(
        "INSERT OR IGNORE INTO runs SELECT * FROM runs WHERE run_id = ?",
        (run_id,),
    )
    conn.execute(
        "INSERT OR IGNORE INTO events SELECT * FROM events WHERE run_id = ?",
        (run_id,),
    )
    conn.execute(
        "INSERT OR IGNORE INTO evidence SELECT * FROM evidence WHERE run_id = ?",
        (run_id,),
    )
    conn.execute(
        "INSERT OR IGNORE INTO findings SELECT * FROM findings WHERE run_id = ?",
        (run_id,),
    )
    # Restore each guard whole. Do NOT split the captured DDL on ';' — trigger
    # bodies are BEGIN ... END and some embed semicolons, which is what
    # previously produced a truncated CREATE and an "incomplete input" abort.
    for _name, sql in guards:
        conn.execute(sql)
    conn.commit()
    # The source ledger runs in WAL mode, and ``backup`` carries the journal
    # mode across, so uncommitted frames can still live in a sidecar
    # ``<archive>.db-wal`` when the connection above closes. Hashing the main
    # file at that moment digests a *partial* database: on CPython 3.11 the
    # implicit close happened to checkpoint first, on 3.10 it does not, and
    # verify_archive then compared the manifest against a file that no longer
    # matched its own digest. Pin the archive to a rollback journal and force a
    # checkpoint so ``.db`` is self-contained and byte-stable before hashing.
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.commit()


# -- archive_run / verify_archive / purge_run --------------------------------


def archive_run(ledger: Ledger, run_id: str, archive_dir: Path) -> Path:
    """Copy all rows for ``run_id`` into ``<archive_dir>/<run_id>.db``.

    Open runs are skipped silently (no archive file created).
    """
    if not run_is_closed(ledger, run_id):
        return archive_dir / f"{run_id}.db"

    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_db = archive_dir / f"{run_id}.db"
    if archive_db.exists():
        archive_db.unlink()

    with sqlite3.connect(str(ledger.path)) as src, sqlite3.connect(str(archive_db)) as dst:
        src.backup(dst)
    with sqlite3.connect(str(archive_db)) as conn:
        _archive_schema(conn, run_id)

    manifest = {
        "run_id": run_id,
        "db": str(archive_db.name),
        "sha256": _file_sha256(archive_db),
        "created_at": time.time(),
        # Recorded so verification can tell "this run genuinely had no events"
        # apart from "every event was deleted after archiving". Without it an
        # emptied archive passes and purge_run destroys the live rows.
        "event_count": int(
            sqlite3.connect(str(archive_db))
            .execute("SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,))
            .fetchone()[0]
        ),
    }
    manifest_path = archive_dir / f"{run_id}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return archive_db


def verify_archive(archive_db: Path, run_id: str) -> dict[str, Any]:
    """Recompute the ledger hash chain against the archive copy.

    Returns a report dict with keys ``ok``, ``checked``, ``broken_at_seq``.
    """
    if not archive_db.exists():
        return {"ok": False, "checked": 0, "broken_at_seq": None}

    report: dict[str, Any] = {"ok": True, "checked": 0, "broken_at_seq": None}
    from hunter.kernel.events import GENESIS_HASH, Event  # local import avoids cycles

    with sqlite3.connect(str(archive_db)) as conn:
        rows = conn.execute(
            "SELECT seq, run_id, kind, payload, ts, prev_hash, hash FROM events"
            " WHERE run_id = ? ORDER BY seq",
            (run_id,),
        ).fetchall()

    expected_prev = GENESIS_HASH
    checked = 0
    for row in rows:
        checked += 1
        seq, _, kind_raw, payload_raw, ts, prev_hash, digest = row
        try:
            event = Event(
                seq=seq,
                run_id=run_id,
                kind=kind_raw,
                payload=json.loads(payload_raw),
                ts=ts,
                prev_hash=prev_hash,
                hash=digest,
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            report["ok"] = False
            if report["broken_at_seq"] is None:
                report["broken_at_seq"] = seq
            continue
        recomputed = event.recompute_hash()
        if recomputed != digest:
            report["ok"] = False
            if report["broken_at_seq"] is None:
                report["broken_at_seq"] = seq
        if prev_hash != GENESIS_HASH and prev_hash != expected_prev:
            report["ok"] = False
            if report["broken_at_seq"] is None:
                report["broken_at_seq"] = seq
        expected_prev = digest
    report["checked"] = checked

    # An empty result is NOT automatically a clean bill of health: the chain
    # cannot detect a deletion by walking what is left. But a legitimately
    # empty run (no events were ever recorded) is fine. Decide using the
    # manifest's recorded event count, which is written at archive time.
    manifest_event_count: int | None = None
    manifest_path = archive_db.with_suffix(".json")
    if manifest_path.exists():
        try:
            _m = json.loads(manifest_path.read_text(encoding="utf-8"))
            _n = _m.get("event_count")
            if isinstance(_n, int):
                manifest_event_count = _n
        except (json.JSONDecodeError, OSError):
            manifest_event_count = None

    if checked == 0 and (manifest_event_count is None or manifest_event_count > 0):
        report["ok"] = False
        if report["broken_at_seq"] is None:
            report["broken_at_seq"] = 0

    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("run_id") != run_id or _file_sha256(archive_db) != manifest.get("sha256"):
                report["ok"] = False
                if report["broken_at_seq"] is None:
                    report["broken_at_seq"] = 0
        except (json.JSONDecodeError, OSError):
            report["ok"] = False
            if report["broken_at_seq"] is None:
                report["broken_at_seq"] = 0

    return report


def purge_run(ledger: Ledger, run_id: str, archive_dir: Path | None = None) -> None:
    """Delete all rows for a closed run inside a safe BEGIN IMMEDIATE.

    Steps:
    1. Refuse if not closed.
    2. Ensure an archive exists. An archive that is ALREADY on disk is never
       overwritten: whoever got there first is the record of truth, and
       re-copying would silently bless live data we are about to destroy.
    3. Verify that archive; if bad, raise RuntimeError and ROLLBACK untouched.
    4. Drop all triggers, delete run rows, recreate triggers from the live db.
    """
    from hunter.runtime_paths import RuntimePaths  # local import

    if not run_is_closed(ledger, run_id):
        raise RuntimeError(f"purge_run: run '{run_id}' is not closed")

    if archive_dir is None:
        archive_dir = RuntimePaths.resolve(migrate=False).state / "archive"
    archive_db = Path(archive_dir) / f"{run_id}.db"
    if not archive_db.exists():
        archive_db = archive_run(ledger, run_id, Path(archive_dir))
    verification = verify_archive(archive_db, run_id)
    if not verification["ok"]:
        raise RuntimeError(
            f"archive verification failed for '{run_id}' at seq"
            f" {verification['broken_at_seq']}"
        )

    with ledger._lock:
        purge_conn = sqlite3.connect(
            str(ledger.path), check_same_thread=False, isolation_level=None
        )
        purge_conn.execute("PRAGMA busy_timeout=5000")
        try:
            trigger_rows = purge_conn.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'trigger' AND sql IS NOT NULL"
            ).fetchall()
            purge_conn.execute("BEGIN IMMEDIATE")
            try:
                for name, _sql in trigger_rows:
                    purge_conn.execute(f"DROP TRIGGER IF EXISTS {name}")
                purge_conn.execute("DELETE FROM hunt_memory WHERE run_id = ?", (run_id,))
                purge_conn.execute("DELETE FROM waves WHERE run_id = ?", (run_id,))
                purge_conn.execute(
                    "DELETE FROM followups WHERE finding_id IN"
                    " (SELECT id FROM findings WHERE run_id = ?)",
                    (run_id,),
                )
                purge_conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
                purge_conn.execute("DELETE FROM evidence WHERE run_id = ?", (run_id,))
                purge_conn.execute("DELETE FROM events WHERE run_id = ?", (run_id,))
                purge_conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
                # Restore each trigger from its ORIGINAL sqlite_master text,
                # one statement at a time.
                #
                # Do NOT split the captured DDL on ';': a trigger body is
                # BEGIN ... END and several ledger triggers embed a semicolon
                # inside their WHEN/WHERE clause. Splitting there produced a
                # truncated "CREATE TRIGGER ... END" and sqlite raised
                # "incomplete input", aborting the purge transaction. The
                # append-only guards must come back byte-identical, otherwise
                # the next write silently loses its integrity check.
                for _name, sql in trigger_rows:
                    purge_conn.execute(sql)
            except BaseException:
                purge_conn.execute("ROLLBACK")
                raise
            purge_conn.execute("COMMIT")
        finally:
            purge_conn.close()


def gc_runs(
    ledger: Ledger,
    archive_dir: Path,
    run_days: int = 30,
    now: float | None = None,
    dry_run: bool = False,
) -> dict[str, int]:
    """Archive+purge closed runs older than ``run_days`` days.

    Returns counts: ``candidates``, ``archived``, ``purged``, ``skipped_open``,
    ``skipped_recent``.

    ``dry_run=True`` reports what would be collected and mutates nothing — not
    even the archive file. Destroying evidence must always be an explicit act.
    """
    current = now or time.time()
    cutoff = current - (run_days * 86400)
    report: dict[str, int] = {
        "candidates": 0,
        "archived": 0,
        "purged": 0,
        "skipped_open": 0,
        "skipped_recent": 0,
    }
    for row in ledger.runs():
        run_id = str(row["run_id"])
        closed_at = row.get("closed_at")
        if closed_at is None:
            report["skipped_open"] += 1
            continue
        if closed_at > cutoff:
            report["skipped_recent"] += 1
            continue
        report["candidates"] += 1
        if dry_run:
            continue
        archive_run(ledger, run_id, archive_dir)
        purge_run(ledger, run_id)
        report["archived"] += 1
        report["purged"] += 1
    return report


def gc_chat(
    store: ChatStore,
    chat_days: int = 7,
    now: float | None = None,
    dry_run: bool = False,
) -> dict[str, int]:
    """Delete chat messages older than ``chat_days`` days.

    Chat rows carry no evidentiary weight (unlike ledger rows), so this is a
    plain delete; the append-only guards are still dropped and restored inside
    one transaction so an interrupted run cannot leave the table unguarded.

    ``dry_run=True`` counts the candidates and deletes nothing.
    """
    current = now or time.time()
    cutoff = current - (chat_days * 86400)
    candidates = 0
    deleted = 0
    retained = 0
    for session in store.list_sessions():
        sid = session["session_id"]
        old_seqs = []
        for msg in store._live_rows(sid):
            if msg["created_at"] < cutoff:
                old_seqs.append(msg["seq"])
            else:
                retained += 1
        candidates += len(old_seqs)
        if not old_seqs or dry_run:
            continue
        with store._lock:
            conn = store._conn
            trigger_rows = conn.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'trigger' AND sql IS NOT NULL"
            ).fetchall()
            conn.execute("BEGIN IMMEDIATE")
            try:
                for name, _sql in trigger_rows:
                    conn.execute(f"DROP TRIGGER IF EXISTS {name}")
                for seq in old_seqs:
                    conn.execute("DELETE FROM chat_messages WHERE seq = ?", (seq,))
                # Restore each trigger from its original DDL verbatim; splitting
                # captured trigger SQL on ';' truncates BEGIN...END bodies.
                for _name, sql in trigger_rows:
                    conn.execute(sql)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        deleted += len(old_seqs)
    return {"candidates": candidates, "deleted": deleted, "retained": retained}
