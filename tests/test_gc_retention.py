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

import json
import sqlite3
import time

import pytest

from hunter.chat.sessions import ChatStore
from hunter.kernel.events import EventKind
from hunter.kernel.findings import Finding, Severity
from hunter.kernel.ledger import Ledger
from hunter.kernel.runs import close_run

RUN = "R-gc-1"
TARGET = "http://127.0.0.1:9/"


def _force_delete(archive_db, sql, params=()):
    """Delete rows from an archive as an attacker with file access would.

    ``archive_run`` now restores the append-only guards inside the archive, so
    a plain DELETE raises BLOCKED. Tamper tests must therefore drop the guards
    first — that is exactly the threat being modelled: anyone holding the file
    can lift them, and ``verify_archive`` is what catches the damage afterwards.
    """
    conn = sqlite3.connect(str(archive_db))
    try:
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall():
            conn.execute(f"DROP TRIGGER IF EXISTS {name}")
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _ledger(tmp_path):
    return Ledger(tmp_path / "ledger.db")


def _seed_run(ledger, run_id=RUN):
    ledger.create_run(run_id, TARGET, "mock", "local")
    return run_id


def _finding(ledger, run_id, key="k", severity=Severity.MEDIUM):
    ev = ledger.add_evidence(run_id, "note", {"obs": key})
    return ledger.create_finding(
        Finding(
            id="",
            run_id=run_id,
            key=key,
            title=f"title {key}",
            severity=severity,
            cwe="CWE-89",
            endpoint="/",
            evidence_ids=(ev,),
        )
    )


def _counts(ledger):
    with ledger._lock:
        return tuple(
            int(ledger._conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
            for t in ("runs", "events", "findings", "evidence")
        )


# =============================================================================
# archive_run / verify_archive
# =============================================================================


def test_archive_run_copies_run_rows(tmp_path):
    from hunter.archive import archive_run

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        ledger.append(RUN, EventKind.ENGINE_EVENT, {"x": 1})
        close_run(ledger, RUN)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        archive_db = archive_dir / f"{RUN}.db"
        assert archive_db.exists()
        with sqlite3.connect(str(archive_db)) as conn:
            assert conn.execute("SELECT COUNT(*) FROM runs WHERE run_id = ?", (RUN,)).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM findings WHERE run_id = ?", (RUN,)).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM evidence WHERE run_id = ?", (RUN,)).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM events WHERE run_id = ?", (RUN,)).fetchone()[0] >= 2
    finally:
        ledger.close()


def test_archive_run_skips_open_run(tmp_path):
    from hunter.archive import archive_run

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        assert not (archive_dir / f"{RUN}.db").exists()
    finally:
        ledger.close()


def test_verify_archive_passes_for_good_copy(tmp_path):
    from hunter.archive import archive_run, verify_archive

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        close_run(ledger, RUN)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        report = verify_archive(archive_dir / f"{RUN}.db", RUN)
        assert report["ok"] is True
        assert report["checked"] >= 1
    finally:
        ledger.close()


def test_verify_archive_detects_tampered_copy(tmp_path):
    from hunter.archive import archive_run, verify_archive

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        close_run(ledger, RUN)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        archive_db = archive_dir / f"{RUN}.db"
        # Tamper with the archive after copying: mutate an event hash so the
        # recomputed chain no longer matches the stored digest.
        conn = sqlite3.connect(str(archive_db))
        try:
            row = conn.execute("SELECT seq FROM events LIMIT 1").fetchone()
            assert row is not None
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall():
                conn.execute(f"DROP TRIGGER IF EXISTS {name}")
            conn.execute(
                "UPDATE events SET hash = 'tampered', prev_hash = 'tampered' WHERE seq = ?",
                (row[0],),
            )
            conn.commit()
        finally:
            conn.close()
        report = verify_archive(archive_dir / f"{RUN}.db", RUN)
        assert report["ok"] is False
        assert report["broken_at_seq"] is not None
    finally:
        ledger.close()


# =============================================================================
# purge_run — safety + rollback
# =============================================================================


def test_purge_run_removes_closed_run_rows(tmp_path):
    from hunter.archive import archive_run, purge_run

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        close_run(ledger, RUN)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        purge_run(ledger, RUN)
        with ledger._lock:
            row = ledger._conn.execute("SELECT * FROM runs WHERE run_id = ?", (RUN,)).fetchone()
        assert row is None
        # Archive still exists.
        assert (archive_dir / f"{RUN}.db").exists()
    finally:
        ledger.close()


def test_purge_run_rolls_back_when_verification_fails(tmp_path):
    from hunter.archive import archive_run, purge_run

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        close_run(ledger, RUN)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        archive_db = archive_dir / f"{RUN}.db"
        # Tamper the archive so verification fails. Target ``events``: it is
        # the table the hash chain and the manifest sha256 actually cover, so
        # damaging it is what a real corrupted archive looks like. Deleting
        # from ``findings`` would prove nothing — that table can legitimately
        # be empty, and an unchanged sha256 is not tampering.
        _force_delete(archive_db, "DELETE FROM events WHERE run_id = ?", (RUN,))
        before = _counts(ledger)
        with pytest.raises(RuntimeError, match="archive verification failed"):
            purge_run(ledger, RUN, archive_dir)
        # Live db is byte-identical in row counts.
        assert _counts(ledger) == before
        # And the run row still exists.
        with ledger._lock:
            row = ledger._conn.execute("SELECT * FROM runs WHERE run_id = ?", (RUN,)).fetchone()
        assert row is not None
    finally:
        ledger.close()


def test_purge_run_refuses_open_run(tmp_path):
    from hunter.archive import purge_run

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        with pytest.raises(RuntimeError, match="not closed"):
            purge_run(ledger, RUN)
    finally:
        ledger.close()


def test_purge_run_recreates_triggers_and_append_only_survives(tmp_path):
    from hunter.archive import archive_run, purge_run

    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        close_run(ledger, RUN)
        archive_dir = tmp_path / "archive"
        archive_run(ledger, RUN, archive_dir)
        purge_run(ledger, RUN)
        conn = sqlite3.connect(str(ledger.path))
        try:
            # DELETE on an empty table never fires a BEFORE DELETE trigger, so
            # the guard can only be proven with a live row present. Re-seed one
            # event belonging to a *different* run and then attempt a wipe.
            conn.execute(
                "INSERT INTO events (seq, run_id, kind, payload, ts, prev_hash, hash)"
                " VALUES (999999, 'survivor', 'note', '{}', 1.0, 'a', 'b')"
            )
            conn.commit()
            with pytest.raises(sqlite3.IntegrityError, match="BLOCKED: append-only"):
                conn.execute("DELETE FROM events")
                conn.commit()
        finally:
            conn.close()
    finally:
        ledger.close()


# =============================================================================
# gc_runs / gc_chat
# =============================================================================


def test_gc_runs_only_affects_closed_and_old(tmp_path):
    from hunter.archive import gc_runs

    ledger = _ledger(tmp_path)
    try:
        old_time = time.time() - (10 * 86400)
        recent_time = time.time() - (1 * 86400)
        with ledger._lock:
            conn = ledger._conn
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO runs (run_id, target, engine, scope_name, started_ts, ended_ts, status, outcome, closed_at, summary_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("R-old", TARGET, "mock", "local", old_time, old_time, "completed", "partial", old_time, "{}"),
            )
            conn.execute(
                "INSERT INTO runs (run_id, target, engine, scope_name, started_ts, ended_ts, status, outcome, closed_at, summary_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("R-recent", TARGET, "mock", "local", recent_time, recent_time, "completed", "partial", recent_time, "{}"),
            )
            conn.execute(
                "INSERT INTO runs (run_id, target, engine, scope_name, started_ts, ended_ts, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("R-open", TARGET, "mock", "local", recent_time, None, "running"),
            )
            conn.execute("COMMIT")
        archive_dir = tmp_path / "archive"
        report = gc_runs(ledger, archive_dir, run_days=7)
        assert report["archived"] == 1
        assert report["purged"] == 1
        assert report["skipped_open"] == 1
        assert report["skipped_recent"] == 1
        assert (archive_dir / "R-old.db").exists()
        with ledger._lock:
            assert ledger._conn.execute("SELECT COUNT(*) FROM runs WHERE run_id = ?", ("R-old",)).fetchone()[0] == 0
            assert ledger._conn.execute("SELECT COUNT(*) FROM runs WHERE run_id = ?", ("R-recent",)).fetchone()[0] == 1
            assert ledger._conn.execute("SELECT COUNT(*) FROM runs WHERE run_id = ?", ("R-open",)).fetchone()[0] == 1
    finally:
        ledger.close()


def test_gc_chat_removes_only_old_rows(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    try:
        old = time.time() - (10 * 86400)
        recent = time.time() - (1 * 86400)
        sid = store.create_session("old-session")
        store.append_message(sid, "user", "old", created_at=old)
        store.append_message(sid, "assistant", "old2", created_at=old)
        sid2 = store.create_session("recent-session")
        store.append_message(sid2, "user", "recent", created_at=recent)
        before = len(store.messages(sid))
        assert before == 2
        from hunter.archive import gc_chat
        report = gc_chat(store, chat_days=7, now=recent)
        assert report["deleted"] == 2
        assert report["retained"] == 1
        assert len(store.messages(sid)) == 0
        assert len(store.messages(sid2)) == 1
    finally:
        store.close()


# =============================================================================
# CLI — `hunter gc`
# =============================================================================


def test_cli_gc_registered():
    from hunter.cli.main import app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(app, ["gc", "--help"])
    assert result.exit_code == 0
    assert "garbage-collect" in result.stdout.lower() or "archive" in result.stdout.lower()


def test_cli_gc_json_output(tmp_path):
    from hunter.cli.main import app
    from typer.testing import CliRunner

    state = tmp_path / "state"
    state.mkdir()
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        close_run(ledger, RUN)
    finally:
        ledger.close()

    runner = CliRunner()
    result = runner.invoke(app, ["gc", "--state", str(state), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert "archived" in payload
    assert "purged" in payload
