"""Tests for the session lifecycle.

The rules being pinned:

* one live daemon per session — a second create on an active session refuses
* a session is resumable — close keeps the value, resume brings it back
* teardown frees RAM and disk but never the findings, PoCs, or skills
* deletion is bounded — a symlink out of the session dir is not followed
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hunter.session import (
    DISCARD_ON_CLOSE,
    KEEP_ON_CLOSE,
    SessionExists,
    SessionNotFound,
    close_session,
    create_session,
    list_sessions,
    open_session,
    resume_session,
    session_dir,
    session_lock,
    sessions_root,
)


@pytest.fixture
def root(tmp_path):
    return tmp_path / "state"


# ------------------------------------------------------------------ creation


def test_create_session_writes_a_record(root):
    record = create_session(target="https://api.relay.link", state_dir=root)
    assert record.status == "active"
    assert record.target == "https://api.relay.link"
    assert (session_dir(record.id, root) / "session.json").is_file()


def test_sessions_live_outside_the_hunt_state_dir(root):
    """Closing one session must not be able to delete the registry."""
    record = create_session(target="t", state_dir=root)
    assert sessions_root(root) == root / "sessions"
    assert record.state_dir == root / "sessions" / record.id


def test_second_create_on_an_active_session_refuses(root):
    first = create_session(target="t", state_dir=root, session_id="s1")
    assert first.status == "active"
    with pytest.raises(SessionExists):
        create_session(target="t2", state_dir=root, session_id="s1")


def test_create_after_close_replaces_the_record(root):
    create_session(target="t", state_dir=root, session_id="s1")
    close_session("s1", state_dir=root)
    # Same id, new hunt: the closed session's value was already kept.
    again = create_session(target="t2", state_dir=root, session_id="s1")
    assert again.status == "active"
    assert again.target == "t2"


def test_open_session_records_the_daemon_pid(root):
    create_session(target="t", state_dir=root, session_id="s1")
    record = open_session("s1", state_dir=root, daemon_pid=4242)
    assert record.daemon_pid == 4242


def test_open_unknown_session_raises(root):
    with pytest.raises(SessionNotFound):
        open_session("nope", state_dir=root)


def test_open_closed_session_raises(root):
    create_session(target="t", state_dir=root, session_id="s1")
    close_session("s1", state_dir=root)
    with pytest.raises(SessionNotFound):
        open_session("s1", state_dir=root)


# --------------------------------------------------------------------- locking


def test_lock_is_exclusive(root):
    create_session(target="t", state_dir=root, session_id="s1")
    with session_lock("s1", root):
        with pytest.raises(SessionExists):
            with session_lock("s1", root):
                pass


def test_lock_releases_after_the_block(root):
    create_session(target="t", state_dir=root, session_id="s1")
    with session_lock("s1", root):
        pass
    # Re-acquiring must succeed — the lock is not sticky.
    with session_lock("s1", root):
        pass


# --------------------------------------------------------------------- closing


def _populate(record) -> None:
    """Give a session the usual mix of durable and transient files."""
    d = record.state_dir
    (d / "daemon").mkdir(parents=True, exist_ok=True)
    (d / "daemon" / "pid.json").write_text("{}", encoding="utf-8")
    (d / "daemon" / "heartbeat.json").write_text("{}", encoding="utf-8")
    (d / "queue").mkdir(exist_ok=True)
    (d / "queue" / "task-1.json").write_text("{}", encoding="utf-8")
    (d / "ledger.db").write_text("findings", encoding="utf-8")
    (d / "ledger.db-wal").write_text("wal", encoding="utf-8")
    (d / "ledger.db-shm").write_text("shm", encoding="utf-8")
    (d / "reports").mkdir()
    (d / "reports" / "R-1.md").write_text("report", encoding="utf-8")
    (d / "pocs").mkdir()
    (d / "pocs" / "poc-1.py").write_text("poc", encoding="utf-8")
    (d / "skills").mkdir()
    (d / "skills" / "s.md").write_text("skill", encoding="utf-8")
    (d / "rag-state.json").write_text("{}", encoding="utf-8")
    (d / "hunt.log").write_text("log", encoding="utf-8")


def test_close_keeps_findings_pocs_and_skills(root):
    record = create_session(target="t", state_dir=root, session_id="s1")
    _populate(record)
    result = close_session("s1", state_dir=root)

    d = record.state_dir
    assert (d / "ledger.db").is_file(), "findings must survive"
    assert (d / "reports" / "R-1.md").is_file(), "reports must survive"
    assert (d / "pocs" / "poc-1.py").is_file(), "PoCs must survive"
    assert (d / "skills" / "s.md").is_file(), "skills must survive"
    assert "ledger.db" in result["kept"]
    assert "reports" in result["kept"]


def test_close_discards_transient_state(root):
    record = create_session(target="t", state_dir=root, session_id="s1")
    _populate(record)
    close_session("s1", state_dir=root)

    d = record.state_dir
    assert not (d / "daemon").exists(), "daemon runtime state must go"
    assert not (d / "queue").exists(), "the queue must go"
    assert not (d / "rag-state.json").exists()
    assert not (d / "hunt.log").exists()
    assert not (d / "ledger.db-wal").exists(), "WAL sidecar must go"
    assert not (d / "ledger.db-shm").exists(), "SHM sidecar must go"


def test_close_marks_the_record_closed(root):
    create_session(target="t", state_dir=root, session_id="s1")
    close_session("s1", state_dir=root)
    records = {r.id: r for r in list_sessions(state_dir=root)}
    assert records["s1"].status == "closed"
    assert records["s1"].closed_ts is not None


def test_close_unknown_session_raises(root):
    with pytest.raises(SessionNotFound):
        close_session("nope", state_dir=root)


def test_close_stops_the_daemon(root, monkeypatch):
    from hunter import session as session_mod

    create_session(target="t", state_dir=root, session_id="s1")
    open_session("s1", state_dir=root, daemon_pid=99999)

    killed: list[int] = []
    monkeypatch.setattr(session_mod, "_pid_alive", lambda pid: pid in killed or pid == 99999)
    monkeypatch.setattr(session_mod.os, "kill", lambda pid, sig: killed.append(pid))

    result = close_session("s1", state_dir=root)
    assert result["daemon_stopped"] is True
    assert 99999 in killed


def test_close_without_a_daemon_is_fine(root):
    create_session(target="t", state_dir=root, session_id="s1")
    result = close_session("s1", state_dir=root)
    assert result["daemon_stopped"] is False


def test_close_does_not_follow_a_symlink_out_of_the_session(root):
    record = create_session(target="t", state_dir=root, session_id="s1")
    outside = root / "precious"
    outside.mkdir(parents=True)
    (outside / "data.txt").write_text("do not delete", encoding="utf-8")
    # A discard-named entry that is a symlink pointing outside the session.
    (record.state_dir / "queue").symlink_to(outside, target_is_directory=True)

    close_session("s1", state_dir=root)
    assert (outside / "data.txt").is_file(), "a symlink must not be followed out"


# ------------------------------------------------------------------- resuming


def test_resume_brings_a_closed_session_back(root):
    create_session(target="t", state_dir=root, session_id="s1")
    close_session("s1", state_dir=root)
    record = resume_session("s1", state_dir=root)
    assert record.status == "active"
    assert record.closed_ts is None


def test_resume_keeps_the_durable_output(root):
    record = create_session(target="t", state_dir=root, session_id="s1")
    _populate(record)
    close_session("s1", state_dir=root)
    resume_session("s1", state_dir=root)

    assert (record.state_dir / "ledger.db").is_file()
    assert (record.state_dir / "pocs" / "poc-1.py").is_file()


def test_resume_unknown_session_raises(root):
    with pytest.raises(SessionNotFound):
        resume_session("nope", state_dir=root)


def test_resume_an_active_session_is_a_noop_ish(root):
    create_session(target="t", state_dir=root, session_id="s1")
    record = resume_session("s1", state_dir=root)
    assert record.status == "active"


# --------------------------------------------------------------------- listing


def test_list_sessions_newest_first(root):
    create_session(target="a", state_dir=root, session_id="s-old")
    import time as _t

    _t.sleep(0.01)
    create_session(target="b", state_dir=root, session_id="s-new")
    ids = [r.id for r in list_sessions(state_dir=root)]
    assert ids == ["s-new", "s-old"]


def test_list_sessions_can_hide_closed(root):
    create_session(target="a", state_dir=root, session_id="s1")
    create_session(target="b", state_dir=root, session_id="s2")
    close_session("s1", state_dir=root)
    active = [r.id for r in list_sessions(state_dir=root, include_closed=False)]
    assert active == ["s2"]


def test_list_sessions_on_an_empty_root(root):
    assert list_sessions(state_dir=root) == []


# ------------------------------------------------------------------ invariants


def test_keep_and_discard_do_not_overlap():
    assert not (KEEP_ON_CLOSE & DISCARD_ON_CLOSE), "a file must not be both kept and discarded"


def test_ledger_is_in_keep():
    assert "ledger.db" in KEEP_ON_CLOSE


def test_daemon_runtime_is_in_discard():
    assert "daemon" in DISCARD_ON_CLOSE
