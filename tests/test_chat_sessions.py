"""ChatStore tests: hash chain, tamper-evidence, tombstone undo, export."""

from __future__ import annotations

import itertools
import json
import sqlite3
import types

import pytest

from hunter.chat import sessions as chat_sessions
from hunter.chat.sessions import ChatStore


@pytest.fixture
def store(tmp_path):
    s = ChatStore(tmp_path / "chat.db")
    yield s
    s.close()


def _converse(store: ChatStore, sid: str, pairs: int = 2) -> None:
    for i in range(pairs):
        store.append_message(sid, "user", f"question {i}")
        store.append_message(sid, "assistant", f"answer {i}", cost_usd=0.01)


# -- sessions ------------------------------------------------------------------


def test_create_session_and_get(store):
    sid = store.create_session("intro")
    session = store.get_session(sid)
    assert session is not None
    assert session["title"] == "intro"
    assert session["model"] == ""
    assert store.get_session("S-does-not-exist") is None


def test_set_title_and_list_order(store, monkeypatch):
    # The three writes below can land inside one wall-clock tick (Windows
    # time.time() ticks every ~15.6ms before py3.13), tying last_active_at and
    # letting the session_id DESC tie-break flip the order. Drive a strictly
    # increasing fake clock so the "most recently active first" contract is
    # tested deterministically on every OS/Python.
    tick = itertools.count(1.0)
    monkeypatch.setattr(
        chat_sessions, "time", types.SimpleNamespace(time=lambda: next(tick))
    )
    first = store.create_session("first")
    second = store.create_session("second")
    store.append_message(first, "user", "wake")  # bumps last_active_at
    sessions = store.list_sessions()
    assert [s["session_id"] for s in sessions][:2] == [first, second]
    store.set_title(first, "renamed")
    assert store.get_session(first)["title"] == "renamed"


def test_append_message_missing_session_raises(store):
    with pytest.raises(KeyError):
        store.append_message("S-missing", "user", "hi")


# -- chain ---------------------------------------------------------------------


def test_hash_chain_verifies(store):
    sid = store.create_session()
    _converse(store, sid)
    ok, checked, broken = store.verify_chain(sid)
    assert ok is True
    assert checked == 4
    assert broken is None


def test_tool_calls_persisted(store):
    sid = store.create_session()
    store.append_message(
        sid, "assistant", "calling", tool_calls=[{"id": "1", "name": "probe", "arguments": {}}]
    )
    assert store.messages(sid)[0]["tool_calls"][0]["name"] == "probe"


def test_tampered_content_detected(store, tmp_path):
    sid = store.create_session()
    _converse(store, sid)
    # Tamper like an attacker: drop the anti-tamper trigger, rewrite a row.
    con = sqlite3.connect(tmp_path / "chat.db")
    con.execute("DROP TRIGGER chat_messages_no_update")
    con.execute("UPDATE chat_messages SET content = 'forged' WHERE seq = 2")
    con.commit()
    con.close()
    ok, checked, broken = store.verify_chain(sid)
    assert ok is False
    assert broken == 2


def test_triggers_block_update_delete_and_replace(store, tmp_path):
    sid = store.create_session()
    store.append_message(sid, "user", "precious")
    con = sqlite3.connect(tmp_path / "chat.db")
    # RAISE(ABORT) in a trigger surfaces as sqlite3.IntegrityError.
    with pytest.raises(sqlite3.IntegrityError, match="BLOCKED"):
        con.execute("UPDATE chat_messages SET content = 'x'")
    with pytest.raises(sqlite3.IntegrityError, match="BLOCKED"):
        con.execute("DELETE FROM chat_messages")
    with pytest.raises(sqlite3.IntegrityError, match="BLOCKED"):
        con.execute("INSERT OR REPLACE INTO chat_messages (seq) VALUES (1)")
    # Identity columns of a session are frozen too.
    with pytest.raises(sqlite3.IntegrityError, match="BLOCKED"):
        con.execute("UPDATE chat_sessions SET created_at = 0")
    con.close()


# -- tombstone undo ---------------------------------------------------------------


def test_undo_hides_last_user_turn(store):
    sid = store.create_session()
    _converse(store, sid)  # q0 a0 q1 a1
    hidden = store.undo(sid, 1)
    assert hidden == 2  # the last user turn + its assistant reply
    live = store.messages(sid)
    assert [m["content"] for m in live] == ["question 0", "answer 0"]
    # The chain — tombstone included — still verifies end to end.
    ok, checked, _broken = store.verify_chain(sid)
    assert ok is True
    assert checked == 5  # 4 original + 1 tombstone


def test_undo_n_turns_and_overdraw(store):
    sid = store.create_session()
    _converse(store, sid)
    assert store.undo(sid, 2) == 4
    assert store.messages(sid) == []
    assert store.undo(sid, 1) == 0  # nothing left to undo


def test_undo_on_empty_session(store):
    sid = store.create_session()
    assert store.undo(sid) == 0


# -- export --------------------------------------------------------------------


def test_export_jsonl_excludes_tombstoned(store):
    sid = store.create_session("log")
    _converse(store, sid)
    store.undo(sid, 1)
    lines = [json.loads(line) for line in store.export(sid, "jsonl").splitlines()]
    assert len(lines) == 2  # q0 a0 kept; q1 a1 tombstoned
    assert {line["content"] for line in lines} == {"question 0", "answer 0"}
    assert all(line["role"] != "tombstone" for line in lines)


def test_export_markdown_has_roles(store):
    sid = store.create_session("chat")
    store.append_message(sid, "user", "hello")
    text = store.export(sid, "markdown")
    assert "chat" in text
    assert "## user" in text and "hello" in text


def test_export_unknown_format_raises(store):
    sid = store.create_session()
    with pytest.raises(ValueError):
        store.export(sid, "xml")


def test_env_db_path(tmp_path, monkeypatch):
    db = tmp_path / "env" / "chat.db"
    monkeypatch.setenv("HUNTEROS_CHAT_DB", str(db))
    s = ChatStore()
    try:
        assert s.path == db
        s.create_session()
    finally:
        s.close()
