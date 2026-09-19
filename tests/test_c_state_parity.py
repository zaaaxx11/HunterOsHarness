"""Planner C — state parity net (ledger.db + chat.db).

These pin EXISTING append-only behavior, so they PASS today and guard every
Planner C implementer against regressing the two hash-chained stores:

  ledger.db ........ hunter.kernel.ledger.Ledger (triggers, verify_chain,
                     findings claim-gate, render_markdown ledger-only)
  chat.db .......... hunter.chat.sessions.ChatStore (triggers, verify_chain,
                     tombstone undo, export excludes hidden)

Per-function contract:
  test_cparity_ledger_triggers_reject_mutation
  test_cparity_chat_triggers_reject_mutation
  test_cparity_hash_chains_verify (ledger + chat)
  test_cparity_tombstone_undo (chain intact, export + messages skip hidden)
  test_cparity_export_excludes_hidden (jsonl + markdown)
  test_cparity_reporting_renders_rows_only (+ ReportBlocked on tamper)
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from hunter.chat.sessions import ChatStore
from hunter.kernel.events import EventKind
from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger
from hunter.reporting.markdown import ReportBlocked, render_markdown


def _ledger(tmp_path) -> Ledger:
    return Ledger(tmp_path / "ledger.db")


def _finding(run_id, ev_ids=("EV-0001",)):
    return Finding(
        id="F-0001", run_id=run_id, key="probe|GET|/|q", title="t",
        severity=Severity.HIGH, cwe="CWE-79", endpoint="/", method="GET",
        status=FindingStatus.CANDIDATE, evidence_ids=tuple(ev_ids),
    )


def test_cparity_ledger_triggers_reject_mutation(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        ledger.create_run("R-1", "http://127.0.0.1:9/", "deterministic", "localhost-only")
        ledger.append("R-1", EventKind.PROBE_STARTED, {"probe": "p"})
        with pytest.raises(Exception, match="(?i)append-only|BLOCKED"):
            ledger._conn.execute("UPDATE events SET payload='{}' WHERE seq=1")
        with pytest.raises(Exception, match="(?i)append-only|BLOCKED"):
            ledger._conn.execute("DELETE FROM events WHERE seq=1")
    finally:
        ledger.close()


def test_cparity_chat_triggers_reject_mutation(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    try:
        sid = store.create_session()
        store.append_message(sid, "user", "hello")
        with pytest.raises(Exception, match="(?i)append-only|BLOCKED"):
            store._conn.execute("UPDATE chat_messages SET content='x' WHERE seq=1")
        with pytest.raises(Exception, match="(?i)append-only|BLOCKED"):
            store._conn.execute("DELETE FROM chat_messages WHERE seq=1")
    finally:
        store.close()


def test_cparity_hash_chains_verify(tmp_path):
    ledger = _ledger(tmp_path)
    store = ChatStore(tmp_path / "chat.db")
    try:
        ledger.create_run("R-1", "http://127.0.0.1:9/", "deterministic", "localhost-only")
        ledger.append("R-1", EventKind.PROBE_STARTED, {"probe": "p"})
        report = ledger.verify_chain("R-1")
        assert report.ok and report.checked >= 1 and report.broken_at_seq is None
        sid = store.create_session()
        store.append_message(sid, "user", "hi")
        store.append_message(sid, "assistant", "hello")
        ok, checked, broken = store.verify_chain(sid)
        assert ok and checked == 2 and broken is None
    finally:
        ledger.close()
        store.close()


def test_cparity_tombstone_undo(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    try:
        sid = store.create_session()
        store.append_message(sid, "user", "one")
        store.append_message(sid, "assistant", "uno")
        store.append_message(sid, "user", "two")
        hidden = store.undo(sid, 1)
        assert hidden == 1
        live = store.messages(sid)
        assert [m["content"] for m in live] == ["one", "uno"]
        ok, _, broken = store.verify_chain(sid)
        assert ok and broken is None, "tombstone keeps the chain intact"
    finally:
        store.close()


def test_cparity_export_excludes_hidden(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    try:
        sid = store.create_session("t")
        store.append_message(sid, "user", "visible-1")
        store.append_message(sid, "user", "secret-hidden")
        store.undo(sid, 1)
        store.append_message(sid, "user", "visible-2")
        jsonl = store.export(sid, fmt="jsonl")
        assert "visible-2" in jsonl and "secret-hidden" not in jsonl
        assert "tombstone" not in jsonl.lower()
        md = store.export(sid, fmt="markdown")
        assert "visible-2" in md and "secret-hidden" not in md
        with pytest.raises(ValueError):
            store.export(sid, fmt="xml")
    finally:
        store.close()


def test_cparity_reporting_renders_rows_only(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        ledger.create_run("R-1", "http://127.0.0.1:9/", "deterministic", "localhost-only")
        ev_id = ledger.add_evidence("R-1", "http_exchange", {"url": "http://127.0.0.1:9/"})
        ledger.create_finding(_finding("R-1", (ev_id,)))
        text = render_markdown(ledger, "R-1")
        assert "F-0001" in text and ev_id in text
        assert "Chain verification: OK" in text
    finally:
        ledger.close()


def test_cparity_reporting_blocked_on_tamper(tmp_path):
    import shutil

    src = tmp_path / "orig"
    src.mkdir()
    ledger = Ledger(src / "ledger.db")
    try:
        ledger.create_run("R-1", "http://127.0.0.1:9/", "deterministic", "localhost-only")
        ev_id = ledger.add_evidence("R-1", "http_exchange", {"url": "http://127.0.0.1:9/"})
        ledger.create_finding(_finding("R-1", (ev_id,)))
    finally:
        ledger.close()
    copy = tmp_path / "copy"
    shutil.copytree(src, copy)
    con = sqlite3.connect(str(copy / "ledger.db"))
    try:
        con.execute("DROP TRIGGER IF EXISTS events_no_update")
        seq, payload = con.execute("SELECT seq, payload FROM events ORDER BY seq LIMIT 1").fetchone()
        data = json.loads(payload)
        data["attacker"] = "rewrite"
        from hunter.kernel.events import canonical_json

        con.execute("UPDATE events SET payload=? WHERE seq=?", (canonical_json(data), seq))
        con.commit()
    finally:
        con.close()
    tampered = Ledger(copy / "ledger.db")
    try:
        assert not tampered.verify_chain("R-1").ok
        with pytest.raises(ReportBlocked):
            render_markdown(tampered, "R-1")
    finally:
        tampered.close()
