"""Kernel ledger tests: hash chain, anti-tamper triggers, claim gate, redaction."""

from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from hunter.kernel.claimgate import ClaimGateBlocked
from hunter.kernel.events import GENESIS_HASH, EventKind, canonical_json, sha256_hex
from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger


@pytest.fixture()
def make_ledger(tmp_path):
    created: list[Ledger] = []

    def _make(name: str = "ledger.db") -> Ledger:
        led = Ledger(tmp_path / name)
        created.append(led)
        return led

    yield _make
    for led in created:
        led.close()


@pytest.fixture()
def ledger(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9000", "deterministic", "scope-x")
    return led


def _finding(**overrides) -> Finding:
    kwargs: dict = dict(
        id="",
        run_id="r1",
        key="reflected-xss|GET|/search|q",
        title="Reflected XSS in q",
        severity=Severity.HIGH,
        cwe="CWE-79",
        endpoint="/search",
        method="GET",
        param="q",
        payload_used="<script>alert(1)</script>",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


# -- I2: hash chain -----------------------------------------------------------


def test_append_and_verify_chain(ledger):
    e1 = ledger.append("r1", EventKind.RUN_STARTED, {"phase": "boot"})
    e2 = ledger.append("r1", "probe_result", {"ok": True})
    assert e1.seq == 1 and e2.seq == 2
    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.hash
    assert e1.verify() and e2.verify()
    report = ledger.verify_chain()
    assert report.ok is True
    assert report.checked == 2
    assert report.broken_at_seq is None
    assert report.details == []


def test_events_returns_seq_order_with_linkage(ledger):
    for i in range(5):
        ledger.append("r1", EventKind.PROBE_RESULT, {"i": i})
    evs = ledger.events()
    assert [e.seq for e in evs] == [1, 2, 3, 4, 5]
    assert evs[0].prev_hash == GENESIS_HASH
    for prev, cur in zip(evs, evs[1:], strict=False):
        assert cur.prev_hash == prev.hash
    assert all(isinstance(e.kind, EventKind) for e in evs)
    assert all(e.run_id == "r1" for e in evs)


def test_chain_spans_runs_globally(ledger):
    ledger.create_run("r2", "http://127.0.0.1:9001", "deterministic", "scope-y")
    tail_r1 = ledger.append("r1", EventKind.ENGINE_EVENT, {"n": 1}).hash
    first_r2 = ledger.append("r2", EventKind.ENGINE_EVENT, {"n": 2})
    assert first_r2.prev_hash == tail_r1  # single global chain, no per-run genesis
    assert ledger.verify_chain().ok
    r2_report = ledger.verify_chain(run_id="r2")
    assert r2_report.ok is True
    assert r2_report.checked == 1
    assert [e.run_id for e in ledger.events(run_id="r2")] == ["r2"]


def test_verify_chain_empty_is_ok(make_ledger):
    led = make_ledger("empty.db")
    report = led.verify_chain()
    assert report.ok is True
    assert report.checked == 0
    assert report.broken_at_seq is None


def test_tampered_payload_detected(tmp_path, make_ledger):
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    led.append("r1", EventKind.PROBE_RESULT, {"v": 1})
    led.append("r1", EventKind.PROBE_RESULT, {"v": 2})
    # An attacker with raw disk access drops the trigger and rewrites history.
    con = sqlite3.connect(tmp_path / "ledger.db")
    try:
        con.execute("DROP TRIGGER events_no_update")
        con.execute(
            "UPDATE events SET payload = ? WHERE seq = 2", (canonical_json({"v": 999}),)
        )
        con.commit()
    finally:
        con.close()
    report = led.verify_chain()
    assert report.ok is False
    assert report.broken_at_seq == 2
    assert report.details
    assert report.checked == 2


# -- I1/I7: anti-tamper triggers ----------------------------------------------


def test_triggers_block_event_and_evidence_tampering(tmp_path, make_ledger):
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    led.append("r1", EventKind.PROBE_RESULT, {"v": 1})
    led.add_evidence("r1", "http_response", {"body": "b"})
    con = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE events SET payload = '{}'")
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("DELETE FROM events")
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE evidence SET data = '{}'")
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("DELETE FROM evidence")
    finally:
        con.close()
    assert led.verify_chain().ok


def test_findings_only_status_and_evidence_ids_mutable(tmp_path, make_ledger):
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    ev_id = led.add_evidence("r1", "http_response", {"body": "b"})
    led.create_finding(_finding(evidence_ids=(ev_id,)))
    con = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE findings SET title = 'pwned'")
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE findings SET severity = 'critical'")
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE findings SET key = 'other'")
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("DELETE FROM findings")
        # Only status and evidence_ids may change.
        con.execute("UPDATE findings SET status = 'ruled_out'")
        con.execute("UPDATE findings SET evidence_ids = '[\"EV-0001\"]'")
    finally:
        con.close()


# -- I3: claim gate on insert --------------------------------------------------


def test_create_finding_requires_evidence(ledger):
    with pytest.raises(ClaimGateBlocked):
        ledger.create_finding(_finding())
    # Fail-closed: no finding row, no FINDING_CREATED event.
    assert ledger.findings() == []
    with pytest.raises(KeyError):
        ledger.get_finding("F-0001")
    kinds = [e.kind_value() for e in ledger.events()]
    assert "finding_created" not in kinds
    assert ledger.verify_chain().ok


def test_create_finding_rejects_unknown_evidence_and_blank_title(ledger):
    with pytest.raises(ClaimGateBlocked):
        ledger.create_finding(_finding(evidence_ids=("EV-9999",)))
    ev_id = ledger.add_evidence("r1", "http_response", {"body": "x"})
    with pytest.raises(ClaimGateBlocked):
        ledger.create_finding(_finding(title="   ", evidence_ids=(ev_id,)))
    assert ledger.findings() == []
    assert [e.kind_value() for e in ledger.events()].count("finding_created") == 0


def test_create_finding_success(ledger):
    ev_id = ledger.add_evidence(
        "r1", "http_response", {"status": 200, "body": "<script>alert(1)</script>"}
    )
    f = ledger.create_finding(_finding(evidence_ids=(ev_id,)))
    assert f.id == "F-0001"
    assert f.status is FindingStatus.CANDIDATE
    assert f.evidence_ids == (ev_id,)
    stored = ledger.get_finding("F-0001")
    assert stored.run_id == "r1"
    assert stored.key == "reflected-xss|GET|/search|q"
    assert stored.title == "Reflected XSS in q"
    assert stored.severity is Severity.HIGH
    created = [e for e in ledger.events() if e.kind_value() == "finding_created"]
    assert len(created) == 1
    assert created[0].payload["finding_id"] == "F-0001"
    assert created[0].payload["evidence_ids"] == [ev_id]
    second = ledger.create_finding(_finding(key="k2", title="Second", evidence_ids=(ev_id,)))
    assert second.id == "F-0002"
    assert [x.id for x in ledger.findings()] == ["F-0001", "F-0002"]
    assert [x.id for x in ledger.findings(run_id="r1")] == ["F-0001", "F-0002"]


# -- I4: status transitions -----------------------------------------------------


def test_verified_requires_replay_evidence(ledger):
    ev_id = ledger.add_evidence("r1", "http_response", {"body": "signal"})
    ledger.create_finding(_finding(evidence_ids=(ev_id,)))
    with pytest.raises(ClaimGateBlocked):
        ledger.set_finding_status("F-0001", FindingStatus.VERIFIED, "no replay yet")
    assert ledger.get_finding("F-0001").status is FindingStatus.CANDIDATE
    # Wrong-kind or unsuccessful replays do not unlock VERIFIED.
    ledger.add_evidence("r1", "http_response", {"replay": True, "finding_id": "F-0001"})
    ledger.add_evidence("r1", "http_exchange", {"replay": False, "finding_id": "F-0001"})
    with pytest.raises(ClaimGateBlocked):
        ledger.set_finding_status("F-0001", FindingStatus.VERIFIED, "still no valid replay")
    replay_id = ledger.add_evidence(
        "r1", "http_exchange", {"replay": True, "finding_id": "F-0001", "status": 200}
    )
    updated = ledger.set_finding_status(
        "F-0001", FindingStatus.VERIFIED, "independent replay succeeded"
    )
    assert updated.status is FindingStatus.VERIFIED
    assert updated.evidence_ids == (ev_id, replay_id)
    assert ledger.get_finding("F-0001").evidence_ids == (ev_id, replay_id)
    trail = [e for e in ledger.events() if e.kind_value() == "finding_status_changed"]
    assert len(trail) == 1
    payload = trail[0].payload
    assert payload["finding_id"] == "F-0001"
    assert payload["old_status"] == "candidate"
    assert payload["new_status"] == "verified"
    assert payload["reason"] == "independent replay succeeded"
    assert payload["evidence_ids"] == [ev_id, replay_id]
    assert ledger.verify_chain().ok


def test_ruled_out_requires_reason_and_keeps_trail(ledger):
    ev_id = ledger.add_evidence("r1", "http_response", {"body": "signal"})
    ledger.create_finding(_finding(evidence_ids=(ev_id,)))
    with pytest.raises(ClaimGateBlocked):
        ledger.set_finding_status("F-0001", FindingStatus.RULED_OUT, "  ")
    updated = ledger.set_finding_status(
        "F-0001", FindingStatus.RULED_OUT, "payload not reflected on replay"
    )
    assert updated.status is FindingStatus.RULED_OUT
    # RULE-E4: ruled-out findings stay in the ledger, never deleted.
    assert ledger.get_finding("F-0001").status is FindingStatus.RULED_OUT
    kinds = [e.kind_value() for e in ledger.events()]
    assert kinds.count("finding_status_changed") == 1
    assert ledger.verify_chain().ok


def test_status_change_unknown_finding_raises(ledger):
    with pytest.raises(KeyError):
        ledger.set_finding_status("F-0042", FindingStatus.RULED_OUT, "nope")


# -- I5/I6: evidence redaction and digests -------------------------------------


def test_evidence_redacted_before_storage(ledger):
    evidence_id = ledger.add_evidence(
        "r1",
        "http_response",
        {"body": "api_key=sk-abcdefghij1234567890", "nested": ["password=hunter2"]},
    )
    rows = ledger.evidence()
    assert [r["id"] for r in rows] == [evidence_id]
    row = rows[0]
    assert row["id"] == "EV-0001"
    assert row["kind"] == "http_response"
    blob = json.dumps(row["data"])
    assert "sk-abcdefghij1234567890" not in blob
    assert "hunter2" not in blob
    assert "[REDACTED]" in blob
    # Digest is over the redacted data exactly as stored.
    assert row["sha256"] == sha256_hex(canonical_json(row["data"]))
    stored_events = [e for e in ledger.events() if e.kind_value() == "evidence_stored"]
    assert len(stored_events) == 1
    assert stored_events[0].payload["evidence_id"] == "EV-0001"
    assert stored_events[0].payload["sha256"] == row["sha256"]
    assert row["created_seq"] == stored_events[0].seq


def test_evidence_ids_global_counter(ledger):
    a = ledger.add_evidence("r1", "http_response", {"b": 1})
    ledger.create_run("r2", "http://127.0.0.1:9001", "deterministic", "scope-y")
    b = ledger.add_evidence("r2", "http_response", {"b": 2})
    assert (a, b) == ("EV-0001", "EV-0002")  # counter is global, not per run
    assert len(ledger.evidence()) == 2
    assert [r["id"] for r in ledger.evidence(run_id="r2")] == ["EV-0002"]


# -- runs ------------------------------------------------------------------------


def test_run_lifecycle(ledger):
    ledger.finish_run("r1", "completed")
    rows = ledger.runs()
    assert len(rows) == 1
    run = rows[0]
    assert run["run_id"] == "r1"
    assert run["target"] == "http://127.0.0.1:9000"
    assert run["engine"] == "deterministic"
    assert run["scope_name"] == "scope-x"
    assert run["status"] == "completed"
    assert run["started_ts"] is not None
    assert run["ended_ts"] is not None
    with pytest.raises(KeyError):
        ledger.finish_run("nope", "completed")


def test_default_state_dir_and_env_override(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    led = Ledger()
    try:
        led.create_run("r1", "t", "e", "s")
        assert (tmp_path / ".hunter" / "ledger.db").exists()
    finally:
        led.close()
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    led2 = Ledger()
    try:
        led2.create_run("r2", "t", "e", "s")
        assert (tmp_path / "state" / "ledger.db").exists()
    finally:
        led2.close()


# -- concurrency -----------------------------------------------------------


def test_concurrent_appends_keep_chain_intact(ledger):
    failures: list[BaseException] = []

    def worker(worker_id: int) -> None:
        try:
            for i in range(10):
                ledger.append("r1", EventKind.PROBE_RESULT, {"worker": worker_id, "i": i})
        except BaseException as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert failures == []
    report = ledger.verify_chain()
    assert report.ok is True
    assert report.checked == 80
    evs = ledger.events()
    assert [e.seq for e in evs] == list(range(1, 81))
    assert evs[0].prev_hash == GENESIS_HASH
    assert all(cur.prev_hash == prev.hash for prev, cur in zip(evs, evs[1:], strict=False))
