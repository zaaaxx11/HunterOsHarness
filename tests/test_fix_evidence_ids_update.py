"""RED: Ledger Bug-1 — raw-SQL evidence_ids tampering must be blocked.

The ``findings_protected_columns`` trigger (ledger.py:156-173) currently
exempts ``evidence_ids``: any UPDATE that only touches ``status`` and/or
``evidence_ids`` passes. There is no ``UPDATE OF evidence_ids`` guard, so:

- ``'[]'`` (empty) is accepted,
- dangling ``'["EV-9999"]'`` is accepted,
- cross-run splice (r1 finding bound to r2 evidence) is accepted,
- stripping replay evidence from a VERIFIED finding without a status
  change is accepted.

The fix must add a storage-layer guard so all four raw-SQL UPDATEs raise
``sqlite3.IntegrityError``, while a valid same-run extension stays allowed.

These tests FAIL now (no exception raised) and must PASS after the fix.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

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


def _finding(run_id: str = "r1", **overrides) -> Finding:
    kwargs: dict = dict(
        id="",
        run_id=run_id,
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


def _raw_conn(tmp_path, name: str = "ledger.db") -> sqlite3.Connection:
    return sqlite3.connect(str(tmp_path / name))


def _seed_simple(tmp_path, make_ledger):
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    ev_id = led.add_evidence("r1", "http_response", {"body": "b"})
    led.create_finding(_finding(evidence_ids=(ev_id,)))
    return led, ev_id


def test_evidence_ids_empty_update_blocked(tmp_path, make_ledger):
    """UPDATE evidence_ids to '[]' must be rejected (RULE-E1 at storage)."""
    led, ev_id = _seed_simple(tmp_path, make_ledger)
    con = _raw_conn(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE findings SET evidence_ids = '[]' WHERE id = 'F-0001'")
        # Guard held: original binding still intact.
        assert led.get_finding("F-0001").evidence_ids == (ev_id,)
    finally:
        con.close()


def test_evidence_ids_dangling_update_blocked(tmp_path, make_ledger):
    """UPDATE evidence_ids to a non-existent id must be rejected."""
    led, ev_id = _seed_simple(tmp_path, make_ledger)
    con = _raw_conn(tmp_path)
    try:
        dangling = json.dumps(["EV-9999"])
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "UPDATE findings SET evidence_ids = ? WHERE id = 'F-0001'",
                (dangling,),
            )
        assert led.get_finding("F-0001").evidence_ids == (ev_id,)
    finally:
        con.close()


def test_evidence_ids_cross_run_splice_blocked(tmp_path, make_ledger):
    """A finding in r1 must not be re-bound to evidence from r2."""
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    led.create_run("r2", "t2", "e", "s")
    ev_r1 = led.add_evidence("r1", "http_response", {"body": "one"})
    ev_r2 = led.add_evidence("r2", "http_response", {"body": "two"})
    assert ev_r1 != ev_r2
    led.create_finding(_finding(run_id="r1", evidence_ids=(ev_r1,)))
    con = _raw_conn(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "UPDATE findings SET evidence_ids = ? WHERE id = 'F-0001'",
                (json.dumps([ev_r2]),),
            )
        assert led.get_finding("F-0001").evidence_ids == (ev_r1,)
    finally:
        con.close()


def test_evidence_ids_strip_replay_without_status_change_blocked(tmp_path, make_ledger):
    """Stripping replay evidence from a VERIFIED finding without a status
    change must be rejected (RULE-E2 at storage)."""
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    ev_id = led.add_evidence("r1", "http_response", {"body": "signal"})
    led.create_finding(_finding(evidence_ids=(ev_id,)))
    replay_id = led.add_evidence(
        "r1", "http_exchange", {"replay": True, "finding_id": "F-0001", "status": 200}
    )
    led.set_finding_status("F-0001", FindingStatus.VERIFIED, "replay ok")
    assert led.get_finding("F-0001").status is FindingStatus.VERIFIED
    assert replay_id in led.get_finding("F-0001").evidence_ids
    con = _raw_conn(tmp_path)
    try:
        # Attacker strips the replay binding but leaves status='verified'.
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "UPDATE findings SET evidence_ids = ? WHERE id = 'F-0001'",
                (json.dumps([ev_id]),),
            )
        current = led.get_finding("F-0001")
        assert replay_id in current.evidence_ids
        assert current.status is FindingStatus.VERIFIED
    finally:
        con.close()


def test_evidence_ids_valid_same_run_update_stays_allowed(tmp_path, make_ledger):
    """A valid same-run extension (append second evidence of same run)
    must stay allowed — the guard must not break legitimate writes."""
    led = make_ledger()
    led.create_run("r1", "t", "e", "s")
    ev1 = led.add_evidence("r1", "http_response", {"body": "one"})
    ev2 = led.add_evidence("r1", "http_response", {"body": "two"})
    led.create_finding(_finding(evidence_ids=(ev1,)))
    con = _raw_conn(tmp_path)
    try:
        con.execute(
            "UPDATE findings SET evidence_ids = ? WHERE id = 'F-0001'",
            (json.dumps([ev1, ev2]),),
        )
        con.commit()
    finally:
        con.close()
    assert set(led.get_finding("F-0001").evidence_ids) == {ev1, ev2}
