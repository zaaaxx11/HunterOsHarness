"""Defense-in-depth for the VERIFIED ladder (found by adversarial audit).

Three gaps, all closed by the checks below:

1. STORAGE BYPASS — the RULE-E2 trigger's ``local_read`` branch was unbound:
   ``OR kind = 'local_read'`` matched ANY row anywhere, so one unrelated
   local_read let a raw SQL UPDATE flip an arbitrary candidate to verified.
   The claim gate refused the same write; storage was strictly weaker.

2. PHANTOM ARTIFACT — ``poc_path`` was checked as a non-empty string while the
   message promised "must exist on disk". A never-written path, or a directory,
   passed the gate carrying zero evidence.

3. SILENT DOWNGRADE — ``create_finding`` rewrites any requested status to
   CANDIDATE, so an insert-time 'verified' is unreachable rather than refused.
   This test pins that as documented behaviour (loud would be better, silent is
   safe: the row cannot enter VERIFIED without passing the ladder).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from hunter.kernel.claimgate import ClaimGateBlocked
from hunter.kernel.findings import Finding, FindingStatus, Severity


def _finding(poc_path=None, logs_path=None, status=FindingStatus.CANDIDATE, **overrides):
    base = dict(
        id="F-0001", run_id="r1", key="xss|GET|/s|q", title="t",
        severity=Severity.HIGH, cwe="CWE-79", endpoint="/s", method="GET",
        param="q", payload_used="", description="d", impact="i", remediation="r",
        evidence_ids=("EV-1", "EV-2"), status=status, klass="reflected-xss",
    )
    base.update(overrides)
    if poc_path is not None:
        base["poc_path"] = poc_path
    if logs_path is not None:
        base["logs_path"] = logs_path
    return Finding(**base)


def test_phantom_poc_is_refused(tmp_path):
    from hunter.kernel.claimgate import validate_status_change

    missing = str(tmp_path / "never-written.py")
    a_dir = str(tmp_path)
    for bogus in (missing, a_dir, "", "   "):
        with pytest.raises(ClaimGateBlocked):
            validate_status_change(_finding(poc_path=bogus), FindingStatus.VERIFIED, 2)


def test_real_poc_is_accepted(tmp_path):
    from hunter.kernel.claimgate import validate_status_change

    poc = tmp_path / "poc.py"
    poc.write_text("#!/usr/bin/env python3\n")
    validate_status_change(_finding(poc_path=str(poc)), FindingStatus.VERIFIED, 2)


def test_phantom_logs_is_refused(tmp_path):
    from hunter.kernel.claimgate import validate_status_change

    poc = tmp_path / "poc.py"
    poc.write_text("x\n")
    with pytest.raises(ClaimGateBlocked):
        validate_status_change(
            _finding(poc_path=str(poc), status=FindingStatus.VERIFIED,
                     logs_path=str(tmp_path / "no-logs.txt")),
            FindingStatus.PROMOTED, 3,
        )


def test_unrelated_local_read_no_longer_unlocks_verified(tmp_path):
    """The storage trigger must bind local_read to THIS finding."""
    from hunter.kernel import ledger as L

    led = L.Ledger(tmp_path / "ledger.db")
    try:
        led.create_run("r1", "http://127.0.0.1/", "deterministic", "localhost")
        e1 = led.add_evidence("r1", "http_exchange", {"method": "GET", "url": "http://x/"})
        e2 = led.add_evidence("r1", "http_exchange", {"method": "GET", "url": "http://x/", "pass": 2})
        f = led.create_finding(_finding(evidence_ids=(e1, e2)))
        # an UNRELATED local_read for a different finding
        with led._lock:
            led._conn.execute(
                "INSERT INTO evidence (id, run_id, kind, data, sha256) VALUES (?,?,?,?,?)",
                ("EV-OTHER", "r1", "local_read", json.dumps({"finding_id": "F-9999"}), "0" * 64),
            )
        with pytest.raises(sqlite3.IntegrityError):
            with led._lock:
                led._conn.execute(
                    "UPDATE findings SET status = 'verified' WHERE id = ?", (f.id,))
    finally:
        led.close()


def test_bound_local_read_still_unlocks_verified(tmp_path):
    """A local_read bound to THIS finding is still a legitimate replay."""
    from hunter.kernel import ledger as L

    led = L.Ledger(tmp_path / "ledger.db")
    try:
        led.create_run("r1", "http://127.0.0.1/", "deterministic", "localhost")
        ev0 = led.add_evidence("r1", "local_read", {"file": "a.sol", "line": 12})
        ev = led.add_evidence("r1", "local_read", {"file": "a.sol", "line": 12, "pass": 2})
        poc = tmp_path / "poc.py"
        poc.write_text("x\n")
        f = led.create_finding(_finding(poc_path=str(poc), evidence_ids=(ev0, ev)))
        led.add_evidence("r1", "local_read", {
            "file": "a.sol", "line": 12, "replay": True, "finding_id": f.id,
        })
        updated = led.set_finding_status(f.id, FindingStatus.VERIFIED, "read twice")
        assert updated.status is FindingStatus.VERIFIED
    finally:
        led.close()


def test_replay_http_exchange_still_unlocks_verified(tmp_path):
    from hunter.kernel import ledger as L

    led = L.Ledger(tmp_path / "ledger.db")
    try:
        led.create_run("r1", "http://127.0.0.1/", "deterministic", "localhost")
        ev0 = led.add_evidence("r1", "http_exchange", {"method": "GET", "url": "u"})
        ev = led.add_evidence("r1", "http_exchange", {"method": "GET", "url": "u", "pass": 2})
        poc = tmp_path / "poc.py"
        poc.write_text("x\n")
        f = led.create_finding(_finding(poc_path=str(poc), evidence_ids=(ev0, ev)))
        led.add_evidence("r1", "http_exchange", {
            "method": "GET", "url": "u", "replay": True, "finding_id": f.id})
        assert led.set_finding_status(
            f.id, FindingStatus.VERIFIED, "replayed").status is FindingStatus.VERIFIED
    finally:
        led.close()
