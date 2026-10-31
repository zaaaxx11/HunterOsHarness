from __future__ import annotations

import json

import pytest

from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger
from hunter.agent.learning import LearningLoop


@pytest.fixture()
def make_ledger(tmp_path):
    created = []

    def _make(name="ledger.db"):
        led = Ledger(tmp_path / name)
        created.append(led)
        return led

    yield _make
    for led in created:
        led.close()


def _finding(led, run_id, klass):
    ev = led.add_evidence(run_id, "note", {"klass": klass})
    f = Finding(
        id="",
        run_id=run_id,
        key=f"{klass}|GET|/x|q",
        title=klass,
        severity=Severity.INFO,
        cwe="CWE-1",
        endpoint="/x",
        method="GET",
        evidence_ids=(ev,),
        klass=klass,
    )
    led.create_finding(f)


def test_review_empty(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9", "deterministic", "scope")
    ll = LearningLoop(led)
    assert ll.review("r1") == {
        "skill_patches": [],
        "promotions": [],
        "negative_memory": [],
    }


def test_review_detects_klass_in_two_runs(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9", "deterministic", "scope")
    led.create_run("r2", "http://127.0.0.1:9", "deterministic", "scope")
    _finding(led, "r1", "reflected-xss")
    _finding(led, "r2", "reflected-xss")
    ll = LearningLoop(led)
    res = ll.review("r1")
    assert "reflected-xss" in res["skill_patches"]
    assert res["promotions"] == [{"klass": "reflected-xss", "runs": ["r1", "r2"]}]


def test_negative_memory_recorded(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9", "deterministic", "scope")
    ll = LearningLoop(led)
    ll.record_negative("r1", "sql-injection", "false positive")
    res = ll.review("r1")
    assert res["negative_memory"] == [
        {"run_id": "r1", "klass": "sql-injection", "reason": "false positive"}
    ]
    with led._lock:
        rows = led._conn.execute(
            "SELECT kind, key, payload FROM hunt_memory"
        ).fetchall()
    assert rows[0][0] == "negative"
    assert rows[0][1] == "sql-injection"
    assert json.loads(rows[0][2])["reason"] == "false positive"


def test_promote_pattern_threshold(make_ledger):
    led = make_ledger()
    ll = LearningLoop(led)
    assert ll.promote_pattern("k", ["r1"]) is False
    assert ll.promote_pattern("k", ["r1", "r2"]) is True


def test_skill_use_count(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9", "deterministic", "scope")
    with led._write() as conn:
        conn.execute(
            "INSERT INTO hunt_memory (id, run_id, kind, key, payload, created_seq) VALUES (?,?,?,?,?,?)",
            ("HM-0001", "r1", "skill_use", "foo", "{}", None),
        )
        conn.execute(
            "INSERT INTO hunt_memory (id, run_id, kind, key, payload, created_seq) VALUES (?,?,?,?,?,?)",
            ("HM-0002", "r1", "skill_use", "foo", "{}", None),
        )
    ll = LearningLoop(led)
    assert ll.skill_use_count("foo") == 2
    assert ll.skill_use_count("bar") == 0


def test_negative_from_ruled_out_finding(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9", "deterministic", "scope")
    _finding(led, "r1", "sql-injection")
    led.set_finding_status("F-0001", FindingStatus.RULED_OUT, "not reproducible")
    ll = LearningLoop(led)
    res = ll.review("r1")
    assert res["negative_memory"] == [
        {"run_id": "r1", "klass": "sql-injection", "reason": "not reproducible"}
    ]
