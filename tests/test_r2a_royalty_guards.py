"""R2-A royalty guards — MUST PASS TODAY (green).

Non-negotiable pins the R2-A hardening must never break:
ledger append-only, RULE-E1..E4, scope exact-host, canonical phase order,
replay as sole VERIFIED path, byte-exact BUSY_MESSAGE, stop-file first.

Adversarial: isolated tmp_path ledgers, second sqlite3 connections for
trigger asserts, negative asserts (no UPDATE/DELETE, no scope widening,
no VERIFIED without replay ids). No network/sleep.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from hunter.errors import HunterError, build_error_surface
from hunter.kernel.claimgate import ClaimGateBlocked
from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger
from hunter.phases import PHASE_ORDER
from hunter.tools.scope import ScopeSet, ScopeViolation


@pytest.fixture()
def r2a_ledger(tmp_path: Any) -> Any:
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run("r-r2a", "http://127.0.0.1:9000", "deterministic", "localhost-only")
    yield ledger
    ledger.close()


def _finding(**overrides: Any) -> Finding:
    kwargs: dict[str, Any] = dict(
        id="",
        run_id="r-r2a",
        key="reflected-xss|GET|/search|q",
        title="Reflected XSS in q",
        severity=Severity.HIGH,
        cwe="CWE-79",
        endpoint="/search",
        method="GET",
        param="q",
        payload_used="canary",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def test_r2a_royalty_events_append_only_rejects_update(r2a_ledger: Ledger, tmp_path: Any) -> None:
    r2a_ledger.add_evidence("r-r2a", "http_response", {"body": "x"})
    conn = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE events SET payload = '{}' WHERE seq = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE evidence SET kind = 'other' WHERE id = 'EV-0001'")
    finally:
        conn.close()


def test_r2a_royalty_no_delete_or_replace_paths(r2a_ledger: Ledger, tmp_path: Any) -> None:
    r2a_ledger.add_evidence("r-r2a", "http_response", {"body": "x"})
    conn = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM events WHERE seq = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM evidence WHERE id = 'EV-0001'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("INSERT OR REPLACE INTO events (seq) VALUES (1)")
    finally:
        conn.close()
    assert len(r2a_ledger.evidence("r-r2a")) == 1


def test_r2a_royalty_rule_e1_finding_requires_bound_evidence(r2a_ledger: Ledger) -> None:
    with pytest.raises(ClaimGateBlocked, match="RULE-E1"):
        r2a_ledger.create_finding(_finding(evidence_ids=()))
    with pytest.raises(ClaimGateBlocked, match="RULE-E1"):
        r2a_ledger.create_finding(_finding(evidence_ids=("EV-9999",)))
    assert r2a_ledger.findings("r-r2a") == []


def test_r2a_royalty_rule_e2_verified_requires_replay(r2a_ledger: Ledger) -> None:
    eid = r2a_ledger.add_evidence("r-r2a", "http_exchange", {"url": "http://127.0.0.1/"})
    created = r2a_ledger.create_finding(_finding(evidence_ids=(eid,)))
    assert created.status is FindingStatus.CANDIDATE
    with pytest.raises(ClaimGateBlocked, match="RULE-E2"):
        r2a_ledger.set_finding_status(created.id, FindingStatus.VERIFIED, reason="looks real")
    replay_id = r2a_ledger.add_evidence(
        "r-r2a", "http_exchange", {"replay": True, "finding_id": created.id}
    )
    verified = r2a_ledger.set_finding_status(created.id, FindingStatus.VERIFIED, reason="replayed")
    assert verified.status is FindingStatus.VERIFIED
    assert replay_id in verified.evidence_ids


def test_r2a_royalty_rule_e3_payloads_redacted_before_storage(r2a_ledger: Ledger) -> None:
    eid = r2a_ledger.add_evidence(
        "r-r2a", "http_exchange", {"api_key": "sk-live-1234567890", "note": "hello"}
    )
    rows = r2a_ledger.evidence("r-r2a")
    assert [r["id"] for r in rows] == [eid]
    assert rows[0]["data"]["api_key"] == "[REDACTED]"
    assert rows[0]["data"]["note"] == "hello"
    assert "sk-live" not in rows[0]["data"]["api_key"]


def test_r2a_royalty_rule_e4_ruled_out_never_deleted(r2a_ledger: Ledger, tmp_path: Any) -> None:
    eid = r2a_ledger.add_evidence("r-r2a", "http_exchange", {"url": "http://127.0.0.1/"})
    created = r2a_ledger.create_finding(_finding(evidence_ids=(eid,)))
    ruled = r2a_ledger.set_finding_status(
        created.id, FindingStatus.RULED_OUT, reason="counterevidence: baseline reflects too"
    )
    assert ruled.status is FindingStatus.RULED_OUT
    conn = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM findings WHERE id = ?", (created.id,))
    finally:
        conn.close()
    assert r2a_ledger.get_finding(created.id).status is FindingStatus.RULED_OUT


def test_r2a_royalty_scope_fail_closed_exact_host_no_alias() -> None:
    scope = ScopeSet(frozenset({"example.com"}), False, name="royalty")
    assert scope.check_url("http://example.com/x") == "example.com"
    for hostile in (
        "http://evil.com/x",
        "http://sub.example.com/x",
        "http://example.com.evil.com/x",
        "http://example.com@evil.com/x",
    ):
        with pytest.raises(ScopeViolation):
            scope.check_url(hostile)


def test_r2a_royalty_phase_order_rejects_skip_ahead(r2a_ledger: Ledger) -> None:
    from hunter.phases import PhaseState

    machine = PhaseState(r2a_ledger, "r-r2a")
    with pytest.raises(HunterError) as excinfo:
        machine.start("hunting")
    assert excinfo.value.code == "phase.out_of_order"
    assert PHASE_ORDER[:2] == ("score", "recon")
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    assert machine.current == "recon"


def test_r2a_royalty_replay_is_sole_verified_path(r2a_ledger: Ledger, tmp_path: Any) -> None:
    eid = r2a_ledger.add_evidence("r-r2a", "http_exchange", {"url": "http://127.0.0.1/"})
    created = r2a_ledger.create_finding(_finding(evidence_ids=(eid,)))
    conn = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="RULE-E2"):
            conn.execute("UPDATE findings SET status = 'verified' WHERE id = ?", (created.id,))
    finally:
        conn.close()
    assert r2a_ledger.get_finding(created.id).status is FindingStatus.CANDIDATE


def test_r2a_royalty_busy_message_byte_exact() -> None:
    from hunter.gateway.app import BUSY_MESSAGE
    from hunter.gateway import durable_lease as durable

    assert BUSY_MESSAGE == "still working on your previous request — try again shortly"
    assert durable.BUSY_MESSAGE == BUSY_MESSAGE
    assert str(durable.LeaseBusy()) == BUSY_MESSAGE
    assert float(durable.DEFAULT_LEASE_TIMEOUT) == pytest.approx(5.0)
    assert durable.HEARTBEAT_INTERVAL_SECONDS == 15
    assert durable.LEASE_STALE_SECONDS == 90


def test_r2a_royalty_stop_file_first(tmp_path: Any) -> None:
    from hunter.llm.budget import RunBudget

    flag = tmp_path / "stop.flag"
    budget = RunBudget(stop_file=str(flag), max_cost_usd=5.0, max_iterations=100)
    assert budget.exhausted() is None
    flag.write_text("", encoding="utf-8")
    reason = budget.exhausted()
    assert reason is not None and "stop file" in str(reason)


def test_r2a_royalty_error_language_single_stable_code() -> None:
    surface = build_error_surface(ValueError("boom"))
    assert isinstance(surface["code"], str) and surface["code"]
    assert surface["code"].count(".") >= 1
    assert isinstance(surface["message"], str) and surface["message"]
    assert set(surface) >= {"code", "message"}
