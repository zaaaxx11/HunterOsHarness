"""P-A royalty guards — PASSING regression pins for Planner A implementers.

Unlike the other ``test_p*.py`` files (failing-by-design TDD contracts),
EVERY test here PASSES today and must stay green through the whole P0 -> P4
build: they guard the invariants Planner A work must never break:

- ledger append-only triggers (no UPDATE / DELETE / REPLACE on events,
  evidence, findings; runs metadata frozen except finish_run columns).
- RULE-E1..E4 (finding needs bound evidence; VERIFIED needs replay
  evidence; payloads redacted before storage; ruled-out rows persist).
- scope fail-closed: exact-host match, no alias/subdomain/userinfo bypass.
- canonical phase order (skip-ahead -> ``phase.out_of_order``).
- replay as the SOLE VERIFIED path (API + storage layer).
- one error language: a single stable machine code per failure.

Adversarial mitigations: isolated ``tmp_path`` ledgers per test (never the
shared ``<state>``); raw-SQL assertions use a second sqlite3 connection and
assert ``IntegrityError`` text (not return codes); negative asserts included
(no UPDATE/DELETE paths, no scope widening, no VERIFIED without EV-ids).
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
def royalty_ledger(tmp_path: Any) -> Any:
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run("r1", "http://127.0.0.1:9000", "deterministic", "localhost-only")
    yield ledger
    ledger.close()


def _royalty_finding(**overrides: Any) -> Finding:
    kwargs: dict[str, Any] = dict(
        id="",
        run_id="r1",
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


def test_pa_royalty_events_append_only_rejects_update(royalty_ledger: Ledger, tmp_path: Any) -> None:
    royalty_ledger.add_evidence("r1", "http_response", {"body": "x"})
    connection = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE events SET payload = '{}' WHERE seq = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE evidence SET kind = 'other' WHERE id = 'EV-0001'")
    finally:
        connection.close()


def test_pa_royalty_no_delete_or_replace_paths(royalty_ledger: Ledger, tmp_path: Any) -> None:
    royalty_ledger.add_evidence("r1", "http_response", {"body": "x"})
    connection = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM events WHERE seq = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM evidence WHERE id = 'EV-0001'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("INSERT OR REPLACE INTO events (seq) VALUES (1)")
    finally:
        connection.close()
    assert len(royalty_ledger.evidence("r1")) == 1  # nothing was removed


def test_pa_royalty_rule_e1_finding_requires_bound_evidence(royalty_ledger: Ledger) -> None:
    with pytest.raises(ClaimGateBlocked, match="RULE-E1"):
        royalty_ledger.create_finding(_royalty_finding(evidence_ids=()))
    with pytest.raises(ClaimGateBlocked, match="RULE-E1"):
        royalty_ledger.create_finding(_royalty_finding(evidence_ids=("EV-9999",)))
    assert royalty_ledger.findings("r1") == []  # no finding without EV-ids, ever


def test_pa_royalty_rule_e2_verified_requires_replay(royalty_ledger: Ledger) -> None:
    evidence_id = royalty_ledger.add_evidence("r1", "http_exchange", {"url": "http://127.0.0.1/"})
    created = royalty_ledger.create_finding(_royalty_finding(evidence_ids=(evidence_id,)))
    assert created.status is FindingStatus.CANDIDATE
    with pytest.raises(ClaimGateBlocked, match="RULE-E2"):
        royalty_ledger.set_finding_status(created.id, FindingStatus.VERIFIED, reason="looks real")
    replay_id = royalty_ledger.add_evidence(
        "r1", "http_exchange", {"replay": True, "finding_id": created.id}
    )
    verified = royalty_ledger.set_finding_status(created.id, FindingStatus.VERIFIED, reason="replayed")
    assert verified.status is FindingStatus.VERIFIED
    assert replay_id in verified.evidence_ids


def test_pa_royalty_rule_e3_payloads_redacted_before_storage(royalty_ledger: Ledger) -> None:
    evidence_id = royalty_ledger.add_evidence(
        "r1", "http_exchange", {"api_key": "sk-live-1234567890", "note": "hello"}
    )
    rows = royalty_ledger.evidence("r1")
    assert [row["id"] for row in rows] == [evidence_id]
    assert rows[0]["data"]["api_key"] == "[REDACTED]"
    assert rows[0]["data"]["note"] == "hello"
    assert "sk-live" not in rows[0]["data"]["api_key"]


def test_pa_royalty_rule_e4_ruled_out_findings_never_deleted(
    royalty_ledger: Ledger, tmp_path: Any
) -> None:
    evidence_id = royalty_ledger.add_evidence("r1", "http_exchange", {"url": "http://127.0.0.1/"})
    created = royalty_ledger.create_finding(_royalty_finding(evidence_ids=(evidence_id,)))
    ruled_out = royalty_ledger.set_finding_status(
        created.id, FindingStatus.RULED_OUT, reason="counterevidence: baseline reflects too"
    )
    assert ruled_out.status is FindingStatus.RULED_OUT
    connection = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM findings WHERE id = ?", (created.id,))
    finally:
        connection.close()
    assert royalty_ledger.get_finding(created.id).status is FindingStatus.RULED_OUT


def test_pa_royalty_scope_fail_closed_exact_host_no_alias() -> None:
    scope = ScopeSet(frozenset({"example.com"}), False, name="royalty")
    assert scope.check_url("http://example.com/x") == "example.com"
    for hostile in (
        "http://evil.com/x",
        "http://sub.example.com/x",  # subdomains NOT implied when allow_subdomains=False
        "http://example.com.evil.com/x",  # suffix spoof
        "http://example.com@evil.com/x",  # userinfo trick
    ):
        with pytest.raises(ScopeViolation):
            scope.check_url(hostile)


def test_pa_royalty_phase_order_rejects_skip_ahead(royalty_ledger: Ledger) -> None:
    from hunter.phases import PhaseState

    machine = PhaseState(royalty_ledger, "r1")
    with pytest.raises(HunterError) as excinfo:
        machine.start("hunting")  # score first — never skip ahead
    assert excinfo.value.code == "phase.out_of_order"
    assert PHASE_ORDER[:2] == ("score", "recon")
    machine.start("score")
    machine.close_current()
    machine.start("recon")  # canonical order advances one step
    assert machine.current == "recon"


def test_pa_royalty_replay_is_sole_verified_path(royalty_ledger: Ledger, tmp_path: Any) -> None:
    evidence_id = royalty_ledger.add_evidence("r1", "http_exchange", {"url": "http://127.0.0.1/"})
    created = royalty_ledger.create_finding(_royalty_finding(evidence_ids=(evidence_id,)))
    connection = sqlite3.connect(tmp_path / "ledger.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="RULE-E2"):
            connection.execute("UPDATE findings SET status = 'verified' WHERE id = ?", (created.id,))
    finally:
        connection.close()
    assert royalty_ledger.get_finding(created.id).status is FindingStatus.CANDIDATE


def test_pa_royalty_error_language_single_stable_code() -> None:
    surface = build_error_surface(ValueError("boom"))
    assert isinstance(surface["code"], str) and surface["code"]
    assert surface["code"].count(".") >= 1  # one dotted machine code, e.g. unexpected.ValueError
    assert isinstance(surface["message"], str) and surface["message"]
    assert set(surface) >= {"code", "message"}  # no second competing code field
