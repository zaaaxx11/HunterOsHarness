"""Part A of docs/RETENTION-SPEC.md — run lifecycle (`hunt close`).

Covers: schema migration v3 (outcome/closed_at/summary_json), ``close_run``,
``assert_run_writable`` and the ``hunter hunt close`` CLI verb.

Invariants proven here (spec "Invariants the tests MUST prove", A-scope):
  1. DELETE FROM events still raises ABORT (triggers untouched by v3).
  2. close on an unknown run -> error, non-zero exit, no rows mutated.
  3. close twice -> second errors, first summary unchanged.
  4. after close, assert_run_writable raises; reading still works.
  14. --json on every new command emits pure JSON on stdout.
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3

import pytest
import typer

from hunter.kernel.events import EventKind
from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger
from hunter.kernel.runs import (
    RunAlreadyClosed,
    RunClosure,
    RunClosed,
    RunNotFound,
    close_run,
    is_run_closed,
)

RUN = "R-close-1"


# -- helpers --------------------------------------------------------------------


def _ledger(tmp_path) -> Ledger:
    return Ledger(tmp_path / "ledger.db")


def _seed_run(ledger: Ledger, run_id: str = RUN) -> str:
    ledger.create_run(run_id, "http://127.0.0.1:9/", "mock", "local")
    return run_id


def _finding(ledger: Ledger, run_id: str, key: str, severity: Severity) -> Finding:
    ev = ledger.add_evidence(run_id, "note", {"obs": key})
    return ledger.create_finding(
        Finding(
            id="",
            run_id=run_id,
            key=key,
            title=f"title {key}",
            severity=severity,
            cwe="CWE-89",
            endpoint="/search",
            evidence_ids=(ev,),
        )
    )


def _proven_finding(ledger: Ledger, run_id: str, key: str, severity: Severity) -> Finding:
    """A finding that has been promoted all the way to verified (proven-live)."""
    f = _finding(ledger, run_id, key, severity)
    ledger.add_evidence(
        run_id,
        "http_exchange",
        {"request": "GET /search", "response": "SQL error", "replay": True, "finding_id": f.id},
    )
    return ledger.set_finding_status(f.id, FindingStatus.VERIFIED, "replayed")


def _counts(ledger: Ledger) -> tuple[int, int, int]:
    with ledger._lock:
        return tuple(
            int(ledger._conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
            for t in ("runs", "events", "findings")
        )


def _run_row(ledger: Ledger, run_id: str = RUN) -> dict:
    with ledger._lock:
        ledger._conn.row_factory = sqlite3.Row
        try:
            row = ledger._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        finally:
            ledger._conn.row_factory = None
    assert row is not None
    return dict(row)


def _call_direct(fn, *args, **kwargs) -> tuple[int, str, str]:
    """Call a command function with separated streams."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            fn(*args, **kwargs)
        code = 0
    except typer.Exit as exc:
        code = int(exc.exit_code)
    return code, out.getvalue(), err.getvalue()


# -- schema migration v3 --------------------------------------------------------


def test_schema_v3_columns_and_user_version(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        cols = {
            r[1]: r[2]
            for r in ledger._conn.execute("PRAGMA table_info(runs)").fetchall()
        }
        assert "outcome" in cols
        assert "closed_at" in cols
        assert "summary_json" in cols
        assert int(ledger._conn.execute("PRAGMA user_version").fetchone()[0]) == 3
    finally:
        ledger.close()


def test_v3_migrates_an_existing_v2_database(tmp_path):
    """An old v2 db (no v3 columns) is migrated in place on open."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY, target TEXT NOT NULL, engine TEXT NOT NULL,
            scope_name TEXT NOT NULL, started_ts REAL, ended_ts REAL,
            status TEXT NOT NULL
        );
        INSERT INTO runs VALUES ('R-old', 'http://127.0.0.1:9/', 'mock', 'local', 1.0, NULL, 'running');
        PRAGMA user_version = 2;
        """
    )
    conn.commit()
    conn.close()

    ledger = Ledger(path)
    try:
        assert int(ledger._conn.execute("PRAGMA user_version").fetchone()[0]) == 3
        row = _run_row(ledger, "R-old")
        assert row["closed_at"] is None and row["outcome"] is None
        closure = close_run(ledger, "R-old")
        assert closure.run_id == "R-old"
    finally:
        ledger.close()


def test_runs_protected_columns_does_not_freeze_v3_columns(tmp_path):
    """The spec's note: outcome/closed_at/summary_json stay writable."""
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        with ledger._lock:
            ledger._conn.execute(
                "UPDATE runs SET outcome = 'partial', closed_at = 1.0, summary_json = '{}'"
                " WHERE run_id = ?",
                (RUN,),
            )
        # Protected columns remain frozen.
        with pytest.raises(sqlite3.IntegrityError):
            ledger._conn.execute("UPDATE runs SET target = 'x' WHERE run_id = ?", (RUN,))
    finally:
        ledger.close()


# -- append-only trigger survives v3 --------------------------------------------


def test_events_delete_still_aborts_after_migration(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        ledger.append(RUN, EventKind.ENGINE_EVENT, {"x": 1})
        with pytest.raises(sqlite3.IntegrityError, match="BLOCKED: append-only"):
            ledger._conn.execute("DELETE FROM events")
        assert len(ledger.events()) == 1
    finally:
        ledger.close()


# -- close_run: errors ----------------------------------------------------------


def test_close_unknown_run_raises_and_mutates_nothing(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        before = _counts(ledger)
        with pytest.raises(RunNotFound):
            close_run(ledger, "R-does-not-exist")
        assert _counts(ledger) == before
        assert _run_row(ledger)["closed_at"] is None
    finally:
        ledger.close()


def test_close_twice_raises_and_keeps_first_summary(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        first = close_run(ledger, RUN)
        row_after_first = _run_row(ledger)
        events_after_first = _counts(ledger)

        with pytest.raises(RunAlreadyClosed):
            close_run(ledger, RUN, outcome="blocked")

        row_after_second = _run_row(ledger)
        assert row_after_second["summary_json"] == row_after_first["summary_json"]
        assert row_after_second["outcome"] == row_after_first["outcome"] == "partial"
        assert row_after_second["closed_at"] == row_after_first["closed_at"]
        assert _counts(ledger) == events_after_first
        assert first.run_id == RUN
    finally:
        ledger.close()


# -- close_run: summary + outcome ------------------------------------------------


def test_close_empty_run_outcome_blocked(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        closure = close_run(ledger, RUN)
        assert isinstance(closure, RunClosure)
        assert closure.outcome == "blocked"
        assert closure.findings_total == 0
        assert closure.findings_proven == 0
        assert closure.findings_by_severity == {}
        assert closure.evidence_total == 0
        assert closure.promotions == []
        assert closure.closed_at is not None and closure.closed_at > 0
        assert closure.started_ts is not None and closure.started_ts <= closure.closed_at
    finally:
        ledger.close()


def test_close_unproven_finding_outcome_partial(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.HIGH)
        closure = close_run(ledger, RUN)
        assert closure.outcome == "partial"
        assert closure.findings_total == 1
        assert closure.findings_proven == 0
        assert closure.promotions == []  # never promote an unproven finding
    finally:
        ledger.close()


def test_close_proven_critical_outcome_proven_and_eligible(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        proven = _proven_finding(ledger, RUN, "sql-error", Severity.CRITICAL)
        _finding(ledger, RUN, "unproven-medium", Severity.MEDIUM)
        proven_medium = _proven_finding(ledger, RUN, "proven-medium", Severity.MEDIUM)

        closure = close_run(ledger, RUN)

        assert closure.outcome == "proven"
        assert closure.findings_total == 3
        assert closure.findings_proven == 2
        assert closure.findings_by_severity == {"critical": 1, "medium": 2}
        # 1 note per finding (3) + 1 http_exchange replay per proven finding (2)
        assert closure.evidence_total == 5
        assert closure.promotions == [proven.key]
        assert proven_medium.key not in closure.promotions
    finally:
        ledger.close()


def test_close_medium_proven_only_is_partial(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _proven_finding(ledger, RUN, "proven-low", Severity.LOW)
        closure = close_run(ledger, RUN)
        assert closure.outcome == "partial"
        assert closure.findings_proven == 1
        assert closure.promotions == []
    finally:
        ledger.close()


def test_explicit_outcome_overrides_derivation(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.HIGH)
        closure = close_run(ledger, RUN, outcome="abandoned")
        assert closure.outcome == "abandoned"
        assert _run_row(ledger)["outcome"] == "abandoned"
    finally:
        ledger.close()


def test_invalid_explicit_outcome_rejected_and_run_stays_open(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        before = _counts(ledger)
        with pytest.raises(ValueError):
            close_run(ledger, RUN, outcome="victory")
        assert _counts(ledger) == before
        assert _run_row(ledger)["closed_at"] is None
    finally:
        ledger.close()


def test_close_persists_row_and_appends_run_closed_event(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        closure = close_run(ledger, RUN)

        row = _run_row(ledger)
        assert row["outcome"] == "partial"
        assert row["closed_at"] == pytest.approx(closure.closed_at)
        summary = json.loads(row["summary_json"])
        assert summary["findings_total"] == 1
        assert summary["outcome"] == "partial"
        assert summary["ended_ts_real"] == pytest.approx(closure.closed_at)

        closed_events = [e for e in ledger.events(RUN) if e.kind_value() == "run_closed"]
        assert len(closed_events) == 1
        payload = closed_events[0].payload
        assert payload["summary"]["findings_total"] == 1
        assert payload["outcome"] == "partial"
        assert ledger.verify_chain(RUN).ok
    finally:
        ledger.close()


# -- assert_run_writable / is_run_closed ----------------------------------------


def test_is_run_closed_reports_state(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        assert is_run_closed(ledger, RUN) is False
        close_run(ledger, RUN)
        assert is_run_closed(ledger, RUN) is True
        assert is_run_closed(ledger, "R-nope") is False
    finally:
        ledger.close()


def test_closed_run_rejects_evidence_and_findings_but_still_reads(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        f = _finding(ledger, RUN, "k1", Severity.MEDIUM)
        closure = close_run(ledger, RUN)
        before = _counts(ledger)

        # direct guard
        with pytest.raises(RunClosed):
            ledger.assert_run_writable(RUN)

        # evidence-store path
        with pytest.raises(RunClosed):
            ledger.add_evidence(RUN, "note", {"late": True})

        # finding-create path
        ev_before = len(ledger.evidence(RUN))
        with pytest.raises(RunClosed):
            _finding(ledger, RUN, "late", Severity.HIGH)

        # status change path
        with pytest.raises(RunClosed):
            ledger.set_finding_status(f.id, FindingStatus.RULED_OUT, "late change")

        assert _counts(ledger) == before
        assert len(ledger.evidence(RUN)) == ev_before

        # reading a closed run is unaffected
        assert [x.id for x in ledger.findings(RUN)] == [f.id]
        assert ledger.get_finding(f.id).key == "k1"
        assert ledger.verify_chain(RUN).ok
        assert [r["run_id"] for r in ledger.runs()] == [RUN]
        assert any(
            e.kind_value() == "run_closed" for e in ledger.events(RUN)
        )
        assert closure.outcome == "partial"
    finally:
        ledger.close()


def test_open_run_is_writable(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger)
        ledger.assert_run_writable(RUN)  # must not raise
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
        assert ledger.findings(RUN)
    finally:
        ledger.close()


def test_close_does_not_block_a_sibling_run(tmp_path):
    ledger = _ledger(tmp_path)
    try:
        _seed_run(ledger, "R-a")
        _seed_run(ledger, "R-b")
        close_run(ledger, "R-a")
        _finding(ledger, "R-b", "k1", Severity.MEDIUM)  # sibling stays writable
        assert len(ledger.findings("R-b")) == 1
        assert len(ledger.findings("R-a")) == 0
    finally:
        ledger.close()


# -- CLI ------------------------------------------------------------------------


def test_cli_close_success_and_json(tmp_path):
    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
        _finding(ledger, RUN, "k1", Severity.MEDIUM)
    finally:
        ledger.close()

    from hunter.cli.hunt_close import hunt_close

    code, out, _ = _call_direct(hunt_close, RUN, outcome=None, state=state, json_out=True)
    assert code == 0, out
    payload = json.loads(out)  # stdout is ONLY the JSON document
    assert payload["run_id"] == RUN
    assert payload["outcome"] == "partial"
    assert payload["findings_total"] == 1
    assert "closed_at" in payload


def test_cli_close_human_output(tmp_path):
    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
    finally:
        ledger.close()

    from hunter.cli.hunt_close import hunt_close

    code, out, err = _call_direct(
        hunt_close, RUN, outcome=None, state=state, json_out=False
    )
    assert code == 0
    # Human text is routed to the reporter (stderr console); verify via
    # the function call path which captures both streams.
    combined = out + err
    assert RUN in combined
    assert "blocked" in combined


def test_cli_close_twice_nonzero_keeps_first_summary(tmp_path):
    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
    finally:
        ledger.close()

    from hunter.cli.hunt_close import hunt_close

    code, _, _ = _call_direct(hunt_close, RUN, outcome=None, state=state, json_out=False)
    assert code == 0
    ledger = Ledger(state / "ledger.db")
    try:
        first = _run_row(ledger)["summary_json"]
        events_before = _counts(ledger)
    finally:
        ledger.close()

    code2, _, _ = _call_direct(
        hunt_close, RUN, outcome=None, state=state, json_out=False
    )
    assert code2 != 0

    ledger = Ledger(state / "ledger.db")
    try:
        assert _run_row(ledger)["summary_json"] == first
        assert _counts(ledger) == events_before
    finally:
        ledger.close()


def test_cli_close_explicit_outcome_and_pure_json_stdout(tmp_path):
    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
    finally:
        ledger.close()

    from hunter.cli.hunt_close import hunt_close

    code, out, err = _call_direct(
        hunt_close, RUN, outcome="abandoned", state=state, json_out=True
    )
    assert code == 0
    assert json.loads(out)["outcome"] == "abandoned"


def test_cli_close_unknown_run_nonzero_no_mutation(tmp_path):
    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
        before = _counts(ledger)
    finally:
        ledger.close()

    from hunter.cli.hunt_close import hunt_close

    code, out, err = _call_direct(
        hunt_close, "R-missing", outcome=None, state=state, json_out=True
    )
    assert code != 0
    # --json failure still keeps stdout pure: only the JSON error document
    payload = json.loads(out) if out.strip() else {}
    assert payload.get("status") == "error"
    assert payload.get("reason") == "not_found"

    ledger = Ledger(state / "ledger.db")
    try:
        assert _counts(ledger) == before
    finally:
        ledger.close()


def test_cli_close_rejects_unknown_outcome_choice(tmp_path):
    from hunter.cli.hunt_close import hunt_close

    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    try:
        _seed_run(ledger)
    finally:
        ledger.close()

    code, out, err = _call_direct(
        hunt_close, RUN, outcome="victory", state=state, json_out=True
    )
    assert code != 0
    payload = json.loads(out) if out.strip() else {}
    assert payload.get("status") in ("error", "usage")

    ledger = Ledger(state / "ledger.db")
    try:
        assert _run_row(ledger)["closed_at"] is None
    finally:
        ledger.close()
