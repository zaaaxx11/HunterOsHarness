"""Phase machine tests — the soul of HunterOS, enforced by the ledger.

Every gate test drives a REAL ``Ledger(tmp_path)``: gates read ONLY the
ledger, so the seeds are real rows (events, findings, evidence) — never
mocks. The exact retro lesson strings are pinned because they are surfaced
to operators (report appendix, ``/retro``).
"""

from __future__ import annotations

import pytest

from hunter.engine.base import CandidateFinding, EngineResult
from hunter.errors import HunterError
from hunter.kernel.events import EventKind
from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger
from hunter.phases import (
    GATES,
    PHASE_ORDER,
    PHASE_RANK,
    GateResult,
    PhaseSnapshot,
    PhaseState,
    RetroReport,
    check_gate,
    compute_retro,
    current_phase,
    mark_report_rendered,
    phase_snapshots,
    record_classification,
    record_retro,
    render_phase_progress,
    render_run_phase_line,
)

RUN = "R-PHASE-0001"
TARGET = "http://127.0.0.1:9/"


# -- seeding helpers -----------------------------------------------------------------


def seed_run(ledger: Ledger) -> None:
    """A run row + run_started event — exactly the score gate's evidence."""
    ledger.create_run(RUN, TARGET, "deterministic", "localhost-only")
    ledger.append(
        RUN,
        EventKind.RUN_STARTED,
        {
            "target": TARGET,
            "engine": "deterministic",
            "scope": {"name": "localhost-only", "hosts": [], "localhost": True},
        },
    )


def make_machine(ledger: Ledger, **kwargs) -> PhaseState:
    return PhaseState(ledger, RUN, **kwargs)


def canonical_closes(ledger: Ledger, phase: str):
    return [
        event
        for event in ledger.events(RUN)
        if event.kind_value() == "phase_ended"
        and event.payload.get("phase") == phase
        and isinstance(event.payload.get("gate"), dict)
    ]


def canonical_starts(ledger: Ledger, phase: str):
    return [
        event
        for event in ledger.events(RUN)
        if event.kind_value() == "phase_started" and event.payload.get("phase") == phase
    ]


def seed_verified_finding(ledger: Ledger, key: str = "reflected-xss|GET|/search|q") -> str:
    """One VERIFIED finding through the real claim gate (RULE-E1/E2 honored)."""
    evidence = ledger.add_evidence(
        RUN, "http_exchange", {"method": "GET", "url": f"{TARGET}search?q=canary", "status": 200}
    )
    finding = ledger.create_finding(
        Finding(
            id="",
            run_id=RUN,
            key=key,
            title="Reflected XSS",
            severity=Severity.HIGH,
            cwe="CWE-79",
            endpoint="/search",
            method="GET",
            param="q",
            evidence_ids=(evidence,),
        )
    )
    ledger.add_evidence(
        RUN,
        "http_exchange",
        {
            "method": "GET",
            "url": f"{TARGET}search?q=canary",
            "status": 200,
            "replay": True,
            "finding_id": finding.id,
        },
    )
    ledger.set_finding_status(finding.id, FindingStatus.VERIFIED, "independent replay reproduced")
    return finding.id


def append_engine_recon_detail(ledger: Ledger, *, pages: int = 3) -> None:
    ledger.append(RUN, "phase_started", {"phase": "recon"})
    ledger.append(RUN, "phase_ended", {"phase": "recon", "pages": pages, "links": 7, "forms": 1})


# -- soul pins -----------------------------------------------------------------------


def test_phase_order_is_the_doctrine_pipeline():
    assert PHASE_ORDER == ("score", "recon", "classify", "hunting", "verify", "report", "retro")
    assert {phase: index for index, phase in enumerate(PHASE_ORDER)} == PHASE_RANK
    assert set(GATES) == set(PHASE_ORDER)


# -- machine transitions ---------------------------------------------------------------


def test_machine_happy_path_pairs_events_in_rank_order(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)

    state.start("score")
    state.close_current()
    state.start("recon")
    append_engine_recon_detail(ledger)
    state.close_current()
    state.start("classify")
    record_classification(
        ledger, RUN, classes=[{"check_id": "missing-headers", "lane": "passive", "source": "engine"}],
        source="engine",
    )
    state.close_current()
    state.start("hunting")
    ledger.append(RUN, "probe_result", {"check_id": "reflected-xss", "candidates": 1, "hit": True})
    state.close_current()
    state.start("verify")
    seed_verified_finding(ledger)
    state.close_current()
    state.start("report")
    mark_report_rendered(ledger, RUN, fmt="markdown", sha256="ab" * 32, chars=42)
    state.close_current()
    state.start("retro")
    record_retro(ledger, RUN)
    state.close_current()

    assert state.current is None
    events = ledger.events(RUN)
    seqs = [event.seq for event in events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    previous_close_seq = -1
    for phase in PHASE_ORDER:
        starts = canonical_starts(ledger, phase)
        closes = canonical_closes(ledger, phase)
        assert len(closes) == 1, phase
        assert closes[0].payload["gate"]["passed"] is True, phase
        assert starts and starts[0].seq < closes[0].seq
        assert previous_close_seq < starts[0].seq, "phases must run in rank order"
        previous_close_seq = closes[0].seq
    snapshots = phase_snapshots(ledger, RUN)
    assert [snapshot.phase for snapshot in snapshots] == list(PHASE_ORDER)
    assert all(snapshot.state == "done" and snapshot.gate_passed is True for snapshot in snapshots)
    assert current_phase(ledger, RUN) is None


def test_skip_attempt_raises_out_of_order(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    with pytest.raises(HunterError) as excinfo:
        state.start("hunting")
    assert excinfo.value.code == "phase.out_of_order"
    with pytest.raises(HunterError) as excinfo:
        state.start("recon")  # score never opened: rank 1 > cursor 0
    assert excinfo.value.code == "phase.out_of_order"


def test_double_close_and_reopen_raise_invalid_transition(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    with pytest.raises(HunterError) as excinfo:
        state.close_current()  # double close
    assert excinfo.value.code == "phase.invalid_transition"
    with pytest.raises(HunterError) as excinfo:
        state.start("score")  # re-open of a closed phase
    assert excinfo.value.code == "phase.invalid_transition"


def test_unknown_phase_raises_phase_unknown(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    with pytest.raises(HunterError) as excinfo:
        state.start("wave")
    assert excinfo.value.code == "phase.unknown"
    # check_gate never raises on an unknown phase — it honestly fails.
    result = check_gate(ledger, RUN, "wave")
    assert isinstance(result, GateResult) and result.passed is False


def test_idempotent_reopen_returns_none_and_appends_nothing(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    first = state.start("score")
    assert first is not None
    assert state.start("score") is None
    assert len(canonical_starts(ledger, "score")) == 1


def test_interleaved_start_while_open_raises_invalid_transition(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    with pytest.raises(HunterError) as excinfo:
        state.start("recon")
    assert excinfo.value.code == "phase.invalid_transition"


def test_advance_closes_then_starts_and_ignores_gate_evidence(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    event = state.advance("recon", gate_evidence={"pages": 99})
    assert event.payload == {"phase": "recon"}
    assert state.current == "recon"
    assert canonical_closes(ledger, "score")  # the close happened first


# -- gates (pass + fail, ledger-only) ----------------------------------------------------


def test_score_gate(tmp_path):
    empty = Ledger(tmp_path / "empty.db")
    assert check_gate(empty, RUN, "score").passed is False  # no run row
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run(RUN, TARGET, "deterministic", "localhost-only")
    result = check_gate(ledger, RUN, "score")
    assert result.passed is False  # run row without run_started
    ledger.append(
        RUN,
        EventKind.RUN_STARTED,
        {
            "target": TARGET,
            "engine": "deterministic",
            "scope": {"name": "localhost-only", "hosts": [], "localhost": True},
        },
    )
    result = check_gate(ledger, RUN, "score")
    assert result.passed is True
    assert result.evidence["target"] == TARGET
    assert result.evidence["engine"] == "deterministic"
    assert result.evidence["scope"]["name"] == "localhost-only"


def test_recon_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    assert check_gate(ledger, RUN, "recon").passed is False
    append_engine_recon_detail(ledger, pages=2)
    result = check_gate(ledger, RUN, "recon")
    assert result.passed is True
    assert result.evidence == {"pages": 2, "links": 7, "forms": 1}
    # fallback path: agent/mock runs with evidence but no engine recon detail
    fallback = Ledger(tmp_path / "fallback.db")
    seed_run(fallback)
    fallback.add_evidence(RUN, "http_exchange", {"method": "GET", "url": TARGET, "status": 200})
    result = check_gate(fallback, RUN, "recon")
    assert result.passed is True
    assert result.evidence == {"surface_facts": 1}


def test_classify_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    assert check_gate(ledger, RUN, "classify").passed is False
    record_classification(ledger, RUN, classes=[], source="agent")
    assert check_gate(ledger, RUN, "classify").passed is False  # empty classes
    record_classification(
        ledger, RUN, classes=[{"check_id": "missing-headers", "lane": "passive", "source": "agent"}],
        source="agent",
    )
    result = check_gate(ledger, RUN, "classify")
    assert result.passed is True
    assert result.evidence["source"] == "agent"
    assert result.evidence["classes"] == [
        {"check_id": "missing-headers", "lane": "passive", "source": "agent"}
    ]
    # the gate evidence payload caps the class list at 12
    many = [{"check_id": f"check-{i}", "lane": "passive", "source": "agent"} for i in range(13)]
    record_classification(ledger, RUN, classes=many, source="agent")
    assert len(check_gate(ledger, RUN, "classify").evidence["classes"]) == 12


def test_hunting_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    assert check_gate(ledger, RUN, "hunting").passed is False
    ledger.append(RUN, "probe_result", {"check_id": "reflected-xss", "candidates": 1, "hit": True})
    ledger.append(RUN, "probe_result", {"check_id": "reflected-xss", "candidates": 0, "hit": False})
    result = check_gate(ledger, RUN, "hunting")
    assert result.passed is True
    assert result.evidence["probes_run"] == 1  # distinct check ids
    agent = Ledger(tmp_path / "agent.db")
    seed_run(agent)
    agent.append(RUN, "engine_event", {"tool": "run_probe", "check_id": "dir-listing", "candidates": 0})
    agent.append(RUN, "engine_event", {"tool": "coverage_record", "surface": "/", "risk_area": "headers",
                                       "outcome": "reported"})
    result = check_gate(agent, RUN, "hunting")
    assert result.passed is True
    assert result.evidence["agent_probes"] == 1 and result.evidence["coverage_rows"] == 1
    candidate = Ledger(tmp_path / "candidate.db")
    seed_run(candidate)
    evidence = candidate.add_evidence(RUN, "http_exchange", {"method": "GET", "url": TARGET, "status": 200})
    candidate.create_finding(
        Finding(id="", run_id=RUN, key="k|GET|/|-", title="t", severity=Severity.LOW, cwe="CWE-0",
                endpoint="/", method="GET", evidence_ids=(evidence,))
    )
    result = check_gate(candidate, RUN, "hunting")
    assert result.passed is True and result.evidence["candidates"] == 1


def test_verify_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    result = check_gate(ledger, RUN, "verify")
    assert result.passed is True  # vacuously: zero findings, zero unresolved
    assert result.evidence["findings"] == 0
    seed_verified_finding(ledger)
    result = check_gate(ledger, RUN, "verify")
    assert result.passed is True
    assert result.evidence == {"findings": 1, "verified": 1, "ruled_out": 0, "unresolved": []}
    # a candidate with a recorded failed replay is resolved-by-record
    evidence = ledger.add_evidence(
        RUN, "http_exchange", {"method": "GET", "url": f"{TARGET}x", "status": 404}
    )
    candidate = ledger.create_finding(
        Finding(id="", run_id=RUN, key="sensitive-file|GET|/x|-", title="t", severity=Severity.LOW,
                cwe="CWE-0", endpoint="/x", method="GET", evidence_ids=(evidence,))
    )
    ledger.append(RUN, "engine_event", {"stage": "verify", "finding_id": candidate.id, "replay": False})
    assert check_gate(ledger, RUN, "verify").passed is True
    # a bare candidate leaves the gate honestly failed, naming the id
    bare = Ledger(tmp_path / "bare.db")
    seed_run(bare)
    ev = bare.add_evidence(RUN, "http_exchange", {"method": "GET", "url": TARGET, "status": 200})
    f1 = bare.create_finding(
        Finding(id="", run_id=RUN, key="k1|GET|/1|-", title="t", severity=Severity.LOW, cwe="CWE-0",
                endpoint="/1", method="GET", evidence_ids=(ev,))
    )
    f2 = bare.create_finding(
        Finding(id="", run_id=RUN, key="k2|GET|/2|-", title="t", severity=Severity.LOW, cwe="CWE-0",
                endpoint="/2", method="GET", evidence_ids=(ev,))
    )
    result = check_gate(bare, RUN, "verify")
    assert result.passed is False
    assert f1.id in result.reason and f2.id in result.reason
    assert result.evidence["unresolved"] == [f1.id, f2.id]


def test_report_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    assert check_gate(ledger, RUN, "report").passed is False
    mark_report_rendered(ledger, RUN, fmt="markdown", sha256="cd" * 32, chars=128, out="/tmp/r.md")
    result = check_gate(ledger, RUN, "report")
    assert result.passed is True
    assert result.evidence == {"fmt": "markdown", "sha256": "cd" * 32, "chars": 128}


def test_retro_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    assert check_gate(ledger, RUN, "retro").passed is False
    record_retro(ledger, RUN)
    result = check_gate(ledger, RUN, "retro")
    assert result.passed is True
    assert set(result.evidence) == {"lessons"}


# -- snapshots from events only ------------------------------------------------------------


def test_snapshots_computed_from_events(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    snapshots = {snapshot.phase: snapshot for snapshot in phase_snapshots(ledger, RUN)}
    assert snapshots["score"].state == "done" and snapshots["score"].gate_passed is True
    assert snapshots["recon"].state == "active" and snapshots["recon"].gate_passed is None
    for phase in ("classify", "hunting", "verify", "report", "retro"):
        assert snapshots[phase].state == "pending" and snapshots[phase].gate_passed is None
    assert current_phase(ledger, RUN) == "recon"


def test_failed_gate_marks_phase_failed_and_run_continues(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    event = state.close_current()  # no surface facts: honest failure, no raise
    assert event.payload["gate"]["passed"] is False
    assert event.payload["gate"]["reason"]
    snapshots = {snapshot.phase: snapshot for snapshot in phase_snapshots(ledger, RUN)}
    assert snapshots["recon"].state == "failed"
    assert snapshots["recon"].gate_passed is False
    assert snapshots["recon"].detail == event.payload["gate"]["reason"]
    # default mode: the run continues — the next phase in rank order may open
    assert state.current is None
    state.start("classify")
    assert state.current == "classify"


def test_abort_closes_open_phase_without_a_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    state.abort()
    aborted = [
        event
        for event in ledger.events(RUN)
        if event.kind_value() == "phase_ended" and event.payload.get("aborted") is True
    ]
    assert len(aborted) == 1 and aborted[0].payload["phase"] == "recon"
    assert state.current is None
    state.abort()  # idempotent: nothing open, nothing appended
    assert len(aborted) == 1
    snapshots = {snapshot.phase: snapshot for snapshot in phase_snapshots(ledger, RUN)}
    assert snapshots["recon"].state == "failed" and snapshots["recon"].detail == "aborted"


def test_strict_mode_raises_after_recording_the_failed_gate(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger, strict=True)
    state.start("score")
    state.close_current()
    state.start("recon")
    with pytest.raises(HunterError) as excinfo:
        state.close_current()
    assert excinfo.value.code == "phase.gate_failed"
    # the failure is a recorded fact even in strict mode
    closes = canonical_closes(ledger, "recon")
    assert closes and closes[0].payload["gate"]["passed"] is False


# -- adapters --------------------------------------------------------------------------------


def test_observe_ignores_early_probe_wrapper_then_transitions_on_engine_probe(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    # the pipeline's own "probe" wrapper event arrives before the engine ran
    # any recon: payload-identical, but the engine's recon sub-phase has not
    # been observed, so it must NOT close recon.
    state.observe("phase_started", {"phase": "probe"})
    assert state.current == "recon"
    # engine recon detail (appended to the ledger, as emit does), then the
    # engine's own probe start: transition.
    append_engine_recon_detail(ledger)
    state.observe("phase_started", {"phase": "recon"})
    state.observe("phase_ended", {"phase": "recon", "pages": 2, "links": 5, "forms": 1})
    state.observe("phase_started", {"phase": "probe"})
    assert state.current == "hunting"
    closes = canonical_closes(ledger, "recon")
    assert closes and closes[0].payload["gate"]["passed"] is True
    assert canonical_starts(ledger, "classify") and canonical_closes(ledger, "classify")
    assert canonical_starts(ledger, "hunting")
    classifications = [e for e in ledger.events(RUN) if e.kind_value() == "classification_recorded"]
    assert len(classifications) == 1
    payload = classifications[0].payload
    assert payload["source"] == "engine"
    lanes = {row["lane"] for row in payload["classes"]}
    assert lanes == {"passive", "active"}
    assert len(payload["classes"]) == 12  # all PROBE_TIERS checks classified


def test_observe_ignores_detail_events_once_hunting(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    append_engine_recon_detail(ledger)
    state.observe("phase_started", {"phase": "recon"})
    state.observe("phase_ended", {"phase": "recon", "pages": 3, "links": 7, "forms": 1})
    state.observe("phase_started", {"phase": "probe"})
    assert state.current == "hunting"
    before = len(ledger.events(RUN))
    state.observe("phase_ended", {"phase": "probe", "raw_candidates": 3})
    state.observe("phase_started", {"phase": "collect"})
    state.observe("phase_ended", {"phase": "collect", "findings": 0})
    state.observe("probe_result", {"check_id": "dir-listing", "candidates": 0, "hit": False})
    state.observe("engine_event", {"tool": "http_request", "status": 200})
    assert len(ledger.events(RUN)) == before
    assert state.current == "hunting"


def test_observe_tool_drives_agent_transition(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    state.observe_tool("think")  # not a surface tool: no transition
    assert state.current == "recon"
    state.observe_tool("coverage_record")
    assert state.current == "hunting"
    classifications = [e for e in ledger.events(RUN) if e.kind_value() == "classification_recorded"]
    assert classifications[0].payload["source"] == "agent"
    closes = canonical_closes(ledger, "recon")
    assert closes and closes[0].payload["gate"]["passed"] is False  # honest: no surface facts yet


def test_engine_run_done_closes_recon_records_classification_opens_hunting(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    result = EngineResult(
        candidates=[
            CandidateFinding(
                key="mock|GET|/mock|-", title="m", severity=Severity.LOW, cwe="CWE-000", endpoint="/mock"
            )
        ],
        stats={},
    )
    state.engine_run_done(result)
    assert state.current == "hunting"  # left OPEN for the pipeline to close
    closes = canonical_closes(ledger, "recon")
    assert closes and closes[0].payload["gate"]["passed"] is False  # honest fail
    assert canonical_closes(ledger, "classify")[0].payload["gate"]["passed"] is True
    classification = next(e for e in ledger.events(RUN) if e.kind_value() == "classification_recorded")
    check_ids = [row["check_id"] for row in classification.payload["classes"]]
    assert check_ids[0] == "mock"  # the candidate's check id comes first
    assert "reflected-xss" in check_ids  # + the PROBE_TIERS lanes
    before = len(ledger.events(RUN))
    state.engine_run_done(result)  # already past recon: no-op
    assert len(ledger.events(RUN)) == before


# -- retro -----------------------------------------------------------------------------------


def test_retro_lesson_no_findings_with_coverage(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    for index in range(3):
        ledger.append(
            RUN,
            "engine_event",
            {
                "tool": "coverage_record",
                "surface": f"/{index}",
                "risk_area": "headers",
                "outcome": "reported",
            },
        )
    report = compute_retro(ledger, RUN)
    assert report.lessons == [
        "No findings across 3 recorded coverage rows — target hardened or scope too narrow."
    ]
    assert report.stats["coverage_closed"] == 3
    assert report.coverage_pct == 100.0


def test_retro_lesson_no_findings_no_coverage(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    report = compute_retro(ledger, RUN)
    assert report.lessons == [
        "No findings and no coverage recorded — the run cannot show what was reviewed."
    ]
    assert report.coverage_pct is None


def test_retro_lesson_gates_failed(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    state.start("recon")
    state.close_current()  # recon gate fails honestly
    report = compute_retro(ledger, RUN)
    assert "Phase gate(s) failed (recon) — widen recon before trusting coverage." in report.lessons
    assert "gate failed: recon" in report.gaps[0]


def test_retro_lesson_ruled_out(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    evidence = ledger.add_evidence(RUN, "http_exchange", {"method": "GET", "url": TARGET, "status": 200})
    finding = ledger.create_finding(
        Finding(id="", run_id=RUN, key="k|GET|/|-", title="t", severity=Severity.LOW, cwe="CWE-0",
                endpoint="/", method="GET", evidence_ids=(evidence,))
    )
    ledger.set_finding_status(finding.id, FindingStatus.RULED_OUT, "debunked by baseline diff")
    report = compute_retro(ledger, RUN)
    assert report.lessons == [
        "1 candidates ruled out by replay — the debunk pass earned its keep; keep the rechecks."
    ]


def test_retro_lesson_verified_ladder_held(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    seed_verified_finding(ledger)
    report = compute_retro(ledger, RUN)
    assert report.lessons == [
        "1 finding(s) verified by independent replay — the evidence ladder held end to end."
    ]


def test_record_retro_appends_and_refreshes_append_only(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    first = record_retro(ledger, RUN)
    second = record_retro(ledger, RUN)  # re-record = refresh; append-only
    events = [e for e in ledger.events(RUN) if e.kind_value() == "retro_recorded"]
    assert len(events) == 2
    assert first == second
    assert events[0].payload == events[1].payload
    assert events[1].payload["stats"]


def test_retro_report_payload_shape(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    report = compute_retro(ledger, RUN)
    assert isinstance(report, RetroReport)
    assert report.to_payload() == {
        "stats": report.stats,
        "coverage_pct": report.coverage_pct,
        "gaps": report.gaps,
        "lessons": report.lessons,
    }
    assert set(report.stats) == {
        "duration_s", "requests", "blocked", "errors", "probes_run", "verified", "ruled_out",
        "coverage_closed",
    }


# -- recorders + renderers ---------------------------------------------------------------------


def test_mark_report_rendered_event_shape(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    event = mark_report_rendered(ledger, RUN, fmt="markdown", sha256="ef" * 32, chars=7, out="out.md")
    assert event.kind_value() == "report_rendered"
    assert event.payload == {"fmt": "markdown", "sha256": "ef" * 32, "chars": 7, "out": "out.md"}


def test_record_classification_event_shape(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    event = record_classification(
        ledger, RUN, classes=[{"check_id": "dir-listing", "lane": "passive"}], source="agent"
    )
    assert event.kind_value() == "classification_recorded"
    assert event.payload["source"] == "agent"
    assert event.payload["classes"] == [{"check_id": "dir-listing", "lane": "passive"}]


def test_renderer_glyphs_unicode_and_ascii():
    snapshots = [
        PhaseSnapshot(phase="score", state="done", gate_passed=True, detail=""),
        PhaseSnapshot(phase="recon", state="failed", gate_passed=False, detail="no facts"),
        PhaseSnapshot(phase="classify", state="active", gate_passed=None, detail=""),
        PhaseSnapshot(phase="hunting", state="pending", gate_passed=None, detail=""),
    ]
    rendered = render_phase_progress(snapshots)
    assert "score ✓" in rendered and "recon ✗" in rendered
    assert "classify ▶" in rendered and "hunting ○" in rendered
    ascii_rendered = render_phase_progress(snapshots, use_ascii=True)
    assert "score ok" in ascii_rendered and "recon x" in ascii_rendered
    assert "classify >" in ascii_rendered and "hunting -" in ascii_rendered


def test_renderer_hunting_bar_and_width():
    snapshots = [PhaseSnapshot(phase="hunting", state="active", gate_passed=None, detail="6/12")]
    rendered = render_phase_progress(snapshots)  # default width 12
    assert "6/12" in rendered
    assert "█" * 6 in rendered and "█" * 7 not in rendered
    assert "·" * 6 in rendered
    ascii_rendered = render_phase_progress(snapshots, use_ascii=True)
    assert "#" * 6 in ascii_rendered and "-" * 6 in ascii_rendered
    narrow = render_phase_progress(snapshots, width=4)  # round(4 * 6/12) = 2 filled
    assert "█" * 2 in narrow and "█" * 3 not in narrow
    assert "6/12" in narrow


def test_render_run_phase_line_reads_ledger(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    state = make_machine(ledger)
    state.start("score")
    state.close_current()
    line = render_run_phase_line(ledger, RUN)
    assert line.startswith("score ✓") and "recon ○" in line and "retro ○" in line
    assert render_run_phase_line(ledger, RUN, use_ascii=True).startswith("score ok")
