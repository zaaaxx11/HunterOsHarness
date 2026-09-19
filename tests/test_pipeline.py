"""Workflow pipeline tests: run_scan end-to-end against PracticeVault, plus
registry and engine-wiring behavior (mock, unknown name, shipped-dark llm) —
and the canonical phase machine wiring (score..retro, all gates ledger-only).
"""

from __future__ import annotations

import pytest

from hunter.kernel.events import sha256_hex
from hunter.kernel.ledger import Ledger
from hunter.phases import mark_report_rendered
from hunter.reporting.markdown import render_markdown
from hunter.tools.registry import available_engines, get_engine
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server
from hunter.workflow.bench import run_demo
from hunter.workflow.pipeline import run_scan

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture()
def no_proxy(monkeypatch):
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


@pytest.fixture()
def vault(no_proxy):
    handle, _port = start_server()
    try:
        yield handle
    finally:
        handle.shutdown()


# -- registry -------------------------------------------------------------------


def test_registry_resolves_every_engine():
    assert available_engines() == ["deterministic", "llm", "mock"]
    for name in available_engines():
        engine = get_engine(name)
        assert engine.name == name


def test_unknown_engine_name_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="unknown engine"):
        run_scan(
            "http://127.0.0.1:1/",
            engine_name="does-not-exist",
            scope=localhost_scope(),
            state_dir=tmp_path / "state",
        )
    # Validation happens before any ledger write.
    assert not (tmp_path / "state" / "ledger.db").exists()


# -- end-to-end against the live vault -------------------------------------------


def test_run_scan_end_to_end_against_vault(vault, tmp_path):
    state_dir = tmp_path / "state"
    summary = run_scan(vault.url, scope=localhost_scope(), state_dir=state_dir)

    assert summary.run_id.startswith("R-")
    assert summary.status == "completed"
    assert summary.engine == "deterministic"
    assert summary.target == vault.url
    assert summary.verified >= 7
    assert summary.findings, "expected findings against PracticeVault"
    for finding in summary.findings:
        assert len(finding.evidence_ids) >= 1, finding.key
        assert all(evidence_id.startswith("EV-") for evidence_id in finding.evidence_ids)
        assert finding.run_id == summary.run_id
    assert summary.stats["requests"] > 0
    assert "elapsed_ms" in summary.stats

    ledger = Ledger(state_dir / "ledger.db")
    try:
        report = ledger.verify_chain(summary.run_id)
        assert report.ok, report.details
        kinds = [event.kind_value() for event in ledger.events(summary.run_id)]
        assert "run_started" in kinds
        assert "run_ended" in kinds
        assert "finding_created" in kinds
        stored = ledger.findings(summary.run_id)
        assert {f.id for f in stored} == {f.id for f in summary.findings}
        assert sum(1 for f in stored if f.status.value == "verified") == summary.verified
    finally:
        ledger.close()


# -- offline engines ---------------------------------------------------------------


def test_run_scan_mock_engine_binds_note_evidence(tmp_path):
    summary = run_scan(
        "http://127.0.0.1:1/",
        engine_name="mock",
        scope=localhost_scope(),
        state_dir=tmp_path / "state",
    )
    assert summary.status == "completed"
    assert len(summary.findings) == 1
    finding = summary.findings[0]
    assert finding.key == "mock|GET|/mock|-"
    assert finding.evidence_ids
    assert summary.stats["requests"] == 0

    ledger = Ledger(tmp_path / "state" / "ledger.db")
    try:
        rows = {row["id"]: row for row in ledger.evidence(summary.run_id)}
        bound_kinds = {rows[eid]["kind"] for eid in finding.evidence_ids}
        assert "note" in bound_kinds
        # MockEngine.replay returns True -> the pipeline ladder promotes the
        # candidate to VERIFIED with the replay evidence bound on top.
        assert finding.status.value == "verified"
        assert summary.verified == 1
        assert summary.candidates == 0
        assert ledger.verify_chain(summary.run_id).ok
    finally:
        ledger.close()


def test_run_scan_llm_engine_fails_gracefully(tmp_path):
    """LLMEngine.run raises the v0.2 RuntimeError by design; the pipeline
    must convert that into a failed run, never a crash."""
    summary = run_scan(
        "http://127.0.0.1:1/",
        engine_name="llm",
        scope=localhost_scope(),
        state_dir=tmp_path / "state",
    )
    assert summary.status == "failed"
    assert summary.findings == []
    assert summary.verified == 0
    assert summary.candidates == 0

    ledger = Ledger(tmp_path / "state" / "ledger.db")
    try:
        assert ledger.verify_chain(summary.run_id).ok
        kinds = [event.kind_value() for event in ledger.events(summary.run_id)]
        assert "error" in kinds
        assert "run_ended" in kinds
        assert ledger.runs()[0]["status"] == "failed"
    finally:
        ledger.close()


# -- canonical phase machine wiring (v0.3) -----------------------------------------

CANONICAL_PHASES = ("score", "recon", "classify", "hunting", "verify", "report", "retro")


def _gate_closes(ledger: Ledger, run_id: str, phase: str):
    return [
        event
        for event in ledger.events(run_id)
        if event.kind_value() == "phase_ended"
        and event.payload.get("phase") == phase
        and isinstance(event.payload.get("gate"), dict)
    ]


def test_run_scan_all_seven_phases_and_gates_green(vault, tmp_path):
    state_dir = tmp_path / "state"
    summary = run_scan(vault.url, scope=localhost_scope(), state_dir=state_dir)
    assert summary.status == "completed"
    assert summary.stats["gates_failed"] == 0
    assert summary.stats["coverage_rows"] == 0

    assert [snapshot.phase for snapshot in summary.phases] == list(CANONICAL_PHASES)
    assert all(snapshot.state == "done" and snapshot.gate_passed is True for snapshot in summary.phases)
    assert summary.phase_line.startswith("score ✓")
    assert "retro ✓" in summary.phase_line
    assert summary.report_markdown.startswith("# HunterOs Report")

    ledger = Ledger(state_dir / "ledger.db")
    try:
        events = ledger.events(summary.run_id)
        seqs = [event.seq for event in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
        previous_close_seq = -1
        for phase in CANONICAL_PHASES:
            starts = [
                event
                for event in events
                if event.kind_value() == "phase_started" and event.payload.get("phase") == phase
            ]
            closes = _gate_closes(ledger, summary.run_id, phase)
            assert starts and closes, phase
            assert closes[0].payload["gate"]["passed"] is True, phase
            assert starts[0].seq < closes[0].seq
            assert previous_close_seq < starts[0].seq, "phases must open in rank order"
            previous_close_seq = closes[0].seq
        # engine-sourced classification with the full PROBE_TIERS lane map
        classifications = [e for e in events if e.kind_value() == "classification_recorded"]
        assert len(classifications) == 1
        assert classifications[0].payload["source"] == "engine"
        lanes = {row["lane"] for row in classifications[0].payload["classes"]}
        assert lanes == {"passive", "active"}
        # the recorded report digest covers exactly the text the pipeline rendered
        rendered = [e for e in events if e.kind_value() == "report_rendered"]
        assert len(rendered) == 1
        assert rendered[0].payload["sha256"] == sha256_hex(summary.report_markdown)
        assert rendered[0].payload["chars"] == len(summary.report_markdown)
        assert ledger.verify_chain(summary.run_id).ok
    finally:
        ledger.close()


def test_run_demo_still_nine_of_nine(tmp_path, no_proxy):
    result = run_demo(state_dir=tmp_path / "demo-state")
    total = len(result.matched) + len(result.missing)
    assert total == 9
    assert len(result.matched) == 9
    assert result.first_blood is True
    assert result.summary.status == "completed"
    assert result.summary.stats["gates_failed"] == 0


def test_second_render_appends_event_and_retro_appendix(vault, tmp_path):
    state_dir = tmp_path / "state"
    summary = run_scan(vault.url, scope=localhost_scope(), state_dir=state_dir)
    ledger = Ledger(state_dir / "ledger.db")
    try:
        run_id = summary.run_id
        first = [e for e in ledger.events(run_id) if e.kind_value() == "report_rendered"]
        assert len(first) == 1
        # the pipeline's digest covers the pre-retro text; a fresh render now
        # includes the retro appendix recorded after it
        assert "## Retro" not in summary.report_markdown
        text = render_markdown(ledger, run_id)
        assert "## Retro" in text
        mark_report_rendered(ledger, run_id, fmt="markdown", sha256=sha256_hex(text), chars=len(text))
        events = [e for e in ledger.events(run_id) if e.kind_value() == "report_rendered"]
        assert len(events) == 2
        assert events[-1].payload["sha256"] == sha256_hex(text)
        assert events[-1].payload["chars"] == len(text)
        # a re-render over an unchanged ledger is byte-identical (deterministic view)
        assert render_markdown(ledger, run_id) == render_markdown(ledger, run_id)
        assert ledger.verify_chain(run_id).ok
    finally:
        ledger.close()


def test_mock_run_completes_with_recon_gate_honestly_failed(tmp_path):
    state_dir = tmp_path / "state"
    summary = run_scan(
        "http://127.0.0.1:1/", engine_name="mock", scope=localhost_scope(), state_dir=state_dir
    )
    assert summary.status == "completed"
    assert summary.stats["gates_failed"] == 1
    snapshots = {snapshot.phase: snapshot for snapshot in summary.phases}
    assert snapshots["recon"].state == "failed" and snapshots["recon"].gate_passed is False
    for phase in ("score", "classify", "hunting", "verify", "report", "retro"):
        assert snapshots[phase].state == "done", phase
    assert "recon ✗" in summary.phase_line

    ledger = Ledger(state_dir / "ledger.db")
    try:
        events = ledger.events(summary.run_id)
        classifications = [e for e in events if e.kind_value() == "classification_recorded"]
        assert classifications
        check_ids = [row["check_id"] for row in classifications[0].payload["classes"]]
        assert "mock" in check_ids  # classified from the candidate keys
        assert ledger.verify_chain(summary.run_id).ok
    finally:
        ledger.close()


def test_llm_no_provider_run_aborts_cleanly(tmp_path):
    state_dir = tmp_path / "state"
    summary = run_scan(
        "http://127.0.0.1:1/", engine_name="llm", scope=localhost_scope(), state_dir=state_dir
    )
    assert summary.status == "failed"

    ledger = Ledger(state_dir / "ledger.db")
    try:
        run_id = summary.run_id
        events = ledger.events(run_id)
        kinds = [event.kind_value() for event in events]
        assert "run_started" in kinds and "run_ended" in kinds and "error" in kinds
        aborted = [
            event
            for event in events
            if event.kind_value() == "phase_ended" and event.payload.get("aborted") is True
        ]
        assert aborted and aborted[0].payload["phase"] == "recon"
        seqs = [event.seq for event in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
        assert ledger.verify_chain(run_id).ok
        assert ledger.runs()[0]["status"] == "failed"
    finally:
        ledger.close()
