"""Workflow pipeline tests: run_scan end-to-end against PracticeVault, plus
registry and engine-wiring behavior (mock, unknown name, shipped-dark llm).
"""

from __future__ import annotations

import pytest

from hunter.kernel.ledger import Ledger
from hunter.tools.registry import available_engines, get_engine
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server
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
