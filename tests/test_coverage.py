"""Coverage matrix tests."""

from __future__ import annotations

import pytest

from hunter.kernel.findings import Finding, Severity
from hunter.kernel.ledger import Ledger
from hunter.workflow.coverage import CoverageMatrix, coverage_for_run


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
        klass="reflected-xss",
        surface="GET /search",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def _evidence(ledger) -> str:
    return ledger.add_evidence(
        "r1", "http_exchange", {"method": "GET", "url": "http://127.0.0.1:9000/search", "status": 200}
    )


def test_empty_ledger(ledger):
    matrix = CoverageMatrix.from_ledger(ledger)
    assert matrix.cells == {}
    assert matrix.gaps() == []
    assert matrix.to_dict() == {}
    assert matrix.render_text() == ""


def test_candidate_finding_marks_covered(ledger):
    ev = _evidence(ledger)
    finding = _finding(evidence_ids=(ev,))
    created = ledger.create_finding(finding)
    assert created.status.value == "candidate"
    matrix = CoverageMatrix.from_ledger(ledger, run_id="r1")
    assert matrix[("reflected-xss", "GET /search")] == "covered"
    assert ("reflected-xss", "GET /search") not in matrix.gaps()
    assert matrix.to_dict() == {("reflected-xss", "GET /search"): "covered"}


def test_theoretical_finding_marks_needs_follow_up(ledger):
    created = ledger.create_theoretical_finding(_finding())
    assert created.status.value == "theoretical"
    matrix = CoverageMatrix.from_ledger(ledger, "r1")
    assert matrix.cells[("reflected-xss", "GET /search")] == "needs_follow_up"
    assert ("reflected-xss", "GET /search") in matrix.gaps()


def test_coverage_for_run_helper(ledger):
    matrix = coverage_for_run(ledger, "r1")
    assert isinstance(matrix, CoverageMatrix)
    assert matrix.gaps() == []


def test_expected_surfaces_gaps(ledger):
    matrix = CoverageMatrix()
    matrix.expected_surfaces = [("reflected-xss", "GET /missing")]
    assert matrix.gaps() == [("reflected-xss", "GET /missing")]


def test_render_text_lists_klass_rows(ledger):
    ev = _evidence(ledger)
    ledger.create_finding(_finding(evidence_ids=(ev,)))
    matrix = CoverageMatrix.from_ledger(ledger, run_id="r1")
    text = matrix.render_text()
    assert "reflected-xss" in text
    assert "GET /search" in text
    assert "covered" in text
