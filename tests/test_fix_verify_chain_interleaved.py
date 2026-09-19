"""RED: Ledger Bug-2 — verify_chain(run_id) false positive on interleaved runs.

Global chain: seq1 A1 -> seq2 B1 -> seq3 A2 -> seq4 B2.
The global chain is intact, but the current ``verify_chain(run_id)``
requires per-run contiguity (prev_hash == previous *filtered* hash), so
per-run verification reports BROKEN and ``render_markdown`` raises
``ReportBlocked`` for perfectly healthy interleaved runs.

Expected (fixed) behavior:
- global ``verify_chain()`` ok,
- per-run ``verify_chain(run_id)`` ok for both runs,
- ``render_markdown`` succeeds for both runs (no ReportBlocked).

These tests FAIL now (per-run ok is False, markdown raises) and must
PASS after the fix.
"""

from __future__ import annotations

import pytest

from hunter.kernel.events import EventKind
from hunter.kernel.ledger import Ledger
from hunter.reporting.markdown import ReportBlocked, render_markdown


@pytest.fixture()
def led(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        yield ledger
    finally:
        ledger.close()


def _seed_interleaved(ledger: Ledger) -> tuple[str, str]:
    ledger.create_run("RA", "http://127.0.0.1:9000", "deterministic", "scope-a")
    ledger.create_run("RB", "http://127.0.0.1:9001", "deterministic", "scope-b")
    # Interleaved global order: seq1 RA, seq2 RB, seq3 RA, seq4 RB.
    ledger.append("RA", EventKind.PROBE_RESULT, {"n": "A1"})
    ledger.append("RB", EventKind.PROBE_RESULT, {"n": "B1"})
    ledger.append("RA", EventKind.PROBE_RESULT, {"n": "A2"})
    ledger.append("RB", EventKind.PROBE_RESULT, {"n": "B2"})
    return "RA", "RB"


def test_interleaved_global_chain_ok(led):
    ra, rb = _seed_interleaved(led)
    report = led.verify_chain()
    assert report.ok is True
    assert report.checked == 4
    assert report.broken_at_seq is None


def test_interleaved_per_run_chain_ok(led):
    _seed_interleaved(led)
    for run_id in ("RA", "RB"):
        report = led.verify_chain(run_id=run_id)
        assert report.ok is True, f"per-run {run_id} falsely BROKEN: {report.details}"
        assert report.checked == 2
        assert report.broken_at_seq is None


def test_interleaved_render_markdown_succeeds(led):
    _seed_interleaved(led)
    for run_id in ("RA", "RB"):
        try:
            text = render_markdown(led, run_id)
        except ReportBlocked as exc:
            pytest.fail(f"render_markdown({run_id}) falsely blocked: {exc}")
        assert "Chain verification: OK" in text
        assert run_id in text
