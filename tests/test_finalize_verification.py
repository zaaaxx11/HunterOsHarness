"""Tests for HuntLoop._finalize_verification — stop-time sweep.

Requirement: when the loop stops (time-expiry, budget, goals, max-cycles,
idle), ALL remaining unverified findings must be resolved, not just the ones
the per-round L1 pass happened to see. A stop must never leave findings
as 'unverified' or any anchored+high finding without its deep-dive.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from hunter.workflow.loop import HuntLoop
from hunter.workflow.state import HuntState

REPO_FILE = "mod.py"
REPO_LINE = 1
REPO_TEXT = "SQL injection: db.exec('SELECT ... ' + user)"


def _provider():
    return SimpleNamespace(complete=lambda *a, **k: "", complete_with_tools=lambda *a, **k: "")


def test_finalize_verifies_all_unverified(tmp_path: Path):
    (tmp_path / REPO_FILE).write_text(REPO_TEXT + "\n", encoding="utf-8")

    state = HuntState(target=str(tmp_path))
    state.findings = [
        {"id": "A", "title": "anchored high", "severity": "high",
         "file": REPO_FILE, "line": REPO_LINE, "status": "unverified"},
        {"id": "B", "title": "no anchor", "severity": "high",
         "status": "unverified"},
        {"id": "C", "title": "missing file", "severity": "high",
         "file": "src/does_not_exist.py", "line": 1, "status": "unverified"},
    ]

    loop = HuntLoop(_provider(), verify_claim=None,
                    target=str(tmp_path), workdir=tmp_path)
    loop.state = state
    loop._finalize_verification()

    by_id = {f["id"]: f for f in state.findings}
    assert by_id["A"]["l1"]["status"] == "anchored"
    assert by_id["A"]["status"] == "in_code"
    assert by_id["C"]["l1"]["status"] == "refuted"
    assert by_id["C"]["status"] == "refuted"
    assert "B" in by_id
    assert by_id["A"].get("deep_dived") is True


def test_finalize_leaves_already_resolved(tmp_path: Path):
    state = HuntState(target=str(tmp_path))
    state.findings = [
        {"id": "X", "title": "t", "severity": "low",
         "status": "verified", "deep_dived": True}
    ]
    loop = HuntLoop(_provider(), verify_claim=None,
                    target=str(tmp_path), workdir=tmp_path)
    loop.state = state
    loop._finalize_verification()
    assert state.findings[0]["status"] == "verified"