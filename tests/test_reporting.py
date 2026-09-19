"""Reporting tests: Markdown + SARIF rendered from a real demo run, and the
tamper-evidence refusal (a rewritten ledger must block the report).
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from hunter.kernel.events import canonical_json
from hunter.kernel.ledger import Ledger
from hunter.reporting.markdown import ReportBlocked, render_markdown
from hunter.reporting.sarif import to_sarif, write_sarif
from hunter.workflow.bench import compare_run_to_key, run_demo

SRC_ANSWER_KEY = Path(__file__).resolve().parents[1] / "src" / "hunter" / "vault" / "answer_key.json"
LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    """One full demo run (vault + scan + compare), shared by this module."""
    state_dir = tmp_path_factory.mktemp("demo-state")
    saved = {var: os.environ.get(var) for var in (*PROXY_ENV_VARS, "NO_PROXY")}
    for var in PROXY_ENV_VARS:
        os.environ.pop(var, None)
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    try:
        result = run_demo(state_dir=state_dir)
    finally:
        for var, value in saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value
    ledger = Ledger(state_dir / "ledger.db")
    try:
        yield result, ledger, state_dir
    finally:
        ledger.close()


# -- DemoResult / comparator ------------------------------------------------------


def test_demo_result_shape_and_first_blood(demo):
    result, _ledger, _state_dir = demo
    assert result.run_id.startswith("R-")
    assert result.server_port > 0
    assert result.summary.status == "completed"
    total = len(result.matched) + len(result.missing)
    assert result.recall == pytest.approx(len(result.matched) / total)
    assert result.first_blood is True
    assert result.summary_line.startswith("FIRST BLOOD")
    assert str(len(result.matched)) in result.summary_line
    assert f"verified {result.summary.verified}" in result.summary_line
    assert isinstance(result.extra, list)


def test_compare_run_to_key_full_recall(demo):
    result, ledger, _state_dir = demo
    assert len(json.loads(SRC_ANSWER_KEY.read_text(encoding="utf-8"))) == 9
    comparison = compare_run_to_key(ledger, result.run_id, SRC_ANSWER_KEY)
    assert set(comparison) == {"matched", "missing", "extra", "recall"}
    assert comparison["recall"] >= 0.77, (
        f"matched {len(comparison['matched'])}/9; missing: {comparison['missing']}; "
        f"extra: {comparison['extra']}"
    )
    # run_demo's DemoResult must agree with a direct compare_run_to_key call.
    assert result.recall == comparison["recall"]
    assert sorted(result.matched) == sorted(comparison["matched"])
    assert result.missing == comparison["missing"]
    assert result.extra == comparison["extra"]


# -- markdown -------------------------------------------------------------------


def test_render_markdown_from_ledger_only(demo):
    result, ledger, _state_dir = demo
    markdown = render_markdown(ledger, result.run_id)
    assert markdown.startswith("# HunterOs Report")
    assert result.run_id in markdown
    assert "Chain verification: OK" in markdown
    for finding in result.summary.findings:
        assert finding.title in markdown
        assert f"## {finding.id} — " in markdown
        assert finding.severity.value in markdown
    evidence_rows = ledger.evidence(result.run_id)
    assert evidence_rows
    assert evidence_rows[0]["sha256"][:12] in markdown  # sha256 fragments rendered
    assert "Rendered from ledger" in markdown


# -- sarif ------------------------------------------------------------------------


def test_to_sarif_round_trip_rules_and_levels(demo):
    result, ledger, _state_dir = demo
    sarif = json.loads(json.dumps(to_sarif(ledger, result.run_id)))  # JSON round-trip
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "HunterOs"
    findings = ledger.findings(result.run_id)
    assert len(run["results"]) == len(findings)
    assert {rule["id"] for rule in driver["rules"]} == {f.key for f in findings}
    for sarif_result in run["results"]:
        severity = sarif_result["properties"]["severity"]
        assert sarif_result["level"] == LEVEL_BY_SEVERITY[severity]
        assert sarif_result["message"]["text"]
        location = sarif_result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"].startswith("/")
        assert {"cwe", "status", "severity", "findingId", "evidenceIds", "replayVerified"} <= set(
            sarif_result["properties"]
        )


def test_write_sarif_pretty_json(tmp_path, demo):
    result, ledger, _state_dir = demo
    out = tmp_path / "nested" / "report.sarif"
    assert write_sarif(ledger, result.run_id, out) == out
    text = out.read_text(encoding="utf-8")
    assert "\n  \"" in text  # pretty-printed
    assert json.loads(text)["version"] == "2.1.0"


# -- tamper-evidence ---------------------------------------------------------------


def test_tampered_ledger_blocks_markdown(demo, tmp_path):
    result, _ledger, state_dir = demo
    # Snapshot the demo ledger (WAL-safe) into a tamperable copy.
    copy_dir = tmp_path / "tampered"
    copy_dir.mkdir()
    copy_db = copy_dir / "ledger.db"
    src_con = sqlite3.connect(str(state_dir / "ledger.db"))
    try:
        dst_con = sqlite3.connect(str(copy_db))
        try:
            src_con.backup(dst_con)
        finally:
            dst_con.close()
    finally:
        src_con.close()

    tampered = Ledger(copy_db)
    try:
        # Sanity: the untampered snapshot still renders.
        assert "Chain verification: OK" in render_markdown(tampered, result.run_id)

        # An attacker with raw disk access drops the trigger and rewrites one
        # event payload of the demo run.
        con = sqlite3.connect(str(copy_db))
        try:
            con.execute("DROP TRIGGER IF EXISTS events_no_update")
            seq, payload = con.execute(
                "SELECT seq, payload FROM events WHERE run_id = ? ORDER BY seq LIMIT 1",
                (result.run_id,),
            ).fetchone()
            data = json.loads(payload)
            data["attacker"] = "rewritten history"
            con.execute("UPDATE events SET payload = ? WHERE seq = ?", (canonical_json(data), seq))
            con.commit()
        finally:
            con.close()

        with pytest.raises(ReportBlocked):
            render_markdown(tampered, result.run_id)
    finally:
        tampered.close()
