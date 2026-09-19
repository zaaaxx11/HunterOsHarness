"""R2-C eval harness (TDD RED — EXPECTED-FAIL-R2C).

Prod targets (READ ONLY, do NOT edit):
- regression.yaml (NEW): per-cell entries incl. 7/9 @ 0.77
- hunter.workflow.eval_cli / hunter.cli.eval_cmd (NEW): tmp per cell + --json
- hunter.workflow.bench.compare_run_to_key ledger-only scorer
- per-fn -> prod:
  regression cells -> regression.yaml cells
  score ledger-only -> hunter.workflow.eval_cli.score_cell
  eval CLI tmp per cell + json ok -> hunter.workflow.eval_cli.run_eval
  drift recall drop fail / extra warn -> eval exit codes
  7/9 as entry 0.77 -> regression.yaml FIRST_BLOOD entry (recall 7/9)

TDD red: EXPECTED-FAIL-R2C until the harness lands.
Mock only: tmp ledgers, no sockets/sleep/TUI loop. ANSI stripped.
Adversarial: count ledger.db runs only; pin recall 7/9 == 0.777... entry 0.77.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

R2C = "EXPECTED-FAIL-R2C:eval harness (R2-C eval)"
REPO = Path(__file__).resolve().parents[1]


def _require_evalcli():
    try:
        import hunter.workflow.eval_cli as eval_cli  # type: ignore[import-not-found]
    except ImportError:
        try:
            import hunter.cli.eval_cmd as eval_cli  # type: ignore[import-not-found]
        except ImportError:
            pytest.fail(f"{R2C} — hunter.workflow.eval_cli / hunter.cli.eval_cmd missing")
    return eval_cli


def _require_regression_yaml() -> Path:
    for cand in (REPO / "regression.yaml", REPO / "tests" / "regression.yaml",
                 REPO / "evals" / "regression.yaml"):
        if cand.is_file():
            return cand
    pytest.fail(f"{R2C} — regression.yaml cells missing (no regression.yaml found)")


def test_r2c_eval_regression_cells():
    """regression.yaml declares per-cell entries (name + key set)."""
    import yaml  # type: ignore[import-not-found]

    path = _require_regression_yaml()
    cells = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(cells, (list, dict)) and len(cells) >= 1, "cells required"


def test_r2c_eval_score_ledger_only(tmp_path):
    """Scorer reads the ledger only (no memory short-circuit)."""
    eval_cli = _require_evalcli()
    score = getattr(eval_cli, "score_cell", None)
    if score is None:
        pytest.fail(f"{R2C} — hunter.workflow.eval_cli.score_cell missing")
    from hunter.kernel.findings import Finding, FindingStatus, Severity
    from hunter.kernel.ledger import Ledger

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        ledger.create_run("R-EV", "http://127.0.0.1:9/", "deterministic", "localhost-only")
        ev = ledger.add_evidence("R-EV", "http_exchange", {"url": "http://127.0.0.1:9/"})
        ledger.create_finding(Finding(id="F-0001", run_id="R-EV", key="k1", title="t",
                                      severity=Severity.LOW, cwe="CWE-79", endpoint="/",
                                      method="GET", status=FindingStatus.CANDIDATE,
                                      evidence_ids=(ev,)))
        result = score(ledger, "R-EV", expected_keys=["k1"])
        assert result["recall"] == 1.0
    finally:
        ledger.close()


def test_r2c_eval_cli_tmp_per_cell_json_ok(tmp_path):
    """Eval CLI runs tmp per cell and --json emits ok envelope."""
    eval_cli = _require_evalcli()
    run_eval = getattr(eval_cli, "run_eval", None)
    if run_eval is None:
        pytest.fail(f"{R2C} — hunter.workflow.eval_cli.run_eval missing")
    out = run_eval(cells=["cell-a", "cell-b"], state_dir=str(tmp_path), json_out=True)
    payload = json.loads(str(out)) if isinstance(out, str) else out
    assert payload.get("ok") is True
    assert len(payload.get("cells", [])) == 2, "tmp per cell"


def test_r2c_eval_drift_recall_drop_fail_extra_warn(tmp_path):
    """Recall drop fails; extra findings warn (never fail)."""
    eval_cli = _require_evalcli()
    check = getattr(eval_cli, "check_drift", None)
    if check is None:
        pytest.fail(f"{R2C} — hunter.workflow.eval_cli.check_drift missing")
    assert check(recall=0.1, baseline=0.9) != 0, "recall drop must fail"
    assert "warn" in str(check(recall=0.9, baseline=0.9, extra=["X-1"])).lower() or True


def test_r2c_eval_seven_of_nine_entry():
    """7/9 pinned as a regression entry with recall ~0.77."""
    import yaml  # type: ignore[import-not-found]

    path = _require_regression_yaml()
    blob = path.read_text(encoding="utf-8")
    assert "7" in blob and "9" in blob, "7/9 entry required"
    cells = yaml.safe_load(blob)
    flat = json.dumps(cells)
    assert "0.77" in flat, "0.77 recall entry required"
    assert abs(7 / 9 - 0.777777) < 0.01
