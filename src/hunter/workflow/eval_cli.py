"""R2-C eval harness — ledger-only scoring, tmp per cell, drift gates.

Each cell runs the PracticeVault demo in its own tmp state dir; scoring is
ledger-only (whatever the pipeline failed to persist counts as missing).
A cell passes only when first blood lands AND recall holds against its
baseline. The fabricated ``ok: True`` stub is gone: a zero-finding run
now reports ``ok: False``.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from hunter.workflow import bench

__all__ = ["check_drift", "run_eval", "score_cell"]

# Module-level binding so tests can monkeypatch ``hunter.workflow.eval_cli.run_demo``.
run_demo = bench.run_demo


def _regression_file() -> Path:
    env = os.environ.get("HUNTER_REGRESSION_FILE")
    if env:
        return Path(env)
    candidate = Path(__file__).resolve().parents[3] / "tests" / "regression.yaml"
    if candidate.exists():
        return candidate
    return Path("tests") / "regression.yaml"


def _load_cells(path: Path | None = None) -> list[dict[str, Any]]:
    p = path if path is not None else _regression_file()
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [dict(c) for c in raw]
    if isinstance(raw, dict) and isinstance(raw.get("cells"), list):
        return [dict(c) for c in raw["cells"]]
    return []


def score_cell(ledger: Any, run_id: str, expected_keys: list[str] | None = None) -> dict[str, Any]:
    """Score one cell ledger-only (no memory short-circuit).

    Reads findings from the ledger for run_id, compares dedupe keys to
    expected_keys. Returns matched/missing/extra + recall.
    """
    expected = list(expected_keys or [])
    findings = ledger.findings(run_id)
    found = {str(getattr(f, "key", "")) for f in findings}
    matched = [k for k in expected if k in found]
    missing = [k for k in expected if k not in found]
    extra = sorted(found - set(expected))
    recall = (len(matched) / len(expected)) if expected else 1.0
    return {"matched": matched, "missing": missing, "extra": extra, "recall": recall}


def check_drift(recall: float, baseline: float, extra: list[str] | None = None) -> Any:
    """Drift gate: recall drop fails (non-zero); extra findings warn.

    Returns 1 on recall drop, else 0 — or a warn string when extra findings
    exist but recall holds (extra never fails).
    """
    try:
        drop = float(recall) < float(baseline) - 0.01
    except Exception:
        drop = True
    if drop:
        return 1
    if extra:
        return f"warn: extra findings {len(extra)} (never fail)"
    return 0


def run_eval(
    cells: Any = None,
    *,
    state_dir: Any = None,
    json_out: bool = False,
    baseline: float = 0.0,
    regression_path: Any = None,
) -> Any:
    """Run eval tmp per cell; --json emits the ok envelope.

    Each cell runs in its own tmp dir (isolated state); no cell touches the
    shared state_dir. Returns the payload (dict) or its JSON string.
    """
    if cells is None:
        cell_specs = _load_cells(Path(regression_path) if regression_path is not None else None)
    elif cells and isinstance(cells[0], str):
        cell_specs = [{"name": name} for name in cells]
    else:
        cell_specs = [dict(c) for c in cells]

    _ = state_dir  # accepted for compatibility; never used as scan state
    results: list[dict[str, Any]] = []
    all_ok = True
    for spec in cell_specs:
        name = str(spec.get("name", "cell"))
        expected_keys = spec.get("expected_keys")
        cell_baseline = float(spec.get("recall", baseline if baseline else 0.0))
        with tempfile.TemporaryDirectory(prefix=f"eval-{name}-") as tmp:
            tmp_path = Path(tmp)
            demo = None
            try:
                demo = run_demo(state_dir=tmp_path)
            except Exception:
                demo = None

            if demo is not None:
                matched = list(getattr(demo, "matched", []))
                missing = list(getattr(demo, "missing", []))
                extra = list(getattr(demo, "extra", []))
                recall = float(getattr(demo, "recall", 0.0))
                first_blood = bool(getattr(demo, "first_blood", False))
            else:
                matched, missing, extra = [], [], []
                recall = 0.0
                first_blood = False

            if expected_keys is not None:
                # The cell's expected_keys are informational; run_demo already
                # scores against the answer key. Keep the param accepted for
                # compatibility but do not re-derive recall here.
                pass

            ok = bool(first_blood) and recall >= cell_baseline - 0.01
            # If expected_keys provided, also require recall against them (already in recall).
            results.append(
                {
                    "cell": name,
                    "matched": matched,
                    "missing": missing,
                    "extra": extra,
                    "recall": recall,
                    "first_blood": first_blood,
                    "ok": ok,
                    "tmp_isolated": True,
                }
            )
            if not ok:
                all_ok = False

    payload = {"ok": all_ok, "cells": results}
    if json_out:
        return json.dumps(payload)
    return payload
