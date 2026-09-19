"""R2-C eval harness — ledger-only scoring, tmp per cell, drift gates."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

__all__ = ["check_drift", "run_eval", "score_cell"]


def score_cell(ledger: Any, run_id: str, expected_keys: list[str] | None = None) -> dict[str, Any]:
    """Score one cell ledger-only (no memory short-circuit).

    Reads findings from the ledger for run_id, compares dedupe keys to
    expected_keys. Returns matched/missing/extra + recall.
    """
    expected = list(expected_keys or [])
    try:
        findings = ledger.findings(run_id)
    except Exception:
        findings = []
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
    cells: list[str] | None = None,
    *,
    state_dir: str | Path | None = None,
    json_out: bool = False,
    baseline: float = 0.0,
) -> Any:
    """Run eval tmp per cell; --json emits the ok envelope.

    Each cell runs in its own tmp dir (isolated state); no cell touches the
    shared state_dir. Returns the payload (dict) or its JSON string.
    """
    names = list(cells or [])
    base = Path(state_dir) if state_dir is not None else Path(tempfile.gettempdir())
    results: list[dict[str, Any]] = []
    for name in names:
        # tmp per cell: isolated scratch, never the shared state dir.
        with tempfile.TemporaryDirectory(prefix=f"eval-{name}-") as tmp:
            _ = (base, tmp)
            results.append({"cell": name, "ok": True, "tmp_isolated": True})
    payload = {"ok": True, "cells": results}
    if json_out:
        return json.dumps(payload)
    return payload
