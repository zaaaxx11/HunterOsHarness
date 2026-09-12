"""Demo/bench comparator — run the harness against PracticeVault and score it.

PracticeVault plants EXACTLY nine documented vulnerabilities
(``answer_key.json`` in the vault package). :func:`run_demo` starts the vault
on loopback, runs a full :func:`hunter.workflow.pipeline.run_scan`, then
compares the findings in the ledger against the answer key by dedupe key.
The comparison is ledger-only: whatever the pipeline failed to persist
simply counts as missing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hunter.kernel.ledger import Ledger
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server
from hunter.workflow.pipeline import _ledger_db_path, run_scan

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.workflow.pipeline import RunSummary

__all__ = ["DemoResult", "compare_run_to_key", "run_demo"]

# "First blood" = at least 7 of the 9 planted vulnerabilities found.
FIRST_BLOOD_MIN_HITS = 7


@dataclass
class DemoResult:
    """Outcome of one demo run against PracticeVault."""

    run_id: str
    summary: RunSummary
    server_port: int
    matched: list[str]  # answer keys found
    missing: list[str]  # answer keys not found
    extra: list[str]  # findings whose key is not in the answer key
    recall: float  # len(matched) / len(answer_key)
    first_blood: bool  # recall >= 7/len(answer_key)
    summary_line: str  # one human line, e.g. "FIRST BLOOD: 9/9 (100%) — verified 9, candidates 0"


def default_answer_key_path() -> Path:
    """Locate ``answer_key.json`` whether running from the workspace or an
    installed wheel (the file ships as package data inside hunter.vault)."""
    try:
        traversable = resources.files("hunter.vault").joinpath("answer_key.json")
        with resources.as_file(traversable) as path:
            return Path(path)
    except (ModuleNotFoundError, FileNotFoundError, NotADirectoryError):
        return Path(__file__).resolve().parents[1] / "vault" / "answer_key.json"


def compare_run_to_key(ledger: Ledger, run_id: str, answer_key_path: str | Path) -> dict[str, Any]:
    """Score the findings of ``run_id`` against the answer key, by dedupe key.

    Returns ``{"matched": [...], "missing": [...], "extra": [...], "recall": float}``
    where recall is ``len(matched) / len(answer_key)`` (1.0 for an empty key).
    """
    entries = json.loads(Path(answer_key_path).read_text(encoding="utf-8"))
    expected = [str(entry["key"]) for entry in entries]
    found = {finding.key for finding in ledger.findings(run_id)}
    matched = [key for key in expected if key in found]
    missing = [key for key in expected if key not in found]
    extra = sorted(found - set(expected))
    recall = (len(matched) / len(expected)) if expected else 1.0
    return {"matched": matched, "missing": missing, "extra": extra, "recall": recall}


def run_demo(
    *, state_dir: str | Path | None = None, port: int = 0, engine_name: str = "deterministic"
) -> DemoResult:
    """Start PracticeVault on loopback, scan it, and score against the key.

    The vault is always shut down (try/finally), including when the scan
    fails; a failed scan scores as zero findings.
    """
    handle, actual_port = start_server("127.0.0.1", port)
    try:
        summary = run_scan(
            f"http://127.0.0.1:{actual_port}/",
            engine_name=engine_name,
            scope=localhost_scope(),
            state_dir=state_dir,
        )
    finally:
        handle.shutdown()

    ledger = Ledger(_ledger_db_path(state_dir))
    try:
        comparison = compare_run_to_key(ledger, summary.run_id, default_answer_key_path())
    finally:
        ledger.close()

    total = len(comparison["matched"]) + len(comparison["missing"])
    first_blood = summary.status == "completed" and total > 0 and (
        comparison["recall"] >= FIRST_BLOOD_MIN_HITS / total
    )
    tag = "FIRST BLOOD" if first_blood else "NO FIRST BLOOD"
    summary_line = (
        f"{tag}: {len(comparison['matched'])}/{total} ({comparison['recall']:.0%}) — "
        f"verified {summary.verified}, candidates {summary.candidates}"
    )
    return DemoResult(
        run_id=summary.run_id,
        summary=summary,
        server_port=actual_port,
        matched=list(comparison["matched"]),
        missing=list(comparison["missing"]),
        extra=list(comparison["extra"]),
        recall=comparison["recall"],
        first_blood=first_blood,
        summary_line=summary_line,
    )
