"""SARIF 2.1.0 renderer — ledger-only, tamper-evident.

Emits findings of a run as a SARIF 2.1.0 log (the de-facto exchange format
for static/scan results) straight from the ledger rows. Like every renderer
in this package it reads ONLY persisted state; it never re-interprets or
embellishes findings. And like the markdown renderer it REFUSES to render
from a ledger whose hash chain fails verification (:class:`ReportBlocked`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hunter import __version__
from hunter.kernel.findings import SEVERITY_ORDER, FindingStatus
from hunter.reporting.markdown import ReportBlocked

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.kernel.ledger import Ledger

__all__ = ["ReportBlocked", "to_sarif", "write_sarif"]

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# critical/high -> error, medium -> warning, low/info -> note
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _level(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "note")


def to_sarif(ledger: Ledger, run_id: str) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log dict for the findings of ``run_id``.

    Like the markdown renderer, this refuses a ledger whose hash chain fails
    verification (:class:`ReportBlocked`) — tamper-evidence over convenience.

    Rules are the distinct finding dedupe keys; results carry severity-mapped
    levels, the physical location (endpoint + method/param) and a properties
    bag (cwe, status, severity, findingId, evidenceIds, replayVerified).

    Raises:
        ReportBlocked: when ``ledger.verify_chain(run_id)`` fails.
        KeyError: when the run does not exist in the ledger.
    """
    chain = ledger.verify_chain(run_id)
    if not chain.ok:
        details = "; ".join(chain.details) or "no detail recorded"
        raise ReportBlocked(
            f"BLOCKED: hash chain verification FAILED for run {run_id!r} "
            f"(broken at seq {chain.broken_at_seq}): {details}. "
            "The ledger may have been tampered with — no SARIF log is rendered."
        )
    if not any(row["run_id"] == run_id for row in ledger.runs()):
        raise KeyError(f"run {run_id!r} not found in the ledger")
    findings = sorted(
        ledger.findings(run_id),
        key=lambda f: (-SEVERITY_ORDER[f.severity.value], f.id),
    )
    rules: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for finding in findings:
        if finding.key in seen_keys:
            continue
        seen_keys.add(finding.key)
        rules.append(
            {
                "id": finding.key,
                "name": finding.key.split("|", 1)[0],
                "shortDescription": {"text": finding.title},
            }
        )
    results = []
    for finding in findings:
        location_text = f"{finding.method} {finding.endpoint}"
        if finding.param is not None:
            location_text += f" (param: {finding.param})"
        results.append(
            {
                "ruleId": finding.key,
                "level": _level(finding.severity.value),
                "message": {"text": finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.endpoint,
                                "description": {"text": location_text},
                            }
                        }
                    }
                ],
                "properties": {
                    "cwe": finding.cwe,
                    "status": finding.status.value,
                    "severity": finding.severity.value,
                    "findingId": finding.id,
                    "evidenceIds": list(finding.evidence_ids),
                    "replayVerified": finding.status is FindingStatus.VERIFIED,
                },
            }
        )
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HunterOs",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(ledger: Ledger, run_id: str, path: str | Path) -> Path:
    """Write the SARIF log for ``run_id`` as pretty JSON; returns the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(to_sarif(ledger, run_id), indent=2, ensure_ascii=False)
    target.write_text(payload + "\n", encoding="utf-8")
    return target
