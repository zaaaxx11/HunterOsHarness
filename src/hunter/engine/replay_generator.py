"""Replay Generator — build JSON PoC scripts from slither detectors.

Each detector gets a structured replay JSON that documents:
- Target contract/function/file/lines
- Vulnerability pattern classification
- Reproduction steps with code snippets
- Forge test stub (for critical findings)
- Verification metadata

These JSON files serve as `poc_path` for ClaimGate RULE-E2,
replacing raw source-file references with reproducible evidence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunter.kernel.findings import Finding

# ---------------------------------------------------------------------------
# Path config
# ---------------------------------------------------------------------------

POC_DIR = Path("poc")
TARGET_REPO = Path("/home/simon/relay-settlement/smart-contracts")


def _poc_path_for(finding: Finding) -> Path:
    """Deterministic PoC path: poc/<check>-<safe_title>-<finding.id>.json"""
    safe = finding.title[:60].replace(" ", "_").replace("/", "_").replace(":", "_")
    return POC_DIR / f"{finding.key.split('|')[0]}-{finding.id}-{safe}.json"


# ---------------------------------------------------------------------------
# Replay JSON builder — template per check_id
# ---------------------------------------------------------------------------

def _build_common(finding: Finding, detector: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    """Common base structure shared by all replay templates."""
    # Extract source info from first element
    first_el = elements[0] if elements else {}
    src = first_el.get("source_mapping", {})
    
    # Derive contract name from parent info
    parent = first_el.get("type_specific_fields", {}).get("parent", {})
    contract = parent.get("name", "Unknown")
    
    return {
        "replay_version": "1.0",
        "finding_id": finding.id,
        "check_id": finding.key.split("|")[0],
        "taxonomy_klass": finding.klass,
        "target": {
            "contract": contract,
            "function": first_el.get("name", "?"),
            "type": first_el.get("type", "?"),
            "file": src.get("filename_short", ""),
            "absolute_path": src.get("filename_absolute", ""),
            "lines": src.get("lines", []),
        },
        "elements_count": len(elements),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "auto_extract.replay_generator",
    }


def _build_reentrancy(finding: Finding, detector: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    """Template for reentrancy-no-eth, reentrancy-benign, reentrancy-events."""
    data = _build_common(finding, detector, elements)
    desc = detector.get("description", "")

    # Parse the reentrancy description for external call + state write
    external_calls: list[str] = []
    state_writes: list[str] = []
    for line in desc.split("\n"):
        line = line.strip()
        if "External calls:" in line:
            continue
        if "State variables written" in line:
            continue
        if line.startswith("\t- "):
            if "State variables" not in desc or desc.index(line) < desc.index("State variables written") if "State variables written" in desc else True:
                external_calls.append(line[2:].strip())
            else:
                state_writes.append(line[2:].strip())

    # Find cross-function reentrancy targets
    cross_funcs: list[str] = []
    for el in elements[1:]:
        name = el.get("name", "")
        if name:
            cross_funcs.append(name)

    # Collect all affected source files for PoC code
    all_files: list[str] = []
    for el in elements:
        f = el.get("source_mapping", {}).get("filename_short", "")
        if f and f not in all_files:
            all_files.append(f)

    data.update({
        "vulnerability_pattern": {
            "type": "reentrancy",
            "subtype": finding.key.split("|")[0],
            "description": desc[:500],
            "external_calls": external_calls[:5],
            "state_writes": state_writes[:5],
            "cross_function_reentrancy": len(cross_funcs) > 1,
            "vulnerable_functions": cross_funcs[:8],
        },
        "reproduction_steps": [
            {
                "step": 1,
                "action": f"Deploy {data['target']['contract']} with controlled dependencies",
                "code": f"// Caller deploys {data['target']['contract']} normally"
            },
            {
                "step": 2,
                "action": "Trigger external call path",
                "code": f"// Invoke {data['target']['function']} — this makes external call"
            },
            {
                "step": 3,
                "action": "During external call, re-enter vulnerable function",
                "code": f"// External contract calls back into {data['target']['contract']}"
            },
            {
                "step": 4,
                "action": "Observe state corruption — state written AFTER external call returns",
                "code": "// Assert: state variable updated twice, or under-collateralized"
            },
        ],
        "poc_test": {
            "language": "solidity",
            "framework": "forge",
            "test_contract": f"Reentrancy{data['target']['contract']}Replay",
            "test_function": f"testReentrancyIn{data['target']['function']}",
            "note": "See reproduction_steps above for test structure. Forge PoC not auto-generated — must be written manually with a mock reentrant caller.",
        },
        "affected_files": all_files,
        "evidence_hashes": [e.get("sha256", "") for e in detector.get("elements", [])],
    })
    return data


def _build_arithmetic(finding: Finding, detector: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    """Template for incorrect-equality / dangerous comparisons."""
    data = _build_common(finding, detector, elements)
    desc = detector.get("description", "")

    # Parse strict equalities
    comparisons: list[str] = []
    for line in desc.split("\n"):
        if "==" in line or "!=" in line:
            comparisons.append(line.strip("- ").strip())

    data.update({
        "vulnerability_pattern": {
            "type": "arithmetic_trust",
            "subtype": "strict_equality",
            "description": desc[:500],
            "dangerous_comparisons": comparisons[:10],
        },
        "reproduction_steps": [
            {
                "step": 1,
                "action": "Identify the strict equality condition",
                "code": comparisons[0] if comparisons else "// See description"
            },
            {
                "step": 2,
                "action": "Determine edge case that makes equality fail silently",
                "code": "// E.g. amount == 0 bypassed by manipulating token decimals"
            },
            {
                "step": 3,
                "action": "Verify no revert on bypass — logic skipped, not halted",
                "code": "// Assert: function continues despite violated assumption"
            },
        ],
        "poc_test": {
            "language": "solidity",
            "framework": "forge",
            "note": "Test edge case input that bypasses strict equality check",
        },
        "evidence_hashes": [e.get("sha256", "") for e in detector.get("elements", [])],
    })
    return data


def _build_unverified(finding: Finding, detector: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    """Template for missing-zero-check, unused-return, other unverified assumptions."""
    data = _build_common(finding, detector, elements)
    desc = detector.get("description", "")

    # Derive what's missing
    issue = "missing validation"
    if "unused-return" in finding.key.split("|")[0]:
        issue = "ignored return value"
    elif "zero-check" in finding.key.split("|")[0]:
        issue = "missing zero-address validation"

    data.update({
        "vulnerability_pattern": {
            "type": "unverified_assumption",
            "subtype": issue.replace(" ", "_"),
            "description": desc[:500],
        },
        "reproduction_steps": [
            {
                "step": 1,
                "action": f"Trigger function with invalid input (zero address / malicious return)",
                "code": f"// Call {data['target']['function']} with address(0)"
            },
            {
                "step": 2,
                "action": "Verify no revert — function proceeds with invalid state",
                "code": "// Assert: no revert, state overwritten with garbage"
            },
        ],
        "poc_test": {
            "language": "solidity",
            "framework": "forge",
            "note": "Test with address(0) or check return value handling",
        },
        "evidence_hashes": [e.get("sha256", "") for e in detector.get("elements", [])],
    })
    return data


def _build_unproven(finding: Finding, detector: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    """Template for timestamp, calls-in-loop, low-level-calls, assembly, costly-loop."""
    data = _build_common(finding, detector, elements)
    desc = detector.get("description", "")
    
    subtype = finding.key.split("|")[0]

    data.update({
        "vulnerability_pattern": {
            "type": "unproven_impact",
            "subtype": subtype,
            "description": desc[:500],
        },
        "reproduction_steps": [
            {
                "step": 1,
                "action": "Identify the gas/DoS/timing concern",
                "code": f"// {subtype} detected — review impact in context of MEV/DoS"
            },
            {
                "step": 2,
                "action": "Assess whether pattern is exploitable or structural",
                "code": "// Structural patterns (e.g. multicall in loop) may be intentional"
            },
        ],
        "poc_test": {
            "language": "forge",
            "framework": "forge",
            "note": "Manual review required — structural pattern, not necessarily exploitable",
        },
        "evidence_hashes": [e.get("sha256", "") for e in detector.get("elements", [])],
    })
    return data


def _build_info(finding: Finding, detector: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    """Template for informational — naming-convention, unused-state, etc."""
    data = _build_common(finding, detector, elements)
    desc = detector.get("description", "")

    data.update({
        "vulnerability_pattern": {
            "type": "information",
            "subtype": finding.key.split("|")[0],
            "description": desc[:500],
            "exploitable": False,
        },
        "reproduction_steps": [
            {
                "step": 1,
                "action": "Verify the informational pattern exists",
                "code": "// Read source — confirm pattern"
            },
        ],
        "poc_test": {
            "language": "n/a",
            "framework": "n/a",
            "note": "Informational — no exploitation path. Documented for completeness.",
            "verdict": "NO_EXPLOIT",
        },
        "evidence_hashes": [e.get("sha256", "") for e in detector.get("elements", [])],
    })
    return data


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

TEMPLATES: dict[str, callable] = {
    "reentrancy-no-eth": _build_reentrancy,
    "reentrancy-benign": _build_reentrancy,
    "reentrancy-events": _build_reentrancy,
    "incorrect-equality": _build_arithmetic,
    "missing-zero-check": _build_unverified,
    "unused-return": _build_unverified,
    "timestamp": _build_unproven,
    "calls-loop": _build_unproven,
    "low-level-calls": _build_unproven,
    "assembly": _build_unproven,
    "costly-loop": _build_unproven,
    "cyclomatic-complexity": _build_unproven,
    "too-many-digits": _build_info,
    "naming-convention": _build_info,
    "unused-state": _build_info,
    "redundant-statements": _build_info,
    "missing-inheritance": _build_info,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_replay(finding: Finding, detector: dict[str, Any]) -> dict[str, Any] | None:
    """Generate a replay JSON for one finding + detector. Returns dict or None."""
    check = finding.key.split("|")[0]
    builder = TEMPLATES.get(check)
    if builder is None:
        return None

    elements = detector.get("elements", [])
    return builder(finding, detector, elements)


def write_replay(finding: Finding, detector: dict[str, Any]) -> Path | None:
    """Generate replay JSON and write to poc/ directory. Returns Path or None."""
    replay = generate_replay(finding, detector)
    if replay is None:
        return None

    poc_path = _poc_path_for(finding)
    poc_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        poc_path.write_text(json.dumps(replay, indent=2), encoding="utf-8")
        return poc_path
    except OSError:
        return None


def generate_and_write_all(
    ledger,
    run_id: str,
    detectors: list[dict[str, Any]],
) -> dict[str, Path | None]:
    """Generate replay JSONs for all findings in a run. Returns {finding_id: poc_path}."""
    from hunter.engine.auto_extract import auto_create_findings

    findings = auto_create_findings(ledger, run_id, detectors)

    result: dict[str, Path | None] = {}
    for finding, detector in zip(findings, detectors):
        poc_path = write_replay(finding, detector)
        result[finding.id] = poc_path

    return result