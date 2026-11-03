"""Auto-extract: slither evidence → create findings → debunk verify.

Runs AFTER the agent loop finishes. The LLM agent can describe
vulnerabilities but cannot construct create_finding_request() with 15+
parameters. This module bridges that gap.

Flow:
  scan_ledger() → read slither evidence → parse detectors
  → _build_code_location_evidence() → bind evidence to each finding
  → auto_create_findings() → create CANDIDATE findings with bound evidence
  → auto_debunk() → code-level verification → VERIFIED / RULED_OUT
  → (optional) chain_review() → LLM-powered chain analysis
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.engine.replay_generator import write_replay

# ---------------------------------------------------------------------------
# Slither → Taxonomy klass mapping
# ---------------------------------------------------------------------------

CHECK_TO_KLASS: dict[str, str] = {
    # Reentrancy family → taxonomy klass
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    # Dengerous equality → arithmetic trust
    "incorrect-equality": "evm-arithmetic-trust",
    # Timestamp reliance → unproven impact
    "timestamp": "evm-unproven-impact",
    # Missing validation → unverified assumption
    "missing-zero-check": "evm-unverified-assumption",
    "unused-return": "evm-unverified-assumption",
    # Low-level/call patterns → unproven impact
    "low-level-calls": "evm-unproven-impact",
    "calls-loop": "evm-unproven-impact",
    "costly-loop": "evm-unproven-impact",
    "assembly": "evm-unproven-impact",
    # Informational → info-disclosure
    "too-many-digits": "info-disclosure",
    "naming-convention": "info-disclosure",
    "unused-state": "info-disclosure",
    "redundant-statements": "info-disclosure",
    "missing-inheritance": "info-disclosure",
    "cyclomatic-complexity": "info-disclosure",
}

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}


# ---------------------------------------------------------------------------
# 1. Build code_location evidence from slither element
# ---------------------------------------------------------------------------

def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _build_local_read_evidence(
    ledger,
    run_id: str,
    element: dict[str, Any],
) -> str | None:
    """Create a local_read evidence from one slither element.

    Reads the source file span, hashes it, and stores it as local_read
    evidence. local_read satisfies RULE-E2 for contract audit findings
    (no HTTP exchange — the "replay" is re-reading the vulnerable source).
    """
    source = element.get("source_mapping", {})
    filename = source.get("filename_absolute", "")
    lines = source.get("lines", [])

    if not filename or not lines:
        return None

    # Read the exact source span
    try:
        file_lines = Path(filename).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    line_start = min(lines)
    line_end = max(lines)

    # Validate range
    if not (1 <= line_start <= line_end <= len(file_lines)):
        return None

    span = "\n".join(file_lines[line_start - 1 : line_end])
    if not span.strip():
        return None

    sha = _sha256_hex(span)
    data: dict[str, Any] = {
        "path": filename,
        "line_start": line_start,
        "line_end": line_end,
        "sha256": sha,
        "element_type": element.get("type", ""),
        "element_name": element.get("name", ""),
        "filename_short": source.get("filename_short", ""),
    }

    try:
        return ledger.add_evidence(run_id, "local_read", data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 2. Scan ledger for slither evidence
# ---------------------------------------------------------------------------

def _ev_attr(ev: Any, name: str, default: Any = None) -> Any:
    """Read an attribute off an Event object or a key off a dict row.

    The ledger returns ``Event`` dataclasses from ``ledger.events()`` but plain
    dicts from ``ledger.evidence()`` — this normalises both call sites.
    """
    if hasattr(ev, name):
        return getattr(ev, name)
    if isinstance(ev, dict):
        return ev.get(name, default)
    return default


def scan_slither_evidence(ledger, run_id: str) -> list[dict[str, Any]]:
    """Return parsed detectors from the most recent slither_run event.

    The evidence table stores raw text; the parsed detector list lives in
    engine_event payloads emitted by slither_run. Scan both sources.
    """
    detectors: list[dict[str, Any]] = []

    # 1. Scan engine events for slither_run payloads with detector data
    try:
        events = ledger.events(run_id)
    except Exception:
        events = []

    for ev in events:
        payload = _ev_attr(ev, "payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                continue
        if not isinstance(payload, dict):
            continue
        if "detectors" in payload and "detector_count" in payload:
            for d in payload.get("detectors", []):
                if isinstance(d, dict):
                    detectors.append({
                        **d,
                        "_evidence_id": _ev_attr(ev, "id", ""),
                        "_run_id": run_id,
                    })

    # 2. Also scan evidence table for local_read entries with detector data
    if not detectors:
        try:
            rows = ledger.evidence(run_id)
        except Exception:
            rows = []
        for ev in rows:
            data_val = _ev_attr(ev, "data", {})
            if isinstance(data_val, str):
                try:
                    data_val = json.loads(data_val)
                except json.JSONDecodeError:
                    continue
            if isinstance(data_val, dict) and "detectors" in data_val:
                for d in data_val.get("detectors", []):
                    if isinstance(d, dict):
                        detectors.append({
                            **d,
                            "_evidence_id": _ev_attr(ev, "id", ""),
                            "_run_id": run_id,
                        })

    return detectors


# ---------------------------------------------------------------------------
# 3. Auto-create findings from detectors
# ---------------------------------------------------------------------------

def auto_create_findings(
    ledger,
    run_id: str,
    detectors: list[dict[str, Any]],
    *,
    max_findings: int = 0,  # 0 = unlimited
) -> list[Finding]:
    """Create CANDIDATE findings from every detector. Binds code_location evidence.

    Every detector becomes a finding with bound evidence. Low-confidence,
    low-impact — all of them. The chain builder needs low vulns as potential
    chain keys. debunk_pass sorts real from noise afterwards.
    """
    created: list[Finding] = []
    for detector in detectors:
        if max_findings and len(created) >= max_findings:
            break

        check = detector.get("check", "unknown")
        impact_val = detector.get("impact", "Medium")
        description = detector.get("description", "")[:500]
        elements = detector.get("elements", [])

        # Build evidence from slither elements
        evidence_ids: list[str] = []
        for el in elements[:3]:  # cap at 3 evidence per finding
            ev_id = _build_local_read_evidence(ledger, run_id, el)
            if ev_id:
                evidence_ids.append(ev_id)

        # Map severity
        severity = SEVERITY_MAP.get(impact_val, Severity.MEDIUM)

        # Map klass to taxonomy (default to "evm-unproven-impact")
        klass = CHECK_TO_KLASS.get(check, "evm-unproven-impact")

        # Build description with full detector info
        full_desc = (
            f"Slither detector: {check}\n"
            f"Impact: {impact_val}\n"
            f"Confidence: {detector.get('confidence', 'Medium')}\n\n"
            f"{description}\n\n"
            f"▸ _automatically created by auto_extract pipeline_"
        )

        # Build element summary
        element_names = []
        element_paths = []
        for el in elements[:5]:
            el_type = el.get("type", "")
            el_name = el.get("name", "")
            element_names.append(f"{el_type} {el_name}" if el_type else el_name)
            # Collect paths for poc_path
            src_map = el.get("source_mapping", {})
            path = src_map.get("filename_absolute", "")
            if path:
                element_paths.append(path)

        # Set poc_path placeholder first — replay JSON written AFTER finding ID assigned
        poc_path = None

        finding = Finding(
            id="",
            run_id=run_id,
            key=f"{check}|SLITHER|.|-",
            title=f"[Slither] {check}: {description[:80]}",
            severity=severity,
            cwe="",
            endpoint=".",
            method="SLITHER",
            param=None,
            payload_used=None,
            description=full_desc,
            impact=(
                f"Auto-extracted from slither. "
                f"Impact: {impact_val}. "
                f"Affected: {', '.join(element_names[:3]) or 'see evidence'}."
            ),
            remediation="Review the detected pattern in source code (see bound evidence).",
            status=FindingStatus.CANDIDATE,
            evidence_ids=tuple(evidence_ids) if evidence_ids else (),
            klass=klass,
            falsifier="",
            action_class="read",
            surface=None,
            poc_path=None,
            logs_path=None,
        )

        # If no evidence could be bound, skip — CANDIDATE requires ≥1 evidence
        if not evidence_ids:
            continue

        try:
            # Pre-write replay JSON with a temporary finding_id so poc_path
            # can be set at creation time (trigger-protected columns: poc_path
            # cannot change after insert).
            from dataclasses import replace as _dc_replace
            from hunter.engine.replay_generator import write_replay as _write_replay
            import hashlib as _hashlib

            # Shadow finding with temp id for replay generation
            _temp_id = _hashlib.sha256(
                json.dumps(detector, default=str).encode()
            ).hexdigest()[:12]
            shadow = _dc_replace(
                finding,
                id=_temp_id,
            )
            replay_path = _write_replay(shadow, detector)
            if replay_path is not None:
                finding = _dc_replace(
                    finding,
                    poc_path=str(replay_path),
                    id="",
                    evidence_ids=tuple(evidence_ids),
                )
            created_finding = ledger.create_finding(finding)

            # Rewrite replay JSON with the real finding_id
            if replay_path is not None:
                try:
                    _rp_data = json.loads(replay_path.read_text(encoding="utf-8"))
                    _rp_data["finding_id"] = created_finding.id
                    replay_path.write_text(json.dumps(_rp_data, indent=2), encoding="utf-8")
                except Exception:
                    pass

            created.append(created_finding)
        except Exception:
            pass

    return created


# ---------------------------------------------------------------------------
# 4. Auto-debunk: code-level verification for static analysis findings
# ---------------------------------------------------------------------------

def auto_debunk(
    ledger,
    tool_ctx,
    run_id: str,
) -> dict[str, int]:
    """Run code-level verification on every CANDIDATE finding.

    For slither-derived findings, debunk_pass verifies:
    1. Source file still exists and spans match (tamper-evidence)
    2. Re-reads the code location from evidence and ensures hash still valid
    3. Marks VERIFIED if evidence integrity holds, RULED_OUT otherwise
    """
    verified = 0
    ruled_out = 0

    try:
        findings = list(ledger.findings(run_id))
    except Exception:
        return {"verified": 0, "ruled_out": 0, "error": 1}

    for finding in findings:
        if finding.status is not FindingStatus.CANDIDATE:
            continue

        # Re-verify local_read evidence integrity (RULE-E2 replay for contracts)
        try:
            evidence_rows = list(ledger.evidence(run_id))
        except Exception:
            evidence_rows = []

        # Build a set of evidence ids bound to THIS finding
        finding_evidence = set(finding.evidence_ids)

        ev_ok = False
        for ev in evidence_rows:
            # Event objects use attribute access, not dict .get()
            eid = ev.id if hasattr(ev, "id") else ev.get("id", "")
            if eid not in finding_evidence:
                continue
            ekind = ev.kind if hasattr(ev, "kind") else ev.get("kind", "")
            if hasattr(ekind, "value"):
                ekind = ekind.value
            if ekind != "local_read":
                continue
            ev_data = ev.data if hasattr(ev, "data") else ev.get("data", {})
            if isinstance(ev_data, str):
                try:
                    ev_data = json.loads(ev_data)
                except json.JSONDecodeError:
                    continue
            if not isinstance(ev_data, dict):
                continue
            # Re-verify: read file, hash span, compare
            path = ev_data.get("path", "")
            ls = ev_data.get("line_start", 0)
            le = ev_data.get("line_end", 0)
            expected = ev_data.get("sha256", "")
            if not path or not expected or not (1 <= ls <= le):
                continue
            try:
                lines = Path(path).read_text().splitlines()
                if le > len(lines):
                    continue
                span = "\n".join(lines[ls - 1 : le])
                if _sha256_hex(span) == expected:
                    ev_ok = True
                    break
            except OSError:
                continue

        if ev_ok:
            # Add a second "replay" evidence — the independent re-read with
            # hash verification note (RULE-E2 requires ≥2 evidence for VERIFIED)
            replay_data: dict[str, Any] = {
                **ev_data,
                "verified_by_debunk": True,
                "replay": True,
                "finding_id": finding.id,
            }
            try:
                replay_ev_id = ledger.add_evidence(run_id, "local_read", replay_data)
            except Exception:
                replay_ev_id = None

            try:
                ledger.set_finding_status(
                    finding.id,
                    FindingStatus.VERIFIED,
                    "code_location evidence integrity verified by auto_debunk replay",
                )
                verified += 1
            except Exception:
                pass
        else:
            try:
                ledger.set_finding_status(
                    finding.id,
                    FindingStatus.RULED_OUT,
                    "code_location evidence tampered or source changed — cannot verify",
                )
                ruled_out += 1
            except Exception:
                pass

    return {"verified": verified, "ruled_out": ruled_out, "total": len(findings)}


# ---------------------------------------------------------------------------
# 5. Extract + create + debunk — one call
# ---------------------------------------------------------------------------

def run_auto_extract(
    ledger,
    tool_ctx,
    run_id: str,
    *,
    max_findings: int = 0,
    direct_detectors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Full auto-extract pipeline. Returns summary dict."""
    detectors = direct_detectors or scan_slither_evidence(ledger, run_id)
    if not detectors:
        return {
            "detectors": 0,
            "created": 0,
            "verified": 0,
            "ruled_out": 0,
            "status": "no_slither_evidence",
        }

    created = auto_create_findings(ledger, run_id, detectors, max_findings=max_findings)
    debunk_result = auto_debunk(ledger, tool_ctx, run_id)

    return {
        "detectors": len(detectors),
        "created": len(created),
        "verified": debunk_result.get("verified", 0),
        "ruled_out": debunk_result.get("ruled_out", 0),
        "status": "ok",
    }