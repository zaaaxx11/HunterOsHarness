"""Auto-extract: slither evidence → create findings → debunk verify.

Runs AFTER the agent loop finishes. The LLM agent can describe
vulnerabilities but cannot construct create_finding_request() with 15+
parameters. This module bridges that gap.

Flow:
  scan_ledger() → read slither evidence → parse detectors
  → auto_create_findings() → create Finding objects → save to ledger
  → auto_debunk() → debunk_pass on every CANDIDATE → VERIFIED / RULED_OUT
  → (optional) chain_review() → LLM-powered chain analysis
"""

from __future__ import annotations

import json
from typing import Any

from hunter.kernel.findings import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# 1. Scan ledger for slither evidence
# ---------------------------------------------------------------------------

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
        payload = ev.get("payload", {})
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
                        "_evidence_id": ev.get("id", ""),
                        "_run_id": run_id,
                    })

    # 2. Also scan evidence table for local_read entries with detector data
    if not detectors:
        try:
            rows = ledger.evidence(run_id)
        except Exception:
            rows = []
        for ev in rows:
            data = ev.get("data", {})
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    continue
            if isinstance(data, dict) and "detectors" in data:
                for d in data.get("detectors", []):
                    if isinstance(d, dict):
                        detectors.append({
                            **d,
                            "_evidence_id": ev.get("id", ""),
                            "_run_id": run_id,
                        })

    return detectors


# ---------------------------------------------------------------------------
# 2. Auto-create findings from detectors
# ---------------------------------------------------------------------------

def auto_create_findings(
    ledger,
    run_id: str,
    detectors: list[dict[str, Any]],
    *,
    max_findings: int = 0,  # 0 = unlimited
) -> list[Finding]:
    """Create CANDIDATE findings from every detector. No filtering.

    Every detector becomes a finding. Low-confidence, low-impact — all of
    them. The chain builder needs low vulns as potential chain keys.
    debunk_pass sorts real from noise afterwards.
    """
    created: list[Finding] = []
    for detector in detectors:
        if max_findings and len(created) >= max_findings:
            break

        check = detector.get("check", "unknown")
        impact_val = detector.get("impact", "Medium")
        confidence_val = detector.get("confidence", "Medium")
        description = detector.get("description", "")[:500]
        evidence_id = detector.get("_evidence_id", "")

        # Map impact to severity
        severity_map = {"High": "high", "Medium": "medium", "Low": "low",
                         "Informational": "info", "Optimization": "info"}
        severity = Severity(severity_map.get(impact_val, "medium"))

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
            description=(
                f"Slither detector: {check}\n"
                f"Impact: {impact_val}\n"
                f"Confidence: {confidence_val}\n\n"
                f"{description}"
            ),
            impact=f"Auto-extracted from slither. Impact: {impact_val}. Confidence: {confidence_val}.",
            remediation="Review the detected pattern in source code.",
            status=FindingStatus.CANDIDATE,
            evidence_ids=(evidence_id,) if evidence_id else (),
            klass=check,
            falsifier="",
            action_class="read",
            surface=None,
            poc_path=None,
            logs_path=None,
        )

        try:
            created_finding = ledger.create_finding(finding)
            created.append(created_finding)
        except Exception:
            # Duplicate key or gate blocked — skip silently
            pass

    return created


# ---------------------------------------------------------------------------
# 3. Auto-debunk: verify or rule out every CANDIDATE
# ---------------------------------------------------------------------------

def auto_debunk(
    ledger,
    tool_ctx,
    run_id: str,
) -> dict[str, int]:
    """Run debunk_pass on every CANDIDATE finding. Returns counts."""
    from hunter.agent.debunk import debunk_pass

    verified = 0
    ruled_out = 0

    try:
        findings = list(ledger.findings(run_id))
    except Exception:
        return {"verified": 0, "ruled_out": 0, "error": 1}

    for finding in findings:
        if finding.status is not FindingStatus.CANDIDATE:
            continue
        try:
            result = debunk_pass(finding, tool_ctx)
            if result == "verified":
                verified += 1
            elif result == "ruled_out":
                ruled_out += 1
        except Exception:
            pass

    return {"verified": verified, "ruled_out": ruled_out, "total": len(findings)}


# ---------------------------------------------------------------------------
# 4. Extract + create + debunk — one call
# ---------------------------------------------------------------------------

def run_auto_extract(
    ledger,
    tool_ctx,
    run_id: str,
    *,
    max_findings: int = 0,
) -> dict[str, Any]:
    """Full auto-extract pipeline. Returns summary dict."""
    detectors = scan_slither_evidence(ledger, run_id)
    if not detectors:
        return {"detectors": 0, "created": 0, "verified": 0, "ruled_out": 0,
                "status": "no_slither_evidence"}

    created = auto_create_findings(ledger, run_id, detectors, max_findings=max_findings)
    debunk_result = auto_debunk(ledger, tool_ctx, run_id)

    return {
        "detectors": len(detectors),
        "created": len(created),
        "verified": debunk_result.get("verified", 0),
        "ruled_out": debunk_result.get("ruled_out", 0),
        "status": "ok",
    }