"""Claim gate — the enforcement layer that makes unbacked claims impossible.

Doctrine: a finding is a claim; the gate refuses any claim the ledger cannot
back with evidence. This module defines the *rules*; ``ledger`` applies them
at the storage layer so they cannot be bypassed by any caller, including
future LLM agents.

Rules (v0.1):
- RULE-E1: creating a finding requires >= 1 bound evidence artifact.
- RULE-E2: promoting a finding to ``verified`` requires a second, independent
  evidence artifact (a successful replay).
- RULE-E3: evidence payloads are redacted before storage (see ``redaction``);
  raw secrets never enter the ledger.
- RULE-E4: ruled-out findings are never deleted — the audit trail is append-only.
"""

from __future__ import annotations

from .findings import Finding, FindingStatus


class ClaimGateBlocked(PermissionError):
    """Raised when a claim lacks the evidence the ledger requires. Fail-closed."""


def validate_finding_insert(finding: Finding, evidence_count: int) -> None:
    """RULE-E1. Raise ClaimGateBlocked when a finding cannot be inserted."""
    if evidence_count < 1:
        raise ClaimGateBlocked(
            f"BLOCKED: finding '{finding.key}' has no bound evidence — "
            "evidence or nothing (RULE-E1)."
        )
    if not finding.title.strip():
        raise ClaimGateBlocked("BLOCKED: finding title is empty (RULE-E1).")


def validate_status_change(
    finding: Finding, new_status: FindingStatus, evidence_count: int
) -> None:
    """RULE-E2/E4. Validate a status transition on an existing finding."""
    if new_status == FindingStatus.VERIFIED and evidence_count < 2:
        raise ClaimGateBlocked(
            f"BLOCKED: finding '{finding.id}' cannot be VERIFIED with "
            f"{evidence_count} evidence artifact(s); an independent replay "
            "evidence is required (RULE-E2)."
        )
