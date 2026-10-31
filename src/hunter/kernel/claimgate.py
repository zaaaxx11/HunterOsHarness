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
- RULE-E5 (v0.7): klass must belong to the taxonomy (or ``unknown``).
"""

from __future__ import annotations

from .findings import Finding, FindingStatus


class ClaimGateBlocked(PermissionError):
    """Raised when a claim lacks the evidence the ledger requires. Fail-closed."""


def _taxonomy_ids() -> set[str]:
    try:
        from hunter.taxonomy import load_klasses
        from hunter.taxonomy import validate_klass as _vk  # noqa: F401

        return set(load_klasses().keys()) | {"unknown"}
    except Exception:
        return {"unknown"}


def validate_klass(klass: str) -> None:
    """RULE-E5. Raise ClaimGateBlocked when klass is not in the taxonomy."""
    if klass not in _taxonomy_ids():
        raise ClaimGateBlocked(
            f"BLOCKED: klass {klass!r} is not in the taxonomy (RULE-E5)."
        )


def validate_finding_insert(finding: Finding, evidence_count: int) -> None:
    """RULE-E1. Raise ClaimGateBlocked when a finding cannot be inserted."""
    # Theoretical findings are hypotheses, not claims: 0 evidence is legal.
    if finding.status != FindingStatus.THEORETICAL and evidence_count < 1:
        raise ClaimGateBlocked(
            f"BLOCKED: finding '{finding.key}' has no bound evidence — "
            "evidence or nothing (RULE-E1)."
        )
    if not finding.title.strip():
        raise ClaimGateBlocked("BLOCKED: finding title is empty (RULE-E1).")
    # RULE-E5: klass must be valid (always, including theoretical).
    validate_klass(finding.klass)


def validate_status_change(
    finding: Finding, new_status: FindingStatus, evidence_count: int
) -> None:
    """RULE-E2/E4/E1 (v0.7 theoretical promotion). Validate a status transition."""
    new_status = (
        new_status if isinstance(new_status, FindingStatus) else FindingStatus(new_status)
    )
    if new_status == FindingStatus.VERIFIED and evidence_count < 2:
        raise ClaimGateBlocked(
            f"BLOCKED: finding '{finding.id}' cannot be VERIFIED with "
            f"{evidence_count} evidence artifact(s); an independent replay "
            "evidence is required (RULE-E2)."
        )
    # Theoretical -> candidate requires at least one bound evidence (RULE-E1).
    if (
        finding.status == FindingStatus.THEORETICAL
        and new_status == FindingStatus.CANDIDATE
        and evidence_count < 1
    ):
        raise ClaimGateBlocked(
            f"BLOCKED: finding '{finding.id}' cannot be promoted from "
            "THEORETICAL to CANDIDATE without evidence (RULE-E1)."
        )
    # Theoretical can never jump straight to verified.
    if finding.status == FindingStatus.THEORETICAL and new_status == FindingStatus.VERIFIED:
        raise ClaimGateBlocked(
            f"BLOCKED: finding '{finding.id}' cannot jump from THEORETICAL to "
            "VERIFIED; promote to CANDIDATE first (RULE-E1)."
        )
