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


def validate_code_location(data) -> None:
    """Re-read the file span and re-hash; refuse on mismatch (tamper-evidence)."""
    from pathlib import Path

    if not isinstance(data, dict):
        raise ClaimGateBlocked("BLOCKED: code_location evidence must be a dict (RULE-E1).")
    path = data.get("path")
    line_start = data.get("line_start")
    line_end = data.get("line_end")
    expected = data.get("sha256")
    # bool is an int subclass — never a line number.
    if (
        not path
        or isinstance(line_start, bool)
        or isinstance(line_end, bool)
        or not isinstance(line_start, int)
        or not isinstance(line_end, int)
        or not expected
        or not isinstance(expected, str)
    ):
        raise ClaimGateBlocked(
            "BLOCKED: code_location requires path/line_start/line_end/sha256 "
            "(line numbers must be ints, sha256 must be a string)."
        )
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ClaimGateBlocked(f"BLOCKED: cannot read code location {path!r}: {exc}") from exc
    # EXACT range, no clamping: start..end must identify the claimed span
    # precisely (a 1..10**9 "span" must not silently verify the whole file).
    if not (1 <= line_start <= line_end <= len(lines)):
        raise ClaimGateBlocked(
            "BLOCKED: code_location line range is invalid "
            f"(file has {len(lines)} lines; requested {line_start}..{line_end})."
        )
    span = "\n".join(lines[line_start - 1 : line_end])
    if not span.strip():
        raise ClaimGateBlocked("BLOCKED: code_location span is empty.")
    expected_hex = expected.strip().lower()
    if len(expected_hex) != 64 or any(c not in "0123456789abcdef" for c in expected_hex):
        raise ClaimGateBlocked("BLOCKED: code_location sha256 is not a lowercase hex digest.")
    import hashlib

    actual = hashlib.sha256(span.encode("utf-8")).hexdigest()
    if actual != expected_hex:
        raise ClaimGateBlocked("BLOCKED: code_location hash mismatch (RULE-E1 tamper-evidence).")
