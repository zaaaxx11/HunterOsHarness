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
    """Allowed klass ids. FAIL-CLOSED: a taxonomy load failure must not
    silently widen the allow-list.

    Returning ``{"unknown"}`` here turned RULE-E5 into a no-op — the gate would
    happily accept the literal string ``unknown`` for every finding, so a
    forged/invalid klass sailed through exactly when the taxonomy was broken.
    A broken taxonomy is a hard error: raise, so the caller blocks.
    """
    from hunter.taxonomy import load_klasses

    return set(load_klasses().keys()) | {"unknown"}


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
    """Validate a status transition with burden-of-proof per ladder.

    Ladder (ascending burden):
    - THEORETICAL: hypothesis, no proof needed (0 evidence legal)
    - CANDIDATE: proposal (>=1 evidence)
    - VERIFIED: tested proposal + basic PoC (>=2 evidence, poc_path set)
    - PROMOTED: additional proof + "if" conditions documented, retested
               for mainnet (>=2 evidence, logs_path set, adversary survived)
    - PROVEN_LIVE: proof of live execution + logs.txt (poc_path + logs_path set,
                   independent second verification)
    - RULED_OUT: terminal — can come from any status
    """
    new_status = (
        new_status if isinstance(new_status, FindingStatus) else FindingStatus(new_status)
    )

    if new_status == FindingStatus.RULED_OUT:
        return  # always allowed, keeps audit trail

    # --- THEORETICAL rules ---
    if finding.status == FindingStatus.THEORETICAL:
        if new_status == FindingStatus.CANDIDATE and evidence_count < 1:
            raise ClaimGateBlocked(
                f"BLOCKED: THEORETICAL → CANDIDATE requires >=1 evidence "
                f"(proposal must cite what you read)."
            )
        if new_status not in (FindingStatus.CANDIDATE, FindingStatus.RULED_OUT):
            raise ClaimGateBlocked(
                f"BLOCKED: THEORETICAL may only promote to CANDIDATE, not {new_status.value}."
            )

    # --- CANDIDATE → VERIFIED ---
    if finding.status == FindingStatus.CANDIDATE and new_status == FindingStatus.VERIFIED:
        if evidence_count < 2:
            raise ClaimGateBlocked(
                "BLOCKED: CANDIDATE → VERIFIED requires >=2 evidence "
                "(independent re-read + re-verification of the claim)."
            )
        if not finding.poc_path:
            raise ClaimGateBlocked(
                "BLOCKED: CANDIDATE → VERIFIED requires poc_path — "
                "a basic PoC artifact must exist on disk."
            )

    # --- VERIFIED → PROMOTED ---
    if finding.status == FindingStatus.VERIFIED and new_status == FindingStatus.PROMOTED:
        if not finding.logs_path:
            raise ClaimGateBlocked(
                "BLOCKED: VERIFIED → PROMOTED requires logs_path — "
                "a plain-text verification log must exist on disk."
            )
        if not finding.falsifier or not finding.falsifier.strip():
            raise ClaimGateBlocked(
                "BLOCKED: VERIFIED → PROMOTED requires falsifier — "
                "the adversary challenge must be recorded (what COULD disprove this)."
            )
        if not finding.poc_path:
            raise ClaimGateBlocked(
                "BLOCKED: VERIFIED → PROMOTED requires poc_path — "
                "the PoC must have been re-tested for mainnet viability."
            )

    # --- PROMOTED → PROVEN_LIVE ---
    if finding.status == FindingStatus.PROMOTED and new_status == FindingStatus.PROVEN_LIVE:
        if not finding.poc_path or not finding.logs_path:
            raise ClaimGateBlocked(
                "BLOCKED: PROMOTED → PROVEN_LIVE requires poc_path AND logs_path — "
                "proof of live execution + execution log are mandatory."
            )
        if evidence_count < 2:
            raise ClaimGateBlocked(
                "BLOCKED: PROMOTED → PROVEN_LIVE requires >=2 evidence — "
                "the second independent verification must be bound."
            )

    # --- general: no backwards movement except to RULED_OUT ---
    _order = {
        FindingStatus.THEORETICAL: 0,
        FindingStatus.CANDIDATE: 1,
        FindingStatus.VERIFIED: 2,
        FindingStatus.PROMOTED: 3,
        FindingStatus.PROVEN_LIVE: 4,
    }
    if _order.get(new_status, -1) < _order.get(finding.status, -1):
        raise ClaimGateBlocked(
            f"BLOCKED: cannot move backwards from {finding.status.value} to "
            f"{new_status.value}."
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
