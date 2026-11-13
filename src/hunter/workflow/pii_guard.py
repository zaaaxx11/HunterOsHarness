"""The hard stop that a prompt cannot be trusted to remember.

Scope policies routinely say "cease testing the moment you encounter user
data". Left in the prompt, that rule survives exactly as long as the model's
attention. This module makes it deterministic: every byte headed for the LLM or
the ledger is scanned first, and a match aborts the run.

Deliberately narrow patterns. A false positive costs one aborted hunt; a false
negative costs a policy violation on a live production target.
"""
from __future__ import annotations

import re

PII_PATTERNS: list[tuple[str, str]] = [
    # Labelled government identifiers FIRST — a 16-digit Indonesian NIK would
    # otherwise be swallowed by the bare card rule and misreported as a card
    # number, which also mis-files the stop reason in the report.
    (r"\b(?:nik|no\.?\s*ktp)\b\s*[:=]?\s*\d{16}", "nik-labeled"),
    (r"\b(?:ktp|KTP)\b.{0,20}\d{16}", "gov-id-labeled"),
    (r"\b\d{16}\s*\|?\s*[A-Z][a-z]+", "nik-row"),    # NIK then a name
    # Payment cards
    (r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b", "card-grouped"),
    (r"\b3[47]\d{13}\b", "amex-15"),
    (r"\b\d{16}\b", "card-16"),                      # PAN with no separators
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn-like"),          # NNN-NN-NNNN
    # Health
    (r"\b\d{2}/\d{2}/19\d{2}\b.{0,60}\b(?:blood|golongan darah)\b", "medical"),
    # Contact
    (r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "email"),
    (r"\+62\s?\d{2,3}[- ]?\d{3,4}[- ]?\d{3,4}", "phone-id"),
]


class PIITriggered(Exception):
    """Raised the instant real-user-data-shaped content is seen."""

    def __init__(self, kind: str, excerpt: str) -> None:
        self.kind = kind
        self.excerpt = excerpt[:200]
        super().__init__(f"PII circuit breaker: {kind}")


def scan(text: str) -> None:
    """Raise :class:`PIITriggered` on the first match. Otherwise return None."""
    if not text or not isinstance(text, str):
        return
    for pattern, kind in PII_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            raise PIITriggered(kind, match.group(0))


def scrub(text: str) -> str:
    """Replace matches with a marker — how a STOP may be logged safely."""
    out = text
    for pattern, kind in PII_PATTERNS:
        out = re.sub(pattern, f"[REDACTED:{kind}]", out, flags=re.IGNORECASE)
    return out
