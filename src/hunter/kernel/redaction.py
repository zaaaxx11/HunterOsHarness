"""Secret redaction — RULE-E3 of the claim gate.

Evidence payloads are scrubbed of credential shapes before they enter the
ledger. Redaction happens at ``ledger.add_evidence`` so no caller can bypass
it. Patterns are deliberately broad (defense over precision): when in doubt,
redact.
"""

from __future__ import annotations

import re

# Token shapes: (name, pattern). Applied to every string leaf of evidence data.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("api-key", re.compile(r"(?i)(sk|xoxb|xoxp|ghp|gho|glpat-)[A-Za-z0-9_\-]{16,}")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
    # Authorization headers carry credentials in unguessable shapes (Basic,
    # Digest, custom schemes) — redact everything after the colon, that line.
    ("auth-header", re.compile(r"(?i)authorization\s*:\s*\S.*")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("password-field", re.compile(r"(?i)(password|passwd|pwd)(\s*[=:]\s*)\S+")),
    ("token-field", re.compile(r"(?i)(token|secret|api[-_]?key|session)(\s*[=:]\s*)\S+")),
)

_REDACTED = "[REDACTED]"


def redact_text(text: str) -> str:
    """Redact credential shapes from a single string."""
    result = text
    for _name, pattern in _PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


def redact_payload(obj):
    """Deep-redact every string leaf of a JSON-able structure. Returns a copy."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_payload(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_payload(v) for v in obj]
    return obj
