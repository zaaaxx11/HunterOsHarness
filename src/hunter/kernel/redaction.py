"""Secret redaction — RULE-E3 of the claim gate.

Evidence payloads are scrubbed of credential shapes before they enter the
ledger. Redaction happens at ``ledger.add_evidence`` so no caller can bypass
it. Patterns are deliberately broad (defense over precision): when in doubt,
redact.
"""

from __future__ import annotations

import re

# Token shapes: (name, pattern). Applied to every string leaf of evidence data.
#
# The prefix list is not decoration: each entry is a credential family whose
# tokens were observed leaking through the earlier, shorter list. A pattern
# that only covers the prefixes we happened to think of is a redaction that
# fails exactly when a new provider shows up — and evidence is committed to a
# ledger that an open-source project publishes. When in doubt, redact.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # Provider token prefixes. Matched on the prefix, then any length of
    # token body, so a family is covered even when the body length changes.
    ("api-key", re.compile(
        r"(?i)\b(?:sk|xoxb|xoxp|xoxa|xoxr|ghp|gho|ghu|ghs|ghr|github_pat|glpat-|"
        r"npm_|pypi-|pypi_|SG\.|sk_live|sk_test|rk_live|AIza|shpat_|shppa_|"
        r"dop_v1_|dop_v2_|flwr_|npm_|phc_|pypi-|xapp-|tsv1\.|AC[0-9a-f]{32}|"
        r"SK[0-9a-f]{32}|IS[0-9a-zA-Z_-]{59}|AAAA[0-9a-zA-Z_-]{7}:[0-9a-zA-Z_-]{35})"
        r"[A-Za-z0-9._\-]{8,}"
    )),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
    # Authorization headers carry credentials in unguessable shapes (Basic,
    # Digest, custom schemes) — redact everything after the colon, that line.
    ("auth-header", re.compile(r"(?i)authorization\s*:\s*\S.*")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # A 0x-prefixed 64-hex string is an Ethereum private key. It is also a
    # keccak hash, so this over-redacts on purpose: a hash in evidence is
    # noise, a leaked key is a drained wallet.
    ("eth-private-key", re.compile(r"\b0x[0-9a-fA-F]{64}\b")),
    # A bare 64-hex string is the same key without the prefix.
    ("hex-private-key", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")),
    # A Telegram bot token is <8-10 digits>:<35 chars of [A-Za-z0-9_-]>. The
    # digits-then-colon shape is distinctive enough to match directly; the
    # generic prefix list cannot express it.
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{30,}\b")),
    # A Discord bot token is three base64-ish segments (24.6.27+). Match the
    # shape rather than a fixed length: the last segment is the one that
    # varies between token generations.
    ("discord-token", re.compile(r"\b[MN][A-Za-z\d]{23,}\.[\w-]{5,7}\.[\w-]{20,}\b")),
    ("password-field", re.compile(r"(?i)(password|passwd|pwd)(\s*[=:]\s*)\S+")),
    ("token-field", re.compile(r"(?i)(token|secret|api[-_]?key|session)(\s*[=:]\s*)\S+")),
)

_REDACTED = "[REDACTED]"

# Keys whose VALUE *is* a digest by definition. Redacting these destroys the
# evidence: a code_location's sha256 is what validate_code_location checks
# against the file on disk, and a ledger hash is what verify_chain checks.
# A 64-hex string under one of these names is a checksum, not a leaked key —
# the same string under any other name is still redacted.
#
# Deliberately NOT here: "signature"/"sig". A signature field is as likely to
# hold a signed token as a digest, and a leaked token is worse than a lost
# checksum. Only unambiguous digest names are exempt.
_DIGEST_KEYS = frozenset({
    "sha256", "sha1", "sha512", "md5", "blake2b", "digest", "hash", "checksum",
    "prev_hash", "hash_chain", "tx", "tx_hash", "txhash", "transaction",
    "block_hash", "root", "commit",
})


def _is_digest_key(key: str) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    if normalized in _DIGEST_KEYS:
        return True
    # Plural and suffixed forms: "hashes", "sha256_list", "tx_hashes".
    # Strip the plural "es" before the plain "s" — "hashes" -> "hash", not
    # "hashe", which is why the naive strip missed it.
    singular = normalized
    if singular.endswith("es") and len(singular) > 2:
        singular = singular[:-2]
    elif singular.endswith("s") and len(singular) > 1:
        singular = singular[:-1]
    return (
        singular in _DIGEST_KEYS
        or normalized.endswith("_hash")
        or normalized.endswith("_hashes")
        or normalized.endswith("_digest")
        or normalized.endswith("_digests")
        or normalized.endswith("_checksums")
    )


def redact_text(text: str) -> str:
    """Redact credential shapes from a single string."""
    result = text
    for _name, pattern in _PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


def redact_payload(obj, _key: str = ""):
    """Deep-redact every string leaf of a JSON-able structure. Returns a copy.

    A leaf whose key names a digest is passed through untouched: the value is
    a checksum the claim gate or the hash chain will verify, and redacting it
    turns valid evidence into an unverifiable one.
    """
    if isinstance(obj, str):
        if _key and _is_digest_key(_key):
            return obj
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_payload(v, _key=str(k)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_payload(v, _key=_key) for v in obj]
    return obj
