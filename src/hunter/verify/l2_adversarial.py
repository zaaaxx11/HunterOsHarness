"""Layer 2 - adversarial LLM review.

The model is injected as ``call_llm(system, user) -> str`` so this module works
with or without a network. If no callable is supplied, or it raises, the result
is ``UNREVIEWED`` with confidence 0 - we never invent a verdict.
"""

from __future__ import annotations

import re

VERDICTS = ("VERIFIED", "REFUTED", "UNREVIEWED")

ADVERSARIAL_PROMPT = (
    "You are a ruthless adversarial verifier inside an authorized audit. Your "
    "ONLY job is to DISPROVE the submitted security claim. Assume the claim is "
    "fabricated until the evidence mechanically forces you to accept it.\n"
    "\n"
    "Rules:\n"
    "1. Attack the evidence, not the prose: what does the cited file:line "
    "actually show, does the HTTP transcript really demonstrate the stated "
    "impact, is the described control flow reachable by a real adversary?\n"
    "2. Name the single WEAKEST ASSUMPTION the claim depends on.\n"
    "3. Refute on any of: missing or unverifiable evidence, wrong file:line, "
    "unreachable or unreachable-by-attacker path, absent precondition, or an "
    "effect that is benign / out of scope.\n"
    "4. Answer VERIFIED only if the evidence mechanically proves the claim. "
    "When in doubt, answer REFUTED.\n"
    "\n"
    "Answer with EXACTLY this shape and nothing before it:\n"
    "VERDICT: <VERIFIED|REFUTED>\n"
    "CONFIDENCE: <0-100>\n"
    "REASON: <one paragraph naming the weakest assumption and why>"
)

_VERDICT_LINE_RE = re.compile(r"^\s*VERDICT:\s*(VERIFIED|REFUTED)\b", re.IGNORECASE | re.MULTILINE)
_VERDICT_ANY_RE = re.compile(r"VERDICT:\s*(VERIFIED|REFUTED)\b", re.IGNORECASE)
_CONFIDENCE_RE = re.compile(r"CONFIDENCE:\s*(\d{1,3})", re.IGNORECASE)
_REASON_RE = re.compile(r"REASON:\s*(.+)", re.IGNORECASE | re.DOTALL)


def parse_verdict(text):
    """Parse a model reply into ``{verdict, confidence, reason}``.

    Everything missing degrades conservatively: no VERDICT line -> UNREVIEWED,
    no CONFIDENCE line -> 0, no REASON line -> empty string.
    """
    result = {"verdict": "UNREVIEWED", "confidence": 0, "reason": ""}
    if not isinstance(text, str) or not text.strip():
        result["reason"] = "empty model output"
        return result

    m = _VERDICT_LINE_RE.search(text)
    if not m:
        m = _VERDICT_ANY_RE.search(text)
    if m:
        result["verdict"] = m.group(1).upper()
    else:
        result["reason"] = "no VERDICT line found in model output"

    cm = _CONFIDENCE_RE.search(text)
    if cm:
        try:
            conf = int(cm.group(1))
        except (TypeError, ValueError):
            conf = 0
        result["confidence"] = max(0, min(100, conf))

    rm = _REASON_RE.search(text)
    if rm:
        result["reason"] = rm.group(1).strip()

    return result


def _build_user(claim, evidence_text):
    return (
        "CLAIM TO DISPROVE\n"
        "id: %s\n"
        "title: %s\n"
        "severity: %s\n"
        "evidence_kind: %s\n"
        "declared file: %s\n"
        "declared line: %s\n"
        "description: %s\n"
        "\n"
        "EVIDENCE (raw claim evidence plus deterministically resolved source):\n"
        "%s\n"
    ) % (
        claim.get("id"),
        claim.get("title"),
        claim.get("severity"),
        claim.get("evidence_kind"),
        claim.get("file"),
        claim.get("line"),
        claim.get("description"),
        evidence_text or "(none provided)",
    )


def adversarial_review(claim, evidence_text, call_llm):
    """Run the skeptic. Returns a verdict dict; never raises, never fabricates."""
    if call_llm is None:
        return {
            "verdict": "UNREVIEWED",
            "confidence": 0,
            "reason": "no LLM available (call_llm is None); claim left unreviewed",
        }
    user = _build_user(claim or {}, evidence_text)
    try:
        raw = call_llm(ADVERSARIAL_PROMPT, user)
    except Exception as exc:
        return {
            "verdict": "UNREVIEWED",
            "confidence": 0,
            "reason": "call_llm failed: %s: %s" % (type(exc).__name__, exc),
        }

    parsed = parse_verdict(raw)
    parsed["raw"] = raw if isinstance(raw, str) else repr(raw)
    return parsed
