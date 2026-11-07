"""B_verify - four-layer anti-fabrication verification library.

Contract: a check that cannot be mechanically performed degrades to ``claim``
or ``refuted``. It never upgrades to ``verified`` on the strength of a model
opinion alone, and a missing/unreachable artifact is a failure, not a free
pass.

Layers
------
L1 ``l1_deterministic``  - pure-Python file:line + HTTP shape grounding.
L2 ``l2_adversarial``    - skeptic LLM review (injected ``call_llm``).
L3 ``l3_crossref``       - dedup, contradiction, chain consistency.
L4 ``l4_evidence``       - evidence directory + append-only trail.

``verify_claim(claim, ctx)`` runs L1, then L2 only when L1 is anchored and a
``call_llm`` is supplied, then L3 against the existing corpus, then L4 writes.
It returns the enriched claim (``l1``/``l2``/``l3``/``l4`` + ``status``).
"""

from __future__ import annotations

from .l1_deterministic import (
    VALID_SEVERITIES,
    extract_file_line_refs,
    extract_http_pair,
    verify_deterministic,
)
from .l2_adversarial import (
    ADVERSARIAL_PROMPT,
    VERDICTS,
    adversarial_review,
    parse_verdict,
)
from .l3_crossref import conclusion, crossref, normalized_key
from .l4_evidence import (
    append_trail,
    load_trail,
    sha256_text,
    trail_path,
    write_evidence,
)

__all__ = [
    "verify_claim",
    "deterministic_verification_pass",
    "verify_deterministic",
    "extract_file_line_refs",
    "extract_http_pair",
    "VALID_SEVERITIES",
    "ADVERSARIAL_PROMPT",
    "VERDICTS",
    "adversarial_review",
    "parse_verdict",
    "crossref",
    "normalized_key",
    "conclusion",
    "write_evidence",
    "append_trail",
    "load_trail",
    "sha256_text",
    "trail_path",
]


def deterministic_verification_pass(claim, target_root=None):
    """Run only the L1 deterministic pass (no LLM, no side effects)."""
    return verify_deterministic(claim, target_root)


def _line_window(path, line, radius=25):
    """Return (lo, hi, numbered_block) around *line* from *path*, or None."""
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except Exception:  # noqa: BLE001
        return None
    if not lines:
        return None
    try:
        line = int(line)
    except (TypeError, ValueError):
        return None
    lo = max(1, line - radius)
    hi = min(len(lines), line + radius)
    body = "".join(
        "%5d | %s" % (i, lines[i - 1]) for i in range(lo, hi + 1)
    )
    return (lo, hi, body)


def _collect_snippet(l1):
    """Assemble the source context L1 actually resolved, for the L2 reviewer.

    A single cited line is not enough to adjudicate most claims: the verdict on
    "nonce consumed before signature verification" depends on seeing that
    verification happens *later in the same function*. L2 was refuting true
    findings because it was handed one line and no context, so hand it a window
    of the real file around every resolved location.
    """
    parts = []
    seen = set()
    for c in l1.get("checks", []):
        if c.get("check") != "file_line" or c.get("line_text") is None:
            continue
        key = (c.get("resolved_path") or c.get("file"), c.get("line"))
        if key in seen:
            continue
        seen.add(key)
        window = _line_window(c.get("resolved_path"), c.get("line"))
        if window:
            lo, hi, body = window
            parts.append("--- %s (lines %d-%d) ---\n%s" % (
                c.get("file") or c.get("resolved_path"), lo, hi, body))
        else:
            parts.append("%s:%s | %s" % (c.get("file"), c.get("line"), c.get("line_text")))
    return "\n".join(parts)


def _compute_status(l1, l2):
    if not l1.get("all_passed"):
        return "refuted"
    verdict = str((l2 or {}).get("verdict") or "").upper()
    if verdict == "REFUTED":
        return "refuted"
    if verdict == "VERIFIED":
        return "verified"
    return "claim"


def _log_line(claim, l1, l2, status):
    return (
        "id=%s status=%s anchored=%s all_passed=%s "
        "verdict=%s confidence=%s reason=%s"
        % (
            claim.get("id"),
            status,
            l1.get("anchored"),
            l1.get("all_passed"),
            (l2 or {}).get("verdict"),
            (l2 or {}).get("confidence"),
            (l2 or {}).get("reason"),
        )
    )


def verify_claim(claim, ctx=None):
    """Verify *claim* through L1->L2->L3->L4 and return the enriched claim."""
    ctx = ctx or {}
    enriched = dict(claim) if isinstance(claim, dict) else {"raw": claim}

    try:
        # --- L1 ----------------------------------------------------------
        l1 = verify_deterministic(enriched, ctx.get("target_root"))
        enriched["l1"] = l1

        # --- L2 (only when anchored and an LLM is injected) --------------
        call_llm = ctx.get("call_llm")
        evidence_text = _collect_snippet(l1)
        raw_ev = str(enriched.get("evidence") or "")
        if raw_ev:
            evidence_text = (raw_ev + "\n" + evidence_text).strip()

        if l1.get("anchored") and call_llm is not None:
            l2 = adversarial_review(enriched, evidence_text, call_llm)
        elif not l1.get("anchored"):
            l2 = {
                "verdict": "UNREVIEWED",
                "confidence": 0,
                "reason": "L1 not anchored; adversarial review skipped",
            }
        else:
            l2 = {
                "verdict": "UNREVIEWED",
                "confidence": 0,
                "reason": "no call_llm provided; adversarial review not run",
            }
        enriched["l2"] = l2

        # --- L3 ----------------------------------------------------------
        existing = [f for f in (ctx.get("existing_findings") or []) if f is not enriched]
        l3 = crossref([enriched] + existing, ctx.get("edges"))
        enriched["l3"] = l3

        # --- status ------------------------------------------------------
        status = _compute_status(l1, l2)
        enriched["status"] = status

        # --- L4 ----------------------------------------------------------
        ev_root = ctx.get("evidence_root")
        if ev_root:
            manifest = write_evidence(
                ev_root,
                enriched,
                source_snippet=_collect_snippet(l1),
                verifier_log=_log_line(enriched, l1, l2, status),
            )
            append_trail(
                ev_root,
                {
                    "event": "verify_claim",
                    "id": enriched.get("id"),
                    "status": status,
                    "anchored": l1.get("anchored"),
                    "verdict": l2.get("verdict"),
                    "evidence_dir": manifest.get("dir"),
                    "claim_sha256": manifest["sha256"]["claim_json"],
                },
            )
            enriched["l4"] = manifest
        else:
            enriched["l4"] = {
                "written": False,
                "reason": "no 'evidence_root' in ctx; nothing persisted",
            }

    except Exception as exc:  # never crash the harness
        enriched.setdefault(
            "l1", {"checks": [], "all_passed": False, "anchored": False}
        )
        enriched.setdefault(
            "l2",
            {
                "verdict": "UNREVIEWED",
                "confidence": 0,
                "reason": "harness error: %s: %s" % (type(exc).__name__, exc),
            },
        )
        enriched.setdefault(
            "l3",
            {
                "duplicates": [],
                "contradictions": [],
                "chain_ok": False,
                "chain_issues": [],
            },
        )
        enriched.setdefault(
            "l4", {"written": False, "reason": "harness error; nothing persisted"}
        )
        enriched["status"] = "claim"
        enriched["error"] = "%s: %s" % (type(exc).__name__, exc)

    return enriched
