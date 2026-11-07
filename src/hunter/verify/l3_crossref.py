"""Layer 3 - cross-reference / de-duplication / contradiction / chain checks.

Pure Python (difflib/os/re). Operates on a *list* of claims so it can reason
about the claim under test together with everything already in the corpus.
"""

from __future__ import annotations

import difflib
import os
import re

from .l1_deterministic import extract_file_line_refs

TITLE_SIMILARITY_THRESHOLD = 0.85

# Conclusion lexicons. Matched on word boundaries so "unchecked" is not read as
# the safe word "checked".
_VULN_WORDS = {
    "vulnerable", "vulnerability", "vulnerabilities", "exploit", "exploitable",
    "exploits", "exploited", "reentrancy", "reentrant", "drain", "drains",
    "theft", "stolen", "overflow", "underflow", "bypass", "unauthorized",
    "unchecked", "missing", "flaw", "insecure", "unsafe", "attack", "attacker",
    "race", "injection", "escalation", "impersonation", "idor", "spoof",
    "bypasses", "leak", "leaks", "manipulation", "traversal",
}
_SAFE_WORDS = {
    "safe", "secure", "protected", "guarded", "mitigated", "benign", "ok",
    "fine", "nonissue", "guarded",
}
_SAFE_PHRASES = (
    "not vulnerable", "no vulnerability", "not exploitable", "false positive",
    "appears safe", "is safe", "cannot be", "unable to", "not reachable",
    "no impact", "not a bug", "not a vulnerability",
)


def _claim_text(claim):
    return " ".join(
        str(claim.get(k) or "") for k in ("title", "description", "evidence")
    )


def normalized_key(claim):
    """Normalized ``(basename_lower, line)`` identity, or None if none exists."""
    f = claim.get("file")
    ln = claim.get("line")
    if f and ln is not None:
        try:
            return (os.path.basename(str(f)).lower(), int(ln))
        except (TypeError, ValueError):
            pass
    for path, line in extract_file_line_refs(_claim_text(claim)):
        return (os.path.basename(path).lower(), int(line))
    return None


def conclusion(claim):
    """Classify a claim's stance at a location as ``'vuln'``, ``'safe'`` or None."""
    text = _claim_text(claim).lower()
    for phrase in _SAFE_PHRASES:
        if phrase in text:
            return "safe"
    words = set(re.findall(r"[a-z]+", text))
    if words & _SAFE_WORDS:
        return "safe"
    if words & _VULN_WORDS:
        return "vuln"
    return None


def crossref(claims, edges=None):
    """Return ``{duplicates, contradictions, chain_ok, chain_issues}``."""
    try:
        return _crossref_inner(list(claims or []), list(edges or []))
    except Exception as exc:
        return {
            "duplicates": [],
            "contradictions": [],
            "chain_ok": False,
            "chain_issues": [{"issue": "crossref_error", "detail": str(exc)}],
        }


def _crossref_inner(claims, edges):
    ids = set()
    for c in claims:
        cid = c.get("id")
        if cid is not None:
            ids.add(str(cid))

    duplicates = []

    # 1) exact normalized file:line duplicate
    seen_key = {}
    for c in claims:
        key = normalized_key(c)
        if key is None:
            continue
        if key in seen_key:
            duplicates.append({
                "kind": "file_line",
                "key": "%s:%d" % (key[0], key[1]),
                "ids": [seen_key[key], c.get("id")],
            })
        else:
            seen_key[key] = c.get("id")

    # 2) fuzzy title duplicate
    for i in range(len(claims)):
        for j in range(i + 1, len(claims)):
            ti = str(claims[i].get("title") or "").lower().strip()
            tj = str(claims[j].get("title") or "").lower().strip()
            if not ti or not tj:
                continue
            ratio = difflib.SequenceMatcher(None, ti, tj).ratio()
            if ratio > TITLE_SIMILARITY_THRESHOLD:
                duplicates.append({
                    "kind": "title",
                    "ratio": round(ratio, 3),
                    "ids": [claims[i].get("id"), claims[j].get("id")],
                })

    # 3) contradiction: same location, opposite conclusions
    by_key = {}
    for c in claims:
        key = normalized_key(c)
        if key is None:
            continue
        by_key.setdefault(key, []).append(c)

    contradictions = []
    for key, group in by_key.items():
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                ci = conclusion(group[i])
                cj = conclusion(group[j])
                if ci and cj and ci != cj:
                    contradictions.append({
                        "key": "%s:%d" % (key[0], key[1]),
                        "ids": [group[i].get("id"), group[j].get("id")],
                        "conclusions": [ci, cj],
                    })

    # 4) chain consistency
    chain_issues = []
    graph = {}
    for edge in edges:
        try:
            a, b = edge[0], edge[1]
        except (TypeError, IndexError):
            chain_issues.append({"issue": "malformed_edge", "edge": edge})
            continue
        graph.setdefault(a, []).append(b)
        graph.setdefault(b, [])

    for edge in edges:
        for node in (edge[0], edge[1]) if len(edge) >= 2 else ():
            if str(node) not in ids:
                chain_issues.append({"issue": "missing_id", "id": node})

    color = {}

    def dfs(node):
        color[node] = 1
        for nxt in graph.get(node, []):
            state = color.get(nxt, 0)
            if state == 1:
                chain_issues.append({"issue": "cycle", "edge": [node, nxt]})
            elif state == 0:
                dfs(nxt)
        color[node] = 2

    for node in list(graph):
        if color.get(node, 0) == 0:
            dfs(node)

    return {
        "duplicates": duplicates,
        "contradictions": contradictions,
        "chain_ok": len(chain_issues) == 0,
        "chain_issues": chain_issues,
    }
