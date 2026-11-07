"""Layer 4 - evidence directory + append-only audit trail.

For each finding id we materialize ``<root>/<id>/`` holding ``claim.json``,
``source_snippet.txt`` and ``verifier_log.txt``, computing sha256 of the
captured source content and of the claim json. The trail is newline-delimited
JSON appended to ``<root>/trail.jsonl`` - append-only, never rewritten.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

_UNSAFE = re.compile(r"[^A-Za-z0-9_.\-]")


def sha256_text(text):
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    try:
        with open(path, "rb") as fh:
            h = hashlib.sha256()
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
            return h.hexdigest()
    except OSError:
        return None


def _safe_id(fid):
    safe = _UNSAFE.sub("_", str(fid or "unknown"))
    return safe or "unknown"


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text if text is not None else "")


def write_evidence(root, claim, source_snippet=None, verifier_log=None):
    """Create/refresh ``<root>/<id>/`` and return a manifest of what was written."""
    fid = claim.get("id") if isinstance(claim, dict) else None
    safe = _safe_id(fid)
    target = os.path.join(root, safe)
    os.makedirs(target, exist_ok=True)

    claim_json = json.dumps(claim, indent=2, sort_keys=True, default=str)
    snippet = source_snippet if source_snippet is not None else ""
    vlog = verifier_log if verifier_log is not None else ""

    claim_path = os.path.join(target, "claim.json")
    snippet_path = os.path.join(target, "source_snippet.txt")
    log_path = os.path.join(target, "verifier_log.txt")

    _write(claim_path, claim_json)
    _write(snippet_path, snippet)
    _write(log_path, vlog)

    return {
        "written": True,
        "id": fid,
        "dir": target,
        "files": {
            "claim.json": claim_path,
            "source_snippet.txt": snippet_path,
            "verifier_log.txt": log_path,
        },
        "sha256": {
            "claim_json": sha256_text(claim_json),
            "source_snippet": sha256_text(snippet) if snippet else None,
            "verifier_log": sha256_text(vlog) if vlog else None,
        },
    }


def trail_path(root):
    return os.path.join(root, "trail.jsonl")


def append_trail(root, event_dict):
    """Append one JSON object as a line to ``<root>/trail.jsonl``. Append-only."""
    os.makedirs(root, exist_ok=True)
    line = json.dumps(event_dict, sort_keys=True, default=str)
    with open(trail_path(root), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return line


def load_trail(root):
    """Read the trail back as a list of dicts (unparseable lines preserved)."""
    path = trail_path(root)
    events = []
    if not os.path.exists(path):
        return events
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"_unparsed": line})
    return events
