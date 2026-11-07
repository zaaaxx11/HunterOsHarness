"""Layer 1 - deterministic, LLM-free verification.

Pure Python (re/os only). Extracts ``file:line`` anchors and HTTP
request/response shapes from a claim's title/description/evidence, resolves the
file under ``target_root``, and captures the *real* source line text.

Design rule: this layer can only ever confirm grounding it actually observed.
A missing file, an out-of-range line, a short description or an unknown severity
degrades to a *failed* check - it never silently passes and it never invents an
anchor. The public entry point never raises: all file I/O is wrapped and any
unexpected error becomes a failing check with ``anchored=False``.
"""

from __future__ import annotations

import json
import os
import re

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Extensions we are willing to treat as a source-file reference. The whitelist
# deliberately excludes things like ``host.com:8080`` from being read as a
# file:line anchor.
_CODE_EXTS = {
    "sol", "py", "pyi", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rs", "go",
    "java", "kt", "kts", "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "cs",
    "rb", "php", "swift", "scala", "sh", "bash", "zsh", "ps1", "yaml", "yml",
    "json", "toml", "ini", "cfg", "conf", "md", "txt", "sql", "html", "htm",
    "vue", "svelte", "xml", "move", "circom", "cairo", "vy", "proto",
}

# path/to/File.sol:142   Foo.py:12   ./src/a/b.js:7
_FILE_LINE_RE = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./\-]*)\.([A-Za-z][A-Za-z0-9_]*):(\d+)"
)
# bare "line 142"
_BARE_LINE_RE = re.compile(r"\bline\s+(\d+)\b", re.IGNORECASE)

# HTTP request line: "GET /path HTTP/1.1" (or without the version)
_HTTP_REQ_RE = re.compile(
    r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", re.MULTILINE
)
# HTTP status: "HTTP/1.1 200 OK", "status: 200" or "200 OK"
_HTTP_STATUS_RE = re.compile(
    r"HTTP/\d(?:\.\d)?\s+(\d{3})"
    r"|status(?:\s*code)?\s*[:=]\s*(\d{3})"
    r"|^\s*(\d{3})\s+[A-Za-z]",
    re.MULTILINE,
)


def as_text(val):
    """Coerce any claim field to searchable text.

    ``evidence`` is not always a string: the hunter/loop layer may hand over a
    structured object such as ``{"file": "src/X.sol", "line": 44}``. Calling
    ``.lower()`` on that used to crash the whole deterministic pass and turn a
    genuinely anchored finding into a refuted one.
    """
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, (dict, list, tuple)):
        try:
            return json.dumps(val, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001
            return str(val)
    return str(val)


def claim_text(claim):
    """Concatenate the free-text fields a claim is allowed to carry evidence in."""
    parts = []
    for key in ("title", "description", "evidence", "file", "vuln_type", "notes"):
        text = as_text(claim.get(key))
        if text:
            parts.append(text)
    return "\n".join(parts)


def extract_file_line_refs(text):
    """Return ordered, de-duplicated ``(path, line)`` refs found in *text*."""
    refs = []
    for m in _FILE_LINE_RE.finditer(text or ""):
        path = "%s.%s" % (m.group(1), m.group(2))
        ext = m.group(2).lower()
        if ext not in _CODE_EXTS:
            continue
        try:
            line = int(m.group(3))
        except (TypeError, ValueError):
            continue
        refs.append((path, line))

    seen = set()
    out = []
    for ref in refs:
        key = (ref[0].lower(), ref[1])
        if key in seen:
            continue
        seen.add(key)
        out.append(ref)
    return out


def extract_http_pair(evidence):
    """Return a validated-shape HTTP transcript dict, or None if not present.

    Trigger: the text carries both a request marker (``GET /`` / ``POST /`` /
    ``request:``) and a response marker (``response:`` / ``HTTP/1``).
    """
    text = as_text(evidence)
    low = text.lower()
    has_req = ("get /" in low) or ("post /" in low) or ("request:" in low)
    has_resp = ("response:" in low) or ("http/1" in low)
    if not (has_req and has_resp):
        return None

    req = _HTTP_REQ_RE.search(text)
    status = _HTTP_STATUS_RE.search(text)
    code = None
    if status:
        code = next((g for g in status.groups() if g), None)
    return {
        "method": req.group(1).upper() if req else None,
        "path": req.group(2) if req else None,
        "status": code,
    }


def _find_file(target_root, ref_path):
    """Locate *ref_path* under *target_root* by exact relative path then basename."""
    if not target_root or not os.path.isdir(target_root):
        return None
    # chunked hunts cite a unit label such as "src/Vault.sol#part2"; the suffix
    # names the audit unit, not a path, so it is stripped before lookup.
    ref_path = str(ref_path or "").split("#", 1)[0]
    rel = str(ref_path).replace("\\", "/").lstrip("./")
    direct = os.path.join(target_root, rel)
    if os.path.isfile(direct):
        return direct

    base = os.path.basename(rel)
    matches = []
    for dirpath, _dirs, files in os.walk(target_root):
        for fn in files:
            if fn == base:
                matches.append(os.path.join(dirpath, fn))
    for m in matches:
        if m.replace(os.sep, "/").endswith(rel):
            return m
    return matches[0] if matches else None


def _read_line(path, line_no):
    """Return the text of 1-indexed *line_no*, or None if it does not exist."""
    if line_no < 1:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for idx, raw in enumerate(fh, 1):
                if idx == line_no:
                    return raw.rstrip("\r\n")
    except OSError:
        return None
    return None


def verify_deterministic(claim, target_root=None):
    """Run all deterministic checks for *claim*. Never raises."""
    try:
        return _verify_deterministic_inner(claim or {}, target_root)
    except Exception as exc:  # defensive: a crash must not become a false pass
        return {
            "checks": [
                {
                    "check": "l1_internal",
                    "passed": False,
                    "reason": "deterministic pass crashed: %s: %s"
                    % (type(exc).__name__, exc),
                }
            ],
            "all_passed": False,
            "anchored": False,
            "resolved": [],
            "http": None,
        }


def _verify_deterministic_inner(claim, target_root):
    checks = []

    def add(check, passed, reason, **extra):
        entry = {"check": check, "passed": bool(passed), "reason": reason}
        entry.update(extra)
        checks.append(entry)

    # --- severity --------------------------------------------------------
    sev = str(claim.get("severity") or "").lower()
    sev_ok = sev in VALID_SEVERITIES
    add(
        "severity_valid",
        sev_ok,
        "severity %r accepted" % sev if sev_ok
        else "severity %r not in %s" % (sev, list(VALID_SEVERITIES)),
        severity=sev,
    )

    # --- description length ---------------------------------------------
    desc = str(claim.get("description") or "")
    desc_ok = len(desc) >= 20
    add(
        "description_length",
        desc_ok,
        "description length %d >= 20" % len(desc) if desc_ok
        else "description length %d < 20" % len(desc),
        length=len(desc),
    )

    # --- file:line anchors ----------------------------------------------
    text = claim_text(claim)
    refs = []
    efile, eline = claim.get("file"), claim.get("line")
    if efile and eline is not None:
        try:
            refs.append((str(efile), int(eline)))
        except (TypeError, ValueError):
            pass
    refs.extend(extract_file_line_refs(text))

    bare = _BARE_LINE_RE.findall(text)
    if efile and eline is None and bare:
        try:
            refs.append((str(efile), int(bare[0])))
        except (TypeError, ValueError):
            pass

    seen = set()
    deduped = []
    for path, line in refs:
        key = (path.lower(), line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((path, line))
    refs = deduped

    anchored = False
    resolved = []
    for path, line in refs:
        found = _find_file(target_root, path)
        if not found:
            add(
                "file_line",
                False,
                "referenced file %r (line %d) not found under target_root"
                % (path, line),
                file=path, line=line,
            )
            continue
        src = _read_line(found, line)
        if src is None:
            add(
                "file_line",
                False,
                "file %r found but line %d does not exist" % (path, line),
                file=path, line=line, resolved_path=found,
            )
            continue
        anchored = True
        resolved.append(
            {"file": path, "line": line, "resolved_path": found, "line_text": src}
        )
        add(
            "file_line",
            True,
            "file %r line %d resolved; source line captured" % (path, line),
            file=path, line=line, resolved_path=found, line_text=src,
        )

    # --- HTTP evidence ---------------------------------------------------
    http = extract_http_pair(claim.get("evidence") or "")
    if http is not None:
        http_ok = bool(http["method"] and http["path"] and http["status"])
        if http_ok:
            anchored = True
        add(
            "http_evidence",
            http_ok,
            "request/response pair parsed: %s %s -> %s"
            % (http["method"], http["path"], http["status"]) if http_ok
            else "request/response markers present but shape incomplete: %r" % (http,),
            http=http,
        )

    # --- bare line references (informational only) ----------------------
    if bare:
        try:
            bare_nums = [int(b) for b in bare]
        except (TypeError, ValueError):
            bare_nums = []
        add(
            "bare_line_refs",
            True,
            "bare line reference(s) detected: %s" % ", ".join(bare),
            lines=bare_nums,
        )

    # --- anchor gate -----------------------------------------------------
    add(
        "has_anchor",
        anchored,
        "deterministic anchor established" if anchored
        else "no resolvable file:line and no valid HTTP pair; claim is unanchored",
    )

    return {
        "checks": checks,
        "all_passed": all(c["passed"] for c in checks),
        "anchored": anchored,
        "resolved": resolved,
        "http": http,
    }
