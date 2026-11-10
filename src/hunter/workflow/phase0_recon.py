"""Phase 0 RECON — LLM-powered target mapping.

Reads a bug-bounty program page (or any target URL), fetches it with tools,
feeds the material to the RECON LLM (using the recon soul), and writes a
structured ``target.json`` into the workspace.

The output is the authoritative target map consumed by all downstream lanes:
scope (in/out), rules, rewards, stack hints, auth mechanism, repo hints,
and seed leads ranked by priority.

Design contract
---------------
* The LLM is injected — callable ``complete(system, user) -> str``.
* Every tool output is captured verbatim; the LLM never invents a host.
* Deterministic fallback: when the LLM is unavailable the module builds a
  minimal machine-readable target from the raw HTML so the hunt can still start.

Used by
-------
* ``hunter.workflow.loop_v4`` — Phase 0 runs once before the CDC loop.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Callable

__all__ = ["Phase0Recon", "run_recon", "TARGET_JSON_SCHEMA"]


# ---------------------------------------------------------------- schema

TARGET_JSON_SCHEMA: dict[str, Any] = {
    "target": {
        "name": "",
        "url": "",
        "type": "web2",          # web2 | web3 | node | repo | api | mixed
        "scope": {
            "in_scope": [],       # [{asset, type, notes}]
            "out_of_scope": [],   # [{asset, reason}]
            "excluded_bugs": [],
        },
        "rules": {
            "max_rps": None,
            "no_ddos": True,
            "no_social_engineering": True,
            "no_automated_scanners": False,
            "account_required": False,
            "custom": [],
        },
        "rewards": {"critical": "", "high": "", "medium": "", "low": ""},
        "stack_hints": [],
        "auth": {"type": "", "mfa": "", "providers": []},
        "repo_hints": [],
        "api_hints": [],
        "contacts": [],
        "notes": [],
    },
    "seed_leads": [],
    "open_questions": [],
    "recon_confidence": 0,
}


# ---------------------------------------------------------------- tools (NO LLM here)

def _http_get(url: str, timeout: int = 20, headers: dict | None = None) -> tuple[int | None, str, str | None]:
    """Plain GET with a browser UA. Returns (status, body, error)."""
    hdrs = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    if headers:
        hdrs.update(headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, None
    except Exception as e:
        return None, "", str(e)


def _html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<script.*?</script>", " ", html)
    html = re.sub(r"(?is)<style.*?</style>", " ", html)
    html = re.sub(r"(?is)<noscript.*?</noscript>", " ", html)
    html = re.sub(r"(?is)<!--.*?-->", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def _fetch_tool_output(url: str) -> dict[str, Any]:
    """Deterministic HTTP collection — NO LLM here."""
    out: dict[str, Any] = {"primary_url": url}
    status, body, err = _http_get(url)
    out["primary_status"] = status
    out["primary_error"] = err
    if body:
        text = _html_to_text(body)[:20000]
        out["primary_text"] = text
        links = re.findall(r'href=["\'](https?://[^"\']+)["\']', body)
        rel = re.findall(r'href=["\'](/[^"\']{1,120})["\']', body)
        seen: set[str] = set()
        uniq: list[str] = []
        for l in links:
            d = l.split("/")[2] if "//" in l else l
            if d not in seen:
                seen.add(d)
                uniq.append(l)
        out["links"] = uniq[:200]
        out["relative_links"] = sorted(set(rel))[:200]
        out["js_bundles"] = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)[:100]

    base = "/".join(url.split("/")[:3])
    for path in ("/robots.txt", "/sitemap.xml"):
        s, b, e = _http_get(base + path, timeout=12)
        out[path.strip("/").replace(".", "_")] = {"status": s, "error": e, "body": (b or "")[:4000]}
    return out


# ---------------------------------------------------------------- LLM prompt

def _load_soul() -> str:
    """Read the recon soul prompt shipped with the harness."""
    # shipped paths (highest priority first)
    candidates = [
        Path(__file__).resolve().parent.parent / "_data" / "prompts" / "souls" / "recon.md",
        Path(os.path.expanduser("~/.hunter/skills/recon/SKILL.md")),
    ]
    for p in candidates:
        if p.exists():
            return p.read_text(encoding="utf-8")
    # lightweight fallback
    return (
        "You are RECON. Map the target: scope, rules, stack, auth, repos, "
        "APIs. Observations only — no vulnerability claims. Return valid JSON."
    )


_RECON_INSTRUCTION = """
You are given a raw planning brief (a bug-bounty program page or target URL)
plus tool output. Your job is to extract a STRUCTURED hunt target — scope,
rules, stack, leads, and open questions. Be exhaustive and literal: copy
domains, URLs, and rules verbatim from the material. Do not invent hosts that
do not appear in the material.

Return ONLY valid JSON, no markdown fence, no commentary:

{
  "target": {
    "name": "",
    "url": "",
    "type": "web2",
    "scope": {
      "in_scope": [{"asset": "", "type": "domain|url|repo|contract|app", "notes": ""}],
      "out_of_scope": [{"asset": "", "reason": ""}],
      "excluded_bugs": []
    },
    "rules": {
      "max_rps": null,
      "no_ddos": true,
      "no_social_engineering": true,
      "no_automated_scanners": false,
      "account_required": false,
      "custom": []
    },
    "rewards": {"critical": "", "high": "", "medium": "", "low": ""},
    "stack_hints": [],
    "auth": {"type": "", "mfa": "", "providers": []},
    "repo_hints": [],
    "api_hints": [],
    "contacts": [],
    "notes": []
  },
  "seed_leads": [{"lead": "", "why": "", "priority": "high|medium|low"}],
  "open_questions": [],
  "recon_confidence": 0
}

Only fill from the material. Use null / [] where unknown.
recon_confidence is 0-100 based on how much of the scope you could pin down.
"""


# ---------------------------------------------------------------- engine

class Phase0Recon:
    """Phase-0 target mapper with injected LLM and deterministic fallback."""

    def __init__(self, llm_complete: Callable[[str, str], str] | None, workspace: str | Path):
        self.llm = llm_complete
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def run(self, target_url: str) -> dict[str, Any]:
        tool_output = _fetch_tool_output(target_url)
        print(f"[phase0] fetched primary (status={tool_output.get('primary_status')}) "
              f"links={len(tool_output.get('links', []))} "
              f"js={len(tool_output.get('js_bundles', []))}", flush=True)

        brief = tool_output.get("primary_text", "")
        tool_dump = json.dumps({k: v for k, v in tool_output.items()
                                if k != "primary_text"}, indent=1)[:12000]

        soul = _load_soul()
        prompt = f"{soul}\n\n{_RECON_INSTRUCTION}\n\n"
        prompt += f"=== PLANNING BRIEF (raw text) ===\n{brief[:40000]}\n\n"
        prompt += f"=== TOOL OUTPUT ===\n{tool_dump}"

        target = None
        if callable(self.llm):
            try:
                raw = self.llm(soul, prompt)
                target = _extract_json(raw)
            except Exception as exc:
                print(f"[phase0] LLM error: {exc} — using deterministic fallback", flush=True)

        if target is None:
            target = _deterministic_fallback(target_url, tool_output)

        target.setdefault("target_url_raw", target_url)
        target["recon_tools"] = {
            "primary_status": tool_output.get("primary_status"),
            "links_found": len(tool_output.get("links", [])),
            "js_bundles": tool_output.get("js_bundles", [])[:40],
            "candidate_hosts": sorted({l.split("/")[2] for l in tool_output.get("links", [])
                                       if "//" in l})[:80],
            "robots": tool_output.get("robots_txt", {}).get("body", "")[:1000],
        }
        target["recon_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target["recon_confidence"] = target.get("recon_confidence", 10)

        path = self.workspace / "target.json"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(target, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        print(f"[phase0] wrote {path} (confidence={target.get('recon_confidence')})", flush=True)
        return target


# ---------------------------------------------------------------- helpers

def _extract_json(raw: str) -> dict | None:
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except Exception:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except Exception:
            return None
    return None


def _deterministic_fallback(url: str, tool_output: dict) -> dict[str, Any]:
    """Minimal machine-readable target when the LLM is unavailable."""
    return {
        "target": {
            "name": url,
            "url": url,
            "type": "web2",
            "scope": {
                "in_scope": [{"asset": url, "type": "url", "notes": "seed"}],
                "out_of_scope": [],
                "excluded_bugs": [],
            },
            "rules": {},
            "rewards": {},
            "stack_hints": [],
            "auth": {},
            "repo_hints": [],
            "api_hints": [],
            "contacts": [],
            "notes": ["LLM recon unavailable — deterministic fallback"],
        },
        "seed_leads": [],
        "open_questions": ["LLM recon failed — run with a provider for full mapping"],
        "recon_confidence": 5,
    }


def run_recon(target_url: str, llm_complete: Callable | None, workspace: str | Path) -> dict[str, Any]:
    """One-shot entry point. Returns the target dict and writes target.json."""
    return Phase0Recon(llm_complete, workspace).run(target_url)