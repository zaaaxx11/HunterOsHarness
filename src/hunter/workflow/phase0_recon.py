"""Phase 0 RECON — the omnivore target mapper.

Accepts ANY target the operator hands over and produces one authoritative
``target.json``:

  * a bug-bounty program page      → parse scope / rules / rewards / stack
  * an app-store link (Play/App)   → pull app metadata, package id, perms
  * a GitHub repo / org            → enumerate repos, languages, config files
  * a local file (scope list, JSON,
    CSV, txt, a pasted brief)      → read it, extract every target inside
  * a local directory              → inventory the audit surface
  * a smart-contract address (0x..)→ chain detect, explorer metadata, source
  * a free-form description        → LLM extracts the targets from prose
  * several of the above at once   → merge into one scope

Design contract
---------------
* Tools gather raw material deterministically (no LLM). The LLM only
  STRUCTURES what the tools found — it never invents a host, repo, or address.
* Every input kind has a deterministic fallback so the hunt starts even when
  no provider is configured.
* The output schema is stable; downstream lanes read ``target.json`` only.

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

__all__ = [
    "Phase0Recon",
    "run_recon",
    "classify_input",
    "gather_material",
    "TARGET_JSON_SCHEMA",
]


# ---------------------------------------------------------------- schema

TARGET_JSON_SCHEMA: dict[str, Any] = {
    "target": {
        "name": "",
        "url": "",
        "type": "web2",          # web2 | web3 | node | repo | api | mobile | mixed
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
        "contracts": [],          # [{address, chain, chain_id, notes}]
        "mobile": [],             # [{package, store, version, notes}]
        "contacts": [],
        "notes": [],
    },
    "seed_leads": [],
    "open_questions": [],
    "recon_confidence": 0,
}


# ---------------------------------------------------------------- input classifier (NO LLM)

_GITHUB_RE = re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)(?:/([A-Za-z0-9_.-]+))?")
_PLAY_RE = re.compile(r"^https?://play\.google\.com/store/apps/details\?.*id=([A-Za-z0-9_.]+)")
_APPSTORE_RE = re.compile(r"^https?://apps\.apple\.com/.*/app/[^/]+/id(\d+)")
_HEX_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ETH_TX_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.I)


def classify_input(raw: str) -> str:
    """Return the input kind: url | github | playstore | appstore | file |
    directory | contract | tx | text."""
    token = (raw or "").strip()
    if not token:
        return "text"

    # local path?
    p = Path(token).expanduser()
    try:
        if p.is_dir():
            return "directory"
        if p.is_file():
            return "file"
    except OSError:
        pass

    if _HEX_ADDR_RE.match(token):
        return "contract"
    if _ETH_TX_RE.match(token):
        return "tx"
    if _GITHUB_RE.match(token):
        return "github"
    if _PLAY_RE.match(token):
        return "playstore"
    if _APPSTORE_RE.match(token):
        return "appstore"
    if _URL_RE.match(token):
        return "url"
    return "text"


# ---------------------------------------------------------------- HTTP helpers

def _http_get(url: str, timeout: int = 20, headers: dict | None = None) -> tuple[int | None, str, str | None]:
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


def _http_get_json(url: str, timeout: int = 20, headers: dict | None = None) -> Any:
    s, body, err = _http_get(url, timeout=timeout, headers=headers)
    if not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


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


# ---------------------------------------------------------------- material gatherers (NO LLM)

def _gather_url(url: str) -> dict[str, Any]:
    """Generic HTTP(S) target: page text, links, JS bundles, robots/sitemap."""
    out: dict[str, Any] = {"kind": "url", "primary_url": url}
    status, body, err = _http_get(url)
    out["primary_status"] = status
    out["primary_error"] = err
    if body:
        out["primary_text"] = _html_to_text(body)[:20000]
        out["raw_html_head"] = body[:3000]
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
    for path in ("/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt"):
        s, b, e = _http_get(base + path, timeout=12)
        out[path.strip("/").replace(".", "_").replace("/", "_")] = {
            "status": s, "error": e, "body": (b or "")[:4000]}
    return out


def _gather_github(url: str) -> dict[str, Any]:
    """GitHub repo/org: metadata, languages, repo list, config-file hunt."""
    m = _GITHUB_RE.match(url)
    owner = m.group(1) if m else ""
    repo = m.group(2) if m else ""
    out: dict[str, Any] = {"kind": "github", "owner": owner, "repo": repo, "url": url}
    api = "https://api.github.com"
    hdrs = {"Accept": "application/vnd.github+json", "User-Agent": "hunteros-recon"}

    if repo and repo not in ("", ".github"):
        meta = _http_get_json(f"{api}/repos/{owner}/{repo}", headers=hdrs)
        if isinstance(meta, dict):
            out["repo_meta"] = {
                "full_name": meta.get("full_name"),
                "description": meta.get("description"),
                "language": meta.get("language"),
                "topics": meta.get("topics"),
                "default_branch": meta.get("default_branch"),
                "homepage": meta.get("homepage"),
                "size_kb": meta.get("size"),
                "archived": meta.get("archived"),
            }
        langs = _http_get_json(f"{api}/repos/{owner}/{repo}/languages", headers=hdrs)
        if isinstance(langs, dict):
            out["languages"] = langs
        tree = _http_get_json(
            f"{api}/repos/{owner}/{repo}/git/trees/{out.get('repo_meta',{}).get('default_branch','main')}?recursive=1",
            headers=hdrs)
        if isinstance(tree, dict) and isinstance(tree.get("tree"), list):
            paths = [t.get("path", "") for t in tree["tree"]]
            out["file_count"] = len(paths)
            # config files that commonly leak scope/secrets/hosts
            interesting = [p for p in paths if re.search(
                r"(docker-compose|\.env|\.ya?ml$|\.json$|\.toml$|\.tf$|\.tfvars$|"
                r"nginx|traefik|Caddyfile|\.github/workflows/|k8s|helm|"
                r"\.sol$|\.move$|\.rs$|hardhat|foundry|truffle)", p, re.I)]
            out["config_files"] = interesting[:300]
            out["sample_paths"] = paths[:200]
    else:
        # org: list repos
        repos = _http_get_json(f"{api}/orgs/{owner}/repos?per_page=100", headers=hdrs)
        if not isinstance(repos, list):
            repos = _http_get_json(f"{api}/users/{owner}/repos?per_page=100", headers=hdrs)
        if isinstance(repos, list):
            out["repos"] = [
                {"name": r.get("name"), "lang": r.get("language"),
                 "fork": r.get("fork"), "archived": r.get("archived"),
                 "desc": (r.get("description") or "")[:120]}
                for r in repos if isinstance(r, dict)
            ][:200]
    return out


def _gather_playstore(url: str) -> dict[str, Any]:
    """Play Store: package id + best-effort page text."""
    m = _PLAY_RE.match(url)
    pkg = m.group(1) if m else ""
    out: dict[str, Any] = {"kind": "playstore", "package": pkg, "url": url}
    s, body, e = _http_get(url)
    out["primary_status"] = s
    if body:
        out["primary_text"] = _html_to_text(body)[:15000]
        # permissions / version often appear in the page
        out["version"] = _first(r'"softwareVersion":\s*"([^"]+)"', body)
        out["developer"] = _first(r'"author":\s*\{[^}]*"name":\s*"([^"]+)"', body)
    return out


def _gather_appstore(url: str) -> dict[str, Any]:
    """App Store: id + the public lookup API (no key needed)."""
    m = _APPSTORE_RE.match(url)
    app_id = m.group(1) if m else ""
    out: dict[str, Any] = {"kind": "appstore", "app_id": app_id, "url": url}
    if app_id:
        data = _http_get_json(f"https://itunes.apple.com/lookup?id={app_id}")
        if isinstance(data, dict) and data.get("results"):
            r0 = data["results"][0]
            out["app_meta"] = {
                "trackName": r0.get("trackName"),
                "bundleId": r0.get("bundleId"),
                "sellerName": r0.get("sellerName"),
                "version": r0.get("version"),
                "minimumOsVersion": r0.get("minimumOsVersion"),
                "genres": r0.get("genres"),
                "description": (r0.get("description") or "")[:1500],
            }
    return out


def _gather_file(path: str) -> dict[str, Any]:
    """Local file: read text; if JSON/CSV, keep structure hints."""
    p = Path(path).expanduser()
    out: dict[str, Any] = {"kind": "file", "path": str(p), "name": p.name}
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        out["error"] = str(e)
        return out
    out["size"] = len(raw)
    out["text"] = raw[:60000]
    out["lines"] = len(raw.splitlines())
    # extract every URL / domain / 0x-address / email in the file
    out["urls_in_file"] = sorted(set(re.findall(r"https?://[^\s\"'<>)\]]+", raw)))[:300]
    out["domains_in_file"] = sorted(set(re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|id|co|dev|app|xyz|go\.id|ac\.id|sch\.id|or\.id|info|biz)\b",
        raw, re.I)))[:300]
    out["addresses_in_file"] = sorted(set(re.findall(r"0x[a-fA-F0-9]{40}", raw)))[:200]
    out["emails_in_file"] = sorted(set(re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw)))[:100]
    if p.suffix.lower() == ".json":
        try:
            out["json_top_keys"] = list(json.loads(raw).keys())[:50] if isinstance(json.loads(raw), dict) else "array"
        except Exception:
            pass
    return out


def _gather_directory(path: str) -> dict[str, Any]:
    """Local directory: inventory the audit surface."""
    root = Path(path).expanduser()
    out: dict[str, Any] = {"kind": "directory", "path": str(root)}
    exts: dict[str, int] = {}
    files: list[str] = []
    skip = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "out", "cache"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            fp = Path(dirpath) / fn
            try:
                rel = str(fp.relative_to(root))
            except ValueError:
                rel = fn
            files.append(rel)
            ext = fp.suffix.lower() or "(none)"
            exts[ext] = exts.get(ext, 0) + 1
    out["file_count"] = len(files)
    out["extensions"] = dict(sorted(exts.items(), key=lambda kv: -kv[1])[:30])
    out["sample_files"] = files[:200]
    return out



def _rpc(url: str, method: str, params: list) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"})
        with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
            return data.get("result")
    except Exception:
        return None


#: Key-free Blockscout v2 instances: name -> (base, chain_id)
_BLOCKSCOUT = [
    ("ethereum", "https://eth.blockscout.com", 1),
    ("base", "https://base.blockscout.com", 8453),
    ("optimism", "https://optimism.blockscout.com", 10),
    ("arbitrum", "https://arbitrum.blockscout.com", 42161),
    ("polygon", "https://polygon.blockscout.com", 137),
    ("gnosis", "https://gnosis.blockscout.com", 100),
    ("zksync", "https://zksync.blockscout.com", 324),
    ("scroll", "https://scroll.blockscout.com", 534352),
    ("sepolia", "https://eth-sepolia.blockscout.com", 11155111),
]

#: Public RPCs (read-only, no key): name -> (rpc, chain_id)
_PUBLIC_RPC = [
    ("ethereum", "https://ethereum-rpc.publicnode.com", 1),
    ("bsc", "https://bsc-rpc.publicnode.com", 56),
    ("polygon", "https://polygon-bor-rpc.publicnode.com", 137),
    ("arbitrum", "https://arbitrum-one-rpc.publicnode.com", 42161),
    ("base", "https://base-rpc.publicnode.com", 8453),
    ("optimism", "https://optimism-rpc.publicnode.com", 10),
    ("avalanche", "https://avalanche-c-chain-rpc.publicnode.com", 43114),
    ("celo", "https://celo-rpc.publicnode.com", 42220),
]


def _gather_contract(address: str, chain: str = "") -> dict[str, Any]:
    """Smart contract: metadata from key-free Blockscout + public RPC probes.

    Read-only public APIs only; never mutates chain state.
    """
    out: dict[str, Any] = {"kind": "contract", "address": address, "chain_hint": chain}

    # 1) Blockscout v2 — contract name, proxy, implementation, verified, token info
    hits = []
    for name, base, cid in _BLOCKSCOUT:
        if chain and name.lower() != chain.lower():
            continue
        data = _http_get_json(
            f"{base}/api/v2/addresses/{address}", timeout=12,
            headers={"User-Agent": "Mozilla/5.0"})
        if isinstance(data, dict) and data.get("hash"):
            info = {
                "chain": name, "chain_id": cid,
                "is_contract": data.get("is_contract"),
                "contract_name": data.get("name"),
                "verified": data.get("is_verified"),
                "proxy_type": data.get("proxy_type"),
                "implementations": [
                    (i.get("address_hash") if isinstance(i, dict) else i)
                    for i in (data.get("implementations") or [])
                ][:5],
                "creator": (data.get("creator_address_hash") or None),
            }
            # token metadata if it is a token
            if data.get("token"):
                tok = data["token"] or {}
                info["token"] = {
                    "symbol": tok.get("symbol"), "name": tok.get("name"),
                    "type": tok.get("type"), "decimals": tok.get("decimals"),
                    "holders": tok.get("holders_count"),
                }
            hits.append(info)
    out["explorer_hits"] = hits

    # 2) public RPC probe — code presence, balance, chain id (read-only)
    probes: dict[str, Any] = {}
    for name, rpc_url, cid in _PUBLIC_RPC:
        if chain and name.lower() != chain.lower():
            continue
        code = _rpc(rpc_url, "eth_getCode", [address, "latest"])
        if code and code != "0x":
            bal = _rpc(rpc_url, "eth_getBalance", [address, "latest"])
            probes[name] = {
                "has_code": True,
                "code_size": (len(code) - 2) // 2,
                "balance_wei": bal,
                "chain_id": cid,
            }
    out["rpc_probes"] = probes
    return out


def _gather_text(text: str) -> dict[str, Any]:
    """Free-form description or pasted brief — extract everything inside."""
    out: dict[str, Any] = {"kind": "text", "text": text[:60000]}
    out["urls_in_text"] = sorted(set(re.findall(r"https?://[^\s\"'<>)\]]+", text)))[:300]
    out["domains_in_text"] = sorted(set(re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|id|co|dev|app|xyz|go\.id|ac\.id|or\.id)\b",
        text, re.I)))[:300]
    out["addresses_in_text"] = sorted(set(re.findall(r"0x[a-fA-F0-9]{40}", text)))[:200]
    out["emails_in_text"] = sorted(set(re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))[:100]
    out["github_in_text"] = sorted(set(re.findall(
        r"(?:https?://)?github\.com/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", text)))[:100]
    return out


def _first(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def gather_material(raw: str) -> dict[str, Any]:
    """Classify the input and gather raw material. NO LLM."""
    kind = classify_input(raw)
    token = raw.strip()
    if kind in ("url",):
        return _gather_url(token)
    if kind == "github":
        return _gather_github(token)
    if kind == "playstore":
        return _gather_playstore(token)
    if kind == "appstore":
        return _gather_appstore(token)
    if kind == "file":
        return _gather_file(token)
    if kind == "directory":
        return _gather_directory(token)
    if kind == "contract":
        return _gather_contract(token)
    if kind == "tx":
        return {"kind": "tx", "hash": token,
                "note": "transaction hash — resolve via explorer/RPC for a contract or address"}
    return _gather_text(token)


# ---------------------------------------------------------------- LLM prompt

def _load_soul() -> str:
    candidates = [
        Path(__file__).resolve().parent.parent / "_data" / "prompts" / "souls" / "recon.md",
        Path(os.path.expanduser("~/.hunter/skills/recon/SKILL.md")),
    ]
    for p in candidates:
        if p.exists():
            return p.read_text(encoding="utf-8")
    return (
        "You are RECON. Map the target: scope, rules, stack, auth, repos, APIs, "
        "contracts, mobile apps. Observations only — no vulnerability claims. "
        "Return valid JSON."
    )


_RECON_INSTRUCTION = """
You are given raw material gathered from a target by deterministic tools. The
material's ``kind`` tells you what it is: url, github, playstore, appstore,
file, directory, contract, tx, or text.

Your job: turn that material into ONE structured hunt target. Be exhaustive
and literal — copy domains, URLs, repos, package ids, contract addresses, and
rules verbatim. NEVER invent a host, repo, address, or rule that is not in the
material. If something is unknown, use null / [] (or "" for strings).

Return ONLY valid JSON, no markdown fence, no commentary:

{
  "target": {
    "name": "",
    "url": "",
    "type": "web2|web3|node|repo|api|mobile|mixed",
    "scope": {
      "in_scope": [{"asset": "", "type": "domain|url|repo|contract|app|mobile|org", "notes": ""}],
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
    "contracts": [{"address": "", "chain": "", "chain_id": "", "notes": ""}],
    "mobile": [{"package": "", "store": "", "version": "", "notes": ""}],
    "contacts": [],
    "notes": []
  },
  "seed_leads": [{"lead": "", "why": "", "priority": "high|medium|low"}],
  "open_questions": [],
  "recon_confidence": 0
}

Guidance by kind:
- url: scope.in_scope from the page's own links/domains; stack from headers/JS.
- github: repo_hints from owner/repo; seed leads = config files that can leak
  secrets or hosts (docker-compose, .env, workflows, IaC). Note languages.
- playstore/appstore: fill ``mobile`` (package/bundle id, store, version); the
  app's backend API domains are prime leads.
- file: if it is a scope list, put every entry in scope.in_scope; if it is a
  brief, follow the url/text rules.
- directory: repo_hints = path; stack_hints from extensions; seed leads =
  entrypoints and config files.
- contract: fill ``contracts`` with address + detected chain; verified source
  and proxy/implementation are leads.
- text: extract every URL, domain, address, and repo mentioned.

recon_confidence is 0-100: how much of the real scope you could pin down.
"""


# ---------------------------------------------------------------- engine

class Phase0Recon:
    """Omnivore Phase-0 target mapper with injected LLM and deterministic fallback."""

    def __init__(self, llm_complete: Callable[[str, str], str] | None, workspace: str | Path):
        self.llm = llm_complete
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def run(self, raw_input: str) -> dict[str, Any]:
        kind = classify_input(raw_input)
        material = gather_material(raw_input)
        _log(f"[phase0] input kind={kind} -> gathered "
             f"{sum(1 for k,v in material.items() if v)} field(s)")

        soul = _load_soul()
        # keep the prompt bounded but complete: drop the biggest raw blobs after
        # they've been summarised into lists by the gatherers.
        material_for_llm = dict(material)
        for big in ("raw_html_head", "total_lines"):
            material_for_llm.pop(big, None)
        if len(json.dumps(material_for_llm, default=str)) > 120000:
            # truncate any single oversized text field, keep the lists
            for k, v in list(material_for_llm.items()):
                if isinstance(v, str) and len(v) > 30000:
                    material_for_llm[k] = v[:30000] + "…[truncated]"

        prompt = (
            f"{soul}\n\n{_RECON_INSTRUCTION}\n\n"
            f"=== MATERIAL (kind={kind}) ===\n"
            f"{json.dumps(material_for_llm, indent=1, ensure_ascii=False, default=str)[:120000]}"
        )

        target = None
        if callable(self.llm):
            try:
                raw = self.llm(soul, prompt)
                target = _extract_json(raw)
            except Exception as exc:
                _log(f"[phase0] LLM error: {exc} — deterministic fallback")

        if target is None:
            target = _deterministic_fallback(raw_input, kind, material)

        target.setdefault("target_url_raw", raw_input)
        target["input_kind"] = kind
        target["recon_tools"] = _summarise_tools(kind, material)
        target["recon_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target["recon_confidence"] = target.get("recon_confidence", 10)

        path = self.workspace / "target.json"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(target, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(tmp, path)
        _log(f"[phase0] wrote {path} (confidence={target.get('recon_confidence')})")
        return target


def _log(msg: str) -> None:
    print(msg, flush=True)


def _summarise_tools(kind: str, material: dict) -> dict[str, Any]:
    """A small, stable summary of what the tools saw (kept in target.json)."""
    out: dict[str, Any] = {"kind": kind}
    if kind == "url":
        out["primary_status"] = material.get("primary_status")
        out["links_found"] = len(material.get("links", []))
        out["js_bundles"] = material.get("js_bundles", [])[:40]
        out["candidate_hosts"] = sorted({
            l.split("/")[2] for l in material.get("links", []) if "//" in l})[:80]
    elif kind == "github":
        out["owner"] = material.get("owner")
        out["repo"] = material.get("repo")
        out["repo_meta"] = material.get("repo_meta")
        out["languages"] = material.get("languages")
        out["file_count"] = material.get("file_count")
        out["config_files"] = material.get("config_files", [])[:80]
        out["repos"] = material.get("repos", [])[:80]
    elif kind in ("playstore", "appstore"):
        out["package"] = material.get("package")
        out["app_id"] = material.get("app_id")
        out["app_meta"] = material.get("app_meta")
        out["version"] = material.get("version")
    elif kind == "file":
        out["path"] = material.get("path")
        out["lines"] = material.get("lines")
        out["urls"] = material.get("urls_in_file", [])[:80]
        out["domains"] = material.get("domains_in_file", [])[:80]
        out["addresses"] = material.get("addresses_in_file", [])[:40]
        out["emails"] = material.get("emails_in_file", [])[:20]
    elif kind == "directory":
        out["path"] = material.get("path")
        out["file_count"] = material.get("file_count")
        out["extensions"] = material.get("extensions")
        out["sample_files"] = material.get("sample_files", [])[:80]
    elif kind == "contract":
        out["address"] = material.get("address")
        out["explorer_hits"] = material.get("explorer_hits")
        out["rpc_probes"] = material.get("rpc_probes")
    elif kind == "text":
        out["urls"] = material.get("urls_in_text", [])[:80]
        out["domains"] = material.get("domains_in_text", [])[:80]
        out["addresses"] = material.get("addresses_in_text", [])[:40]
        out["github"] = material.get("github_in_text", [])[:40]
    return out


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


def _deterministic_fallback(raw_input: str, kind: str, material: dict) -> dict[str, Any]:
    """Minimal machine-readable target when the LLM is unavailable."""
    t: dict[str, Any] = {
        "target": {
            "name": raw_input,
            "url": raw_input if kind in ("url", "github") else "",
            "type": {"github": "repo", "contract": "web3", "playstore": "mobile",
                     "appstore": "mobile", "directory": "repo", "file": "mixed"}
                    .get(kind, "web2"),
            "scope": {"in_scope": [], "out_of_scope": [], "excluded_bugs": []},
            "rules": {}, "rewards": {}, "stack_hints": [], "auth": {},
            "repo_hints": [], "api_hints": [], "contracts": [], "mobile": [],
            "contacts": [], "notes": [f"deterministic fallback (kind={kind})"],
        },
        "seed_leads": [],
        "open_questions": ["LLM recon unavailable — deterministic mapping only"],
        "recon_confidence": 5,
    }
    tgt = t["target"]

    if kind == "url":
        tgt["scope"]["in_scope"].append({"asset": raw_input, "type": "url", "notes": "seed"})
        for h in sorted({l.split("/")[2] for l in material.get("links", []) if "//" in l})[:50]:
            tgt["scope"]["in_scope"].append({"asset": h, "type": "domain", "notes": "linked host"})
    elif kind == "github":
        owner, repo = material.get("owner"), material.get("repo")
        if repo:
            tgt["scope"]["in_scope"].append(
                {"asset": f"{owner}/{repo}", "type": "repo", "notes": "seed"})
        for r in (material.get("repos") or [])[:50]:
            tgt["scope"]["in_scope"].append(
                {"asset": f"{owner}/{r.get('name')}", "type": "repo", "notes": "org repo"})
        tgt["repo_hints"] = material.get("config_files", [])[:50]
        if material.get("languages"):
            tgt["stack_hints"] = list(material["languages"].keys())
    elif kind in ("playstore", "appstore"):
        pkg = material.get("package") or material.get("app_id")
        tgt["mobile"].append({"package": pkg, "store": kind, "version": material.get("version", ""),
                              "notes": "seed"})
        for d in re.findall(r"([a-z0-9-]+\.)+[a-z]{2,}", material.get("primary_text", ""))[:30]:
            tgt["scope"]["in_scope"].append({"asset": d, "type": "domain", "notes": "from app page"})
    elif kind == "file":
        for u in material.get("urls_in_file", [])[:100]:
            tgt["scope"]["in_scope"].append({"asset": u, "type": "url", "notes": "from file"})
        for d in material.get("domains_in_file", [])[:100]:
            tgt["scope"]["in_scope"].append({"asset": d, "type": "domain", "notes": "from file"})
        for a in material.get("addresses_in_file", [])[:50]:
            tgt["contracts"].append({"address": a, "chain": "", "chain_id": "", "notes": "from file"})
    elif kind == "directory":
        tgt["repo_hints"] = [material.get("path", "")]
        tgt["stack_hints"] = list((material.get("extensions") or {}).keys())[:15]
    elif kind == "contract":
        tgt["contracts"].append({"address": material.get("address", raw_input),
                                 "chain": (material.get("rpc_probes") or {}).keys().__iter__().__next__()
                                 if material.get("rpc_probes") else "",
                                 "chain_id": "", "notes": "seed"})
        tgt["scope"]["in_scope"].append({"asset": material.get("address", raw_input),
                                         "type": "contract", "notes": "seed"})
    elif kind == "text":
        for u in material.get("urls_in_text", [])[:100]:
            tgt["scope"]["in_scope"].append({"asset": u, "type": "url", "notes": "from text"})
        for d in material.get("domains_in_text", [])[:100]:
            tgt["scope"]["in_scope"].append({"asset": d, "type": "domain", "notes": "from text"})
    return t


def run_recon(raw_input: str, llm_complete: Callable | None, workspace: str | Path) -> dict[str, Any]:
    """One-shot entry point. Returns the target dict and writes target.json."""
    return Phase0Recon(llm_complete, workspace).run(raw_input)


# ---------------------------------------------------------------- CLI

if __name__ == "__main__":  # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(prog="phase0_recon", description="Omnivore target mapper")
    ap.add_argument("input", help="URL, github repo, app link, file, dir, 0x-address, or text")
    ap.add_argument("--workspace", default=".", help="where to write target.json")
    args = ap.parse_args()
    out = run_recon(args.input, None, args.workspace)
    print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
