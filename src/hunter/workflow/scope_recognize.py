"""Scope recognizer — LLM-assisted classification of hunt targets.

Given one raw target (URL, git repo, directory, smart-contract address, ...)
this module asks the LLM (utility tier) to classify it and propose a scope
manifest. Every LLM answer is validated; a bad or missing answer falls back
to a deterministic URL/directory scope so the loop never dies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunter.tools.scope import ScopeSet

__all__ = ["recognize", "recognize_from_file", "recognize_scope"]


def recognize_from_file(provider: Any, file_path: str | Path) -> dict[str, Any]:
    """Return a scope manifest dict for a policy file (VDP JSON, text, AGENTS.md).

    The file is read and handed to the LLM with a prompt designed to extract
    scope boundaries from free-form vulnerability-disclosure policies, security
    manifests, and project-context files.  A bad/missing LLM answer falls back
    to a best-effort regex on the raw text so the harness never dies.
    """
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"not a file: {path}")
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    if not raw_text.strip():
        return {"kind": "url", "name": path.stem, "hosts": [], "local_roots": [],
                "allow_subdomains": False, "engine": "deterministic",
                "notes": "empty file"}

    # Try JSON first — structured VDP manifests are the primary use case.
    import json as _json
    try:
        data = _json.loads(raw_text)
    except (ValueError, _json.JSONDecodeError):
        data = None

    if isinstance(data, dict):
        return _scope_from_vdp_json(data, path)

    # Not JSON — treat as free-form text (AGENTS.md, Markdown policy, etc.)
    if provider is not None:
        from hunter.agent.soul import CORE_IDENTITY

        messages = [
            {
                "role": "system",
                "content": (
                    f"{CORE_IDENTITY}\n\n"
                    "You are a scope extractor for a security-audit harness. "
                    "Read the provided file and extract ALL in-scope assets into "
                    "a JSON object with keys: kind (url|repo|smartcontract|api|web), "
                    "name, hosts (list), local_roots (list), allow_subdomains (bool), "
                    "engine, notes. For repo add git_url; for smartcontract add chain/address. "
                    "IMPORTANT: also extract OUT OF SCOPE hosts/URLs and put them in an "
                    "\"exclude_hosts\" list. No prose — return ONLY the JSON object."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"File: {path.name}\n\nContents:\n{raw_text[:16000]}\n"
                    f"Return JSON only."
                ),
            },
        ]
        try:
            turn = provider.complete("utility", messages, budget=None)
            llm_data = _parse_json_obj(getattr(turn, "text", "") or "")
        except Exception:
            llm_data = None
        if llm_data is not None:
            scope = _coerce_scope(llm_data)
            if scope is not None:
                return scope

    # Deterministic fallback: extract URLs from the raw text.
    return _scope_from_raw_text(raw_text, path)


def _scope_from_vdp_json(data: dict, path: Path) -> dict[str, Any]:
    """Extract a scope manifest from a structured VDP / Bugcrowd-style JSON."""
    # Bugcrowd / VDP shape: {"program":..., "scope": {"in_scope": [...], "out_of_scope": [...]}}
    scope = data.get("scope", {}) if isinstance(data.get("scope"), dict) else {}
    in_scope = scope.get("in_scope") or []
    out_of_scope = scope.get("out_of_scope") or []
    program = data.get("program", {}) if isinstance(data.get("program"), dict) else {}

    hosts: list[str] = []
    exclude: list[str] = []
    name = str(program.get("name") or program.get("company") or path.stem)
    kind = "url"
    engine = "llm"

    for entry in (in_scope if isinstance(in_scope, list) else []):
        if not isinstance(entry, dict):
            continue
        entry_type = str(entry.get("type", "")).lower()
        # URL field takes priority — it carries the actual host.
        target_raw = str(entry.get("url") or entry.get("target") or "").strip()
        if not target_raw:
            continue

        if entry_type == "mobile_android":
            continue  # mobile apps — the web API is what we hunt

        # Parse host from the URL.
        parsed = urlparse(target_raw if "://" in target_raw else f"https://{target_raw}")
        host = (parsed.hostname or "").lower()
        # Only accept real-looking hostnames: must contain a dot and no spaces.
        if host and "." in host and " " not in host and host not in ("play.google.com", "example.com"):
            host = host.lstrip("www.")
            if host and host not in hosts:
                hosts.append(host)
            continue

        # Not parseable as URL — try extracting domain from text.
        notes = str(entry.get("notes") or entry.get("description") or "")
        combined = f"{target_raw} {notes}"
        import re as _re2
        found = _re2.findall(r"\b([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", combined)
        for f in found:
            h = f.lower().lstrip("www.")
            if h and h not in hosts and h not in ("example.com", "play.google.com"):
                hosts.append(h)

    for entry in (out_of_scope if isinstance(out_of_scope, list) else []):
        if isinstance(entry, str):
            parsed = urlparse(entry if "://" in entry else f"https://{entry}")
            host = (parsed.hostname or entry).lower()
            if host and host not in exclude:
                exclude.append(host)
        elif isinstance(entry, dict):
            t = str(entry.get("target") or entry.get("url") or "").lower()
            if t:
                parsed = urlparse(t if "://" in t else f"https://{t}")
                host = (parsed.hostname or t).lower()
                if host and host not in exclude:
                    exclude.append(host)

    return {
        "kind": kind,
        "name": name,
        "hosts": hosts,
        "exclude_hosts": exclude,
        "local_roots": [],
        "allow_subdomains": True,  # VDP scopes typically allow subdomains
        "engine": engine,
        "notes": f"Extracted from VDP: {path.name}",
    }


def _scope_from_raw_text(text: str, path: Path) -> dict[str, Any]:
    """Best-effort URL extraction from free-form text (AGENTS.md, Markdown, etc.)."""
    import re
    urls: list[str] = re.findall(r"https?://[^\s,;)\]]+", text or "")
    hosts: list[str] = []
    for u in urls:
        try:
            host = urlparse(u).hostname
            if host and host not in hosts:
                hosts.append(host.lower())
        except Exception:
            pass
    if not hosts:
        # Last resort: look for domains in the text.
        candidates = re.findall(r"\b([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", text)
        for c in candidates:
            if c.count(".") >= 1 and len(c) > 4 and c not in hosts and c not in ("example.com", "google.com"):
                hosts.append(c.lower())
    return {
        "kind": "url",
        "name": path.stem,
        "hosts": hosts[:100],
        "exclude_hosts": [],
        "local_roots": [],
        "allow_subdomains": False,
        "engine": "deterministic",
        "notes": f"Extracted from text: {path.name}",
    }


_ALLOWED_KINDS = {"url", "repo", "smartcontract", "api", "web"}


def _deterministic(target: str) -> dict[str, Any]:
    """Fallback scope manifest without an LLM."""
    token = (target or "").strip()
    path = Path(token).expanduser()
    try:
        if path.is_dir():
            return {
                "kind": "url",
                "name": path.name or "local",
                "hosts": [],
                "local_roots": [str(path.resolve())],
                "allow_subdomains": False,
                "engine": "review",
                "notes": "local directory (deterministic)",
            }
    except OSError:
        pass
    parsed = urlparse(token)
    host = (parsed.hostname or "").lower()
    if host:
        return {
            "kind": "url",
            "name": host,
            "hosts": [host],
            "local_roots": [],
            "allow_subdomains": False,
            "engine": "deterministic",
            "notes": "deterministic URL scope",
        }
    return {
        "kind": "url",
        "name": "unknown",
        "hosts": [],
        "local_roots": [],
        "allow_subdomains": False,
        "engine": "deterministic",
        "notes": "unrecognized target (deterministic fallback)",
    }


def _parse_json_obj(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _coerce_scope(data: dict[str, Any]) -> dict[str, Any] | None:
    kind = str(data.get("kind", "")).strip().lower()
    if kind not in _ALLOWED_KINDS:
        return None
    hosts = data.get("hosts") or []
    local_roots = data.get("local_roots") or []
    if not isinstance(hosts, list):
        hosts = []
    if not isinstance(local_roots, list):
        local_roots = []
    scope = {
        "kind": kind,
        "name": str(data.get("name") or kind),
        "hosts": [str(h).strip().lower() for h in hosts if str(h).strip()],
        "local_roots": [str(r) for r in local_roots if str(r).strip()],
        "allow_subdomains": bool(data.get("allow_subdomains", False)),
        "engine": str(data.get("engine") or "deterministic"),
        "notes": str(data.get("notes") or ""),
    }
    if kind == "repo":
        scope["git_url"] = str(data.get("git_url") or "")
    if kind == "smartcontract":
        scope["chain"] = str(data.get("chain") or "")
        scope["address"] = str(data.get("address") or "")
    if not scope["hosts"] and not scope["local_roots"]:
        return None
    return scope


def recognize(provider: Any, target: str) -> dict[str, Any]:
    """Return a scope manifest dict for ``target`` (LLM with deterministic fallback)."""
    if provider is not None:
        from hunter.agent.soul import CORE_IDENTITY

        messages = [
            {
                "role": "system",
                "content": (
                    f"{CORE_IDENTITY}\n\n"
                    "You are a scope recognizer for a security-audit harness. "
                    "Classify the target and return ONLY a JSON object with keys: "
                    "kind (url|repo|smartcontract|api|web), name, hosts (list), "
                    "local_roots (list), allow_subdomains (bool), engine, notes. "
                    "For repo add git_url; for smartcontract add chain/address. "
                    "No prose."
                ),
            },
            {"role": "user", "content": f"Target: {target}\nReturn JSON only."},
        ]
        try:
            turn = provider.complete("utility", messages, budget=None)
            data = _parse_json_obj(getattr(turn, "text", "") or "")
        except Exception:  # noqa: BLE001
            data = None
        if data is not None:
            scope = _coerce_scope(data)
            if scope is not None:
                return scope
    return _deterministic(target)


def extract_targets(provider: Any, description: str) -> list[str]:
    """Ask the LLM to extract concrete hunt targets from a free-form description.

    Returns a list of target strings. Falls back to regex URL extraction when
    the LLM is unavailable or answers something unusable.
    """
    import json as _json
    import re

    urls = re.findall(r"https?://[^\s,;)\]]+", description or "")
    if provider is not None:
        from hunter.agent.soul import CORE_IDENTITY

        messages = [
            {
                "role": "system",
                "content": (
                    f"{CORE_IDENTITY}\n\n"
                    "You extract concrete hunt targets from a free-form description. "
                    "Return ONLY a JSON array of target strings (URLs, hosts, repo "
                    "URLs, local paths). No prose."
                ),
            },
            {"role": "user", "content": f"Description: {description}\nReturn JSON array only."},
        ]
        try:
            turn = provider.complete("utility", messages, budget=None)
            text = (getattr(turn, "text", "") or "").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                text = "\n".join(lines).strip()
            start = text.find("[")
            end = text.rfind("]")
            if start != -1 and end != -1 and end > start:
                text = text[start : end + 1]
            data = _json.loads(text)
        except Exception:  # noqa: BLE001
            data = []
        if isinstance(data, list) and data:
            return [str(x).strip() for x in data if str(x).strip()]
    return urls


def recognize_scope(provider: Any, target: str) -> ScopeSet:
    """Convenience: return a :class:`ScopeSet` for ``target``."""
    manifest = recognize(provider, target)
    return ScopeSet(
        allowed_hosts=frozenset(manifest.get("hosts") or []),
        allow_subdomains=bool(manifest.get("allow_subdomains", False)),
        name=str(manifest.get("name") or "scope"),
        local_roots=tuple(manifest.get("local_roots") or []),
    )
