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

__all__ = ["recognize", "recognize_scope"]


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
        messages = [
            {
                "role": "system",
                "content": (
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
        messages = [
            {
                "role": "system",
                "content": (
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
