"""Auto-failover provider — no config required.

Scans ``~/.hermes/config.yaml`` for every usable OpenAI-compatible provider,
probes them with a 1-token ping, and keeps a TTL-cached alive-list. The
``FailoverLLM`` adapter wraps any single LLM and transparently retries on the
next alive provider when the primary fails.

Design contract
---------------
* No new config file or env var. Reads the Hermes config that already exists.
* Alive list is re-probed every 300 s (5 min), so a provider that comes back
  online is picked up automatically.
* Providers whose key is ``sk-xxx...yyy`` (masked) are skipped.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

_HERMES_CONFIG = Path(os.path.expanduser("~/.hermes/config.yaml"))
_CACHE_TTL = 300  # seconds


# ── discovery ──────────────────────────────────────────────────────

def _discover_providers() -> list[dict]:
    """Read every OpenAI-compatible provider from the Hermes config."""
    if not _HERMES_CONFIG.exists():
        return []
    try:
        import yaml
        cfg = yaml.safe_load(_HERMES_CONFIG.read_text())
    except Exception:
        return []
    out: list[dict] = []
    for p in (cfg.get("custom_providers") or []):
        if not isinstance(p, dict):
            continue
        key = str(p.get("api_key") or "")
        base = str(p.get("base_url") or "")
        if not base or not key or "..." in key:
            continue
        models = list((p.get("models") or {}).keys())
        if key.startswith("sk-") and len(models) > 0:
            model = next((m for m in models if "flash" in m), models[0])
            out.append({"name": p.get("name", base), "base": base,
                        "key": key, "model": model})
    return out


# ── cache ──────────────────────────────────────────────────────────

_alive_cache: dict[str, Any] = {}


def alive_providers(force: bool = False) -> list[dict[str, str]]:
    """Return currently-alive providers, re-probing if the cache is stale."""
    now = time.time()
    if not force and _alive_cache.get("ts", 0) > now - _CACHE_TTL:
        return _alive_cache.get("list", [])

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    alive: list[dict[str, str]] = []
    for p in _discover_providers():
        payload = json.dumps({
            "model": p["model"], "max_tokens": 2,
            "messages": [{"role": "user", "content": "ok"}],
        }).encode()
        try:
            req = urllib.request.Request(
                f"{p['base']}/chat/completions",
                data=payload,
                headers={"Authorization": f"Bearer {p['key']}",
                         "Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
                if "choices" in d:
                    alive.append(p)
        except Exception:
            pass
    _alive_cache["ts"] = now
    _alive_cache["list"] = alive
    return alive


# ── adapter ────────────────────────────────────────────────────────

class FailoverLLM:
    """Wraps a primary LLM; transparently fails over on error.

    Usage::

        llm = FailoverLLM(my_primary, log=print)
        llm.complete(system, user)          # auto-failover on crash
        llm.complete_with_tools(s, u, t)    # same
    """

    def __init__(self, primary: Any, log: Any = None):
        self.primary = primary
        self.log = log or (lambda m: None)
        self._fallback: list[dict] = []
        self._built: dict[str, Any] = {}

    def _next(self) -> Any:
        """Return the next available provider adapter or None."""
        if not self._fallback:
            # pick an alive provider different from the primary name
            primary_name = getattr(self.primary, "name", None)
            for p in alive_providers():
                if p.get("name") != primary_name:
                    self._fallback.append(p)
        if not self._fallback:
            return None
        p = self._fallback.pop(0)
        key = f"{p['base']}|{p['model']}"
        if key not in self._built:
            self._built[key] = _SimpleCompatLLM(p["base"], p["key"], p["model"])
        return self._built[key]

    def _try(self, method: str, *args, **kw):
        """Call method on primary, then every fallback, then None."""
        primary_fn = getattr(self.primary, method, None)
        if callable(primary_fn):
            try:
                return primary_fn(*args, **kw)
            except Exception as e:
                self.log(f"[failover] primary {type(e).__name__}: {e}")
        for _ in range(len(self._fallback) + 1):
            fb = self._next()
            if fb is None:
                break
            fn = getattr(fb, method, None)
            if not callable(fn):
                continue
            try:
                self.log(f"[failover] -> {getattr(fb, 'name', '?')}/{getattr(fb, 'model', '?')}")
                return fn(*args, **kw)
            except Exception as e:
                self.log(f"[failover] {getattr(fb,'name','?')} {type(e).__name__}: {e}")
                continue
        # total failure: return empty
        if method == "complete_with_tools":
            return {"text": "", "tool_calls": [], "cost": 0.0}
        return ""

    def complete(self, system: str, user: str) -> str:
        out = self._try("complete", system, user)
        return out if isinstance(out, str) else str(out or "")

    def complete_with_tools(self, system: str, user: str, tools,
                            tool_choice=None) -> dict:
        out = self._try("complete_with_tools", system, user, tools,
                        tool_choice=tool_choice)
        if isinstance(out, dict):
            return out
        return {"text": str(out or ""), "tool_calls": [], "cost": 0.0}


class _SimpleCompatLLM:
    """Minimal OpenAI-compatible client — no extra deps."""

    def __init__(self, base: str, key: str, model: str):
        self.base = base
        self.key = key
        self.model = model
        self.name = self.model
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _post(self, messages, tools=None, tool_choice=None):
        payload: dict[str, Any] = {
            "model": self.model, "max_tokens": 6000, "messages": messages}
        if tools:
            payload["tools"] = tools
        if tool_choice:
            payload["tool_choice"] = tool_choice
        req = urllib.request.Request(
            f"{self.base}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120, context=self._ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def _turn(self, system, user, tools=None, tool_choice=None):
        msgs = [{"role": "system", "content": system},
                {"role": "user", "content": user}]
        return self._post(msgs, tools=tools, tool_choice=tool_choice)

    def complete(self, system, user):
        d = self._turn(system, user)
        if d and "choices" in d:
            return d["choices"][0].get("message", {}).get("content", "")
        return ""

    def complete_with_tools(self, system, user, tools, tool_choice=None):
        d = self._turn(system, user, tools=tools, tool_choice=tool_choice)
        if d and "choices" in d:
            msg = d["choices"][0].get("message", {})
            calls: list[dict] = []
            for tc in (msg.get("tool_calls") or []):
                fn = tc.get("function", {})
                args = fn.get("arguments", "{}")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                calls.append({"name": fn.get("name", ""), "arguments": args})
            return {"text": msg.get("content", ""), "tool_calls": calls, "cost": 0.0}
        return {"text": "", "tool_calls": [], "cost": 0.0}