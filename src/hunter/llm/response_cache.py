"""Short-lived response cache / request de-dup for identical LLM calls.

An agent loop sometimes emits the exact same prompt twice (e.g. a retry at a
higher layer, or two parallel tool calls with identical context). Without a
cache each of those is a billed provider hit. This module hashes the request
shape and reuses a successful :class:`TurnResult` within a short TTL.

Rules
-----
* Only successful, non-streaming responses are cached. Errors and streaming
  callbacks are never replayed silently.
* A 429 clears the provider's cached entries — stale successes must not be
  served while a provider is throttling us.
* Thread-safe: the singleton is shared by every NativeProvider in the process.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from hunter.llm.base import TurnResult

__all__ = ["ResponseCache", "cache", "cache_key"]


def _freeze(value: Any) -> Any:
    """Best-effort stable snapshot for hashing (dicts/lists/scalars)."""
    if isinstance(value, dict):
        return {str(k): _freeze(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_freeze(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def cache_key(tier: str, messages: list[dict], tools: list[dict] | None, route: Any) -> str:
    """Deterministic SHA-256 over everything that affects the response."""
    payload = {
        "tier": tier,
        "messages": _freeze(messages),
        "tools": _freeze(tools) if tools else None,
        "model": getattr(route, "model", ""),
        "provider": getattr(route, "provider", ""),
        "base_url": getattr(route, "base_url", ""),
        "reasoning_effort": getattr(route, "reasoning_effort", ""),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ResponseCache:
    """TTL cache of successful TurnResults, keyed by :func:`cache_key`."""

    def __init__(self, ttl_seconds: float = 60.0) -> None:
        self._ttl = max(0.0, float(ttl_seconds))
        self._entries: dict[str, tuple[float, TurnResult, str]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> TurnResult | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, result, _provider = entry
            if self._ttl <= 0 or time.monotonic() - stored_at > self._ttl:
                self._entries.pop(key, None)
                return None
            return result

    def put(self, key: str, value: TurnResult, provider: str = "") -> TurnResult:
        if self._ttl > 0:
            with self._lock:
                self._entries[key] = (time.monotonic(), value, provider)
        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def clear_provider(self, provider: str) -> None:
        with self._lock:
            stale = [k for k, (_t, _v, p) in self._entries.items() if p == provider]
            for key in stale:
                self._entries.pop(key, None)


cache = ResponseCache()
