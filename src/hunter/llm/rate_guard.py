"""Cross-session rate-limit guard — shared state file for provider cooldowns.

Mirrors Hermes `nous_rate_guard.py`: when one HunterOsHunt session hits a rate
limit, all concurrent/sequential hunts targeting the same provider see the
cooldown before they dial — no wasted 429s.

State file: ``~/.hunter/rate_limits/<provider>.json``
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path

__all__ = ["record", "remaining", "clear"]


def _state_dir() -> Path:
    """Canonical rate-limit state directory. Defaults to ~/.hunter/rate_limits."""
    env = os.environ.get("HUNTEROS_STATE_DIR")
    base = Path(env) if env else Path.home() / ".hunter"
    return base / "rate_limits"


def record(
    provider: str,
    *,
    headers: Any | None = None,
    error_context: dict[str, Any] | None = None,
    default_cooldown: float = 300.0,
) -> None:
    """Write a rate-limit cooldown to the shared state file.

    *provider* — canonical provider name (e.g. ``"customin"``, ``"devora"``).
    *headers* — optional HTTP response headers; ``Retry-After`` wins over
      *default_cooldown*.
    *error_context* — reserved for future body-parsed resets; currently unused.
    """
    now = time.time()
    reset_at = now + default_cooldown

    # Honour Retry-After from headers if present.
    if headers is not None:
        getter = getattr(headers, "get", None)
        if callable(getter):
            for key in ("retry-after", "Retry-After"):
                try:
                    raw = getter(key)
                    if raw:
                        parsed = min(float(raw), 3600.0)
                        if parsed > 0:
                            reset_at = now + parsed
                            break
                except (TypeError, ValueError):
                    continue

    path = _state_dir() / f"{provider}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps({"reset_at": reset_at, "recorded_at": now}))
    except OSError:
        pass


def remaining(provider: str) -> float | None:
    """Seconds until provider cooldown resets, or None if not rate-limited.

    Returns a positive float while the cooldown is active; expired state files
    are silently removed.
    """
    path = _state_dir() / f"{provider}.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8-sig"))
        r = float(state.get("reset_at", 0)) - time.time()
        if r > 0:
            return r
        with contextlib.suppress(OSError):
            path.unlink()
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError):
        pass
    return None


def clear(provider: str) -> None:
    """Remove the rate-limit cooldown for *provider* (call after a successful request)."""
    try:
        (_state_dir() / f"{provider}.json").unlink(missing_ok=True)
    except OSError:
        pass