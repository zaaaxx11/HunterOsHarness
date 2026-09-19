"""ESTOP — resumable pause for NEW gateway turns only.

WHY: an operator pause must refuse new turns while in-flight turns always
complete. pause.flag body is JSON {reason, engaged_at}; a corrupt/empty
file still counts as engaged (fail safe). stop.flag kills via the
budget's exhausted() first. Log once per engagement.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "is_engaged",
    "engage",
    "resume",
    "describe",
    "should_accept_new_turn",
    "should_kill_inflight",
]

_lock = threading.Lock()
_logged: set[str] = set()


def _pause_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "pause.flag"


def _stop_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "stop.flag"


def is_engaged(state_dir: str | Path) -> bool:
    try:
        return _pause_path(state_dir).exists()
    except OSError:
        return True


def engage(state_dir: str | Path, reason: str = "") -> None:
    import contextlib

    path = _pause_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"reason": reason or "", "engaged_at": time.time()}
    try:
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        with contextlib.suppress(OSError):
            path.touch(exist_ok=True)


def resume(state_dir: str | Path) -> None:
    import contextlib

    with contextlib.suppress(OSError):
        _pause_path(state_dir).unlink(missing_ok=True)
    with _lock:
        _logged.discard(str(state_dir))


def describe(state_dir: str | Path) -> dict[str, Any]:
    path = _pause_path(state_dir)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {"reason": "", "engaged_at": ""}
    if not raw.strip():
        return {"reason": "", "engaged_at": ""}
    try:
        data = json.loads(raw)
    except ValueError:
        return {"reason": "", "engaged_at": ""}
    if not isinstance(data, dict):
        return {"reason": "", "engaged_at": ""}
    return {"reason": str(data.get("reason") or ""), "engaged_at": data.get("engaged_at") or ""}


def should_accept_new_turn(state_dir: str | Path) -> bool:
    """False while paused; logs once per engagement."""
    if not is_engaged(state_dir):
        with _lock:
            _logged.discard(str(state_dir))
        return True
    with _lock:
        first = str(state_dir) not in _logged
        _logged.add(str(state_dir))
    if first:
        logger.info("estop engaged; refusing new turn (%s)", state_dir)
    return False


def should_kill_inflight(state_dir: str | Path, budget: Any = None) -> bool:
    """In-flight ALWAYS completes on pause; only stop.flag kills (via exhausted)."""
    if budget is not None:
        fn = getattr(budget, "exhausted", None)
        if callable(fn):
            try:
                reason = fn()
            except Exception:
                return False
            return reason is not None and "stop file" in str(reason)
        return False
    try:
        return _stop_path(state_dir).is_file()
    except OSError:
        return False
