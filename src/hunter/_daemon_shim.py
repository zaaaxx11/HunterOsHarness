"""Daemon compatibility shim — noop stubs for the post-daemon world.

The daemon infrastructure has been removed. All callers that previously
imported `daemon_status`, `start_daemon`, `stop_daemon` now import from
this module instead. Every function returns a safe fallback so the TUI,
doctor, gateway, and lease subsystems continue to render without errors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def daemon_status(state_dir: str | Path | None = None) -> dict[str, Any]:
    return {
        "running": False,
        "pid": 0,
        "uptime_seconds": 0,
        "heartbeat_age_seconds": 0,
        "queue_pending": 0,
        "queue_claimed": 0,
        "paused": False,
        "drain": False,
        "last_run": {},
        "last_run_id": None,
    }


def start_daemon(*args: Any, **kwargs: Any) -> int:
    return 0


def stop_daemon(*args: Any, **kwargs: Any) -> None:
    pass


def daemon_running(*args: Any, **kwargs: Any) -> tuple[bool, str]:
    return False, "daemon removed — use `hunter loop` instead"


def enqueue_hunt(*args: Any, **kwargs: Any) -> None:
    pass


def enqueue_hunts(*args: Any, **kwargs: Any) -> int:
    return 0


def enqueue_task(*args: Any, **kwargs: Any) -> None:
    pass


def pause_flag_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "pause.flag"


def queue_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "queue"


def process_identity(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return {"pid": 0, "proc_identity_verified": False}


def dispatch_hunt_alias(*args: Any, **kwargs: Any) -> int:
    return 3  # refused — use hunter loop


def register_daemon_commands(*args: Any, **kwargs: Any) -> None:
    pass


def _parse_duration_or_exit(*args: Any, **kwargs: Any) -> float:
    return 0.0


def _cmd_start(*args: Any, **kwargs: Any) -> int:
    return 3


def _cmd_stop(*args: Any, **kwargs: Any) -> int:
    return 0


def _cmd_status(*args: Any, **kwargs: Any) -> int:
    return 0


def _cmd_restart(*args: Any, **kwargs: Any) -> int:
    return 3


def _cmd_logs(*args: Any, **kwargs: Any) -> int:
    return 0


def _validate_hunt_task(*args: Any, **kwargs: Any) -> None:
    pass


def stop_flag_path(*args: Any, **kwargs: Any) -> Path:
    return Path("/dev/null")


def start_daemon_locked(*args: Any, **kwargs: Any) -> int:
    return 0


def spawn_detached(*args: Any, **kwargs: Any) -> None:
    pass


def drain_daemon(*args: Any, **kwargs: Any) -> None:
    pass


def log_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "daemon.log"


def heartbeat_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "heartbeat.json"


def pid_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "pid.json"


def daemon_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon"


def drain_flag_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "drain.flag"


def restart_marker_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon" / "restart.json"


def claim_task(*args: Any, **kwargs: Any) -> dict[str, Any] | None:
    return None


def existing_targets(state_dir: str | Path) -> set[str]:
    return set()
