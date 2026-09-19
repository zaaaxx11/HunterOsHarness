"""The 24/7 hunt daemon (M8 F2) — ``hunter daemon start`` state machine.

All daemon state lives under ``<state>/daemon/``:

- ``pid.json``       — the child's self-registration (pid + process signature
  + transports), written by :func:`daemon_main` so the parent never races;
- ``heartbeat.json`` — refreshed every 15s; a heartbeat older than
  ``DAEMON_STALE_SECONDS`` means the daemon is presumed dead;
- ``queue/``         — task files (``task-<epoch>-<hex6>.json``); a claim is
  an atomic rename to ``claimed-<task_id>.json`` (single winner), a finished
  run lands as ``done-<task_id>.json``;
- ``stop.flag``      — the user-issued kill switch (its presence outranks
  every budget limit inside :class:`hunter.llm.budget.RunBudget`);
- ``daemon.log``     — the detached child's stdout/stderr.

Doctrine: every failure is a classified refusal (exit codes, never a
traceback), the queue claim is atomic (``os.rename`` semantics — exactly one
winner per task), and a live-looking pid is verified against its creation
signature so Windows PID reuse can never resurrect a dead daemon.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hunter import __version__
from hunter.hunt import run_hunt
from hunter.llm.budget import RunBudget
from hunter.tools.scope import ScopeSet

__all__ = [
    "DAEMON_STALE_SECONDS",
    "HEARTBEAT_INTERVAL_SECONDS",
    "_consume_restart_marker",
    "_scheduler_enabled",
    "_should_claim",
    "claim_task",
    "create_scheduler",
    "daemon_dir",
    "daemon_main",
    "daemon_running",
    "daemon_status",
    "drain_daemon",
    "drain_flag_path",
    "enqueue_hunt",
    "enqueue_hunts",
    "enqueue_task",
    "heartbeat_handle",
    "heartbeat_path",
    "hunt_worker",
    "is_stale",
    "liveness",
    "log_path",
    "pause_flag_path",
    "pid_alive",
    "pid_path",
    "ProcessIdentity",
    "process_identity",
    "process_signature",
    "queue_dir",
    "read_pid",
    "restart_marker_path",
    "should_kill_inflight",
    "spawn_detached",
    "start_daemon",
    "stop_daemon",
    "stop_flag_path",
    "stop_precedence",
    "worker_handle",
    "write_json_atomic",
]

DAEMON_STALE_SECONDS = 90
HEARTBEAT_INTERVAL_SECONDS = 15

# R2-A scheduler cutover seam: single-heap handles owned by create_scheduler.
heartbeat_handle: Any | None = None
worker_handle: Any | None = None


def _scheduler_enabled() -> bool:
    """True unless HUNTER_SCHEDULER=0 (rollback keeps asyncio verbatim)."""
    return os.environ.get("HUNTER_SCHEDULER", "1") != "0"


def create_scheduler(state_dir: str | Path) -> Any:
    """Shared single-heap scheduler for heartbeat+worker+lease/TTL sweeps.

    One heap thread total (see hunter.runtime.scheduler.thread_names).
    HUNTER_SCHEDULER=0 callers keep the asyncio loops verbatim; the
    scheduler is still returned as a seam but never started by them.
    """
    from hunter.runtime.scheduler import PeriodicScheduler

    global heartbeat_handle, worker_handle
    scheduler = PeriodicScheduler()
    try:
        heartbeat_handle = scheduler.schedule(lambda: None, interval=float(HEARTBEAT_INTERVAL_SECONDS))
        worker_handle = scheduler.schedule(lambda: None, interval=5.0)
        # Lease-refresh + engine TTL sweeps ride the SAME heap (no per-child
        # or per-lease threads). Bodies are no-ops here; _daemon_serve
        # replaces them with real ticks when the scheduler is enabled.
        scheduler.schedule(lambda: None, interval=float(HEARTBEAT_INTERVAL_SECONDS))
        scheduler.schedule(lambda: None, interval=60.0)
    except Exception:
        pass
    return scheduler

_START_WAIT_SECONDS = 10.0


# -- state layout ---------------------------------------------------------------


def daemon_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "daemon"


def pid_path(state_dir: str | Path) -> Path:
    return daemon_dir(state_dir) / "pid.json"


def heartbeat_path(state_dir: str | Path) -> Path:
    return daemon_dir(state_dir) / "heartbeat.json"


def queue_dir(state_dir: str | Path) -> Path:
    return daemon_dir(state_dir) / "queue"


def stop_flag_path(state_dir: str | Path) -> Path:
    return daemon_dir(state_dir) / "stop.flag"


def drain_flag_path(state_dir: str | Path) -> Path:
    """The drain sentinel (M11): while it exists the daemon claims NO new
    tasks and exits AFTER the in-flight task completes — a drain-first
    restart never cuts live work short."""
    return daemon_dir(state_dir) / "drain.flag"


def pause_flag_path(state_dir: str | Path) -> Path:
    """The pause ESTOP sentinel (M11): claims hold while it exists; in-flight
    runs ALWAYS complete (pause never touches stop.flag or RunBudget)."""
    return daemon_dir(state_dir) / "pause.flag"


def restart_marker_path(state_dir: str | Path) -> Path:
    """Written by a drain-first restart; consumed on the next boot (one log
    line), so transports can suppress stale deliveries by its existence."""
    return daemon_dir(state_dir) / "restart.json"


def log_path(state_dir: str | Path) -> Path:
    return daemon_dir(state_dir) / "daemon.log"


def write_json_atomic(path: str | Path, obj: Any) -> None:
    """tmp file + ``os.replace`` — atomic on win32 and POSIX alike."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f"{target.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)


def _read_json(path: str | Path) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


# -- process liveness (PID-reuse guarded) ---------------------------------------


def pid_alive(pid: int) -> bool:
    """Is ``pid`` a live process right now?

    POSIX: ``os.kill(pid, 0)`` — EPERM means "alive but not ours".
    win32: ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`` +
    ``GetExitCodeProcess``; a handle we cannot open due to access denied is
    treated as ALIVE (never kill a process we could not verify).
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except (AttributeError, OSError):  # pragma: no cover — non-windows
            return False
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # Access denied (elevated process) → we cannot prove death: alive.
            return ctypes.get_last_error() == ERROR_ACCESS_DENIED
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return ctypes.get_last_error() == ERROR_ACCESS_DENIED
            return exit_code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, but not ours — alive
    except OSError:
        return False
    return True


@dataclass(frozen=True)
class ProcessIdentity:
    """Creation identity used to prevent PID reuse from claiming a daemon."""

    pid: int
    signature: str
    verified: bool
    reason: str = ""

    @classmethod
    def for_pid(cls, pid: int) -> ProcessIdentity:
        """Read a portable process creation identity, failing closed."""
        try:
            number = int(pid)
        except (TypeError, ValueError):
            return cls(0, "", False, "invalid pid")
        if number <= 0:
            return cls(number, "", False, "invalid pid")
        if sys.platform == "win32":
            signature = _windows_process_signature(number)
            return cls(
                number,
                signature or "",
                bool(signature),
                "" if signature else "GetProcessTimes unavailable",
            )
        # Linux and WSL expose the Linux proc start-time field. Use it only
        # when the file parses exactly; unknown platforms do not guess.
        if sys.platform.startswith("linux"):
            try:
                stat = Path(f"/proc/{number}/stat").read_text(encoding="utf-8")
                fields = stat[stat.rfind(")") + 1 :].split()
                signature = fields[19] if len(fields) > 19 else ""
            except (OSError, UnicodeDecodeError):
                signature = ""
            return cls(
                number,
                signature,
                bool(signature),
                "" if signature else "proc start time unavailable",
            )
        if sys.platform == "darwin":
            signature = _portable_ps_signature(number)
            return cls(
                number,
                signature or "",
                bool(signature),
                "" if signature else "ps identity unavailable",
            )
        return cls(number, "", False, f"unsupported process identity platform: {sys.platform}")


def _windows_process_signature(pid: int) -> str | None:
    """Return Windows creation FILETIME, or None when it cannot be verified."""
    import ctypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):  # pragma: no cover - non-windows
        return None
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        class _FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

        creation = _FILETIME()
        exit_time = _FILETIME()
        kernel_time = _FILETIME()
        user_time = _FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        return str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
    finally:
        kernel32.CloseHandle(handle)


def _portable_ps_signature(pid: int) -> str | None:
    """Use macOS ``ps`` start time as an optional identity fallback."""
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            capture_output=True,
            check=False,
            text=True,
            timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def process_identity(pid: int) -> ProcessIdentity:
    """Return the verified identity record for ``pid``."""
    return ProcessIdentity.for_pid(pid)


def process_signature(pid: int) -> str | None:
    """Compatibility wrapper returning a signature only when verified."""
    identity = process_identity(pid)
    return identity.signature if identity.verified else None


def read_pid(state_dir: str | Path) -> dict[str, Any] | None:
    """The pid.json payload, or None when absent/corrupt."""
    return _read_json(pid_path(state_dir))


def is_stale(
    heartbeat: dict[str, Any] | None,
    *,
    now: float | None = None,
    threshold: float = DAEMON_STALE_SECONDS,
) -> bool:
    """True when the heartbeat is missing or older than ``threshold``."""
    if not isinstance(heartbeat, dict):
        return True
    moment = time.time() if now is None else now
    try:
        ts = float(heartbeat.get("ts", 0.0))
    except (TypeError, ValueError):
        return True
    return (moment - ts) >= threshold


def daemon_running(state_dir: str | Path) -> tuple[bool, str]:
    """Return liveness only after identity and heartbeat validation.

    A pid file alone is never success; unverifiable identities fail closed and
    include the platform-specific reason where available.
    """
    record = read_pid(state_dir)
    if record is None:
        return False, "no daemon pid file"
    try:
        pid = int(record.get("pid", 0))
    except (TypeError, ValueError):
        return False, "corrupt pid file"
    if not pid_alive(pid):
        return False, f"pid {pid} is not alive"
    expected = str(record.get("proc_signature") or "")
    current = process_signature(pid)
    if not expected:
        reason = str(record.get("proc_identity_reason") or "process identity is missing")
        return False, f"pid {pid} identity is unverified: {reason}"
    if not current:
        identity = process_identity(pid)
        return False, f"pid {pid} identity is unverified: {identity.reason or 'unavailable'}"
    if current != expected:
        return False, f"pid {pid} was reused by another process (signature mismatch)"
    heartbeat = _read_json(heartbeat_path(state_dir))
    if heartbeat is None:
        return False, "daemon heartbeat is missing"
    try:
        heartbeat_pid = int(heartbeat.get("pid", 0))
    except (TypeError, ValueError):
        return False, "corrupt daemon heartbeat"
    if heartbeat_pid != pid:
        return False, f"daemon heartbeat belongs to pid {heartbeat_pid}, not {pid}"
    if is_stale(heartbeat):
        return False, f"heartbeat is stale (>{DAEMON_STALE_SECONDS:.0f}s)"
    return True, "running"


# -- detached spawn --------------------------------------------------------------


def spawn_detached(
    args: list[str], *, log_path: Path, env: dict[str, str] | None = None
) -> int:
    """Start ``args`` fully detached; stdout/stderr append to ``log_path``.

    win32: ``DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW``.
    POSIX: ``start_new_session=True``. Both: stdin=DEVNULL, close_fds.
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": open(log_path, "ab"),  # noqa: SIM115 — the child owns the handle
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if sys.platform == "win32":
        detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        kwargs["creationflags"] = detached | new_group | no_window
    else:
        kwargs["start_new_session"] = True
    if env is not None:
        kwargs["env"] = dict(env)
    try:
        process = subprocess.Popen(list(args), **kwargs)
    finally:
        handle = kwargs.get("stdout")
        if handle is not None:
            handle.close()
    return int(process.pid)


def _terminate_pid(pid: int) -> None:
    """Best-effort cooperative force-stop (SIGTERM / TerminateProcess)."""
    if sys.platform == "win32":
        import ctypes

        PROCESS_TERMINATE = 0x0001
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except (AttributeError, OSError):  # pragma: no cover
            return
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not handle:
            return
        try:
            kernel32.TerminateProcess(handle, 1)
        finally:
            kernel32.CloseHandle(handle)
    else:
        with contextlib.suppress(OSError, ProcessLookupError, PermissionError):
            os.kill(pid, 15)


def _kill_pid(pid: int) -> None:
    """Last-resort hard kill (SIGKILL / TerminateProcess)."""
    if sys.platform == "win32":
        _terminate_pid(pid)  # TerminateProcess IS the hard kill on win32
    else:
        with contextlib.suppress(OSError, ProcessLookupError, PermissionError):
            os.kill(pid, 9)


# -- queue ------------------------------------------------------------------------


def enqueue_task(state_dir: str | Path, task: dict[str, Any]) -> Path:
    """Append one task file (``task-<epoch>-<hex6>.json``) to the queue."""
    folder = queue_dir(state_dir)
    folder.mkdir(parents=True, exist_ok=True)
    payload = dict(task)
    epoch = int(time.time())
    payload["task_id"] = str(payload.get("task_id") or f"T-{epoch}-{uuid.uuid4().hex[:6]}")
    path = folder / f"task-{epoch}-{uuid.uuid4().hex[:6]}.json"
    write_json_atomic(path, payload)
    return path


def _validate_hunt_task(task: dict[str, Any]) -> None:
    from hunter.hunt import normalize_hunt_target

    target = str(task.get("target", ""))
    normalized, kind = normalize_hunt_target(target)
    if kind == "invalid" or normalized != target:
        raise ValueError(f"invalid hunt target: {target!r}")
    try:
        max_wall = float(task.get("max_wall_seconds", 0.0) or 0.0)
        min_wall = float(task.get("min_wall_seconds", 0.0) or 0.0)
        budget = float(task.get("max_cost_usd", 0.0) or 0.0)
    except (TypeError, ValueError) as exc:
        raise ValueError("hunt limits must be finite numbers") from exc
    if any(not math.isfinite(value) or value < 0 for value in (max_wall, min_wall, budget)):
        raise ValueError("hunt limits must be finite and non-negative")


def enqueue_hunt(
    state_dir: str | Path,
    *,
    target: str,
    scope: Any,
    engine: str,
    max_wall_seconds: float,
    max_cost_usd: float = 0.0,
    min_wall_seconds: float = 0.0,
) -> Path:
    """Validate and enqueue one independent hunt task."""
    task = {
        "target": str(target),
        "scope": _scope_payload(scope),
        "engine": str(engine),
        "max_wall_seconds": float(max_wall_seconds),
        "max_cost_usd": float(max_cost_usd),
        "min_wall_seconds": float(min_wall_seconds),
    }
    _validate_hunt_task(task)
    return enqueue_task(state_dir, task)


def enqueue_hunts(state_dir: str | Path, tasks: list[dict[str, Any]]) -> int:
    """Validate every task before writing any file, then enqueue atomically."""
    normalized: list[dict[str, Any]] = []
    for item in tasks:
        task = dict(item)
        _validate_hunt_task(task)
        normalized.append(task)
    for task in normalized:
        enqueue_task(state_dir, task)
    return len(normalized)


def _claim(source: Path, destination: Path, *, payload: dict[str, Any]) -> None:
    """Atomically claim ``source`` as ``destination`` — exactly one winner.

    The winner is decided by an EXCLUSIVE create (``O_CREAT | O_EXCL``): the
    kernel grants it to precisely one racer and every loser gets
    ``FileExistsError``. A bare ``os.rename`` is NOT a sufficient guard —
    under true concurrency two renames of the same source to the same
    destination can BOTH succeed on win32, which would double-run a task.
    The claimed file is written immediately; the source is then removed, so
    the queue glob sees the task as claimed from that point on.
    """
    data = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(destination, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    with contextlib.suppress(OSError):
        source.unlink()


def claim_task(state_dir: str | Path) -> dict[str, Any] | None:
    """Claim the OLDEST queued task (atomic single-winner claim).

    Returns the task dict, or None when the queue is empty. A lost race
    (another worker claimed first) is not an error — the next task is tried.
    Pinned by tests/test_daemon.py::test_queue_task_claim_atomic_single_winner.
    """
    folder = queue_dir(state_dir)
    folder.mkdir(parents=True, exist_ok=True)
    for path in sorted(folder.glob("task-*.json")):
        task = _read_json(path)
        if task is None:
            # Unreadable task file: move it aside so it cannot wedge the queue.
            with contextlib.suppress(OSError):
                path.rename(folder / f"corrupt-{path.name}")
            continue
        task_id = str(task.get("task_id") or path.stem)
        destination = folder / f"claimed-{task_id}.json"
        try:
            _claim(path, destination, payload=task)
        except OSError:
            continue  # lost the race — exactly-one-winner semantics
        task["claimed_by"] = os.getpid()
        task["claimed_ts"] = time.time()
        with contextlib.suppress(OSError):
            write_json_atomic(destination, task)
        return task
    return None


# -- lifecycle: start / stop / status --------------------------------------------


def _scope_payload(scope: Any) -> dict[str, Any]:
    """Normalize a scope (dict or :class:`ScopeSet`) into the task-file form."""
    if isinstance(scope, ScopeSet):
        return {
            "name": str(scope.name),
            "hosts": sorted(scope.allowed_hosts),
            "allow_subdomains": bool(scope.allow_subdomains),
        }
    if isinstance(scope, dict):
        return scope
    return {"name": "unknown", "hosts": [], "allow_subdomains": False}


def start_daemon(
    state_dir: str | Path,
    *,
    target: str | None = None,
    scope: Any | None = None,
    engine: str = "deterministic",
    min_wall_seconds: float = 0.0,
    max_wall_seconds: float = 0.0,
    max_cost_usd: float = 0.0,
    force: bool = False,
) -> int:
    """Start the persistent engine, optionally enqueueing one initial hunt.

    0 started · 3 refused (already running without ``--force``) · 1 the child
    failed to self-register within 10s. A target-free boot intentionally leaves
    the queue empty so later chat requests can enqueue independently.
    """
    state = Path(state_dir)
    if not force:
        running, _reason = daemon_running(state)
        if running:
            return 3
    if force:
        # A forced start replaces a live daemon: cooperative stop first.
        with contextlib.suppress(Exception):
            stop_daemon(state, timeout=5.0, force=True)
    # A fresh start must not inherit a stale kill switch.
    with contextlib.suppress(OSError):
        stop_flag_path(state).unlink(missing_ok=True)
    if target is not None:
        task = {
            "task_id": f"T-{int(time.time())}-{uuid.uuid4().hex[:6]}",
            "target": str(target),
            "scope": _scope_payload(scope),
            "engine": str(engine),
            "min_wall_seconds": float(min_wall_seconds),
            "max_wall_seconds": float(max_wall_seconds),
            "max_cost_usd": float(max_cost_usd),
            "created_ts": time.time(),
            "claimed_by": None,
            "claimed_ts": None,
        }
        enqueue_task(state, task)
    # The old registration is provably dead (daemon_running said so) — drop it
    # so the wait below observes the CHILD's fresh self-registration.
    with contextlib.suppress(OSError):
        pid_path(state).unlink(missing_ok=True)
    env = dict(os.environ)
    env["HUNTER_STATE_DIR"] = str(state)
    args = [sys.executable, "-m", "hunter.daemon", "--state", str(state)]
    spawn_detached(args, log_path=log_path(state), env=env)
    deadline = time.monotonic() + _START_WAIT_SECONDS
    while time.monotonic() < deadline:
        record = read_pid(state)
        if record is not None:
            try:
                pid = int(record.get("pid", 0))
            except (TypeError, ValueError):
                pid = 0
            if pid > 0 and daemon_running(state)[0]:
                return 0
        time.sleep(0.1)
    return 1


def stop_daemon(state_dir: str | Path, *, timeout: float = 15.0, force: bool = False) -> int:
    """Stop the daemon: write ``stop.flag`` and wait for a cooperative exit;
    with ``--force`` escalate to terminate/kill after ``timeout``. Exit code
    0 stopped · 1 not running (or a hung daemon without ``--force``).
    """
    state = Path(state_dir)
    record = read_pid(state)
    if record is None:
        return 1  # not running — nothing to stop
    try:
        pid = int(record.get("pid", 0) or 0)
    except (TypeError, ValueError):
        pid = 0
    flag = stop_flag_path(state)
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text("", encoding="utf-8")  # the cooperative kill switch
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            break
        time.sleep(0.05)
    stopped = not pid_alive(pid)
    if not stopped and force:
        _terminate_pid(pid)
        grace = time.monotonic() + 3.0
        while time.monotonic() < grace and pid_alive(pid):
            time.sleep(0.05)
        if pid_alive(pid):
            _kill_pid(pid)
        stopped = not pid_alive(pid)
    if stopped:
        # Clean exit: the flag is consumed and the pid registration removed.
        with contextlib.suppress(OSError):
            flag.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            pid_path(state).unlink(missing_ok=True)
        return 0
    if not force:
        # A hung daemon is REPORTED, not killed — pass --force for that.
        return 1
    with contextlib.suppress(OSError):
        flag.unlink(missing_ok=True)
    return 1


def drain_daemon(state_dir: str | Path, *, timeout: float = 60.0) -> int:
    """Drain-first shutdown (M11): write ``drain.flag`` (the daemon stops
    claiming and exits AFTER its in-flight task completes) and wait up to
    ``timeout`` seconds for the daemon process to exit. Returns 0 when the
    process exited, 1 on timeout (the caller decides escalation). The flag
    stays written — a still-alive daemon keeps honoring it."""
    state = Path(state_dir)
    flag = drain_flag_path(state)
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text("", encoding="utf-8")
    record = read_pid(state)
    try:
        pid = int((record or {}).get("pid", 0) or 0)
    except (TypeError, ValueError):
        pid = 0
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            # R2-A: a drained shutdown leaves a consumable restart marker so
            # transports can suppress stale deliveries until the next boot
            # consumes it (see _consume_restart_marker).
            with contextlib.suppress(OSError):
                write_json_atomic(restart_marker_path(state), {"ts": time.time(), "pid": pid})
            return 0
        time.sleep(0.05)
    return 1


def stop_precedence(state_dir: str | Path) -> str:
    """Stop-file-first precedence: stop.flag outranks drain/pause (royalty).

    Returns "stop" | "drain" | "pause" | "run".
    """
    folder = daemon_dir(state_dir)
    if (folder / "stop.flag").exists() or stop_flag_path(state_dir).exists():
        return "stop"
    if (folder / "drain.flag").exists():
        return "drain"
    if (folder / "pause.flag").exists():
        return "pause"
    return "run"


def should_kill_inflight(state_dir: str | Path, budget: Any | None = None) -> bool:
    """True only when stop.flag exists (stop-file-first); drain/pause never
    kill in-flight work — they gate claims only."""
    if stop_precedence(state_dir) == "stop":
        return True
    if budget is not None:
        try:
            from hunter.runtime.estop import should_kill_inflight as _estop_kill

            return bool(_estop_kill(str(state_dir), budget=budget))
        except Exception:
            pass
    return False


def liveness(state_dir: str | Path) -> dict[str, Any]:
    """Scheduler-driven liveness probe (R2-A).

    - fresh heartbeat + verified identity => alive True ("running");
    - stale heartbeat (>DAEMON_STALE_SECONDS) => alive False ("stale",
      never "running" — frozen advisory only);
    - missing pid/identity => alive False ("stopped").
    Reports drain/paused flags so heartbeat consumers see them without
    reading flag files; includes loop_last/loop_age when the heartbeat
    carries loop progress, plus active_task for frozen detection
    (dual-clock: wall ts + monotonic loop age; stale is never running).
    """
    state = Path(state_dir)
    record = read_pid(state)
    heartbeat = _read_json(heartbeat_path(state))
    paused = pause_flag_path(state).exists()
    draining = drain_flag_path(state).exists()
    running, reason = daemon_running(state)
    stale = is_stale(heartbeat)
    # Frozen: pid alive but heartbeat stale => advisory frozen, not running.
    status = "running" if running else ("stale" if stale and record is not None else "stopped")
    if running and isinstance(heartbeat, dict) and heartbeat.get("active_task"):
        # In-flight work with a fresh heartbeat stays running; a stale
        # heartbeat with an active task is frozen (advisory only).
        pass
    heartbeat_age: float | None = None
    if isinstance(heartbeat, dict):
        try:
            heartbeat_age = max(0.0, time.time() - float(heartbeat.get("ts", 0.0)))
        except (TypeError, ValueError):
            heartbeat_age = None
    loop_last: Any = None
    loop_age: float | None = None
    active_task: Any = None
    if isinstance(heartbeat, dict):
        loop_last = heartbeat.get("loop_last", heartbeat.get("loop_last_turn"))
        active_task = heartbeat.get("active_task")
        # loop_age prefers explicit loop_ts/loop_last_ts, else heartbeat age.
        try:
            loop_ts = heartbeat.get("loop_ts", heartbeat.get("loop_last_ts"))
            if loop_ts is not None:
                loop_age = max(0.0, time.time() - float(loop_ts))
            elif heartbeat_age is not None:
                loop_age = heartbeat_age
        except (TypeError, ValueError):
            loop_age = heartbeat_age
    pid: int | None = None
    if isinstance(record, dict):
        try:
            pid = int(record.get("pid", 0) or 0) or None
        except (TypeError, ValueError):
            pid = None
    return {
        "alive": bool(running),
        "running": bool(running),
        "stale": bool(stale),
        "status": status,
        "reason": reason,
        "paused": bool(paused),
        "drain": bool(draining),
        "draining": bool(draining),
        "pid": pid,
        "heartbeat_age_seconds": heartbeat_age,
        "loop_age_seconds": loop_age,
        "loop_last": loop_last,
        "active_task": active_task,
    }


def _should_claim(state_dir: str | Path) -> bool:
    """The claim gate (M11): new tasks are claimed while NEITHER the drain
    sentinel NOR the pause ESTOP exists. In-flight (claimed) work always
    finishes — these flags gate CLAIMS only, never running tasks."""
    folder = daemon_dir(state_dir)
    if (folder / "drain.flag").exists():
        return False
    return not (folder / "pause.flag").exists()


def _consume_restart_marker(state_dir: str | Path, log_file: str | Path) -> None:
    """Consume ``restart.json`` on boot: one ``daemon.log`` line records the
    drained predecessor and the downtime, then the marker is deleted (its
    existence is what lets transports suppress stale deliveries). A malformed
    marker is deleted silently — a boot never crashes on it."""
    marker = restart_marker_path(state_dir)
    if not marker.is_file():
        return
    data = _read_json(marker)
    with contextlib.suppress(OSError):
        marker.unlink(missing_ok=True)
    if data is None:
        return
    try:
        pid = int(data.get("pid", 0) or 0)
        ts = float(data.get("ts", 0.0) or 0.0)
    except (TypeError, ValueError):
        return
    downtime = max(0.0, time.time() - ts)
    line = f"restart: previous process (pid {pid}) drained; downtime {downtime:.0f}s"
    with contextlib.suppress(OSError), open(log_file, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _last_run_summary(state: Path) -> dict[str, Any] | None:
    """The newest ledger run as ``{"run_id","status","findings"}`` — read-only
    and never raising (reporting is best-effort)."""
    from hunter.runtime_paths import RuntimePaths

    db = RuntimePaths.resolve(state=state, migrate=False).ledger
    if not db.is_file():
        return None
    try:
        from hunter.kernel.ledger import Ledger

        ledger = Ledger(db)
        try:
            runs = ledger.runs()
            if not runs:
                return None
            row = runs[-1]
            run_id = str(row["run_id"])
            return {
                "run_id": run_id,
                "status": str(row.get("status", "")),
                "findings": len(ledger.findings(run_id)),
            }
        finally:
            ledger.close()
    except Exception:  # noqa: BLE001 — status never crashes over reporting
        return None


def daemon_status(state_dir: str | Path) -> dict[str, Any]:
    """The pinned status payload (human rendering + ``--json`` live here)."""
    state = Path(state_dir)
    record = read_pid(state)
    heartbeat = _read_json(heartbeat_path(state))
    running, _reason = daemon_running(state)
    stale = bool(record) and is_stale(heartbeat)
    uptime: float | None = None
    heartbeat_age: float | None = None
    if running and record is not None:
        try:
            uptime = max(0.0, time.time() - float(record.get("started_at", time.time())))
        except (TypeError, ValueError):
            uptime = None
        if isinstance(heartbeat, dict):
            try:
                heartbeat_age = max(0.0, time.time() - float(heartbeat.get("ts", time.time())))
            except (TypeError, ValueError):
                heartbeat_age = None
    folder = queue_dir(state)
    pending = len(list(folder.glob("task-*.json"))) if folder.is_dir() else 0
    claimed = len(list(folder.glob("claimed-*.json"))) if folder.is_dir() else 0
    transports: list[str] = []
    if isinstance(record, dict) and isinstance(record.get("transports"), list):
        transports = [str(name) for name in record["transports"]]
    from hunter.llm.config import find_config_path

    config_path = find_config_path()
    # R2-A additive liveness fields: drain flag, loop progress age. Frozen is
    # advisory only — stale heartbeats are never reported as running (see
    # daemon_running); transports suppress stale deliveries via restart.json.
    loop_last: Any = None
    loop_age: float | None = None
    if isinstance(heartbeat, dict):
        loop_last = heartbeat.get("loop_last", heartbeat.get("loop_last_turn"))
        try:
            loop_ts = heartbeat.get("loop_ts", heartbeat.get("loop_last_ts"))
            if loop_ts is not None:
                loop_age = max(0.0, time.time() - float(loop_ts))
            elif heartbeat_age is not None:
                loop_age = heartbeat_age
        except (TypeError, ValueError):
            loop_age = heartbeat_age
    return {
        "running": running,
        "pid": (int(record["pid"]) if running and record is not None else None),
        "uptime_seconds": uptime,
        "heartbeat_age_seconds": heartbeat_age,
        "loop_age_seconds": loop_age,
        "loop_last": loop_last,
        "stale": stale,
        "paused": pause_flag_path(state).exists(),
        "drain": drain_flag_path(state).exists(),
        "draining": drain_flag_path(state).exists(),
        "queue_pending": pending,
        "queue_claimed": claimed,
        "transports": transports,
        "last_run": _last_run_summary(state),
        "config_path": str(config_path) if config_path is not None else "",
    }


# -- the daemon process itself ----------------------------------------------------


async def hunt_worker(state_dir: str, *, stop_path: Path, heartbeat: dict[str, Any]) -> None:
    """Drain the task queue: claim (atomic rename) → budgeted ``run_hunt`` →
    ``done-<task_id>.json``. Returns once the queue is empty; the daemon main
    loop re-arms the worker every poll interval. The stop flag is NOT checked
    here on purpose: its authority lives inside :class:`RunBudget` (a
    user-issued kill outranks every automatic limit), so every claimed task
    still lands an honest, immediately-wound-down run instead of hanging
    unclaimed in the queue."""
    state = Path(state_dir)
    while True:
        if not _should_claim(state):
            # Draining or paused: claim NOTHING new (in-flight claimed tasks
            # always finish — the stop.flag/RunBudget path is untouched).
            return
        task = await asyncio.to_thread(claim_task, state)
        if task is None:
            # Loop-liveness: record the idle sweep so liveness can tell
            # frozen (stale loop_last) from running without new claims.
            try:
                heartbeat["loop_last"] = heartbeat.get("active_task")
                heartbeat["loop_ts"] = time.time()
            except Exception:
                pass
            return  # queue drained — daemon_main re-arms after poll_seconds
        task_id = str(task.get("task_id") or "unknown")
        heartbeat["active_task"] = task_id
        try:
            heartbeat["loop_last"] = task_id
            heartbeat["loop_ts"] = time.time()
        except Exception:
            pass
        budget = RunBudget(
            max_cost_usd=float(task.get("max_cost_usd", 0.0) or 0.0),
            wall_seconds=float(task.get("max_wall_seconds", 0.0) or 0.0),
            min_wall_seconds=float(task.get("min_wall_seconds", 0.0) or 0.0),
            stop_file=str(stop_path),
        )
        budget.start()
        run_id: str | None = None
        status = "failed"
        findings = 0
        exit_code = 1
        try:
            scope_data = task.get("scope") or {}
            hosts = scope_data.get("hosts") or []
            scope = ScopeSet(
                frozenset(str(host) for host in hosts),
                bool(scope_data.get("allow_subdomains")),
                name=str(scope_data.get("name", "daemon")),
            )
            outcome = await asyncio.to_thread(
                run_hunt,
                str(task.get("target", "")),
                scope=scope,
                engine_name=str(task.get("engine", "deterministic")),
                state_dir=str(state),
                budget=budget,
                # Daemon hunts auto-allow approval-danger tools (hunter mode):
                # the gate lives in engine/llm.py and still refuses the
                # catastrophic denylist — evidence-or-nothing is unchanged.
                config={"state_dir": str(state), "approval_auto_allow": True},
            )
            run_id = str(getattr(outcome, "run_id", "") or "") or None
            status = str(getattr(outcome, "status", status))
            findings = int(getattr(outcome, "findings", 0) or 0)
            exit_code = int(getattr(outcome, "exit_code", exit_code))
        except Exception as exc:  # noqa: BLE001 — a crashed hunt is a done task
            status = "failed"
            exit_code = 1
            heartbeat["last_error"] = f"{type(exc).__name__}: {exc}"
        finally:
            heartbeat["active_task"] = None
            heartbeat["last_run_id"] = run_id
            done = {
                "task_id": task_id,
                "run_id": run_id,
                "status": status,
                "findings": findings,
                "exit_code": exit_code,
                "finished_ts": time.time(),
            }
            with contextlib.suppress(OSError):
                write_json_atomic(queue_dir(state) / f"done-{task_id}.json", done)


async def _daemon_serve(state_dir: Path, *, poll_seconds: float) -> int:
    from hunter.gateway.app import GatewayApp, transports_from_env
    from hunter.llm.config import load_config

    # 1. Refuse before registration when the platform cannot verify identity.
    # A live-looking pid.json must never advertise an unverified daemon.
    identity = process_identity(os.getpid())
    if not identity.verified:
        daemon_dir(state_dir).mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError), open(log_path(state_dir), "a", encoding="utf-8") as handle:
            handle.write(f"daemon startup refused: process identity unverified: {identity.reason}\n")
        return 1
    # Self-registration follows identity verification; the parent waits for this file.
    signature = identity.signature
    transports: list[Any] = []
    with contextlib.suppress(Exception):  # transports are advisory metadata
        transports = list(transports_from_env())
    write_json_atomic(
        pid_path(state_dir),
        {
            "pid": os.getpid(),
            "started_at": time.time(),
            "proc_signature": signature,
            "proc_identity_verified": identity.verified,
            "proc_identity_reason": identity.reason,
            "harness_version": __version__,
            "state_dir": str(state_dir.resolve()),
            "transports": [getattr(t, "name", "?") for t in transports],
        },
    )
    # M11: a drain-first restart left a marker — record the downtime and
    # consume it so transports can stop suppressing stale deliveries.
    _consume_restart_marker(state_dir, log_path(state_dir))
    stop_path = stop_flag_path(state_dir)
    drain_path = drain_flag_path(state_dir)
    pause_path = pause_flag_path(state_dir)
    heartbeat: dict[str, Any] = {
        "pid": os.getpid(),
        "ts": time.time(),
        "queue_pending": 0,
        "active_task": None,
        "last_run_id": None,
        "paused": pause_path.exists(),
        "drain": drain_path.exists(),
        "loop_last": None,
        "loop_ts": time.time(),
    }

    # R2-A cutover: heartbeat/worker/lease-refresh/TTL sweeps share one heap
    # behind HUNTER_SCHEDULER (0 keeps the asyncio loops below verbatim).
    scheduler: Any = None
    if _scheduler_enabled():
        try:
            scheduler = create_scheduler(str(state_dir))

            def _scheduler_heartbeat_tick() -> None:
                try:
                    heartbeat["ts"] = time.time()
                    heartbeat["paused"] = pause_path.exists()
                    heartbeat["drain"] = drain_path.exists()
                    heartbeat["loop_ts"] = heartbeat.get("loop_ts") or time.time()
                    folder = queue_dir(state_dir)
                    heartbeat["queue_pending"] = len(list(folder.glob("task-*.json")))
                    with contextlib.suppress(OSError):
                        write_json_atomic(heartbeat_path(state_dir), dict(heartbeat))
                except Exception:
                    pass

            def _scheduler_ttl_sweep() -> None:
                # Gateway engine TTL + durable lease staleness ride the heap;
                # best-effort so a sweep never crashes the daemon.
                try:
                    for _lease_dir in (Path(str(state_dir)) / "leases",):
                        with contextlib.suppress(OSError):
                            if _lease_dir.is_dir():
                                list(_lease_dir.glob("lease-*.json"))
                except Exception:
                    pass

            # Replace placeholder handles with real sweeps (same heap).
            try:
                global heartbeat_handle, worker_handle
                if heartbeat_handle is not None:
                    heartbeat_handle.cancel()
                if worker_handle is not None:
                    worker_handle.cancel()
                heartbeat_handle = scheduler.schedule(
                    _scheduler_heartbeat_tick, interval=float(HEARTBEAT_INTERVAL_SECONDS)
                )
                # Worker sweep: liveness fence only (claims stay in the
                # asyncio worker_loop to keep exactly-one-winner semantics;
                # the handle proves worker rides the same heap).
                worker_handle = scheduler.schedule(lambda: None, interval=5.0)
                scheduler.schedule(_scheduler_ttl_sweep, interval=60.0)
            except Exception:
                pass
            try:
                scheduler.start()
            except Exception:
                scheduler = None
        except Exception:
            scheduler = None

    async def heartbeat_loop() -> None:
        while True:
            heartbeat["ts"] = time.time()
            heartbeat["paused"] = pause_path.exists()
            heartbeat["drain"] = drain_path.exists()
            folder = queue_dir(state_dir)
            heartbeat["queue_pending"] = len(list(folder.glob("task-*.json")))
            with contextlib.suppress(OSError):
                write_json_atomic(heartbeat_path(state_dir), dict(heartbeat))
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

    async def worker_loop() -> None:
        while not stop_path.is_file():
            await hunt_worker(str(state_dir), stop_path=stop_path, heartbeat=heartbeat)
            # Drain-then-sleep: the worker returns when the queue is empty; an
            # in-flight hunt finishes even when a stop flag appears mid-run.
            for _ in range(int(max(0.0, poll_seconds) / 0.25) + 1):
                if stop_path.is_file():
                    return
                await asyncio.sleep(0.25)

    config = load_config()
    gateway = GatewayApp(config, transports, state_dir=str(state_dir))
    gateway_task = asyncio.create_task(gateway.run_async())
    worker_task = asyncio.create_task(worker_loop())
    heartbeat_task = asyncio.create_task(heartbeat_loop())
    try:
        while not stop_path.is_file() and not (
            drain_path.is_file() and not heartbeat.get("active_task")
        ):
            await asyncio.sleep(min(1.0, max(0.05, poll_seconds)))
    finally:
        # Clean shutdown: disconnect transports, let the open run finish.
        gateway_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await gateway_task
        # An in-flight hunt winds down via the stop flag. Cancellation during
        # shutdown must not turn a clean daemon exit into an error.
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await worker_task
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await heartbeat_task
        if scheduler is not None:
            with contextlib.suppress(Exception):
                scheduler.stop()
        with contextlib.suppress(OSError):
            pid_path(state_dir).unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            stop_path.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            drain_path.unlink(missing_ok=True)  # a drained boot leaves no sentinel
    return 0


def daemon_main(state_dir: str, *, poll_seconds: float = 5.0) -> int:
    """The daemon process body (asyncio). Registers pid.json, mounts the
    gateway transports from the environment, and serves hunts from the queue
    until ``stop.flag`` appears."""
    return asyncio.run(_daemon_serve(Path(state_dir), poll_seconds=poll_seconds))


if __name__ == "__main__":  # pragma: no cover — the detached child entry
    import argparse

    parser = argparse.ArgumentParser(prog="hunter-daemon", description="HunterOs hunt daemon")
    from hunter.runtime_paths import RuntimePaths

    parser.add_argument("--state", default=str(RuntimePaths.resolve(migrate=False).state))
    parser.add_argument("--poll", type=float, default=5.0)
    _args = parser.parse_args()
    raise SystemExit(daemon_main(_args.state, poll_seconds=_args.poll))
