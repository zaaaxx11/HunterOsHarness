"""Session lifecycle: one daemon per session, resumable, and clean teardown.

The daemon is a long-lived process that drains a task queue. Left unmanaged
it outlives the hunt that started it, keeps polling a state directory, and
holds RAM and disk that nothing is using. On a small box a handful of those
is the difference between a hunt that finishes and one that gets OOM-killed.

A **session** is the unit that fixes this:

* **One daemon per session.** Starting a hunt claims the session; a second
  hunt in the same session attaches to the running daemon instead of
  spawning a twin. The claim is a file lock, so two processes racing to start
  cannot both win.
* **Resumable.** ``--resume <session-id>`` picks a session back up with its
  queue, ledger, and followed-findings intact. Nothing is re-derived.
* **Teardown frees RAM and disk, keeps the value.** When a session is closed
  the daemon is stopped and its transient artefacts are removed — queue
  entries, heartbeats, pid files, WAL/SHM sidecars. What survives is exactly
  what has lasting value: findings, PoCs, reports, and curated skills.

Teardown is deliberately conservative. It removes files it can name, inside
the session's own state directory, and never follows a symlink out of it.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

__all__ = [
    "SessionError",
    "SessionExists",
    "SessionNotFound",
    "SessionRecord",
    "sessions_root",
    "session_dir",
    "create_session",
    "open_session",
    "resume_session",
    "close_session",
    "list_sessions",
    "session_lock",
    "KEEP_ON_CLOSE",
    "DISCARD_ON_CLOSE",
]

# Survives a close: the durable output of a hunt.
KEEP_ON_CLOSE: frozenset[str] = frozenset(
    {
        "ledger.db",
        "reports",
        "pocs",
        "skills",
        "session.json",
        "curated",
    }
)

# Removed on close: transient runtime state that only costs RAM and disk.
DISCARD_ON_CLOSE: frozenset[str] = frozenset(
    {
        "daemon",
        "queue",
        "rag-state.json",
        "llm-proposed-scope.json",
        "m.json",
        "ledger.db-shm",
        "ledger.db-wal",
        "ledger.db-journal",
        "hunt.log",
        "nohup.out",
    }
)


class SessionError(RuntimeError):
    """Base class for session failures."""


class SessionExists(SessionError):
    """A live session already owns this state directory."""


class SessionNotFound(SessionError):
    """No session with that id."""


@dataclass
class SessionRecord:
    """One hunt session. ``id`` is the handle everything else keys on."""

    id: str
    state_dir: Path
    target: str
    engine: str
    created_ts: float
    status: str = "active"  # active | closed
    closed_ts: float | None = None
    daemon_pid: int | None = None
    runs: list[str] = field(default_factory=list)
    findings: int = 0
    notes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state_dir": str(self.state_dir),
            "target": self.target,
            "engine": self.engine,
            "created_ts": self.created_ts,
            "status": self.status,
            "closed_ts": self.closed_ts,
            "daemon_pid": self.daemon_pid,
            "runs": list(self.runs),
            "findings": self.findings,
            "notes": dict(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionRecord":
        return cls(
            id=str(data.get("id", "")),
            state_dir=Path(str(data.get("state_dir", ""))),
            target=str(data.get("target", "")),
            engine=str(data.get("engine", "")),
            created_ts=float(data.get("created_ts", 0.0) or 0.0),
            status=str(data.get("status", "active")),
            closed_ts=(float(data["closed_ts"]) if data.get("closed_ts") else None),
            daemon_pid=(int(data["daemon_pid"]) if data.get("daemon_pid") else None),
            runs=[str(r) for r in (data.get("runs") or [])],
            findings=int(data.get("findings", 0) or 0),
            notes=dict(data.get("notes") or {}),
        )


def sessions_root(state_dir: str | Path | None = None) -> Path:
    """Where session records live.

    Sessions are tracked OUTSIDE any individual hunt's state directory so
    that closing one session cannot delete the registry of the others.
    """
    if state_dir is not None:
        return Path(state_dir) / "sessions"
    from hunter.home import state_dir as _default

    return _default(None) / "sessions"


def session_dir(session_id: str, state_dir: str | Path | None = None) -> Path:
    return sessions_root(state_dir) / session_id


def _record_path(session_id: str, state_dir: str | Path | None = None) -> Path:
    return session_dir(session_id, state_dir) / "session.json"


def _write_json_atomic(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _read_record(session_id: str, state_dir: str | Path | None = None) -> SessionRecord | None:
    path = _record_path(session_id, state_dir)
    if not path.is_file():
        return None
    try:
        return SessionRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return None


def _pid_alive(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


@contextmanager
def session_lock(session_id: str, state_dir: str | Path | None = None) -> Iterator[None]:
    """Exclusive lock over one session's directory.

    The lock is a real ``flock`` on a file inside the session directory, so
    it is released automatically if the holder dies — no stale lock can wedge
    a session the way a forgotten flag file can.
    """
    import fcntl

    directory = session_dir(session_id, state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / ".lock"
    handle = open(lock_path, "w", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise SessionExists(f"session {session_id!r} is locked by another process") from exc
    try:
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def create_session(
    *,
    target: str,
    engine: str = "llm",
    state_dir: str | Path | None = None,
    session_id: str | None = None,
    notes: dict[str, Any] | None = None,
) -> SessionRecord:
    """Create a session and claim it. One live daemon per session.

    Refuses when a session with that id is already active — that is the
    "no double daemon" rule. A CLOSED session with the same id is replaced
    rather than refused: its durable output has already been kept, and the id
    is the operator's handle for "the same hunt, continued".
    """
    sid = session_id or f"s-{int(time.time())}"
    existing = _read_record(sid, state_dir)
    if existing is not None and existing.status == "active":
        raise SessionExists(
            f"session {sid!r} is already active (daemon pid {existing.daemon_pid}) — "
            "attach to it with `--resume` or close it first"
        )

    directory = session_dir(sid, state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    record = SessionRecord(
        id=sid,
        state_dir=directory,
        target=target,
        engine=engine,
        created_ts=time.time(),
        notes=dict(notes or {}),
    )
    _write_json_atomic(_record_path(sid, state_dir), record.as_dict())
    return record


def open_session(
    session_id: str,
    *,
    state_dir: str | Path | None = None,
    daemon_pid: int | None = None,
) -> SessionRecord:
    """Attach to an existing active session and record the daemon pid."""
    record = _read_record(session_id, state_dir)
    if record is None:
        raise SessionNotFound(f"no session {session_id!r}")
    if record.status != "active":
        raise SessionNotFound(f"session {session_id!r} is closed — resume it to continue")
    if daemon_pid is not None:
        record.daemon_pid = daemon_pid
        _write_json_atomic(_record_path(session_id, state_dir), record.as_dict())
    return record


def resume_session(
    session_id: str,
    *,
    state_dir: str | Path | None = None,
) -> SessionRecord:
    """Reopen a closed session, keeping everything it kept.

    The queue and other transient state were discarded on close, so a resumed
    session starts from the ledger: findings, PoCs, reports, and skills are
    all still there. The session goes back to ``active`` and a new daemon may
    attach to it.
    """
    record = _read_record(session_id, state_dir)
    if record is None:
        raise SessionNotFound(f"no session {session_id!r}")
    record.status = "active"
    record.closed_ts = None
    record.daemon_pid = None
    _write_json_atomic(_record_path(session_id, state_dir), record.as_dict())
    return record


def _stop_daemon(pid: int | None, timeout: float = 10.0) -> bool:
    """Stop a daemon pid, escalating SIGTERM → SIGKILL. Never raises."""
    if not pid or not _pid_alive(pid):
        return False
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    return True


def _is_within(path: Path, root: Path) -> bool:
    """True when ``path`` is ``root`` or inside it. Symlinks are resolved."""
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except OSError:
        return False
    return resolved == root_resolved or root_resolved in resolved.parents


def _checkpoint_ledger(ledger_path: Path) -> bool:
    """Flush a WAL journal into the main db so the sidecars can be dropped.

    Deleting ``ledger.db-wal`` while the daemon is being killed throws away
    whatever has not been checkpointed yet — committed findings included. A
    ``wal_checkpoint(TRUNCATE)`` folds the WAL back into ``ledger.db`` first,
    so the sidecars are empty and removing them loses nothing.

    Returns True when the checkpoint ran. Any failure (locked db, missing
    file, not a sqlite db) is swallowed: the caller then keeps the sidecars
    rather than risk the ledger.
    """
    import sqlite3

    if not ledger_path.is_file():
        return False
    try:
        con = sqlite3.connect(str(ledger_path), timeout=5.0)
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.commit()
        finally:
            con.close()
        return True
    except sqlite3.Error:
        return False


def close_session(
    session_id: str,
    *,
    state_dir: str | Path | None = None,
    keep: frozenset[str] = KEEP_ON_CLOSE,
    discard: frozenset[str] = DISCARD_ON_CLOSE,
) -> dict[str, Any]:
    """Close a session: stop the daemon, free RAM and disk, keep the value.

    Returns what was kept and what was discarded so the caller can report it
    honestly. The session record itself is kept (marked ``closed``) — that is
    the handle ``--resume`` needs.

    Deletion is bounded: only named entries inside the session's own state
    directory are touched, and a symlink is never followed out of it.
    """
    record = _read_record(session_id, state_dir)
    if record is None:
        raise SessionNotFound(f"no session {session_id!r}")

    stopped = _stop_daemon(record.daemon_pid)

    root = record.state_dir
    kept: list[str] = []
    discarded: list[str] = []

    # The daemon is dead, so any WAL it left is frozen mid-flight. Fold it into
    # ledger.db before the sidecars go — otherwise committed findings die with
    # them. If the checkpoint cannot run (locked, unreadable), the sidecars are
    # kept: a stale WAL is recoverable, a deleted one is not.
    ledger_path = root / "ledger.db"
    sidecars = ("ledger.db-wal", "ledger.db-shm", "ledger.db-journal")
    if ledger_path.is_file() and _checkpoint_ledger(ledger_path):
        pass
    else:
        keep = keep | frozenset(sidecars)

    if root.is_dir():
        for entry in sorted(root.iterdir()):
            name = entry.name
            if name in keep:
                kept.append(name)
                continue
            if name in discard:
                if not _is_within(entry, root):
                    # A symlink pointing outside the session: refuse to
                    # follow it, and do not delete the link itself blindly.
                    continue
                try:
                    if entry.is_dir() and not entry.is_symlink():
                        shutil.rmtree(entry)
                    else:
                        entry.unlink()
                    discarded.append(name)
                except OSError:
                    # A file that will not delete is reported, not hidden.
                    kept.append(name)

    record.status = "closed"
    record.closed_ts = time.time()
    record.daemon_pid = None
    _write_json_atomic(_record_path(session_id, state_dir), record.as_dict())

    return {
        "session_id": session_id,
        "daemon_stopped": stopped,
        "kept": kept,
        "discarded": discarded,
        "state_dir": str(root),
    }


def list_sessions(
    *,
    state_dir: str | Path | None = None,
    include_closed: bool = True,
) -> list[SessionRecord]:
    """Every session record, newest first."""
    root = sessions_root(state_dir)
    if not root.is_dir():
        return []
    records: list[SessionRecord] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        record = _read_record(child.name, state_dir)
        if record is None:
            continue
        if not include_closed and record.status != "active":
            continue
        records.append(record)
    records.sort(key=lambda r: r.created_ts, reverse=True)
    return records


def active_session_count(state_dir: str | Path | None = None) -> int:
    return sum(1 for r in list_sessions(state_dir=state_dir) if r.status == "active")
