"""``~/.hunter`` — the one home for user-facing HunterOS state (M11).

Locked decision 1 (m11-hermes-ux §2.1): ``~/.hunter`` holds ALL user-facing
state — ``config.yaml``, ``keys.env``, ``chat.db``, the default ledger state
dir, ``daemon/``, ``approvals/``, ``reports/``, ``sessions/``, ``skills/``.
``~/.hunteros`` remains ONLY plumbing (venv, ``bin/`` shims,
``update-check.json``) and is never deleted.

Migration contract (locked decision 2): on first load of home/config, when the
``~/.hunter`` counterpart is ABSENT and the legacy ``~/.hunteros/`` file
exists, COPY it (originals stay). When both exist, the new home wins.
Idempotent, race-safe (staged via an exclusive-create tmp sibling + atomic
``os.replace`` — two racers converge on identical bytes), HOME/USERPROFILE
divergence safe (ONE base resolution feeds both homes). A corrupt legacy file
is copied as bytes (validity is the loader's job) and an uncopyable legacy
``skills`` entry is SKIPPED with a recorded note — a broken legacy must never
brick a command.

Stdlib-only module (no hunter imports → no import cycles). Every path goes
through :class:`pathlib.Path`; nothing here ever writes to the legacy home.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

__all__ = [
    "HOME_DIRNAME",
    "LEGACY_DIRNAME",
    "MIGRATABLE_FILES",
    "MIGRATABLE_DIRS",
    "MIGRATION_NOTICE",
    "hunter_home",
    "legacy_home",
    "state_dir",
    "migration_plan",
    "ensure_home",
    "migration_notes",
]

HOME_DIRNAME = ".hunter"        # unified user-facing home (M11)
LEGACY_DIRNAME = ".hunteros"    # plumbing only: venv, bin shims, update-check
MIGRATABLE_FILES: tuple[str, ...] = ("config.yaml", "keys.env", "chat.db")
MIGRATABLE_DIRS: tuple[str, ...] = ("skills",)

# Pinned summary notice (§3.1) — printed by the CLI root callback once per
# process, and fired through ensure_home's ``notice`` callback per migration.
MIGRATION_NOTICE = (
    "📋 migrated legacy HunterOS state from ~/.hunteros to ~/.hunter"
    " — originals kept (details: hunter where)"
)

_SKIP_PREFIX = "skipped: "  # notes for uncopyable legacy entries carry this prefix

# Per-process state: what THIS process migrated (notes), guarded for threads.
_notes_lock = threading.Lock()
_notes: list[str] = []


# --------------------------------------------------------------- resolution --


def _home_base(env: Mapping[str, str], home: Path | None) -> Path:
    """The single base resolution feeding BOTH homes (divergence-safe).

    An explicit ``home`` override wins. Otherwise the SAME env lookup drives
    the new home and the legacy dir: HOME wins on POSIX, USERPROFILE on
    Windows — with ``Path.home()`` as the last resort.
    """
    if home is not None:
        return Path(home)
    if sys.platform == "win32":
        raw = (env.get("USERPROFILE") or env.get("HOME") or "").strip()
    else:
        raw = (env.get("HOME") or env.get("USERPROFILE") or "").strip()
    return Path(raw) if raw else Path.home()


def hunter_home(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """``~/.hunter`` — never creates the directory, never touches the disk
    beyond resolution. home override → the SAME single env resolution feeds
    both the new home and the legacy dir, which is what makes HOME/USERPROFILE
    divergence safe (HOME wins on POSIX, USERPROFILE on Windows)."""
    env_map = os.environ if env is None else env
    return _home_base(env_map, home) / HOME_DIRNAME


def legacy_home(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """``~/.hunteros`` (read-only by this module's contract — never written,
    never deleted)."""
    env_map = os.environ if env is None else env
    return _home_base(env_map, home) / LEGACY_DIRNAME


def state_dir(
    explicit: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Explicit ``--state`` → ``$HUNTER_STATE_DIR`` → ``~/.hunter``.

    Resolution is delegated to :class:`hunter.runtime_paths.RuntimePaths` so
    ``~`` and HOME/USERPROFILE handling stay identical across every surface.
    """
    from hunter.runtime_paths import RuntimePaths

    return RuntimePaths.resolve(
        state=explicit, env=env, home=home, migrate=False
    ).state


# ---------------------------------------------------------------- migration --


def migration_plan(
    *, env: Mapping[str, str] | None = None, home: Path | None = None
) -> list[tuple[Path, Path]]:
    """Pure read: the ``(src, dst)`` pairs that would migrate RIGHT NOW.

    Migration is a FIRST-BOOT contract: it runs only while the new home does
    not exist yet. Once ``~/.hunter`` exists — even partially populated — the
    new home wins wholesale and the plan is empty (``dst absent AND src
    exists`` is evaluated against the home itself, then per file). Migratable
    files first, then the ``skills/`` dir. Never touches the disk beyond
    ``exists`` checks."""
    env_map = os.environ if env is None else env
    legacy = legacy_home(env=env_map, home=home)
    target = hunter_home(env=env_map, home=home)
    if target.exists() or not legacy.exists():
        return []
    plan: list[tuple[Path, Path]] = []
    for name in MIGRATABLE_FILES:
        src = legacy / name
        dst = target / name
        if src.is_file():
            plan.append((src, dst))
    for name in MIGRATABLE_DIRS:
        src = legacy / name
        dst = target / name
        if src.exists():
            plan.append((src, dst))
    return plan


def _copy_file_once(src: Path, dst: Path) -> None:
    """Copy ``src`` → ``dst`` so two racers converge on identical bytes.

    Stage into an exclusive-create tmp sibling (``O_CREAT | O_EXCL``), copy
    the bytes, then atomic ``os.replace`` onto the destination. The legacy
    file is never written; a loser's staging file is always cleaned up.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    staging = dst.with_name(f"{dst.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.migrating")
    try:
        data = src.read_bytes()
        # O_BINARY: without it Windows opens the staging handle in text mode
        # and silently rewrites every b"\n" to b"\r\n" — a byte-exact copy
        # (chat.db! keys.env!) is the whole migration contract.
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(staging, flags, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        except FileExistsError:  # pragma: no cover — names carry pid+uuid
            staging = dst.with_name(f"{dst.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.migrating")
            fd = os.open(staging, flags, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        # Two racers may both replace — with IDENTICAL bytes (same source),
        # so the outcome converges either way. Retry transient Windows locks.
        error: OSError | None = None
        for attempt in range(5):
            try:
                os.replace(staging, dst)
                return
            except PermissionError as exc:  # Windows AV/reader lock specialty
                error = exc
                time.sleep(0.01 * (attempt + 1))
            except OSError as exc:
                error = exc
                break
        raise error if error is not None else OSError(f"could not migrate {src}")
    except BaseException:
        with contextlib.suppress(OSError):
            staging.unlink(missing_ok=True)
        raise


def _copy_dir_children(src: Path, dst: Path, notes: list[str]) -> None:
    """Per-child copy loop for a migratable directory (``skills/``).

    Never deletes; existing children are skipped; a child that cannot be
    copied is skipped with a recorded note — never raised (a corrupt legacy
    entry must not brick every command).
    """
    try:
        children = sorted(src.iterdir())
    except OSError as exc:
        notes.append(f"{_SKIP_PREFIX}{src.name}: unreadable legacy directory ({exc})")
        return
    dst.mkdir(parents=True, exist_ok=True)
    for child in children:
        target = dst / child.name
        if target.exists():
            continue  # the new home wins — never overwritten
        try:
            if child.is_dir():
                shutil.copytree(child, target)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(child, target)
            notes.append(str(target))
        except OSError as exc:
            notes.append(f"{_SKIP_PREFIX}{child}: could not copy ({exc})")


def ensure_home(
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    migrate: bool = True,
    notice: Callable[[str], None] | None = None,
) -> Path:
    """Resolve the home; run the copy-once migration; return the home path.

    Per migratable file: skip when the destination exists; otherwise stage
    via an exclusive-create tmp sibling, copy the bytes, and ``os.replace``
    (two racers converge on identical bytes — the legacy file is never
    written by hunter). ``skills/``: per-child copy loop (skip on error,
    collect a note), never deletes; a missing destination dir is created.

    On a migration that moved at least one item, calls ``notice(summary_line)``
    with the pinned §3.1 summary and records the moved paths (plus skip notes)
    in :func:`migration_notes`. NEVER raises for an unreadable legacy file:
    it is skipped and recorded — a corrupt legacy config must not brick every
    command.
    """
    env_map = os.environ if env is None else env
    target = hunter_home(env=env_map, home=home)
    if not migrate or target.exists():
        return target  # the new home exists — it wins wholesale, never merged
    legacy = legacy_home(env=env_map, home=home)
    if not legacy.exists():
        return target

    moved: list[str] = []
    notes: list[str] = []
    for name in MIGRATABLE_FILES:
        src = legacy / name
        dst = target / name
        if not src.is_file() or dst.exists():
            continue  # absent on the legacy side, or the new home wins
        try:
            _copy_file_once(src, dst)
        except OSError as exc:
            notes.append(f"{_SKIP_PREFIX}{name}: could not copy ({exc})")
            continue
        moved.append(str(dst))
    for name in MIGRATABLE_DIRS:
        src = legacy / name
        dst = target / name
        if not src.exists() or dst.exists():
            continue
        before = len(notes)
        _copy_dir_children(src, dst, notes)
        copied = [note for note in notes[before:] if not note.startswith(_SKIP_PREFIX)]
        moved.extend(copied)
        if not copied and len(notes) == before:
            notes.append(str(dst))

    if moved or notes:
        with _notes_lock:
            _notes.extend(moved)
            _notes.extend(notes)
        if moved and notice is not None:
            notice(MIGRATION_NOTICE)
    return target


def migration_notes() -> tuple[str, ...]:
    """What THIS process migrated (empty when nothing was migrated). Skip
    notes for uncopyable legacy entries are prefixed ``skipped: ``."""
    with _notes_lock:
        return tuple(_notes)
