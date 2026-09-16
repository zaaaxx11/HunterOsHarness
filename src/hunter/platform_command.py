"""Portable command parsing and execution helpers.

Two portability problems are solved here, both of which used to be handled
ad-hoc at the call sites:

1. **Parsing a user-supplied command line into argv.** ``shlex.split`` with
   its POSIX default mangles Windows paths (``C:\\Tools\\x.exe`` becomes
   ``C:Toolsx.exe``) and Windows quoting rules. :func:`split_command` picks the
   parser that matches the host platform and keeps POSIX quoting on POSIX.

2. **Launching a process tree that can actually be stopped.** A timed-out
   child previously left its own descendants running. :func:`run_command`
   places the child in a platform process group/job so a timeout tears down the
   whole tree (``killpg`` on POSIX, ``taskkill /T`` on Windows).

Both helpers are deliberately shell-free: no ``shell=True`` anywhere, so a
parsed argument can never be re-interpreted by a shell.
"""

from __future__ import annotations

import contextlib
import os
import shlex
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CommandResult", "join_command", "run_command", "split_command"]


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one executed command."""

    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    spawn_error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.spawn_error


def _is_windows() -> bool:
    return sys.platform == "win32" or os.name == "nt"


def split_command(command: str) -> list[str]:
    """Parse a user-supplied command string into argv for THIS platform.

    POSIX keeps ``shlex.split`` semantics; Windows uses the same
    ``CommandLineToArgvW``-compatible rules as :func:`subprocess.list2cmdline`
    by round-tripping through the stdlib parser. An empty/blank command parses
    to an empty list (the caller decides whether that is a usage error).
    """
    text = (command or "").strip()
    if not text:
        return []
    if _is_windows():
        return _split_windows(text)
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        # Unbalanced quotes: fall back to the whole string as one token rather
        # than raising out of a config/editor code path.
        return [text]


def _split_windows(text: str) -> list[str]:
    """CommandLineToArgvW-compatible splitting without a shell.

    The stdlib exposes the inverse (``list2cmdline``) but not the parser, so a
    minimal Windows-rule lexer is implemented here: backslash runs are literal
    unless they precede a quote, ``""`` escapes a quote, and single quotes are
    NOT quoting characters (matching the Windows CRT).
    """
    argv: list[str] = []
    current: list[str] = []
    in_quotes = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            run_start = index
            while index < length and text[index] == "\\":
                index += 1
            backslashes = index - run_start
            if index < length and text[index] == '"':
                current.append("\\" * (backslashes // 2))
                if backslashes % 2:
                    current.append('"')
                    index += 1
                else:
                    in_quotes = not in_quotes
                    index += 1
                continue
            current.append("\\" * backslashes)
            continue
        if char == '"':
            in_quotes = not in_quotes
            index += 1
            continue
        if char in (" ", "\t") and not in_quotes:
            if current:
                argv.append("".join(current))
                current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if current:
        argv.append("".join(current))
    return argv


def join_command(argv: Sequence[str]) -> str:
    """Render argv back to one string using the host quoting rules."""
    parts = [str(part) for part in argv]
    if _is_windows():
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)


def run_command(
    argv: Sequence[str],
    *,
    timeout: float = 30.0,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run ``argv`` shell-free with whole-tree cleanup on timeout.

    POSIX: the child gets ``start_new_session`` so a timeout can ``killpg`` the
    child's OWN group. Windows: the child is created in a new process group and
    a timeout escalates to ``taskkill /T`` for its tree. Nothing here ever
    raises for a failed spawn — the failure is reported in
    :attr:`CommandResult.spawn_error`.
    """
    parts = [str(part) for part in argv]
    if not parts:
        return CommandResult(argv=[], returncode=127, spawn_error="empty command")
    kwargs: dict[str, object] = {
        "cwd": str(cwd) if cwd is not None else None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        "text": True,
        "errors": "replace",
    }
    if env is not None:
        kwargs["env"] = dict(env)
    if _is_windows():
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(parts, **kwargs)  # type: ignore[arg-type]
    except OSError as exc:
        return CommandResult(argv=parts, returncode=127, spawn_error=f"{type(exc).__name__}: {exc}")
    try:
        stdout, stderr = process.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except (subprocess.TimeoutExpired, OSError):  # pragma: no cover — best effort
            stdout, stderr = "", ""
        return CommandResult(
            argv=parts,
            returncode=124,
            stdout=_as_text(stdout),
            stderr=_as_text(stderr),
            timed_out=True,
        )
    return CommandResult(
        argv=parts,
        returncode=int(process.returncode or 0),
        stdout=_as_text(stdout),
        stderr=_as_text(stderr),
    )


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _kill_tree(process: subprocess.Popen) -> None:
    """Best-effort teardown of a timed-out child's process tree."""
    pid = int(process.pid)
    if _is_windows():
        # `/T` takes the tree down; if taskkill is unavailable, fall back to
        # the direct kill so at least the child does not leak.
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                check=False,
                timeout=10.0,
            )
            return
        except (OSError, subprocess.SubprocessError):  # pragma: no cover — best effort
            pass
        with contextlib.suppress(OSError, ProcessLookupError, PermissionError):
            process.kill()
        return
    # POSIX: the child was started in its OWN session, so killing that group
    # tears down its descendants without touching the harness process group.
    import signal

    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (OSError, ProcessLookupError, PermissionError):  # pragma: no cover — best effort
        with contextlib.suppress(OSError, ProcessLookupError, PermissionError):
            process.kill()
