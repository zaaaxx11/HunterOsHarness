"""Interactive chat REPL for the HUNT CLI.

The REPL owns terminal I/O only -- it never imports the command layer.  The
host application injects two callbacks:

``on_chat(text) -> None``
    Streams a plain chat turn to the user (stdout).

``on_command(cmd_line) -> bool``
    Handles a ``/``-prefixed slash command.  Return ``False`` to leave the
    REPL; anything else (including ``None``) keeps it running.

Input prefixes handled here (before any callback):

``!cmd``    run ``cmd`` in a shell and show the result
``@path``   reference a file/directory -- shown as a side note
``#note``   append a memory note to ``~/.hunter/notes.md``
``/cmd``    dispatched to ``on_command`` (``/exit`` and ``/quit`` are built in)

Line editing uses ``prompt_toolkit`` with persistent history in
``~/.hunter/history``.  ``Enter`` sends the message, a trailing backslash
continues on the next line, and ``Shift+Enter`` (or ``Alt+Enter``) inserts a
hard newline.  When stdin/stdout are not a TTY the REPL degrades to a plain
``input()`` loop so it can be driven by a harness or a pipe.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

try:  # pragma: no cover - import shim for script / sys.path usage
    from theme import paint
except ImportError:  # pragma: no cover - package usage
    from .theme import paint

__all__ = [
    "EXIT_COMMANDS",
    "HISTORY_FILE",
    "NOTES_FILE",
    "PROMPT",
    "QUIT_HINT",
    "append_note",
    "dispatch",
    "ensure_home",
    "history_path",
    "hunt_home",
    "notes_path",
    "run_repl",
    "run_shell_command",
    "show_reference",
]

PROMPT = "hunteros> "
CONTINUATION = "... "
QUIT_HINT = "Ctrl+D or /exit to quit"
EXIT_COMMANDS = frozenset({"/exit", "/quit", "/q"})
NOTE_PREFIX = "  \u25b8 "          # "  ▸ "
REFERENCE_LIMIT = 40

ChatCallback = Callable[[str], None]
CommandCallback = Callable[[str], bool]


# --------------------------------------------------------------------------
# State paths
# --------------------------------------------------------------------------

def hunt_home() -> Path:
    """State directory (``HUNT_HOME`` override, else ``~/.hunter``)."""
    override = os.environ.get("HUNT_HOME", "").strip()
    return Path(override).expanduser() if override else Path.home() / ".hunter"


def history_path() -> Path:
    return hunt_home() / "history"


def notes_path() -> Path:
    return hunt_home() / "notes.md"


#: Convenience constants mirroring the default location.
HISTORY_FILE = Path.home() / ".hunter" / "history"
NOTES_FILE = Path.home() / ".hunter" / "notes.md"


def ensure_home() -> bool:
    """Create the state directory if needed; ``True`` when usable."""
    try:
        hunt_home().mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return True


# --------------------------------------------------------------------------
# Side-note output
# --------------------------------------------------------------------------

def _note(message: str, role: str = "text_dim") -> None:
    print(paint(f"{NOTE_PREFIX}{message}", role), flush=True)


# --------------------------------------------------------------------------
# Prefix handlers
# --------------------------------------------------------------------------

def run_shell_command(command: str) -> int:
    """Run ``!command`` in a shell; returns the exit status."""
    if not command.strip():
        _note("nothing to run", "warn")
        return 1
    _note(f"$ {command}", "primary_dim")
    try:
        completed = subprocess.run(command, shell=True)
    except OSError as exc:
        _note(f"shell failed: {exc}", "error")
        return 1
    status = int(completed.returncode)
    if status != 0:
        _note(f"exit {status}", "warn")
    return status


def show_reference(reference: str, *, limit: int = REFERENCE_LIMIT) -> None:
    """Show ``@path`` as a side note (existence, size, directory listing)."""
    if not reference.strip():
        _note("no reference given", "warn")
        return
    target = Path(os.path.expanduser(reference.strip()))
    _note(f"reference {target}", "primary_dim")
    if not target.exists():
        _note("not found", "warn")
        return
    try:
        if target.is_dir():
            entries = sorted(
                target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
            )
            _note(f"directory \u00b7 {len(entries)} entrie(s)")
            for entry in entries[:limit]:
                suffix = "/" if entry.is_dir() else ""
                _note(f"  {entry.name}{suffix}")
            if len(entries) > limit:
                _note(f"  \u2026 {len(entries) - limit} more")
        else:
            _note(f"file \u00b7 {target.stat().st_size} byte(s)")
    except OSError as exc:
        _note(f"unreadable: {exc}", "error")


def append_note(text: str) -> bool:
    """Append ``#note`` to ``~/.hunter/notes.md``; ``True`` on success."""
    content = text.strip()
    if not content:
        _note("empty note ignored", "warn")
        return False
    if not ensure_home():
        _note("state directory is not writable", "error")
        return False
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with notes_path().open("a", encoding="utf-8") as handle:
            handle.write(f"- {stamp} {content}\n")
    except OSError as exc:
        _note(f"could not write note: {exc}", "error")
        return False
    _note(f"noted \u2192 {notes_path()}", "success")
    return True


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

def dispatch(line: str, on_chat: ChatCallback, on_command: CommandCallback) -> bool:
    """Route one input line; returns ``False`` when the REPL should exit."""
    text = line.rstrip("\n")
    stripped = text.strip()
    if not stripped:
        return True

    if stripped.startswith("/"):
        head = stripped.split()[0].lower()
        if head in EXIT_COMMANDS:
            return False
        try:
            result = on_command(stripped)
        except Exception as exc:  # noqa: BLE001 - a bad handler must not kill the REPL
            _note(f"command failed: {exc}", "error")
            return True
        return result is not False

    if stripped.startswith("!"):
        run_shell_command(stripped[1:])
        return True

    if stripped.startswith("@"):
        show_reference(stripped[1:])
        return True

    if stripped.startswith("#"):
        append_note(stripped[1:])
        return True

    try:
        on_chat(text)
    except Exception as exc:  # noqa: BLE001 - a bad handler must not kill the REPL
        _note(f"chat failed: {exc}", "error")
    return True


# --------------------------------------------------------------------------
# prompt_toolkit session
# --------------------------------------------------------------------------

def _can_prompt() -> bool:
    """True when an interactive prompt_toolkit session is usable."""
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
    except (AttributeError, ValueError, OSError):
        return False
    try:
        import prompt_toolkit  # noqa: F401
    except ImportError:  # pragma: no cover - prompt_toolkit is a hard dependency
        return False
    return True


def _make_history(path: Path):
    from prompt_toolkit.history import FileHistory, InMemoryHistory

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        return FileHistory(str(path))
    except OSError:  # pragma: no cover - read-only home
        return InMemoryHistory()


def _make_key_bindings():
    from prompt_toolkit.key_binding import KeyBindings

    bindings = KeyBindings()

    @bindings.add("enter")
    def _accept_or_continue(event) -> None:  # noqa: ANN001 - ptk event
        """Enter sends the message; a trailing backslash continues the line."""
        buffer = event.current_buffer
        if buffer.text.endswith("\\"):
            buffer.delete_before_cursor(count=1)
            buffer.insert_text("\n")
        else:
            buffer.validate_and_handle()

    def _insert_newline(event) -> None:  # noqa: ANN001 - ptk event
        event.current_buffer.insert_text("\n")

    @bindings.add("escape", "enter")
    def _alt_enter(event) -> None:  # noqa: ANN001 - ptk event
        """Alt+Enter adds a hard newline."""
        _insert_newline(event)

    # Terminals that report Shift+Enter as a distinct escape sequence.
    for sequence in ("\x1b[13;2u", "\x1b[13;2~", "\x1b[27;2;13~"):
        try:
            bindings.add(sequence)(_insert_newline)
        except Exception:  # pragma: no cover - unsupported on this ptk build
            pass

    return bindings


def _make_session(prompt: str, history_file: Optional[Path]):
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.formatted_text import FormattedText
    from prompt_toolkit.styles import Style

    path = Path(history_file) if history_file else history_path()

    style = Style.from_dict(
        {
            "prompt": "fg:#00FFE5",
            "continuation": "fg:#00B4A0",
            "": "fg:#FFFFFF",
        }
    )

    def _continuation(width, line_number, is_soft_wrap):  # noqa: ANN001 - ptk API
        if is_soft_wrap:
            return ""
        return FormattedText([("class:continuation", CONTINUATION)])

    return PromptSession(
        message=FormattedText([("class:prompt", prompt)]),
        history=_make_history(path),
        key_bindings=_make_key_bindings(),
        multiline=True,
        prompt_continuation=_continuation,
        auto_suggest=AutoSuggestFromHistory(),
        style=style,
        complete_while_typing=False,
        enable_history_search=False,
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def _default_chat(text: str) -> None:
    print(paint(text, "text"), flush=True)


def _default_command(command_line: str) -> bool:
    _note("unknown command", "warn")
    return True


def run_repl(
    on_chat: Optional[ChatCallback] = None,
    on_command: Optional[CommandCallback] = None,
    *,
    prompt: str = PROMPT,
    history_file: Optional[Path] = None,
) -> int:
    """Run the interactive loop; returns the process exit status."""
    chat: ChatCallback = on_chat or _default_chat
    command: CommandCallback = on_command or _default_command

    ensure_home()
    print(paint(QUIT_HINT, "text_dim"), flush=True)

    session = _make_session(prompt, history_file) if _can_prompt() else None

    while True:
        try:
            if session is not None:
                line = session.prompt()
            else:
                # Non-interactive fallback: plain line input, still EOF aware.
                line = input(paint(prompt, "primary"))
        except KeyboardInterrupt:
            print(paint("^C", "warn"), flush=True)
            continue
        except EOFError:
            print("", flush=True)
            print(paint("session closed", "text_dim"), flush=True)
            return 0

        if not dispatch(line, chat, command):
            print(paint("session closed", "text_dim"), flush=True)
            return 0
