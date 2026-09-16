"""CLI error handling — the LAST line of defense for the terminal UX.

:func:`handle_cli_error` renders ANY exception the way the errors.py doctrine
demands (classified line + ``where:`` location, never a surprise traceback)
and returns the exit code for :class:`SystemExit`. It is used both by the
``main()`` backstop and by per-command handlers (typer/click consume
``typer.Exit`` inside ``app()``, so command-level wraps and the backstop
complement each other).

Verbose plumbing is a flag/env hybrid: the ``--verbose`` global flag OR
``HUNTEROS_VERBOSE=1``. Verbose prints the full traceback to STDERR — the
user asked for it, so it is not a leak.

:func:`run_app` drives the typer-generated click command in NON-standalone
mode so the harness owns the exits typer would otherwise own silently:
argument errors keep typer's rich rendering, EOF/interrupts become
``[interrupted]`` + exit 130 (not click's "Aborted!" + 1), and HunterError /
unexpected errors fall into the ``main()`` backstop.
"""

from __future__ import annotations

import contextlib
import errno
import os
import sys
import traceback
from pathlib import PurePosixPath
from typing import Any

import click
from rich.console import Console

from hunter.branding import make_console
from hunter.errors import EXIT_ERROR, EXIT_INTERRUPT, HunterError

__all__ = ["handle_cli_error", "is_verbose", "run_app", "set_verbose"]

ISSUE_URL = "https://github.com/zaaaxx11/HunterOsHarness/issues"

_VERBOSE_TRUTHY = frozenset({"1", "true", "yes", "on"})

_verbose_flag = False


def set_verbose(value: bool) -> None:
    """Set the ``--verbose`` flag (called by the root CLI callback)."""
    global _verbose_flag
    _verbose_flag = bool(value)


def is_verbose() -> bool:
    """Verbose = the global ``--verbose`` flag OR ``HUNTEROS_VERBOSE=1``."""
    if _verbose_flag:
        return True
    return os.environ.get("HUNTEROS_VERBOSE", "").strip().lower() in _VERBOSE_TRUTHY


def _err_console() -> Console:
    return make_console(stderr=True)


def _hunter_location(exc: BaseException) -> str:
    """``hunter/llm/config.py:242`` for the DEEPEST traceback frame that lives
    inside the hunter package — the raise site, never the catch site (the
    backstop's own ``handle.py`` frame or a per-command ``main.py`` wrap would
    otherwise name themselves for every error). Any hunter frame is used when
    none carries a formattable package path."""
    tb = exc.__traceback__
    fallback = ""
    deepest = ""
    while tb is not None:
        filename = (tb.tb_frame.f_code.co_filename or "").replace("\\", "/")
        if "hunter" in filename:
            formatted = _format_hunter_path(filename)
            if formatted:
                # Keep walking: the chain runs outermost -> deepest, so the
                # last hunter frame seen is the one closest to the raise.
                deepest = f"{formatted}:{tb.tb_lineno}"
            else:
                fallback = fallback or f"{filename}:{tb.tb_lineno}"
        tb = tb.tb_next
    return deepest or fallback or "(unknown location)"


def _format_hunter_path(filename: str) -> str:
    """Strip everything before the hunter package directory so the location
    reads the same on every install (``.../src/hunter/llm/config.py`` →
    ``hunter/llm/config.py``)."""
    parts = PurePosixPath(filename).parts
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] == "hunter":
            return "/".join(parts[index:])
    return ""


def _one_line(exc: BaseException) -> str:
    return str(exc).replace("\n", " ")[:300] or type(exc).__name__


def handle_cli_error(exc: BaseException, *, verbose: bool = False) -> int:
    """Print ``exc`` the doctrine way and return the exit code.

    - HunterError → ``[ERROR <layer>]`` / ``[BLOCKED]`` user message plus a
      ``where:`` line naming the deepest hunter frame — exit from the error's
      own exit code.
    - KeyboardInterrupt → ``[interrupted]`` — exit 130.
    - Anything else → one ``[ERROR engine]`` line plus the issue URL; with
      ``verbose`` the full traceback goes to STDERR (and only there).
    """
    err = _err_console()
    if isinstance(exc, HunterError):
        err.print(exc.user_message(), markup=False, highlight=False)
        err.print(f"where: {_hunter_location(exc)}", markup=False, highlight=False)
        if not exc.hint:
            from hunter.hospitality import exit_hint

            hint = exit_hint(exc.exit_code, blocked=exc.blocked)
            if hint:
                err.print(hint, markup=False, highlight=False)
        return exc.exit_code
    if isinstance(exc, KeyboardInterrupt):
        err.print("[interrupted]", markup=False, highlight=False)
        return EXIT_INTERRUPT
    err.print(
        f"[ERROR engine] unexpected {type(exc).__name__}: {_one_line(exc)}",
        markup=False,
        highlight=False,
    )
    err.print(
        f"[report] re-run with --verbose for the full traceback, or file an issue: {ISSUE_URL}",
        markup=False,
        highlight=False,
    )
    if verbose:
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
    return EXIT_ERROR


def _print_interrupted() -> None:
    _err_console().print("[interrupted]", markup=False, highlight=False)


def _pacify_stdout() -> None:
    """Make the interpreter's shutdown flush of stdout never raise (the pipe
    is already gone — the operator closed it on purpose)."""
    with contextlib.suppress(Exception):  # nothing left to save
        sys.stdout.flush()
    wrapper = getattr(click.utils, "PacifyFlushWrapper", None) or getattr(
        click.utils, "_PacifyFlushWrapper", None
    )
    if wrapper is not None:
        with contextlib.suppress(Exception):
            sys.stdout = wrapper(sys.stdout)  # type: ignore[assignment]


def _show_click_exception(exc: click.exceptions.ClickException, rich_markup_mode: Any) -> None:
    """Render an argument-parsing error exactly like typer's standalone path
    (rich-formatted when the app uses rich markup)."""
    try:
        if rich_markup_mode is not None:
            from typer import rich_utils

            rich_utils.rich_format_error(exc)
            return
    except Exception:  # noqa: BLE001 — rendering must never crash the error path
        pass
    exc.show()


def run_app(app_command: click.Command, *, args: Any = None) -> None:
    """Drive the typer-generated click command in non-standalone mode.

    Argument errors keep typer's own rendering and exit code; EOF /
    KeyboardInterrupt become ``[interrupted]`` + 130; every other escape is
    rendered by :func:`handle_cli_error` — zero surprise tracebacks.
    """
    rich_markup_mode = getattr(app_command, "rich_markup_mode", None)
    try:
        rv = app_command.main(args=args, standalone_mode=False)
    except OSError as exc:
        # `hunter ... | head` closes the pipe mid-render: pacify like click
        # does for EPIPE (Windows reports EINVAL for the same situation).
        if exc.errno in (errno.EPIPE, errno.EINVAL):
            _pacify_stdout()
            raise SystemExit(EXIT_ERROR) from None
        raise
    except click.exceptions.Abort:
        # click converts EOFError into Abort; the operator stopped us.
        _print_interrupted()
        raise SystemExit(EXIT_INTERRUPT) from None
    except click.exceptions.ClickException as exc:
        _show_click_exception(exc, rich_markup_mode)
        raise SystemExit(exc.exit_code) from exc
    except KeyboardInterrupt:  # pragma: no cover — typer converts these to Exit(130)
        raise SystemExit(handle_cli_error(KeyboardInterrupt(), verbose=is_verbose())) from None
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — this IS the backstop
        raise SystemExit(handle_cli_error(exc, verbose=is_verbose())) from exc
    if isinstance(rv, int) and rv != 0:
        if rv == EXIT_INTERRUPT:  # typer maps KeyboardInterrupt → Exit(130)
            _print_interrupted()
        raise SystemExit(rv)
