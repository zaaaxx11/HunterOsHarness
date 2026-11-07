"""Claude-Code-style terminal motion: a live status line and tool activity rows.

Two pieces:

* :class:`Spinner` — one line, redrawn in place while a turn runs: a starburst
  glyph, a rotating verb, the elapsed time, a live token count and the interrupt
  hint. Nothing is printed when stdout is not a TTY, so piped or scripted runs
  stay byte-clean.
* :func:`tool_call` / :func:`tool_result` — the ``● name(args)`` / ``⎿ result``
  pair, so a turn that calls tools says what it is doing instead of going quiet.
"""

from __future__ import annotations

import itertools
import random
import sys
import threading
import time
from typing import Any, TextIO

#: Tosca palette — primary family, dimmer for chrome.
PRIMARY = "\x1b[38;2;0;255;229m"
DIM = "\x1b[38;2;120;120;120m"
RESET = "\x1b[0m"

#: The starburst ping-pong Claude Code cycles through.
FRAMES = "\u00b7\u2722\u2733\u2736\u273b\u273d\u273b\u2736\u2733\u2722"

#: Verbs rotate so a long wait reads as progress, not a hang.
VERBS = (
    "Thinking", "Pondering", "Calculating", "Deliberating", "Mulling",
    "Ruminating", "Cogitating", "Synthesizing", "Noodling", "Scheming",
    "Tracing", "Cross-checking",
)

#: Left-to-right connector for a tool result line.
RESULT_GLYPH = "\u23bf"


def _supports_color(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except Exception:  # noqa: BLE001
        return False


def _human_tokens(count: int) -> str:
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}k"
    return str(count)


class Spinner:
    """A single redrawn status line, active only on a TTY.

    Use as a context manager::

        with Spinner() as spin:
            spin.add_tokens(120)      # called as the turn streams
    """

    def __init__(
        self,
        label: str | None = None,
        stream: TextIO | None = None,
        interval: float = 0.09,
        show_elapsed: bool = True,
        interrupt_hint: str = "ctrl-c to interrupt",
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.label = label or random.choice(VERBS)
        self.interval = interval
        self.show_elapsed = show_elapsed
        self.interrupt_hint = interrupt_hint
        self.tokens = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = 0.0
        # TTY only: a redrawn status line corrupts piped or redirected output.
        self.enabled = _supports_color(self.stream)
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self) -> "Spinner":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._started = time.monotonic()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        if self.enabled:
            self.stream.write("\r\x1b[K")
            self.stream.flush()

    # -- live updates -------------------------------------------------------
    def add_tokens(self, count: int) -> None:
        """Add to the token counter shown beside the timer."""
        with self._lock:
            self.tokens += max(0, int(count))

    def set_label(self, label: str) -> None:
        with self._lock:
            self.label = label

    def log(self, message: str) -> None:
        """Print a line without tearing the spinner (clear, write, resume)."""
        if not self.enabled:
            return
        self.stream.write("\r\x1b[K")
        self.stream.write(f"{message}\n")
        self.stream.flush()

    # -- rendering ----------------------------------------------------------
    def _render(self, frame: str) -> str:
        with self._lock:
            label = self.label
            tokens = self.tokens
        bits: list[str] = []
        if self.show_elapsed:
            elapsed = int(time.monotonic() - self._started)
            if elapsed >= 1:
                bits.append(f"{elapsed}s")
        if tokens:
            bits.append(f"\u26a1 {_human_tokens(tokens)} tokens")
        if self.interrupt_hint:
            bits.append(self.interrupt_hint)
        joined = " \u00b7 ".join(bits)
        tail = f"  {DIM}({joined}){RESET}" if bits else ""
        return f"\r\x1b[K{PRIMARY}{frame}{RESET} {label}\u2026{tail}"

    def _run(self) -> None:
        frames = itertools.cycle(FRAMES)
        while not self._stop.is_set():
            try:
                self.stream.write(self._render(next(frames)))
                self.stream.flush()
            except Exception:  # noqa: BLE001 - a dead terminal must not crash a turn
                return
            self._stop.wait(self.interval)


def tool_call(name: str, detail: str = "", stream: TextIO | None = None) -> None:
    """Print ``● name(detail)`` — the row that announces a tool invocation."""
    out = stream if stream is not None else sys.stdout
    if not _supports_color(out):
        return
    suffix = f"{DIM}({detail}){RESET}" if detail else ""
    out.write(f"{PRIMARY}\u25cf{RESET} {name}{suffix}\n")
    out.flush()


def tool_result(text: str, stream: TextIO | None = None, limit: int = 160) -> None:
    """Print the indented ``⎿ result`` line under the last :func:`tool_call`."""
    out = stream if stream is not None else sys.stdout
    if not _supports_color(out):
        return
    body = " ".join(str(text).split())
    if len(body) > limit:
        body = body[: limit - 1] + "\u2026"
    out.write(f"  {DIM}{RESULT_GLYPH}  {body}{RESET}\n")
    out.flush()


def banner_wordmark(text: str = "HUNTER", stream: TextIO | None = None) -> str:
    """Return ``text`` styled as the banner wordmark (tosca, bold)."""
    return f"{PRIMARY}\x1b[1m{text}{RESET}"

class ProgressLine:
    """A live hunt status line: round, findings, verified, budget, time left.

    Redrawn in place between rounds so a long hunt shows movement instead of a
    wall of log lines. Silent when stdout is not a TTY.
    """

    def __init__(self, total_rounds: int | None = None, stream: TextIO | None = None,
                 width: int = 12) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.total_rounds = total_rounds
        self.width = max(4, width)
        self.round: int | None = None
        self.findings = 0
        self.verified = 0
        self.chains = 0
        self.elapsed = 0.0
        self.remaining: float | None = None
        self.spent: float | None = None
        self.budget: float | None = None
        self.enabled = _supports_color(self.stream)
        self._lock = threading.Lock()

    def update(self, **fields: Any) -> None:
        with self._lock:
            for key, value in fields.items():
                if value is not None and hasattr(self, key):
                    setattr(self, key, value)

    def _bar(self) -> str:
        with self._lock:
            done, total = self.round or 0, self.total_rounds
        if not total:
            return ""
        filled = min(self.width, max(0, round(self.width * done / total)))
        return "[" + "\u2588" * filled + "\u2591" * (self.width - filled) + "]"

    def render(self) -> str:
        with self._lock:
            parts: list[str] = []
            if self.round:
                parts.append(f"round {self.round}/{self.total_rounds}" if self.total_rounds
                             else f"round {self.round}")
            bar = self._bar()
            parts.append(f"{self.findings} findings")
            if self.verified:
                parts.append(f"{PRIMARY}{self.verified} verified{RESET}{DIM}")
            if self.chains:
                parts.append(f"{self.chains} chains")
            if self.remaining is not None:
                mins, secs = divmod(int(max(0.0, self.remaining)), 60)
                parts.append(f"{mins:02d}:{secs:02d} left")
            if self.spent is not None and self.budget:
                parts.append(f"${self.spent:.2f}/${self.budget:.0f}")
            body = " \u00b7 ".join(parts)
        bar = f"{PRIMARY}{bar}{RESET}{DIM} " if bar else ""
        return f"\r\x1b[K{bar}{DIM}{body}{RESET}"

    def draw(self) -> None:
        if not self.enabled:
            return
        try:
            self.stream.write(self.render())
            self.stream.flush()
        except Exception:  # noqa: BLE001
            self.enabled = False

    def clear(self) -> None:
        if not self.enabled:
            return
        self.stream.write("\r\x1b[K")
        self.stream.flush()
