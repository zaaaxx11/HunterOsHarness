"""CLI motion: the status line must be live on a TTY and silent everywhere else.

Behaviour contracts only — no snapshots of exact glyph output.
"""

from __future__ import annotations

import io
import re
import time

from hunter.cli.spinner import (
    FRAMES,
    VERBS,
    Spinner,
    _human_tokens,
    tool_call,
    tool_result,
)


class _FakeTTY(io.StringIO):
    def isatty(self) -> bool:  # noqa: D102
        return True


def test_piped_output_stays_clean() -> None:
    buf = io.StringIO()
    with Spinner(stream=buf) as spin:
        spin.add_tokens(10)
    assert buf.getvalue() == "", "a non-TTY run must not emit control sequences"


def test_tty_run_draws_and_clears() -> None:
    buf = _FakeTTY()
    with Spinner(stream=buf) as spin:
        spin.add_tokens(500)
    out = buf.getvalue()
    assert any(frame in out for frame in FRAMES), "no spinner frame was drawn"
    assert out.endswith("\r\x1b[K"), "the line must be cleared on exit"


def test_status_line_carries_verb_timer_and_hint() -> None:
    buf = _FakeTTY()
    spin = Spinner(stream=buf)
    spin.enabled = True
    spin._started = time.monotonic() - 5
    spin.add_tokens(2400)
    line = spin._render(FRAMES[0])
    assert any(v in line for v in VERBS)
    assert re.search(r"\d+s", line), "elapsed seconds missing"
    assert "2.4k tokens" in line, "token count missing"
    assert "ctrl-c" in line, "the interrupt hint must match what actually works"


def test_token_labels_are_human_readable() -> None:
    assert _human_tokens(999) == "999"
    assert _human_tokens(1500) == "1.5k"
    assert _human_tokens(2_000_000) == "2.0M"


def test_tool_rows_are_bullet_and_connector() -> None:
    calls = _FakeTTY()
    tool_call("hunt", "1 tool call", stream=calls)
    assert "\u25cf" in calls.getvalue()
    results = _FakeTTY()
    tool_result("1 candidate", stream=results)
    assert "\u23bf" in results.getvalue()


def test_tool_rows_silent_when_piped() -> None:
    buf = io.StringIO()
    tool_call("hunt", "x", stream=buf)
    tool_result("y", stream=buf)
    assert buf.getvalue() == ""


def test_long_tool_result_is_truncated() -> None:
    buf = _FakeTTY()
    tool_result("z" * 900, stream=buf, limit=40)
    body = buf.getvalue()
    assert "\u2026" in body and len(body) < 200


def test_spinner_is_idempotent_on_double_stop() -> None:
    buf = _FakeTTY()
    spin = Spinner(stream=buf)
    spin.start()
    spin.stop()
    spin.stop()  # must not raise or hang
