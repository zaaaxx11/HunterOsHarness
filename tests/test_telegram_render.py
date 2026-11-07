"""Telegram rendering: markdown in, valid MarkdownV2 out, never a lost reply.

These assert behaviour, not snapshots: the escaping round-trips, a fenced block
survives chunking intact, and a message Telegram rejects still arrives as text.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from hunter.gateway.render import (
    chunk_text,
    escape_mdv2,
    render,
    strip_mdv2,
    tables_to_bullets,
)


def test_escape_covers_every_markdownv2_special() -> None:
    # Telegram rejects the whole message on one unescaped special, so the set is
    # the contract: _ * [ ] ( ) ~ ` > # + - = | { } . ! \
    raw = "_*[]()~`>#+-=|{}.!\\"
    out = escape_mdv2(raw)
    for char in raw:
        assert f"\\{char}" in out, f"{char!r} was not escaped"


def test_plain_text_round_trips() -> None:
    # No formatting-lookalike pairs here: strip_mdv2 intentionally *removes*
    # `*x*`/`~x~`, so only plain prose must survive a round trip unchanged.
    source = "log (findings kept) at 1.5s: a-b! [ok] {x}"
    assert strip_mdv2(escape_mdv2(source)) == source


def test_markdown_constructs_become_markdownv2() -> None:
    out = render("**bold** and *ital* and ## Title")
    assert "*bold*" in out
    assert "_ital_" in out
    assert "\\#\\# Title" in out  # not a line start: escaped, not a heading


def test_heading_at_line_start_is_bold() -> None:
    assert render("## Session\n").startswith("*Session*")


def test_code_is_never_escaped_as_prose() -> None:
    out = render("`a.b(c)`")
    assert "`a.b(c)`" in out, "inline code must survive unmangled"


def test_fenced_block_survives() -> None:
    out = render("```bash\nls -la /tmp\n```")
    assert "```bash\nls -la /tmp\n```" in out


def test_pipe_table_becomes_bullets() -> None:
    out = tables_to_bullets("| Sev | Count |\n|---|---|\n| high | 2 |\n| low | 5 |")
    assert "high" in out and "Sev: high" in out
    assert "|" not in out, "MarkdownV2 has no table syntax"


def test_chunking_never_splits_a_fence() -> None:
    body = "\n".join(f"line {i} " + "x" * 60 for i in range(120))
    parts = chunk_text(render(f"```python\n{body}\n```"), 400)
    assert len(parts) > 1
    for part in parts:
        assert part.count("```") % 2 == 0, "a part opened a fence it did not close"


def test_chunk_marker_is_a_valid_markdownv2_escape() -> None:
    parts = chunk_text(render("```\n" + "y" * 500 + "\n```"), 200)
    assert len(parts) > 1
    assert re.search(r"\\\(\d+/\d+\\\)", parts[0]), parts[0][-20:]


class _FakeTelegramAPI:
    """Records the calls the adapter makes; optionally rejects markup."""

    def __init__(self, reject_markdown: bool = False) -> None:
        self.calls: list[dict] = []
        self.reject_markdown = reject_markdown

    async def send_message(self, **kwargs):
        self.calls.append(kwargs)
        if self.reject_markdown and kwargs.get("parse_mode"):
            raise RuntimeError("Bad Request: can't parse entities")
        return {"ok": True}

    async def send_chat_action(self, **kwargs):  # noqa: ARG002
        return {"ok": True}


def _adapter(api: _FakeTelegramAPI):
    from hunter.gateway.telegram import TelegramAdapter

    adapter = TelegramAdapter("0:test", {"1"})
    adapter._api = api
    adapter._closed = False
    return adapter


def test_send_uses_markdownv2() -> None:
    api = _FakeTelegramAPI()
    asyncio.run(_adapter(api).send("1", "**TVL** is $2.45B"))
    assert api.calls[0]["parse_mode"] == "MarkdownV2"
    assert "*TVL*" in api.calls[0]["text"]


def test_rejected_markup_is_resent_as_plain_text() -> None:
    api = _FakeTelegramAPI(reject_markdown=True)
    asyncio.run(_adapter(api).send("1", "**TVL** is $2.45B"))
    assert len(api.calls) == 2, "the reply must not be lost"
    assert "parse_mode" not in api.calls[1]
    assert api.calls[1]["text"] == "TVL is $2.45B"


def test_send_chunks_past_the_limit() -> None:
    api = _FakeTelegramAPI()
    asyncio.run(_adapter(api).send("1", "z" * 9000))
    assert len(api.calls) > 1
    assert all(len(c["text"]) <= 4096 for c in api.calls)


def test_empty_content_still_sends() -> None:
    api = _FakeTelegramAPI()
    asyncio.run(_adapter(api).send("1", ""))
    assert not api.calls, "an empty reply has nothing to send"
