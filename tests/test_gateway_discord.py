"""M8 F6 — Discord gateway adapter (test-first).

Mirrors the Telegram adapter tests: pure helpers + update mapping via a
FakeApi seam — no discord.py import, no network. The api seam is pinned as
``register_on_message(async_fn)``, ``start()``, ``close()``,
``send_message(chat_id, content)``.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from hunter.errors import HunterError
from hunter.gateway.discord import DISCORD_MESSAGE_LIMIT, DiscordAdapter, _default_api, _is_authorized
from hunter.gateway.transport import is_authorized

TOKEN = "test-token"


class FakeApi:
    """Test seam standing in for the discord client — no SDK, no network."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.registered: list[Any] = []
        self.started = False
        self.closed = False

    def register_on_message(self, fn: Any) -> None:
        self.registered.append(fn)

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.closed = True

    async def send_message(self, chat_id: str, content: str) -> None:
        self.sent.append((chat_id, content))


def _discord_message(
    *,
    user_id: str = "42",
    channel_id: str = "10",
    content: str = "hello",
    chat_type: str = "private",
    message_id: int = 77,
) -> SimpleNamespace:
    author = SimpleNamespace(id=user_id, name="tester")
    channel = SimpleNamespace(id=channel_id, type=chat_type)
    return SimpleNamespace(author=author, channel=channel, content=content, id=message_id)


async def _noop_handler(_message: Any) -> str | None:
    return None


# -- authorization (fail-closed, shared with the transport layer) -----------------


def test_discord_allowlist_fail_closed():
    assert is_authorized("42", set()) is False  # shared transport-level helper
    assert is_authorized("42", None) is False
    assert is_authorized(None, {"42"}) is False
    assert is_authorized("", {"42"}) is False
    assert is_authorized("42", {"42", "7"}) is True
    assert is_authorized("43", {"42"}) is False
    # the adapter exposes the same fail-closed semantics
    assert _is_authorized("42", set()) is False
    assert _is_authorized("42", {"42"}) is True
    assert _is_authorized("43", {"42"}) is False


def test_discord_adapter_requires_token():
    with pytest.raises(HunterError):
        DiscordAdapter("", {"42"})
    with pytest.raises(HunterError):
        DiscordAdapter("   ", {"42"})


def test_discord_default_api_missing_sdk_is_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "discord", None)  # import discord -> ImportError
    with pytest.raises(HunterError) as excinfo:
        _default_api(TOKEN)
    assert excinfo.value.code == "config.dependency_missing"
    assert "hunteros-harness[discord]" in excinfo.value.hint


def test_discord_adapter_class_and_limits():
    assert DiscordAdapter.name == "discord"
    assert DiscordAdapter.max_message_length == 2000
    assert DISCORD_MESSAGE_LIMIT == 2000
    assert DiscordAdapter.supports_markdown is True


def test_discord_send_chunks_at_2000_utf16():
    async def scenario():
        api = FakeApi()
        adapter = DiscordAdapter(TOKEN, {"42"}, api=api)
        long_text = "x" * (DISCORD_MESSAGE_LIMIT + 10)
        await adapter.send("10", long_text)
        assert len(api.sent) == 2
        for _chat_id, part in api.sent:
            assert len(part.encode("utf-16-le")) // 2 <= DISCORD_MESSAGE_LIMIT
        assert "".join(part for _chat_id, part in api.sent) == long_text

        # astral-plane characters are never split mid-chunk
        api.sent.clear()
        astral = "\U0001D11E" * 1500  # 3000 UTF-16 units
        await adapter.send("10", astral)
        assert len(api.sent) >= 2
        for _chat_id, part in api.sent:
            assert part.encode("utf-16").decode("utf-16") == part
        assert "".join(part for _chat_id, part in api.sent) == astral

    asyncio.run(scenario())


def test_discord_unauthorized_sender_never_reaches_handler(caplog):
    async def scenario():
        received: list[Any] = []

        async def on_message(message: Any) -> str | None:
            received.append(message)
            return "reply"

        adapter = DiscordAdapter(TOKEN, {"42"}, api=FakeApi())
        assert await adapter.connect(on_message) is True
        await adapter._dispatch(_discord_message(user_id="999"))
        await adapter.disconnect()
        assert received == []  # fail-closed: nothing ran

    with caplog.at_level(logging.WARNING):
        asyncio.run(scenario())
    assert sum(1 for record in caplog.records if record.levelno >= logging.WARNING) == 1


def test_discord_authorized_message_reaches_handler():
    async def scenario():
        received: list[Any] = []

        async def on_message(message: Any) -> str | None:
            received.append(message)
            return "reply"

        adapter = DiscordAdapter(TOKEN, {"42"}, api=FakeApi())
        assert await adapter.connect(on_message) is True
        assert adapter._api.started is True
        assert adapter._api.registered  # the handler was registered with the api

        await adapter._dispatch(
            _discord_message(user_id="42", channel_id="10", content="scan 127.0.0.1")
        )
        assert len(received) == 1
        message = received[0]
        assert message.transport == "discord"
        assert message.text == "scan 127.0.0.1"
        assert message.user_id == "42"
        assert message.chat_id == "10"
        assert message.chat_type == "dm"  # private channel -> dm

        # a non-private channel maps to its type string
        received.clear()
        await adapter._dispatch(
            _discord_message(user_id="42", channel_id="11", content="group ping", chat_type="text")
        )
        assert received[0].chat_type == "text"
        await adapter.disconnect()
        assert adapter._api.closed is True
        await adapter.disconnect()  # idempotent

    asyncio.run(scenario())


def test_transports_from_env_discord_contract():
    from hunter.gateway.app import transports_from_env

    transports = transports_from_env(
        {
            "HUNTEROS_DISCORD_TOKEN": TOKEN,
            "HUNTEROS_DISCORD_ALLOWED_USERS": "42, 7",
        }
    )
    assert [transport.name for transport in transports] == ["discord"]
    assert transports[0].max_message_length == DISCORD_MESSAGE_LIMIT

    # token WITHOUT an allowlist -> an open bot is never an accident
    with pytest.raises(HunterError) as excinfo:
        transports_from_env({"HUNTEROS_DISCORD_TOKEN": TOKEN})
    assert excinfo.value.code == "gateway.discord_allowlist"
    assert "HUNTEROS_DISCORD_ALLOWED_USERS" in excinfo.value.hint

    # no token -> no discord adapter (fail-closed by omission)
    assert transports_from_env({}) == []
