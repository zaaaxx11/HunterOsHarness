"""Telegram adapter tests — pure helpers + update mapping, no SDK required."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from types import SimpleNamespace

import pytest

from hunter.chat.commands import resolve_command
from hunter.errors import HunterError
from hunter.gateway.telegram import (
    TELEGRAM_MESSAGE_LIMIT,
    TelegramAdapter,
    _chunk_text,
    _default_api,
    _is_authorized,
)

HAS_TELEGRAM_SDK = importlib.util.find_spec("telegram") is not None


# -- authorization (fail-closed) --------------------------------------------------


def test_empty_allowlist_denies_everyone():
    assert _is_authorized("42", set()) is False
    assert _is_authorized("42", None) is False


def test_listed_user_allowed_and_unknown_denied():
    assert _is_authorized("42", {"42", "7"}) is True
    assert _is_authorized("43", {"42"}) is False


def test_none_or_blank_user_denied():
    assert _is_authorized(None, {"42"}) is False
    assert _is_authorized("", {"42"}) is False
    assert _is_authorized("  ", {"42"}) is False


# -- chunking (4096 UTF-16 units, astral-safe) -------------------------------------


def test_chunk_text_ascii_within_limit_is_single_chunk():
    text = "a" * 4096
    chunks = _chunk_text(text)
    assert chunks == [text]


def test_chunk_text_splits_at_utf16_boundary():
    text = "a" * (TELEGRAM_MESSAGE_LIMIT - 1) + "\U0001D11E" + "b"  # astral costs 2
    chunks = _chunk_text(text)
    assert len(chunks) == 2
    # No surrogate pair ever split: every chunk round-trips UTF-16.
    for chunk in chunks:
        assert chunk.encode("utf-16").decode("utf-16") == chunk
    assert sum(len(c) for c in chunks) == len(text)


def test_chunk_text_respects_limit_in_utf16_units():
    text = "\U0001D11E" * 5000  # each char = 2 UTF-16 units
    chunks = _chunk_text(text)
    for chunk in chunks:
        assert len(chunk.encode("utf-16-le")) // 2 <= TELEGRAM_MESSAGE_LIMIT
    assert "".join(chunks) == text


def test_chunk_text_empty_and_invalid_limit():
    assert _chunk_text("", 10) == []
    with pytest.raises(ValueError):
        _chunk_text("x", 0)


# -- command mapping (registry shared with the REPL) --------------------------------


def test_command_mapping_with_mention():
    cmd, args = resolve_command("/scan@hunterbot http://127.0.0.1:8941/")
    assert cmd.name == "scan"
    assert args == "http://127.0.0.1:8941/"


def test_command_mapping_non_command_text():
    assert resolve_command("is my server ok?") is None


# -- construction / seams --------------------------------------------------------------


def test_adapter_requires_token():
    with pytest.raises(HunterError):
        TelegramAdapter("", {"42"})


def test_default_api_missing_sdk_is_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "telegram", None)  # import telegram → ImportError
    with pytest.raises(HunterError) as excinfo:
        _default_api("token")
    assert "hunteros-harness[telegram]" in excinfo.value.hint


@pytest.mark.skipif(not HAS_TELEGRAM_SDK, reason="python-telegram-bot not installed")
def test_default_api_returns_bot_when_installed():
    from telegram import Bot

    assert isinstance(_default_api("token"), Bot)


class _FakeApi:
    """Test seam standing in for telegram.Bot — no SDK, no network."""

    def __init__(self, updates=None):
        self.updates = list(updates or [])
        self.sent: list[dict] = []

    async def get_updates(self, offset=0, timeout=0):
        return self.updates

    async def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return SimpleNamespace(message_id=len(self.sent))

    async def send_chat_action(self, **kwargs):
        self.sent.append({"action": kwargs.get("action")})


class _FakeSdkBot(_FakeApi):
    """Mimics the real SDK surface just enough for connect/disconnect."""

    async def initialize(self):
        self.initialized = True

    async def shutdown(self):
        self.shutdown_called = True


def _fake_update(text, user_id="42", chat_id="10", chat_type="private"):
    sender = SimpleNamespace(id=int(user_id), full_name="Tester", username="tester")
    chat = SimpleNamespace(id=int(chat_id), type=chat_type)
    message = SimpleNamespace(
        text=text, caption=None, from_user=sender, chat=chat, message_id=77
    )
    return SimpleNamespace(update_id=5, message=message, edited_message=None)


def test_adapter_connect_disconnect_lifecycle():
    """connect() against the api seam: task starts, disconnect is clean. This
    exercises the adapter loop without the SDK; the SDK-only constructor path
    is covered by test_default_api_* above."""

    async def scenario():
        adapter = TelegramAdapter("token", {"42"}, api=_FakeSdkBot())
        assert await adapter.connect(None) is True
        await adapter.disconnect()
        assert getattr(adapter._api, "shutdown_called", False) is True

    asyncio.run(scenario())


def test_authorized_update_maps_to_inbound_message():
    async def scenario():
        received: list = []
        api = _FakeApi()

        async def on_message(message):
            received.append(message)
            return "reply"

        adapter = TelegramAdapter("token", {"42"}, api=api)
        adapter._on_message = on_message
        await adapter._dispatch(_fake_update("scan 127.0.0.1", user_id="42"))
        assert len(received) == 1
        message = received[0]
        assert message.transport == "telegram"
        assert message.text == "scan 127.0.0.1"
        assert message.chat_id == "10" and message.user_id == "42"
        assert message.chat_type == "dm"

    asyncio.run(scenario())


def test_denied_sender_never_reaches_handler():
    async def scenario():
        received: list = []

        async def on_message(message):
            received.append(message)

        adapter = TelegramAdapter("token", {"42"}, api=_FakeApi())
        adapter._on_message = on_message
        await adapter._dispatch(_fake_update("you do not know me", user_id="999"))
        assert received == []  # fail-closed: nothing ran

    asyncio.run(scenario())


def test_send_chunks_at_telegram_limit():
    async def scenario():
        api = _FakeApi()
        adapter = TelegramAdapter("token", {"42"}, api=api)
        long_text = "x" * (TELEGRAM_MESSAGE_LIMIT + 10)
        await adapter.send("10", long_text)
        assert len(api.sent) == 2
        for message in api.sent:
            assert len(message["text"]) <= TELEGRAM_MESSAGE_LIMIT

    asyncio.run(scenario())


def test_send_empty_content_sends_nothing():
    async def scenario():
        api = _FakeApi()
        adapter = TelegramAdapter("token", {"42"}, api=api)
        await adapter.send("10", "")
        assert api.sent == []

    asyncio.run(scenario())


# -- env wiring (hunter gateway start) ----------------------------------------


def test_transports_from_env_empty_by_default(monkeypatch):
    from hunter.gateway.app import transports_from_env

    for var in (
        "HUNTEROS_TELEGRAM_TOKEN",
        "HUNTEROS_TELEGRAM_ALLOWED_USERS",
        "HUNTEROS_WEBHOOK_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    assert transports_from_env({}) == []


def test_transports_from_env_token_without_allowlist_refused():
    from hunter.gateway.app import transports_from_env

    with pytest.raises(HunterError) as excinfo:
        transports_from_env({"HUNTEROS_TELEGRAM_TOKEN": "tok"})
    assert "HUNTEROS_TELEGRAM_ALLOWED_USERS" in excinfo.value.hint


def test_transports_from_env_builds_adapters():
    from hunter.gateway.app import transports_from_env

    transports = transports_from_env(
        {
            "HUNTEROS_TELEGRAM_TOKEN": "tok",
            "HUNTEROS_TELEGRAM_ALLOWED_USERS": "42, 7",
            "HUNTEROS_WEBHOOK_SECRET": "s3cret",
            "HUNTEROS_WEBHOOK_PORT": "8899",
        }
    )
    assert [t.name for t in transports] == ["telegram", "webhook"]
    telegram, webhook = transports
    assert telegram.max_message_length == TELEGRAM_MESSAGE_LIMIT
    assert webhook.port == 8899
