"""M8 F11 — WhatsApp Cloud gateway adapter (written FIRST — TDD).

Mirrors the Discord/Telegram adapter discipline: pure helpers + the pinned
api seam (``register_on_message``, ``start()``, ``close()``,
``send_message(chat_id, content)``) via a FakeApi — no Meta SDK, no network.
The loopback webhook runs for real on an ephemeral 127.0.0.1 port: hub
verification round-trip, fail-closed X-Hub-Signature-256 checks, and the
default-deny allowlist. Fully offline.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import http.client
import json
import logging
import urllib.parse
from typing import Any

import httpx
import pytest

from hunter.errors import HunterError
from hunter.gateway.transport import InboundMessage
from hunter.gateway.whatsapp import (
    WHATSAPP_MESSAGE_LIMIT,
    WhatsAppAdapter,
    WhatsAppCloudApi,
    _is_authorized,
)

TOKEN = "eaag-test-token"
PHONE_NUMBER_ID = "123456789"
SECRET = "test-app-secret"
VERIFY_TOKEN = "test-verify-token"
ALLOWED = {"15551234567"}


class FakeApi:
    """Test seam standing in for the Cloud client — no SDK, no network."""

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


def _signed(body: bytes, secret: str = SECRET) -> str:
    """The exact X-Hub-Signature-256 a sender must produce."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _whatsapp_payload(from_number: str = "15551234567") -> dict:
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "ENTRY-1",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [
                                {
                                    "from": from_number,
                                    "id": "wamid.A",
                                    "type": "text",
                                    "text": {"body": "scan 127.0.0.1"},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }


def _get(port: int, params: dict) -> tuple[int, str]:
    """Blocking GET — callers must run it off the event loop."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/whatsapp?" + urllib.parse.urlencode(params))
    response = conn.getresponse()
    raw = response.read().decode("utf-8", "replace")
    conn.close()
    return response.status, raw


def _post(port: int, body: bytes, headers: dict | None = None) -> tuple[int, str]:
    """Blocking POST — callers must run it off the event loop."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", "/whatsapp", body=body, headers=dict(headers or {}))
    response = conn.getresponse()
    raw = response.read().decode("utf-8", "replace")
    conn.close()
    return response.status, raw


async def _serve(**kwargs: Any):
    """Connect an adapter (ephemeral loopback port); returns (adapter, received)."""
    adapter = WhatsAppAdapter(
        TOKEN,
        PHONE_NUMBER_ID,
        ALLOWED,
        app_secret=SECRET,
        verify_token=VERIFY_TOKEN,
        api=FakeApi(),
        port=0,
        **kwargs,
    )
    received: list[InboundMessage] = []

    async def on_message(message: InboundMessage) -> str | None:
        received.append(message)
        return "ack"

    assert await adapter.connect(on_message) is True
    return adapter, received


# -- authorization (fail-closed, shared with the transport layer) -----------------


def test_whatsapp_allowlist_fail_closed():
    assert _is_authorized("15551234567", set()) is False  # empty allowlist denies everyone
    assert _is_authorized("15551234567", None) is False
    assert _is_authorized(None, ALLOWED) is False
    assert _is_authorized("", ALLOWED) is False
    assert _is_authorized("15551234567", ALLOWED) is True
    assert _is_authorized("15999999999", ALLOWED) is False


def test_whatsapp_adapter_requires_token_and_phone_number_id():
    with pytest.raises(HunterError) as excinfo:
        WhatsAppAdapter("", PHONE_NUMBER_ID, ALLOWED)
    assert excinfo.value.code == "config.value"
    with pytest.raises(HunterError):
        WhatsAppAdapter("   ", PHONE_NUMBER_ID, ALLOWED)
    with pytest.raises(HunterError) as excinfo:
        WhatsAppAdapter(TOKEN, "", ALLOWED)
    assert excinfo.value.code == "config.value"
    with pytest.raises(HunterError):
        WhatsAppAdapter(TOKEN, "  ", ALLOWED)


def test_whatsapp_send_chunks_at_4096_and_posts_cloud_body():
    async def scenario():
        api = FakeApi()
        adapter = WhatsAppAdapter(TOKEN, PHONE_NUMBER_ID, ALLOWED, api=api)
        long_text = "x" * (WHATSAPP_MESSAGE_LIMIT + 10)
        await adapter.send("15551234567", long_text)
        assert len(api.sent) == 2
        for _chat_id, part in api.sent:
            assert len(part.encode("utf-16-le")) // 2 <= WHATSAPP_MESSAGE_LIMIT
        assert "".join(part for _chat_id, part in api.sent) == long_text

        # astral-plane characters are never split mid-chunk
        api.sent.clear()
        astral = "\U0001D11E" * 3000  # 6000 UTF-16 units
        await adapter.send("15551234567", astral)
        for _chat_id, part in api.sent:
            assert part.encode("utf-16").decode("utf-16") == part
        assert "".join(part for _chat_id, part in api.sent) == astral

        # the Cloud request body/headers are pinned through WhatsAppCloudApi
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"messaging_product": "whatsapp"})

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="https://graph.facebook.com/v21.0"
        )
        cloud = WhatsAppCloudApi(TOKEN, PHONE_NUMBER_ID, client=client)
        await cloud.send_message("15551234567", "hello there")
        await cloud.close()
        assert len(seen) == 1
        request = seen[0]
        assert request.method == "POST"
        assert str(request.url) == f"https://graph.facebook.com/v21.0/{PHONE_NUMBER_ID}/messages"
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert json.loads(request.content.decode("utf-8")) == {
            "messaging_product": "whatsapp",
            "to": "15551234567",
            "type": "text",
            "text": {"body": "hello there"},
        }

    asyncio.run(scenario())


def test_whatsapp_webhook_verification_challenge_round_trip():
    async def scenario():
        adapter, _received = await _serve()
        port = adapter.port
        status, body = await asyncio.to_thread(
            _get,
            port,
            {"hub.mode": "subscribe", "hub.verify_token": VERIFY_TOKEN, "hub.challenge": "CHAL-123"},
        )
        assert status == 200
        assert body == "CHAL-123"  # echoed verbatim

        status, _body = await asyncio.to_thread(
            _get,
            port,
            {"hub.mode": "subscribe", "hub.verify_token": "wrong-token", "hub.challenge": "CHAL-123"},
        )
        assert status == 403
        await adapter.disconnect()

    asyncio.run(scenario())


def test_whatsapp_bad_or_missing_signature_is_403_and_handler_not_called():
    async def scenario():
        adapter, received = await _serve()
        port = adapter.port
        raw = json.dumps(_whatsapp_payload()).encode("utf-8")
        for headers in (
            {"Content-Type": "application/json"},  # missing signature
            {"Content-Type": "application/json", "X-Hub-Signature-256": "sha256=" + "0" * 64},  # forged
            {  # signed with the wrong key
                "Content-Type": "application/json",
                "X-Hub-Signature-256": _signed(raw, "other-secret"),
            },
        ):
            status, _body = await asyncio.to_thread(_post, port, raw, headers)
            assert status == 403, headers
        assert received == []  # fail-closed: the handler is NEVER called
        await adapter.disconnect()

    asyncio.run(scenario())


def test_whatsapp_valid_signed_message_reaches_handler_with_pinned_fields():
    async def scenario():
        adapter, received = await _serve()
        port = adapter.port
        payload = _whatsapp_payload()
        # a delivery receipt rides the same value: it must be ignored
        payload["entry"][0]["changes"][0]["value"]["statuses"] = [
            {"id": "wamid.S", "status": "delivered"}
        ]
        # a non-text message must also be ignored
        payload["entry"][0]["changes"][0]["value"]["messages"].append(
            {"from": "15551234567", "id": "wamid.B", "type": "image", "image": {"id": "IMG-1"}}
        )
        raw = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-Hub-Signature-256": _signed(raw)}
        status, _body = await asyncio.to_thread(_post, port, raw, headers)
        assert status == 200
        assert len(received) == 1  # the text message only
        message = received[0]
        assert isinstance(message, InboundMessage)
        assert message.transport == "whatsapp"
        assert message.chat_id == "15551234567"
        assert message.chat_type == "dm"
        assert message.text == "scan 127.0.0.1"
        assert message.user_id == "15551234567"
        await adapter.disconnect()

    asyncio.run(scenario())


def test_whatsapp_unauthorized_sender_never_reaches_handler(caplog):
    async def scenario():
        adapter, received = await _serve()
        port = adapter.port
        raw = json.dumps(_whatsapp_payload(from_number="15999999999")).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-Hub-Signature-256": _signed(raw)}
        status, _body = await asyncio.to_thread(_post, port, raw, headers)
        assert status == 200  # Meta gets its ACK; nothing runs locally
        assert received == []
        await adapter.disconnect()

    with caplog.at_level(logging.WARNING):
        asyncio.run(scenario())
    assert sum(1 for record in caplog.records if record.levelno >= logging.WARNING) == 1


def test_transports_from_env_whatsapp_contract():
    from hunter.gateway.app import transports_from_env

    transports = transports_from_env(
        {
            "HUNTEROS_WHATSAPP_TOKEN": TOKEN,
            "HUNTEROS_WHATSAPP_PHONE_NUMBER_ID": PHONE_NUMBER_ID,
            "HUNTEROS_WHATSAPP_ALLOWED_USERS": "15551234567",
        }
    )
    assert [transport.name for transport in transports] == ["whatsapp"]
    assert transports[0].max_message_length == WHATSAPP_MESSAGE_LIMIT

    # token+phone WITHOUT an allowlist -> an open bot is never an accident
    with pytest.raises(HunterError) as excinfo:
        transports_from_env(
            {
                "HUNTEROS_WHATSAPP_TOKEN": TOKEN,
                "HUNTEROS_WHATSAPP_PHONE_NUMBER_ID": PHONE_NUMBER_ID,
            }
        )
    assert excinfo.value.code == "gateway.whatsapp_allowlist"
    assert "HUNTEROS_WHATSAPP_ALLOWED_USERS" in excinfo.value.hint

    # no token -> no whatsapp adapter (fail-closed by omission)
    assert transports_from_env({}) == []
