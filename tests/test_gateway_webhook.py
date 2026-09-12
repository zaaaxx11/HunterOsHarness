"""Webhook transport tests: HMAC auth, replay window, body cap, reply round-trip."""

from __future__ import annotations

import asyncio
import http.client
import json
import time

import pytest

from hunter.errors import HunterError
from hunter.gateway.transport import InboundMessage
from hunter.gateway.webhook import (
    INSECURE_NO_AUTH,
    MAX_BODY_BYTES,
    WebhookAdapter,
    sign_payload,
)

SECRET = "test-secret"


def _post(port, body, ts=None, sig=None, path="/hunter", headers=None):
    """Blocking POST — callers must run it off the event loop.

    ``ts=None`` sends a fresh timestamp; ``ts=""`` sends NO timestamp header
    (same for ``sig=""``) to exercise missing-header refusals.
    """
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    ts = str(int(time.time())) if ts is None else ts
    headers = dict(headers or {})
    headers.setdefault("Content-Type", "application/json")
    if ts:
        headers.setdefault("X-Hunter-Timestamp", ts)
    if sig:
        headers.setdefault("X-Hunter-Signature", sig)
    conn.request("POST", path, body=body, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        payload = {"raw": raw.decode("utf-8", "replace")}
    return response.status, payload


def _valid_body(text="scan please", **extra):
    payload = {"text": text, **extra}
    return json.dumps(payload)


async def _serve(handler_reply="ack:done", secret=SECRET, **kwargs):
    """Connect an adapter; returns (adapter, received, handler_exception)."""
    adapter = WebhookAdapter(secret, port=0, **kwargs)
    received: list[InboundMessage] = []

    async def on_message(message: InboundMessage):
        received.append(message)
        return handler_reply

    assert await adapter.connect(on_message) is True
    return adapter, received


def test_sign_payload_is_deterministic_hmac():
    import hashlib
    import hmac as hmac_mod

    expected = hmac_mod.new(
        SECRET.encode(), b"1712345678.{\"a\":1}", hashlib.sha256
    ).hexdigest()
    assert sign_payload(SECRET, "1712345678", '{"a":1}') == expected
    assert sign_payload(SECRET, 1712345678, '{"a":1}') == expected


def test_valid_post_round_trips_reply():
    async def scenario():
        adapter, received = await _serve()
        loop = asyncio.get_running_loop()
        body = _valid_body("hello webhook", user_id="u-1", chat_id="c-1")
        ts = str(int(time.time()))
        status, payload = await loop.run_in_executor(
            None, _post, adapter.port, body, ts, sign_payload(SECRET, ts, body)
        )
        await adapter.disconnect()
        assert status == 200
        assert payload == {"reply": "ack:done"}
        assert len(received) == 1
        message = received[0]
        assert message.transport == "webhook"
        assert message.text == "hello webhook"
        assert message.user_id == "u-1" and message.chat_id == "c-1"
        return True

    assert asyncio.run(scenario()) is True


def test_bad_signature_403():
    async def scenario():
        adapter, received = await _serve()
        loop = asyncio.get_running_loop()
        body = _valid_body()
        ts = str(int(time.time()))
        status, payload = await loop.run_in_executor(
            None, _post, adapter.port, body, ts, "0" * 64
        )
        await adapter.disconnect()
        assert status == 403
        assert received == []

    asyncio.run(scenario())


def test_missing_headers_403():
    async def scenario():
        adapter, received = await _serve()
        loop = asyncio.get_running_loop()
        body = _valid_body()
        status, _ = await loop.run_in_executor(None, _post, adapter.port, body, "", "")
        await adapter.disconnect()
        assert status == 403
        assert received == []

    asyncio.run(scenario())


def test_stale_timestamp_403():
    async def scenario():
        adapter, received = await _serve()
        loop = asyncio.get_running_loop()
        body = _valid_body()
        stale_ts = str(int(time.time()) - 1000)  # far outside ±300s
        status, payload = await loop.run_in_executor(
            None, _post, adapter.port, body, stale_ts, sign_payload(SECRET, stale_ts, body)
        )
        await adapter.disconnect()
        assert status == 403
        assert "stale" in payload["error"]
        assert received == []

    asyncio.run(scenario())


def test_unknown_path_404():
    async def scenario():
        adapter, _ = await _serve()
        loop = asyncio.get_running_loop()
        ts = str(int(time.time()))
        # Zero-length body: the path check fires before any read, and an
        # empty upload cannot race the early refusal.
        status, _ = await loop.run_in_executor(
            None, _post, adapter.port, "", ts, sign_payload(SECRET, ts, ""), "/other"
        )
        await adapter.disconnect()
        assert status == 404

    asyncio.run(scenario())


def test_body_over_cap_refused_before_read():
    async def scenario():
        adapter, received = await _serve()
        loop = asyncio.get_running_loop()

        def post_oversized():
            # Declare a body over the cap but send only a few bytes: the
            # server must answer 413 from the Content-Length header alone —
            # if it drained the body first, this request would hang.
            conn = http.client.HTTPConnection("127.0.0.1", adapter.port, timeout=10)
            conn.putrequest("POST", "/hunter")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
            conn.endheaders()
            conn.send(b'{"text": "partial"}')
            response = conn.getresponse()
            data = response.read()
            conn.close()
            return response.status, json.loads(data)

        status, payload = await loop.run_in_executor(None, post_oversized)
        await adapter.disconnect()
        assert status == 413
        assert "exceeds" in payload["error"]
        assert received == []  # nothing was parsed, nothing ran

    asyncio.run(scenario())


def test_missing_content_length_411():
    async def scenario():
        adapter, _ = await _serve()
        loop = asyncio.get_running_loop()

        def post_without_length():
            conn = http.client.HTTPConnection("127.0.0.1", adapter.port, timeout=10)
            conn.putrequest("POST", "/hunter")
            conn.endheaders()
            response = conn.getresponse()
            data = response.read()
            conn.close()
            return response.status, json.loads(data)

        status, payload = await loop.run_in_executor(None, post_without_length)
        await adapter.disconnect()
        assert status == 411
        assert "Content-Length" in payload["error"]

    asyncio.run(scenario())


def test_invalid_json_400():
    async def scenario():
        adapter, received = await _serve()
        loop = asyncio.get_running_loop()
        ts = str(int(time.time()))
        status, _ = await loop.run_in_executor(
            None, _post, adapter.port, "{not json", ts, sign_payload(SECRET, ts, "{not json")
        )
        await adapter.disconnect()
        assert status == 400
        assert received == []

    asyncio.run(scenario())


def test_insecure_no_auth_loopback_allowed_and_answered():
    async def scenario():
        adapter, received = await _serve(handler_reply="no-auth-ok", secret=INSECURE_NO_AUTH)
        loop = asyncio.get_running_loop()
        status, payload = await loop.run_in_executor(
            None, _post, adapter.port, _valid_body("ping")  # no auth headers at all
        )
        await adapter.disconnect()
        assert status == 200
        assert payload == {"reply": "no-auth-ok"}
        assert received[0].text == "ping"

    asyncio.run(scenario())


def test_insecure_no_auth_non_loopback_refused_at_construction():
    with pytest.raises(HunterError):
        WebhookAdapter(INSECURE_NO_AUTH, host="0.0.0.0", port=8807)


def test_empty_secret_refused():
    with pytest.raises(HunterError):
        WebhookAdapter("", host="127.0.0.1", port=8807)


def test_disconnect_is_idempotent():
    async def scenario():
        adapter, _ = await _serve()
        await adapter.disconnect()
        await adapter.disconnect()  # no error

    asyncio.run(scenario())
