"""WhatsApp Cloud API transport — Meta Graph semantics over a loopback webhook.

Authorization is FAIL-CLOSED at every boundary, mirroring the Telegram and
Discord adapters:

- construction refuses an empty token or phone number id (`config.value`);
- an empty allowlist denies EVERY sender, unauthorized senders cost one log
  line and zero compute, and nothing they send ever reaches the handler;
- the loopback webhook validates Meta's ``X-Hub-Signature-256`` (hex
  HMAC-SHA256 over the RAW body with the app secret, timing-safe compared)
  BEFORE any parsing — missing, malformed, or forged signatures get 403 and
  the handler is never called. No app secret configured → 403 as well
  (verification cannot be proven, so nothing is accepted);
- hub verification echoes ``hub.challenge`` only for the configured verify
  token, timing-safe compared; anything else is 403.

The send path rides the pinned api seam (``register_on_message``, ``start``,
``close``, ``send_message(chat_id, content)``) —
:class:`WhatsAppCloudApi` is the production seam over ``httpx.AsyncClient``;
tests inject a fake. Non-text and ``status`` payloads are ignored, and an
exact duplicate POST is refused as a replay (the webhook adapter's
anti-replay pattern).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx

from hunter.errors import HunterError
from hunter.gateway.transport import ChatTransport, InboundMessage, chunk_text, is_authorized

__all__ = [
    "GRAPH_API_BASE",
    "WHATSAPP_MESSAGE_LIMIT",
    "WhatsAppAdapter",
    "WhatsAppCloudApi",
    "_is_authorized",
]

logger = logging.getLogger(__name__)

WHATSAPP_MESSAGE_LIMIT = 4096  # WhatsApp's limit, in UTF-16 code units
GRAPH_API_BASE = "https://graph.facebook.com/v21.0"
WEBHOOK_PATH = "/whatsapp"
DEFAULT_WEBHOOK_PORT = 8808  # webhook.py's 8807 stays untouched
MAX_BODY_BYTES = 64 * 1024
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _is_authorized(user_id: str | None, allowed_users) -> bool:
    """Adapter-local alias of the shared transport-level fail-closed check."""
    return is_authorized(user_id, allowed_users)


def _timing_safe_equal(provided: str, expected: str) -> bool:
    """compare_digest raises on non-ASCII str — compare UTF-8 bytes to fail closed."""
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


class WhatsAppCloudApi:
    """Production api seam: the Meta Cloud messages endpoint over httpx."""

    def __init__(
        self,
        token: str,
        phone_number_id: str,
        *,
        base_url: str = GRAPH_API_BASE,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token = token
        self._phone_number_id = phone_number_id
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=30.0)

    # The pinned seam — inbound arrives via the adapter's loopback webhook,
    # so registration/start are accepted and intentionally inert here.
    def register_on_message(self, fn: Any) -> None:
        return None

    def start(self) -> None:
        return None

    async def close(self) -> None:
        await self._client.aclose()

    async def send_message(self, chat_id: str, content: str) -> None:
        response = await self._client.post(
            f"/{self._phone_number_id}/messages",
            json={
                "messaging_product": "whatsapp",
                "to": chat_id,
                "type": "text",
                "text": {"body": content},
            },
            headers={"Authorization": f"Bearer {self._token}"},
        )
        response.raise_for_status()


def _default_api(token: str, phone_number_id: str) -> Any:
    """The production api seam (kept async-import-free for offline tests)."""
    return WhatsAppCloudApi(token, phone_number_id)


class WhatsAppAdapter(ChatTransport):
    """WhatsApp Cloud adapter: cloud send + loopback signed webhook inbound."""

    name = "whatsapp"
    max_message_length = WHATSAPP_MESSAGE_LIMIT
    supports_markdown = False

    def __init__(
        self,
        token: str,
        phone_number_id: str,
        allowed_users: set[str],
        *,
        app_secret: str | None = None,
        verify_token: str | None = None,
        host: str = "127.0.0.1",
        port: int = DEFAULT_WEBHOOK_PORT,
        api: Any = None,
    ) -> None:
        if not token or not token.strip():
            raise HunterError(
                code="config.value",
                layer="config",
                message="WhatsApp adapter needs a token",
                hint="set HUNTEROS_WHATSAPP_TOKEN and HUNTEROS_WHATSAPP_PHONE_NUMBER_ID",
            )
        if not phone_number_id or not phone_number_id.strip():
            raise HunterError(
                code="config.value",
                layer="config",
                message="WhatsApp adapter needs a phone_number_id",
                hint="set HUNTEROS_WHATSAPP_TOKEN and HUNTEROS_WHATSAPP_PHONE_NUMBER_ID",
            )
        host = (host or "").strip().lower()
        if host not in _LOOPBACK_HOSTS:
            raise HunterError(
                code="gateway.insecure_bind",
                layer="config",
                message="the WhatsApp webhook may only bind a loopback host",
                hint="bind 127.0.0.1 and terminate TLS at your tunnel instead",
            )
        self._token = token.strip()
        self._phone_number_id = phone_number_id.strip()
        self._allowed = frozenset(allowed_users or set())
        self._app_secret = (app_secret or "").strip() or None
        self._verify_token = (verify_token or "").strip()
        self._host = "127.0.0.1" if host in {"localhost", "::1"} else host
        self._port = int(port)
        self._api = api
        self._on_message: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._closed = False
        # Anti-replay (the webhook adapter's pattern): every accepted
        # signature is remembered for the window so the exact same signed
        # POST can never drive two agent turns.
        self._seen_signatures: dict[str, float] = {}
        self._seen_lock = threading.Lock()

    @property
    def port(self) -> int:
        """The bound port (after connect with port=0, the ephemeral port)."""
        if self._server is not None:
            return int(self._server.server_address[1])
        return self._port

    # -- ChatTransport --------------------------------------------------------

    async def connect(self, on_message: Any) -> bool:
        self._loop = asyncio.get_running_loop()
        self._on_message = on_message
        if self._api is None:
            self._api = _default_api(self._token, self._phone_number_id)
        register = getattr(self._api, "register_on_message", None)
        if callable(register):
            register(self._on_api_message)
        start = getattr(self._api, "start", None)
        if callable(start):
            result = start()
            if asyncio.iscoroutine(result):
                await result
        self._start_webhook_server()
        self._closed = False
        return True

    async def disconnect(self) -> None:
        if self._closed:
            return
        self._closed = True
        server, self._server = self._server, None
        thread, self._thread = self._thread, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5.0)
        close = getattr(self._api, "close", None)
        if callable(close):
            result = close()
            if asyncio.iscoroutine(result):
                await result

    async def send(self, chat_id: str, content: str, *, reply_to: str | None = None) -> str:
        """Send ``content`` chunked at WhatsApp's 4096 UTF-16-unit limit."""
        last = ""
        for part in chunk_text(content or "", WHATSAPP_MESSAGE_LIMIT):
            await self._api.send_message(chat_id, part)
            last = part
        return last

    # -- inbound: loopback webhook (runs on server threads) -------------------

    def _start_webhook_server(self) -> None:
        adapter = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 — stdlib naming
                adapter._handle_verification(self)

            def do_POST(self) -> None:  # noqa: N802
                adapter._handle_post(self)

            def log_message(self, fmt: str, *args: object) -> None:
                logger.debug("whatsapp: " + fmt, *args)

        self._server = ThreadingHTTPServer((self._host, self._port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="hunter-whatsapp-webhook", daemon=True
        )
        self._thread.start()

    def _handle_verification(self, handler: BaseHTTPRequestHandler) -> None:
        query = {}
        raw_path = handler.path.split("?", 1)
        if len(raw_path) == 2:
            with contextlib.suppress(ValueError):
                query = dict(pair.split("=", 1) for pair in raw_path[1].split("&") if "=" in pair)
        challenge = query.get("hub.challenge", "")
        mode = query.get("hub.mode", "")
        provided = query.get("hub.verify_token", "")
        if (
            mode == "subscribe"
            and self._verify_token
            and challenge
            and _timing_safe_equal(provided, self._verify_token)
        ):
            body = challenge.encode("utf-8")
            handler.send_response(200)
        else:
            body = b""
            handler.send_response(403)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            status, payload = self._process_post(handler)
        except Exception:  # noqa: BLE001 — the server must answer, always
            logger.exception("whatsapp webhook handler failed")
            status, payload = 500, {"error": "internal"}
        body = json.dumps(payload).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _process_post(self, handler: BaseHTTPRequestHandler) -> tuple[int, dict]:
        if handler.path.split("?", 1)[0] != WEBHOOK_PATH:
            return 404, {"error": "not found"}

        # 1. Body cap BEFORE reading anything.
        length_header = handler.headers.get("Content-Length")
        if length_header is None:
            return 411, {"error": "Content-Length required"}
        try:
            length = int(length_header)
        except ValueError:
            return 400, {"error": "invalid Content-Length"}
        if length > MAX_BODY_BYTES:
            return 413, {"error": f"body exceeds {MAX_BODY_BYTES} bytes"}
        raw = handler.rfile.read(length) if length > 0 else b""

        # 2. Signature gate BEFORE any parsing — fail closed. Without an app
        # secret nothing can be verified, so nothing is accepted.
        if self._app_secret is None:
            return 403, {"error": "signature verification is not configured"}
        provided = handler.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            self._app_secret.encode("utf-8"), raw, hashlib.sha256
        ).hexdigest()
        if not provided or not _timing_safe_equal(provided, expected):
            return 403, {"error": "invalid signature"}
        if self._remember_signature(provided):
            return 403, {"error": "replayed payload"}

        # 3. Parse and dispatch only allowlisted text messages.
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, {"error": "body is not valid JSON"}
        dispatched = 0
        for message in self._text_messages(payload):
            sender = str(message.get("from", "") or "")
            if not _is_authorized(sender, self._allowed):
                # ONE line per denied sender; nothing runs, nothing is stored.
                logger.warning(
                    "whatsapp: denied sender %s (not in allowlist)", sender or "<unknown>"
                )
                continue
            callback, loop = self._on_message, self._loop
            if callback is None or loop is None:
                return 503, {"error": "whatsapp not connected"}
            inbound = InboundMessage(
                text=str(message.get("text", {}).get("body", "") or ""),
                transport=self.name,
                chat_id=sender,
                user_id=sender,
                chat_type="dm",
                message_id=str(message.get("id", "") or ""),
            )
            asyncio.run_coroutine_threadsafe(callback(inbound), loop)
            dispatched += 1
        return 200, {"received": dispatched}

    def _remember_signature(self, signature: str) -> bool:
        """Record an accepted signature; refuse a duplicate (replay)."""
        now = time.time()
        with self._seen_lock:
            seen = self._seen_signatures
            if signature in seen:
                return True
            seen[signature] = now
            cutoff = now - 300.0
            for key in [k for k, ts in seen.items() if ts < cutoff]:
                del seen[key]
        return False

    async def _on_api_message(self, raw: Any) -> None:
        """Seam path for push-style apis: map + authorize, then dispatch."""
        callback, loop = self._on_message, self._loop
        if callback is None or loop is None:
            return
        for message in self._text_messages(raw):
            sender = str(message.get("from", "") or "")
            if not _is_authorized(sender, self._allowed):
                logger.warning(
                    "whatsapp: denied sender %s (not in allowlist)", sender or "<unknown>"
                )
                continue
            await callback(
                InboundMessage(
                    text=str(message.get("text", {}).get("body", "") or ""),
                    transport=self.name,
                    chat_id=sender,
                    user_id=sender,
                    chat_type="dm",
                    message_id=str(message.get("id", "") or ""),
                )
            )

    @staticmethod
    def _text_messages(payload: Any) -> list[dict]:
        """entry[].changes[].value.messages[] with type=="text" only —
        receipts (statuses) and non-text payloads are ignored."""
        messages: list[dict] = []
        if not isinstance(payload, dict):
            return messages
        for entry in payload.get("entry") or []:
            if not isinstance(entry, dict):
                continue
            for change in entry.get("changes") or []:
                value = (change or {}).get("value") if isinstance(change, dict) else None
                if not isinstance(value, dict):
                    continue
                for message in value.get("messages") or []:
                    if isinstance(message, dict) and message.get("type") == "text":
                        messages.append(message)
        return messages
