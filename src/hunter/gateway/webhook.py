"""Webhook transport — HMAC-authenticated HTTP POSTs drive the harness.

Threat model: the webhook endpoint is reachable by anyone who can reach the
socket, so EVERY request pays for exactly three cheap checks before any
harness code runs:

1. body cap — Content-Length over 64 KiB is refused with 413 BEFORE the
   body is read (no drain, no memory);
2. replay window — ``X-Hunter-Timestamp`` must be within ±300 s of now, AND
   each accepted signature is remembered for that window: re-posting the
   exact same signed request is refused (the sender must re-sign with a
   fresh timestamp);
3. authenticity — ``X-Hunter-Signature`` must equal
   ``hex(hmac-sha256(secret, "{timestamp}.{body}"))``, compared
   timing-safe.

``INSECURE_NO_AUTH`` disables checks 2-3 but is refused at construction
unless the bind host is loopback — a dev convenience, never a deployment
footgun (hermes pattern, tightened: refusal happens before any socket
exists).
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

from hunter.errors import HunterError
from hunter.gateway.transport import ChatTransport, InboundMessage

__all__ = ["INSECURE_NO_AUTH", "WebhookAdapter", "sign_payload"]

logger = logging.getLogger(__name__)

INSECURE_NO_AUTH = "INSECURE_NO_AUTH"
MAX_BODY_BYTES = 64 * 1024
TIMESTAMP_WINDOW_SECONDS = 300
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def sign_payload(secret: str, ts: str | int, body: str | bytes) -> str:
    """The exact signature a client must send: hex hmac-sha256 over
    ``f"{timestamp}.{body}"`` (timestamp binds the body — replay-proof)."""
    body_bytes = body.encode() if isinstance(body, str) else body
    message = f"{ts}.".encode() + body_bytes
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def _is_loopback_host(host: str | None) -> bool:
    return bool(host) and host.strip().lower() in _LOOPBACK_HOSTS


def _timing_safe_equal(provided: str, expected: str) -> bool:
    """compare_digest raises on non-ASCII str — compare UTF-8 bytes to fail closed."""
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


class WebhookAdapter(ChatTransport):
    """Stdlib ``ThreadingHTTPServer`` in a daemon thread; the reply is the
    HTTP response (``inline_reply``), bridged onto the connect()-loop via
    ``asyncio.run_coroutine_threadsafe``."""

    name = "webhook"
    inline_reply = True

    def __init__(
        self,
        secret: str,
        *,
        host: str = "127.0.0.1",
        port: int = 8807,
        path: str = "/hunter",
    ) -> None:
        if secret == INSECURE_NO_AUTH and not _is_loopback_host(host):
            raise HunterError(
                code="gateway.insecure_bind",
                layer="config",
                message="INSECURE_NO_AUTH may only bind a loopback host",
                hint="bind 127.0.0.1 for local testing, or configure a real secret",
            )
        if not secret:
            raise HunterError(
                code="gateway.webhook_secret",
                layer="config",
                message="webhook adapter needs a shared secret",
                hint="set a long random secret shared with the sender",
            )
        self._secret = secret
        self._host = host
        self._port = port
        self._path = "/" + path.strip("/")
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._on_message: Any = None
        # Replay protection (QA red-audit v0.2): the ±300s timestamp window
        # alone lets an intercepted request be re-posted inside the window and
        # re-executed. Every accepted signature is remembered for the window;
        # a second post with the SAME (ts, sig, body) is refused — the sender
        # must re-sign with a fresh timestamp.
        self._seen_signatures: dict[str, float] = {}
        self._seen_lock = threading.Lock()

    @property
    def port(self) -> int:
        """The bound port (after connect with port=0, the ephemeral port)."""
        if self._server is not None:
            return int(self._server.server_address[1])
        return self._port

    @property
    def path(self) -> str:
        return self._path

    # -- ChatTransport --------------------------------------------------------

    async def connect(self, on_message: Any) -> bool:
        self._loop = asyncio.get_running_loop()
        self._on_message = on_message
        adapter = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 — stdlib naming
                adapter._handle_post(self)

            def do_GET(self) -> None:  # noqa: N802
                self._send_json(404, {"error": "not found"})

            def _send_json(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                logger.debug("webhook: " + fmt, *args)

        self._server = ThreadingHTTPServer((self._host, self._port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="hunter-webhook", daemon=True
        )
        self._thread.start()
        return True

    async def disconnect(self) -> None:
        server, self._server = self._server, None
        thread, self._thread = self._thread, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5.0)

    async def send(self, chat_id: str, content: str, *, reply_to: str | None = None) -> str:
        """Inline-reply transport: replies ride the HTTP response, so send()
        is only used for out-of-band pushes (none today)."""
        raise HunterError(
            code="gateway.webhook_send",
            layer="engine",
            message="webhook replies ride the HTTP response; there is no push channel",
            hint="return the reply from the connect() handler instead",
        )

    # -- request handling (runs on server threads) ----------------------------

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            status, payload = self._process(handler)
        except Exception as exc:  # noqa: BLE001 — the server must answer, always
            logger.exception("webhook handler failed")
            status, payload = 500, {"error": f"{type(exc).__name__}"}
        body = json.dumps(payload).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _process(self, handler: BaseHTTPRequestHandler) -> tuple[int, dict]:
        if handler.path.split("?", 1)[0] != self._path:
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
            # Discard the unread bytes (bounded) so the 413 response is not
            # killed by a TCP reset while the client is still sending —
            # Windows aborts such connections before the response lands.
            self._drain_request_body(handler)
            return 413, {"error": f"body exceeds {MAX_BODY_BYTES} bytes"}
        body_bytes = handler.rfile.read(length) if length > 0 else b""

        # 2./3. Authenticity (skipped only for INSECURE_NO_AUTH on loopback).
        if self._secret != INSECURE_NO_AUTH:
            ts_header = handler.headers.get("X-Hunter-Timestamp", "")
            sig_header = handler.headers.get("X-Hunter-Signature", "")
            auth_error = self._check_auth(ts_header, sig_header, body_bytes)
            if auth_error is not None:
                return 403, {"error": auth_error}
            replay_error = self._remember_signature(sig_header)
            if replay_error is not None:
                return 403, {"error": replay_error}

        try:
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, {"error": "body is not valid JSON"}
        if not isinstance(payload, dict) or not str(payload.get("text", "")).strip():
            return 400, {"error": 'JSON body must be {"text": str, ...}'}

        text = str(payload["text"])
        user_id = str(payload["user_id"]) if payload.get("user_id") else None
        chat_id = str(payload["chat_id"]) if payload.get("chat_id") else (user_id or "anonymous")
        inbound = InboundMessage(
            text=text,
            transport=self.name,
            chat_id=chat_id,
            user_id=user_id,
            chat_type="dm",
        )
        loop = self._loop
        callback = self._on_message
        if loop is None or callback is None:
            return 503, {"error": "webhook not connected"}
        future = asyncio.run_coroutine_threadsafe(callback(inbound), loop)
        try:
            reply = future.result(timeout=120.0)
        except Exception as exc:  # noqa: BLE001 — surface, never crash the thread
            logger.exception("webhook handler coroutine failed")
            return 500, {"error": f"{type(exc).__name__}"}
        return 200, {"reply": reply if isinstance(reply, str) else ""}

    @staticmethod
    def _drain_request_body(
        handler: BaseHTTPRequestHandler, *, max_bytes: int = 1_000_000, timeout: float = 0.25
    ) -> None:
        try:
            handler.connection.settimeout(timeout)
            remaining = max_bytes
            while remaining > 0:
                chunk = handler.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                handler.connection.settimeout(None)

    def _check_auth(
        self, ts_header: str, sig_header: str, body_bytes: bytes
    ) -> str | None:
        if not ts_header or not sig_header:
            return "missing X-Hunter-Timestamp / X-Hunter-Signature"
        try:
            ts = int(float(ts_header))
        except ValueError:
            return "invalid X-Hunter-Timestamp"
        if abs(time.time() - ts) > TIMESTAMP_WINDOW_SECONDS:
            return "stale or future timestamp (±300s window)"
        expected = sign_payload(self._secret, ts_header, body_bytes)
        if not _timing_safe_equal(sig_header, expected):
            return "invalid signature"
        return None

    # Bounded memory: signatures are pruned by age and hard-capped; the cap
    # only ever drops the OLDEST entries, so a flood evicts stale signatures
    # first and can never make a fresh replay look unseen.
    _MAX_TRACKED_SIGNATURES = 4096

    def _remember_signature(self, sig_header: str) -> str | None:
        """Record an accepted signature; refuse a duplicate within the window."""
        now = time.time()
        with self._seen_lock:
            seen = self._seen_signatures
            if sig_header in seen:
                return "replayed request — this exact signed request was already accepted"
            cutoff = now - TIMESTAMP_WINDOW_SECONDS
            for key in [k for k, ts in seen.items() if ts < cutoff]:
                del seen[key]
            seen[sig_header] = now
            while len(seen) > self._MAX_TRACKED_SIGNATURES:
                oldest = min(seen, key=seen.get)  # type: ignore[arg-type]
                del seen[oldest]
        return None
