"""GatewayApp — chat platforms driving the SAME engine as the REPL.

The gateway is deliberately thin: it owns per-chat session routing and the
turn lease, then delegates every line to :class:`hunter.chat.repl.ChatEngine`
— the identical executors, scope gates, provider path, and audit loop the
terminal uses. Platform policy lives in the adapters (Telegram allowlist,
webhook HMAC); orchestration policy lives here:

- one lease per ``(transport, chat_id)`` — a second message while a turn is
  in flight is refused with the busy line, nothing runs unserialized;
- blocking provider/executor work runs on a worker thread so one slow LLM
  turn never stalls other chats or the Telegram poll loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from hunter.chat.repl import ChatEngine
from hunter.chat.sessions import ChatStore
from hunter.errors import build_error_surface
from hunter.gateway.lease import LeaseBusy, TurnLeaseRegistry
from hunter.gateway.transport import ChatTransport, InboundMessage

__all__ = ["BUSY_MESSAGE", "GatewayApp"]

logger = logging.getLogger(__name__)

BUSY_MESSAGE = (
    "still working on your previous request — try again shortly"
)


class GatewayApp:
    """Multi-transport gateway over one ChatStore and per-chat engines."""

    def __init__(
        self,
        config: Any,
        transports: list[ChatTransport],
        *,
        state_dir: str | None = None,
    ) -> None:
        self.config = config
        self.transports = list(transports)
        self.state_dir = state_dir
        self._store: ChatStore | None = None
        self._engines: dict[str, ChatEngine] = {}
        self._options: dict[str, dict[str, Any]] = {}
        self._leases = TurnLeaseRegistry()

    # -- engines ----------------------------------------------------------

    @property
    def store(self) -> ChatStore:
        if self._store is None:
            self._store = ChatStore()
        return self._store

    def engine_for(self, session_key: str) -> ChatEngine:
        """One engine (== one chat session) per transport+chat pair."""
        engine = self._engines.get(session_key)
        if engine is None:
            options: dict[str, Any] = {
                "verbosity": "normal",
                "state_dir": self.state_dir,
            }
            engine = ChatEngine(
                store=self.store,
                session_id=None,
                state_dir=self.state_dir,
                config=self.config,
                options=options,
            )
            self.store.set_title(engine.session_id, session_key)
            self._engines[session_key] = engine
        return engine

    # -- message handling ---------------------------------------------------

    async def handle_message(self, transport: ChatTransport, message: InboundMessage) -> str:
        """Authorize-by-transport -> lease -> engine.handle_text. Returns the
        reply text (never raises — errors become [ERROR ...] replies)."""
        session_key = f"{transport.name}:{message.chat_id}"
        try:
            lease = await self._leases.acquire(session_key)
        except LeaseBusy:
            return BUSY_MESSAGE
        try:
            engine = self.engine_for(session_key)
            out = await asyncio.to_thread(engine.handle_text, message.text)
            return out.text
        except Exception as exc:  # noqa: BLE001 — the platform gets an answer, always
            surface = build_error_surface(exc)
            logger.exception("gateway handler failed for %s", session_key)
            message = f"[ERROR {surface['layer']}] {surface['message']}"
            hint = surface.get("hint") or ""
            if hint:
                message += f"\nHint: {hint}"
            return message
        finally:
            await lease.release()

    def _callback(self, transport: ChatTransport) -> Any:
        async def on_message(message: InboundMessage) -> str | None:
            reply = await self.handle_message(transport, message)
            if transport.inline_reply:
                return reply  # webhook: rides the HTTP response
            await transport.send(message.chat_id, reply)
            return None

        return on_message

    # -- lifecycle -----------------------------------------------------------

    async def run_async(self) -> None:
        """Connect all transports and serve until cancelled."""
        connected: list[ChatTransport] = []
        try:
            for transport in self.transports:
                if await transport.connect(self._callback(transport)):
                    connected.append(transport)
                    logger.info("gateway: %s connected", transport.name)
            stop = asyncio.Event()
            await stop.wait()  # serve until run() is interrupted / task cancelled
        finally:
            await self._shutdown(connected)

    async def _shutdown(self, connected: list[ChatTransport]) -> None:
        for engine in self._engines.values():
            try:
                engine.close()  # finishes any active audit; store stays shared
            except Exception:  # noqa: BLE001
                logger.exception("gateway: engine shutdown failed")
        for transport in reversed(connected):
            try:
                await transport.disconnect()
            except Exception:  # noqa: BLE001
                logger.exception("gateway: %s disconnect failed", transport.name)

    def run(self) -> None:
        """Sync entry: serve until Ctrl-C; clean shutdown, exit code 0."""
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(self.run_async())


# --------------------------------------------------------------------------
# wiring helper for `hunter gateway start` (the CLI composes from this)
# --------------------------------------------------------------------------


def transports_from_env(env: dict[str, str] | None = None) -> list[ChatTransport]:
    """Build the transports the environment asks for — nothing configured,
    nothing started (fail-closed by omission, like every other surface).

    - ``HUNTEROS_TELEGRAM_TOKEN`` + ``HUNTEROS_TELEGRAM_ALLOWED_USERS``
      (comma/whitespace-separated ids) start the Telegram long-poll adapter;
      a token WITHOUT an allowlist raises HunterError — an open Telegram bot
      is never an accident.
    - ``HUNTEROS_WEBHOOK_SECRET`` starts the webhook adapter on
      ``HUNTEROS_WEBHOOK_HOST`` (default 127.0.0.1) / ``..._PORT``
      (default 8807) / ``..._PATH`` (default /hunter).
    """
    import os

    from hunter.errors import HunterError
    from hunter.gateway.telegram import TelegramAdapter
    from hunter.gateway.webhook import WebhookAdapter

    env = os.environ if env is None else env
    transports: list[ChatTransport] = []

    token = (env.get("HUNTEROS_TELEGRAM_TOKEN") or "").strip()
    if token:
        allowed_raw = (env.get("HUNTEROS_TELEGRAM_ALLOWED_USERS") or "").strip()
        if not allowed_raw:
            raise HunterError(
                code="gateway.telegram_allowlist",
                layer="config",
                message="HUNTEROS_TELEGRAM_TOKEN is set but no allowlist is configured",
                hint="set HUNTEROS_TELEGRAM_ALLOWED_USERS to a comma-separated list "
                "of authorized Telegram user ids",
            )
        allowed = {part.strip() for part in allowed_raw.replace(";", ",").split(",") if part.strip()}
        transports.append(TelegramAdapter(token, allowed))

    secret = (env.get("HUNTEROS_WEBHOOK_SECRET") or "").strip()
    if secret:
        kwargs: dict[str, Any] = {}
        if env.get("HUNTEROS_WEBHOOK_HOST"):
            kwargs["host"] = env["HUNTEROS_WEBHOOK_HOST"].strip()
        if env.get("HUNTEROS_WEBHOOK_PORT"):
            # A non-integer port is a config error (exit 8), not a traceback.
            try:
                kwargs["port"] = int(env["HUNTEROS_WEBHOOK_PORT"])
            except ValueError as exc:
                raise HunterError(
                    code="gateway.port_invalid",
                    layer="config",
                    message="HUNTEROS_WEBHOOK_PORT must be an integer — "
                    f"got {env['HUNTEROS_WEBHOOK_PORT']!r}",
                    hint="e.g. export HUNTEROS_WEBHOOK_PORT=8807",
                ) from exc
        if env.get("HUNTEROS_WEBHOOK_PATH"):
            kwargs["path"] = env["HUNTEROS_WEBHOOK_PATH"]
        transports.append(WebhookAdapter(secret, **kwargs))
    return transports
