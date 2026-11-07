"""Telegram transport — long-poll adapter over python-telegram-bot.

Authorization is FAIL-CLOSED at the adapter boundary: an empty allowlist
denies every sender, unauthorized senders cost one log line and zero
compute, and no message from them ever reaches the shared handler. The
SDK is a lazy import behind the ``api`` test seam — every pure decision
(``_is_authorized``, ``_chunk_text``) is a module-level function so tests
need no telegram package and no network.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from hunter.errors import HunterError
from hunter.gateway.transport import ChatTransport, InboundMessage, chunk_text

__all__ = ["TELEGRAM_MESSAGE_LIMIT", "TelegramAdapter", "_chunk_text", "_is_authorized"]

logger = logging.getLogger(__name__)

TELEGRAM_MESSAGE_LIMIT = 4096  # Telegram's limit, in UTF-16 code units

#: Server-side long-poll hold; the client ceiling is this plus slack.
POLL_HOLD_SECONDS = 25


def _chunk_text(text: str, limit: int = TELEGRAM_MESSAGE_LIMIT) -> list[str]:
    return chunk_text(text, limit)


def _is_authorized(user_id: str | None, allowed_users: set[str] | frozenset[str]) -> bool:
    """Fail-closed allowlist check: empty allowlist denies EVERYONE."""
    if not user_id or not allowed_users:
        return False
    return str(user_id).strip() in {str(u).strip() for u in allowed_users}


def _default_api(token: str) -> Any:
    """Lazy python-telegram-bot import — the production api seam."""
    try:
        from telegram import Bot
    except ImportError as exc:
        raise HunterError(
            code="config.dependency_missing",
            layer="config",
            message="python-telegram-bot is not installed",
            hint="pip install 'hunteros-harness[telegram]'",
        ) from exc
    return Bot(token)


class TelegramAdapter(ChatTransport):
    """Long-polling Telegram adapter (module-level ``get_updates`` loop)."""

    name = "telegram"
    max_message_length = TELEGRAM_MESSAGE_LIMIT
    supports_markdown = True

    def __init__(self, token: str, allowed_users: set[str], *, api: Any = None) -> None:
        if not token:
            raise HunterError(
                code="config.telegram_token",
                layer="config",
                message="Telegram adapter needs a bot token",
                hint="create a bot with @BotFather and pass the token",
            )
        self._token = token
        self._allowed = frozenset(allowed_users or set())
        self._api = api
        self._on_message: Any = None
        self._poll_task: asyncio.Task[None] | None = None
        self._offset = 0
        self._closed = False

    # -- ChatTransport --------------------------------------------------------

    async def connect(
        self, on_message: Any
    ) -> bool:
        self._on_message = on_message
        if self._api is None:
            self._api = _default_api(self._token)
        initialize = getattr(self._api, "initialize", None)
        if callable(initialize):
            await initialize()
        self._closed = False
        self._start_poll_task()
        return True

    async def disconnect(self) -> None:
        self._closed = True
        task, self._poll_task = self._poll_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001 — shutdown is best-effort
                pass
        shutdown = getattr(self._api, "shutdown", None)
        if callable(shutdown):
            with contextlib.suppress(Exception):
                await shutdown()

    async def send(self, chat_id: str, content: str, *, reply_to: str | None = None) -> str:
        """Send ``content`` chunked at Telegram's 4096 UTF-16-unit limit."""
        last = ""
        for part in _chunk_text(content or "", TELEGRAM_MESSAGE_LIMIT):
            kwargs: dict[str, Any] = {"chat_id": chat_id, "text": part}
            if reply_to:
                with contextlib.suppress(TypeError, ValueError):
                    kwargs["reply_to_message_id"] = int(reply_to)
            await self._api.send_message(**kwargs)
            last = part
        return last

    async def set_status(self, chat_id: str, status: str = "typing") -> None:
        action = getattr(self._api, "send_chat_action", None)
        if not callable(action):
            return
        try:
            await action(chat_id=chat_id, action="typing")
        except Exception:  # noqa: BLE001 — presence hints never break delivery
            return

    # -- polling ----------------------------------------------------------------

    def _start_poll_task(self) -> None:
        self._poll_task = asyncio.create_task(
            self._supervise(), name="hunter-telegram-poll"
        )
        self._poll_task.add_done_callback(self._on_poll_done)

    def _on_poll_done(self, task: "asyncio.Task") -> None:
        """Restart polling if it ever stops, and say why.

        Without this the bot simply goes quiet: the task ends (clean return or a
        propagated cancellation), nothing observes it, and no log is written.
        """
        if self._closed:
            return
        if task.cancelled():
            reason = "cancelled"
        else:
            exc = task.exception()
            if exc is not None:
                reason = f"{type(exc).__name__}: {exc}"
                logger.error("telegram: poll task ended (%s)", reason, exc_info=exc)
            else:
                reason = "returned"
        if not task.cancelled():
            logger.warning("telegram: poll task stopped (%s) — restarting", reason)
        self._start_poll_task()

    async def _supervise(self) -> None:
        """Keep polling alive: a dead poll task means a permanently silent bot.

        The loop used to die on the first handler exception (dispatch sat outside
        the try), and because the task exception is never retrieved nothing was
        logged — the bot simply stopped answering. Restart it instead.
        """
        while not self._closed:
            try:
                await self._poll_loop()
                return  # closed cleanly
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - never let the bot go silent
                logger.exception("telegram: poll loop died — restarting in 5s")
                try:
                    await asyncio.sleep(5.0)
                except asyncio.CancelledError:
                    raise

    async def _poll_loop(self) -> None:
        """Long-poll get_updates until closed; per-error backoff, no crash."""
        backoff = 1.0
        while not self._closed:
            try:
                updates = await asyncio.to_thread(self._blocking_get_updates, self._offset)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — network hiccups must not kill polling
                logger.warning(
                    "telegram get_updates failed (%s: %s) — retrying in %.0fs",
                    type(exc).__name__, str(exc)[:120], backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(30.0, backoff * 2)
                continue
            logger.info("telegram: poll -> %d update(s) (offset=%s)", len(updates or []), self._offset)
            backoff = 1.0
            for update in updates or []:
                self._offset = max(self._offset, int(getattr(update, "update_id", 0)) + 1)
                # One bad message must never take the transport down with it, and
                # the failure has to be visible in the log.
                try:
                    await self._dispatch(update)
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    logger.exception(
                        "telegram: dispatch failed for update %s",
                        getattr(update, "update_id", "?"),
                    )

    def _blocking_get_updates(self, offset: int) -> list:
        """Long-poll Telegram with a socket timeout the OS enforces.

        The async PTB long poll could sit on a half-open socket indefinitely:
        monitored live, the gateway stayed idle in the event loop for 11+ minutes
        while getWebhookInfo reported four queued messages and nothing was
        consumed. Neither PTB's read timeout nor asyncio.wait_for recovered it —
        wait_for still waits on a coroutine that swallows CancelledError. A
        blocking call with ``timeout`` always raises, so the loop always advances.
        """
        import json as _json
        import urllib.parse as _urlparse
        import urllib.request as _urlrequest

        url = (
            f"https://api.telegram.org/bot{self._token}/getUpdates?"
            + _urlparse.urlencode({"offset": int(offset), "timeout": POLL_HOLD_SECONDS})
        )
        request = _urlrequest.Request(url, method="GET")
        with _urlrequest.urlopen(request, timeout=POLL_HOLD_SECONDS + 10) as response:
            payload = _json.loads(response.read().decode("utf-8"))
        if not payload.get("ok"):
            raise RuntimeError(f"getUpdates failed: {str(payload)[:200]}")
        from telegram import Update

        return [Update.de_json(item, self._api) for item in (payload.get("result") or [])]

    async def _dispatch(self, update: Any) -> None:
        message = getattr(update, "message", None) or getattr(update, "edited_message", None)
        if message is None:
            return
        text = getattr(message, "text", None) or getattr(message, "caption", None) or ""
        if not text.strip():
            return
        sender = getattr(message, "from_user", None)
        user_id = str(sender.id) if sender is not None and sender.id is not None else None
        if not _is_authorized(user_id, self._allowed):
            # ONE line per denied sender; nothing runs, nothing is stored.
            logger.warning(
                "telegram: denied sender %s on chat %s (not in allowlist)",
                user_id or "<unknown>",
                getattr(getattr(message, "chat", None), "id", "?"),
            )
            return
        chat = getattr(message, "chat", None)
        chat_type_value = str(getattr(chat, "type", "private"))
        inbound = InboundMessage(
            text=text,
            transport=self.name,
            chat_id=str(getattr(chat, "id", "") or ""),
            user_id=user_id,
            user_name=(getattr(sender, "full_name", None) or getattr(sender, "username", None)),
            chat_type="dm" if chat_type_value == "private" else chat_type_value,
            message_id=str(getattr(message, "message_id", "") or ""),
        )
        callback = self._on_message
        if callback is None:
            return
        await callback(inbound)
