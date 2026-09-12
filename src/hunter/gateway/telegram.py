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
        self._poll_task = asyncio.create_task(
            self._poll_loop(), name="hunter-telegram-poll"
        )
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

    async def _poll_loop(self) -> None:
        """Long-poll get_updates until closed; per-error backoff, no crash."""
        backoff = 1.0
        while not self._closed:
            try:
                updates = await self._api.get_updates(offset=self._offset, timeout=25)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — network hiccups must not kill polling
                logger.warning("telegram get_updates failed — retrying in %.0fs", backoff)
                await asyncio.sleep(backoff)
                backoff = min(30.0, backoff * 2)
                continue
            backoff = 1.0
            for update in updates or []:
                self._offset = max(self._offset, int(getattr(update, "update_id", 0)) + 1)
                await self._dispatch(update)

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
