"""Discord transport — event adapter over discord.py.

Authorization is FAIL-CLOSED at the adapter boundary, mirroring the Telegram
adapter: an empty allowlist denies every sender, unauthorized senders cost
one log line and zero compute, and no message from them ever reaches the
shared handler. The SDK is a lazy import behind the ``api`` test seam — every
pure decision is a module-level function so tests need no discord package and
no network.

Pinned api seam (the same four operations every chat adapter gets):
``register_on_message(async_fn)``, ``start()``, ``close()``,
``send_message(chat_id, content)``.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any

from hunter.errors import HunterError
from hunter.gateway.transport import ChatTransport, InboundMessage, chunk_text, is_authorized

__all__ = ["DISCORD_MESSAGE_LIMIT", "DiscordAdapter", "_default_api", "_is_authorized"]

logger = logging.getLogger(__name__)

DISCORD_MESSAGE_LIMIT = 2000  # Discord's limit, in UTF-16 code units


def _is_authorized(user_id: str | None, allowed_users) -> bool:
    """Adapter-local alias of the shared transport-level fail-closed check."""
    return is_authorized(user_id, allowed_users)


def _default_api(token: str) -> Any:
    """Lazy discord.py import — the production api seam.

    Wraps ``discord.Client`` in the pinned four-operation seam. The intents /
    message_content wiring needs a manual smoke test with a real bot before
    release (the offline suite covers the seam only).
    """
    try:
        import discord
    except ImportError as exc:
        raise HunterError(
            code="config.dependency_missing",
            layer="config",
            message="discord.py is not installed",
            hint="pip install 'hunteros-harness[discord]'",
        ) from exc

    class _DiscordClientApi:
        """discord.Client bridged onto the pinned seam."""

        def __init__(self, bot_token: str) -> None:
            self._token = bot_token
            intents = discord.Intents.default()
            intents.message_content = True
            self._client = discord.Client(intents=intents)
            self._handler: Any = None

        def register_on_message(self, fn: Any) -> None:
            self._handler = fn

            @self._client.event
            async def on_message(message: Any) -> None:
                author = getattr(message, "author", None)
                if getattr(self._client.user, "id", None) is not None and getattr(
                    author, "id", None
                ) == self._client.user.id:
                    return  # never dispatch the bot's own messages
                if self._handler is not None:
                    await self._handler(message)

        def start(self) -> None:
            self._client_task = asyncio.create_task(self._client.start(self._token))

        async def close(self) -> None:
            await self._client.close()

        async def send_message(self, chat_id: str, content: str) -> None:
            channel = self._client.get_channel(int(chat_id))
            if channel is None:
                channel = await self._client.fetch_channel(int(chat_id))
            await channel.send(content)

    return _DiscordClientApi(token)


class DiscordAdapter(ChatTransport):
    """Event-driven Discord adapter over the pinned api seam."""

    name = "discord"
    max_message_length = DISCORD_MESSAGE_LIMIT
    supports_markdown = True

    def __init__(self, token: str, allowed_users: set[str], *, api: Any = None) -> None:
        if not token or not token.strip():
            raise HunterError(
                code="config.discord_token",
                layer="config",
                message="Discord adapter needs a bot token",
                hint="create an application bot in the Discord developer portal "
                "and pass the token",
            )
        self._token = token.strip()
        self._allowed = frozenset(allowed_users or set())
        self._api = api
        self._on_message: Any = None
        self._closed = False

    # -- ChatTransport --------------------------------------------------------

    async def connect(self, on_message: Any) -> bool:
        self._on_message = on_message
        if self._api is None:
            self._api = _default_api(self._token)
        self._api.register_on_message(self._dispatch)
        self._api.start()
        self._closed = False
        return True

    async def disconnect(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._api, "close", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result

    async def send(self, chat_id: str, content: str, *, reply_to: str | None = None) -> str:
        """Send ``content`` chunked at Discord's 2000 UTF-16-unit limit."""
        last = ""
        for part in chunk_text(content or "", DISCORD_MESSAGE_LIMIT):
            await self._api.send_message(chat_id, part)
            last = part
        return last

    # -- dispatch ---------------------------------------------------------------

    async def _dispatch(self, message: Any) -> None:
        """Map one raw Discord message to InboundMessage — fail-closed."""
        text = str(getattr(message, "content", "") or "")
        if not text.strip():
            return
        sender = getattr(message, "author", None)
        sender_id = getattr(sender, "id", None)
        user_id = str(sender_id) if sender_id is not None else None
        if not _is_authorized(user_id, self._allowed):
            # ONE line per denied sender; nothing runs, nothing is stored.
            logger.warning(
                "discord: denied sender %s on channel %s (not in allowlist)",
                user_id or "<unknown>",
                getattr(getattr(message, "channel", None), "id", "?"),
            )
            return
        channel = getattr(message, "channel", None)
        channel_type = str(getattr(channel, "type", "private"))
        inbound = InboundMessage(
            text=text,
            transport=self.name,
            chat_id=str(getattr(channel, "id", "") or ""),
            user_id=user_id,
            user_name=getattr(sender, "name", None),
            chat_type="dm" if channel_type == "private" else channel_type,
            message_id=str(getattr(message, "id", "") or ""),
        )
        callback = self._on_message
        if callback is None:
            return
        await callback(inbound)
