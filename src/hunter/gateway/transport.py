"""Chat transports — the normalized inbound-message seam for gateway platforms.

Every chat platform (Telegram long-poll, HTTP webhook, ...) adapts to three
things: it produces :class:`InboundMessage`, it consumes
``ChatTransport.send`` calls, and it enforces its OWN authorization
(fail-closed) before anything reaches the shared handler. The gateway app
never sees platform specifics — hermes' surface-independence, applied to
transports.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

__all__ = ["ChatTransport", "InboundMessage", "chunk_text", "is_authorized"]


@dataclass(frozen=True, slots=True)
class InboundMessage:
    """One inbound chat message, normalized across platforms."""

    text: str
    transport: str  # "telegram" | "webhook" | ...
    chat_id: str
    user_id: str | None = None
    user_name: str | None = None
    chat_type: str = "dm"  # "dm" | "group" | "channel"
    message_id: str | None = None


class ChatTransport(ABC):
    """Base class for chat platform adapters.

    ``connect`` receives the async handler the gateway runs for each inbound
    message. Handlers may return a reply string (``str | None``): transports
    that deliver replies out-of-band (Telegram) ignore it and use
    ``send``; inline-reply transports (webhook) await it and answer the
    originating request directly.
    """

    name: str = "base"
    max_message_length: int = 0  # 0 = unlimited
    supports_markdown: bool = False
    inline_reply: bool = False  # True → connect()'s handler return value IS the reply

    @abstractmethod
    async def connect(
        self, on_message: Callable[[InboundMessage], Awaitable[str | None]]
    ) -> bool:
        """Start receiving; call ``on_message`` per authorized inbound message."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Stop receiving and release every resource. Idempotent."""

    @abstractmethod
    async def send(self, chat_id: str, content: str, *, reply_to: str | None = None) -> str:
        """Deliver ``content`` to ``chat_id`` (chunked per platform limits)."""

    async def set_status(self, chat_id: str, status: str = "typing") -> None:
        """Best-effort presence hint (e.g. Telegram typing). Default no-op."""
        return None


def is_authorized(user_id: str | None, allowed_users) -> bool:
    """Fail-closed allowlist check shared by every messaging surface.

    An empty or missing allowlist denies EVERYONE — an open bot is never an
    accident. ``user_id`` must be a non-empty id present (after whitespace
    normalization) in ``allowed_users``. Adapters keep thin local aliases of
    this helper so their modules stay self-describing; the semantics live here.
    """
    if not user_id or not allowed_users:
        return False
    allowed = {str(u).strip() for u in allowed_users}
    return str(user_id).strip() in allowed


def chunk_text(text: str, limit: int) -> list[str]:
    """Split ``text`` into chunks of at most ``limit`` UTF-16 code units.

    Telegram and friends measure message limits in UTF-16 code units: BMP
    characters cost 1, astral-plane characters (emoji, 𝄞) cost 2, and a
    surrogate pair must never be split mid-chunk. ``limit <= 0`` raises
    ValueError; an empty text yields an empty list; a single unit that
    cannot fit any chunk is emitted alone rather than dropped.
    """
    if limit <= 0:
        raise ValueError("chunk limit must be a positive number of UTF-16 units")
    if not text:
        return []
    chunks: list[str] = []
    current: list[str] = []
    current_units = 0
    for char in text:
        units = 2 if ord(char) > 0xFFFF else 1
        if current and current_units + units > limit:
            chunks.append("".join(current))
            current = []
            current_units = 0
        current.append(char)
        current_units += units
    if current or not chunks:
        chunks.append("".join(current))
    return chunks
