"""Per-chat turn leases — nothing runs unserialized, nothing fails open.

One asyncio lock per session key (``transport:chat_id``). A second message
for the same chat while a turn is in flight waits at most ``timeout``
seconds, then FAILS CLOSED with :class:`LeaseBusy`: the caller answers
"still working on your previous request" and NOTHING executes — hermes'
turn-lease doctrine, minus the routing-key complexity our gateway does not
have (key == session here, one engine per chat).
"""

from __future__ import annotations

import asyncio
from typing import Any

__all__ = ["Lease", "LeaseBusy", "TurnLeaseRegistry"]

DEFAULT_LEASE_TIMEOUT = 5.0


class LeaseBusy(RuntimeError):
    """The chat's previous turn still holds the lease — fail closed."""

    def __init__(self, session_key: str, timeout: float) -> None:
        self.session_key = session_key
        self.timeout = timeout
        super().__init__(
            f"lease for '{session_key}' still held after {timeout:.1f}s — turn refused"
        )


class Lease:
    """Held-lease handle; ``release`` is idempotent and async-context safe."""

    def __init__(self, release: Any) -> None:
        self._release_coro: Any = release

    async def release(self) -> None:
        if self._release_coro is None:
            return
        coro, self._release_coro = self._release_coro, None
        await coro


    async def __aenter__(self) -> Lease:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.release()


class TurnLeaseRegistry:
    """Process-local registry of per-key turn leases (single event loop)."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, session_key: str) -> asyncio.Lock:
        lock = self._locks.get(session_key)
        if lock is None:
            lock = self._locks[session_key] = asyncio.Lock()
        return lock

    async def acquire(self, session_key: str, timeout: float = DEFAULT_LEASE_TIMEOUT) -> Lease:
        """Acquire the lease for ``session_key``.

        Raises:
            LeaseBusy: the previous turn still holds the lease after
                ``timeout`` seconds — the caller must run NOTHING.
        """
        if not session_key:
            raise ValueError("session_key must be non-empty")
        lock = self._lock_for(session_key)
        try:
            await asyncio.wait_for(lock.acquire(), timeout=max(0.0, float(timeout)))
        except asyncio.TimeoutError as exc:
            raise LeaseBusy(session_key, timeout) from exc
        return Lease(self._release(session_key, lock))

    async def _release(self, session_key: str, lock: asyncio.Lock) -> None:
        lock.release()
