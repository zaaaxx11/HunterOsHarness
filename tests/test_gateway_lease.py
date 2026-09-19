"""Turn lease tests: serialize per chat, fail closed on contention."""

from __future__ import annotations

import asyncio

import pytest

from hunter.gateway.lease import LeaseBusy, TurnLeaseRegistry


def _run(coro):
    return asyncio.run(coro)


def test_acquire_release_roundtrip():
    async def scenario():
        registry = TurnLeaseRegistry()
        lease = await registry.acquire("telegram:42", timeout=1.0)
        await lease.release()
        lease2 = await registry.acquire("telegram:42", timeout=1.0)
        await lease2.release()

    _run(scenario())


def test_second_acquire_times_out_busy():
    async def scenario():
        registry = TurnLeaseRegistry()
        lease = await registry.acquire("telegram:42", timeout=1.0)
        with pytest.raises(LeaseBusy) as excinfo:
            await registry.acquire("telegram:42", timeout=0.05)
        assert "telegram:42" in str(excinfo.value)
        await lease.release()
        return True

    assert _run(scenario()) is True


def test_release_then_reacquire_ok():
    async def scenario():
        registry = TurnLeaseRegistry()
        lease = await registry.acquire("webhook:abc", timeout=1.0)
        await lease.release()
        # After release the chat is immediately servable again.
        lease2 = await registry.acquire("webhook:abc", timeout=0.01)
        await lease2.release()

    _run(scenario())


def test_release_is_idempotent():
    async def scenario():
        registry = TurnLeaseRegistry()
        lease = await registry.acquire("webhook:abc", timeout=1.0)
        await lease.release()
        await lease.release()  # must be a no-op, not an error
        lease2 = await registry.acquire("webhook:abc", timeout=0.01)
        await lease2.release()

    _run(scenario())


def test_async_context_manager_releases():
    async def scenario():
        registry = TurnLeaseRegistry()
        async with await registry.acquire("webhook:abc", timeout=1.0):
            with pytest.raises(LeaseBusy):
                await registry.acquire("webhook:abc", timeout=0.01)
        lease = await registry.acquire("webhook:abc", timeout=0.01)  # free again
        await lease.release()

    _run(scenario())


def test_different_keys_do_not_block_each_other():
    async def scenario():
        registry = TurnLeaseRegistry()
        lease_a = await registry.acquire("telegram:1", timeout=1.0)
        lease_b = await registry.acquire("telegram:2", timeout=0.01)  # independent chat
        await lease_a.release()
        await lease_b.release()

    _run(scenario())


def test_empty_key_rejected():
    async def scenario():
        registry = TurnLeaseRegistry()
        with pytest.raises(ValueError):
            await registry.acquire("", timeout=0.01)

    _run(scenario())
