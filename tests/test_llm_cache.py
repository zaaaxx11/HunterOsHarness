"""Tests for the LLM response cache / de-dup (gap-analysis point 6)."""

from __future__ import annotations

import pytest

from hunter.llm.config import AgentConfig, FallbackEntry, HunterConfig, ProviderConfig, TierConfig
from hunter.llm.native import NativeProvider
from hunter.llm.response_cache import ResponseCache, cache_key


class Resp:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = {}

    def json(self) -> dict:
        return self._body

    @property
    def text(self) -> str:
        return ""


class CountingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def post(self, url, json=None, headers=None) -> Resp:
        self.calls += 1
        return Resp(
            200,
            {
                "choices": [
                    {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
                ],
                "usage": {},
            },
        )


def config() -> HunterConfig:
    return HunterConfig(
        model_tiers={
            "orchestrator": TierConfig(
                provider="customin", model="m", base_url="https://a.test/v1", timeout=5
            )
        },
        providers={"customin": ProviderConfig(api_key="k")},
        fallback_providers=[],
        agent=AgentConfig(api_max_retries=1),
    )


def msgs() -> list[dict]:
    return [{"role": "user", "content": "ping"}]


def test_identical_call_does_not_hit_provider_twice():
    transport = CountingTransport()
    provider = NativeProvider(config(), transport=transport)
    first = provider.complete("orchestrator", msgs())
    second = provider.complete("orchestrator", msgs())
    assert transport.calls == 1, "second identical call must be served from cache"
    assert first.text == second.text == "ok"


def test_different_messages_are_not_deduped():
    transport = CountingTransport()
    provider = NativeProvider(config(), transport=transport)
    provider.complete("orchestrator", msgs())
    provider.complete("orchestrator", [{"role": "user", "content": "different"}])
    assert transport.calls == 2


class StreamingTransport:
    """Minimal stream-capable transport emitting one SSE chunk."""

    def __init__(self) -> None:
        self.calls = 0

    def stream(self, method, url, json=None, headers=None):
        self.calls += 1
        response = self

        class _Ctx:
            def __enter__(self_inner):
                return response

            def __exit__(self_inner, *args):
                return False

        return _Ctx()

    @property
    def status_code(self) -> int:
        return 200

    def iter_lines(self):
        yield 'data: {"choices":[{"delta":{"content":"x"},"finish_reason":"stop"}]}'
        yield "data: [DONE]"

    def json(self) -> dict:
        return {}


def test_streaming_is_never_cached():
    transport = StreamingTransport()
    provider = NativeProvider(config(), transport=transport)
    provider.complete("orchestrator", msgs(), stream_cb=lambda _text: None)
    provider.complete("orchestrator", msgs(), stream_cb=lambda _text: None)
    assert transport.calls == 2, "streaming calls must always hit the provider"


def test_cache_key_is_stable_and_order_independent():
    from hunter.llm.native import _Route

    route = _Route(provider="p", model="m", base_url="u", api_key="k", timeout=5)
    a = cache_key("orchestrator", [{"role": "user", "content": "x"}], None, route)
    b = cache_key("orchestrator", [{"content": "x", "role": "user"}], None, route)
    assert a == b


def test_cache_ttl_expires(monkeypatch):
    import hunter.llm.response_cache as rc

    clock = {"now": 100.0}
    monkeypatch.setattr(rc.time, "monotonic", lambda: clock["now"])
    c = ResponseCache(ttl_seconds=10.0)
    c.put("k", object(), "p")  # type: ignore[arg-type]
    assert c.get("k") is not None
    clock["now"] += 11.0
    assert c.get("k") is None


def test_clear_provider_only_removes_that_provider(monkeypatch):
    import hunter.llm.response_cache as rc

    monkeypatch.setattr(rc.time, "monotonic", lambda: 100.0)
    c = ResponseCache(ttl_seconds=60.0)
    c.put("a", object(), "p1")  # type: ignore[arg-type]
    c.put("b", object(), "p2")  # type: ignore[arg-type]
    c.clear_provider("p1")
    assert c.get("a") is None
    assert c.get("b") is not None
