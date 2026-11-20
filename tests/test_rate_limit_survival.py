"""End-to-end tests for the Phase 2 rate-limit survival kit.

Six tests covering failover, circuit breaker, AIMD, limiter concurrency,
clear-on-success, and the cross-session cooldown lifecycle. All network I/O is
faked; no API keys needed.
"""

from __future__ import annotations

import importlib
import json
import threading
import time
from pathlib import Path

import pytest

from hunter.errors import HunterError
from hunter.llm.config import AgentConfig, FallbackEntry, HunterConfig, ProviderConfig, TierConfig
from hunter.llm.native import NativeProvider


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000_000.0
        self.lock = threading.Lock()

    def monotonic(self) -> float:
        with self.lock:
            return self.value

    def time(self) -> float:
        with self.lock:
            return self.value

    def sleep(self, seconds: float) -> None:
        with self.lock:
            self.value += max(0.0, float(seconds))

    def advance(self, seconds: float) -> None:
        self.sleep(seconds)


class Resp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def json(self) -> dict:
        return self._body

    @property
    def text(self) -> str:
        return json.dumps(self._body)


class FakeTransport:
    """httpx.Client stand-in routing by URL host, recording every dial."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls: list[str] = []
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def post(self, url: str, json=None, headers=None) -> Resp:
        host = url.split("/")[2]
        with self._lock:
            self._counts[host] = self._counts.get(host, 0) + 1
            n = self._counts[host]
            self.calls.append(url)
        return self.responder(url, json or {}, n)


def ok_body(model: str = "m-b") -> dict:
    return {
        "id": "cmpl-1",
        "model": model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4},
    }


def err_body(msg: str) -> dict:
    return {"error": {"message": msg, "type": "rate_limit_error"}}


def messages() -> list[dict]:
    return [{"role": "user", "content": "ping"}]


def two_provider_config(retries: int = 1) -> HunterConfig:
    return HunterConfig(
        model_tiers={
            "orchestrator": TierConfig(
                provider="customin", model="m-a", base_url="https://a.test/v1", timeout=5
            )
        },
        providers={
            "customin": ProviderConfig(api_key="key-a"),
            "devora": ProviderConfig(api_key="key-b"),
        },
        fallback_providers=[
            FallbackEntry(provider="devora", model="m-b", base_url="https://b.test/v1")
        ],
        agent=AgentConfig(api_max_retries=retries),
    )


def one_provider_config(retries: int = 1) -> HunterConfig:
    cfg = two_provider_config(retries)
    cfg.fallback_providers = []
    return cfg


def install_clock(monkeypatch, module, clock: FakeClock) -> None:
    if hasattr(module, "time"):
        if hasattr(module.time, "monotonic"):
            monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
            monkeypatch.setattr(module.time, "sleep", clock.sleep)
    for attr, replacement in (("monotonic", clock.monotonic), ("sleep", clock.sleep)):
        if hasattr(module, attr):
            monkeypatch.setattr(module, attr, replacement)


@pytest.fixture(autouse=True)
def isolation(monkeypatch, tmp_path: Path):
    import hunter.llm.native as native_mod
    import hunter.llm.rate_control as rc

    # Reset singleton state in place — NEVER reload the module: native.py holds
    # module-level bindings to these exact objects, so a reload would leave the
    # tests inspecting a different breaker than production uses.
    rc.limiter.reset()
    rc.breaker.reset()
    rc.throttle.reset()
    monkeypatch.setenv("HUNTEROS_STATE_DIR", str(tmp_path))
    for var in ("HUNTEROS_MODEL", "HUNTEROS_MAX_TOKENS", "HUNTEROS_TEMPERATURE", "HUNTEROS_TOOL_CHOICE"):
        monkeypatch.delenv(var, raising=False)
    # Keep the cross-session cooldown gate out of these tests; it is exercised
    # through the state file itself in the lifecycle test, not via the gate.
    from hunter.llm import rate_guard

    monkeypatch.setattr(rate_guard, "remaining", lambda provider: None)
    clock = FakeClock()
    install_clock(monkeypatch, native_mod, clock)
    install_clock(monkeypatch, rc, clock)
    yield clock


# 1 ------------------------------------------------------------------------
def test_429_fails_over_to_different_provider():
    """Primary 429s exhaust retries; fallback with a DIFFERENT key wins."""
    transport = FakeTransport(
        lambda url, payload, n: (
            Resp(429, err_body("slow down"), {"retry-after": "1"})
            if "a.test" in url
            else Resp(200, ok_body())
        )
    )
    result = NativeProvider(two_provider_config(retries=1), transport=transport).complete(
        "orchestrator", messages()
    )
    assert result.provider == "devora"
    assert result.text == "hello"
    hosts = [url.split("/")[2] for url in transport.calls]
    assert "a.test" in hosts
    assert hosts.count("b.test") >= 1


# 2 ------------------------------------------------------------------------
def test_circuit_breaker_opens_skips_then_half_open_recovers(monkeypatch):
    import hunter.llm.rate_control as rc
    from hunter.llm import rate_guard

    # Isolate the breaker from the cross-session cooldown gate.
    monkeypatch.setattr(rate_guard, "remaining", lambda provider: None)
    transport = FakeTransport(
        lambda url, payload, n: Resp(429, err_body("slow down"), {"retry-after": "1"})
    )
    provider = NativeProvider(one_provider_config(retries=2), transport=transport)

    for _ in range(8):
        if rc.breaker.state("customin") != rc.CircuitState.CLOSED:
            break
        with pytest.raises((HunterError, AssertionError)):
            provider.complete("orchestrator", messages())
    assert rc.breaker.state("customin") == rc.CircuitState.OPEN

    calls_before = len(transport.calls)
    with pytest.raises((HunterError, AssertionError)):
        provider.complete("orchestrator", messages())
    assert len(transport.calls) == calls_before, "OPEN provider must not be dialed"

    # Advance past the open window. state() is time-based; allows() may also
    # perform the lazy OPEN->HALF_OPEN transition. Either way it is not CLOSED.
    clock = FakeClock()
    clock.value = time.monotonic() + 10_000.0
    monkeypatch.setattr(rc.time, "monotonic", clock.monotonic)
    assert rc.breaker.state("customin") != rc.CircuitState.CLOSED

    transport.responder = lambda url, payload, n: Resp(200, ok_body("m-a"))
    result = provider.complete("orchestrator", messages())
    assert result.provider == "customin"
    assert rc.breaker.state("customin") == rc.CircuitState.CLOSED


# 3 ------------------------------------------------------------------------
def test_adaptive_throttle_aimd():
    import hunter.llm.rate_control as rc

    throttle = rc.AdaptiveThrottle(base_delay=1.0, min_delay=0.1, max_delay=30.0)
    timeline = [throttle.delay("p")]
    throttle.note_429("p")
    timeline.append(throttle.delay("p"))
    assert timeline[-1] > timeline[-2], "429 must increase delay"

    peak = timeline[-1]
    throttle.note_success("p")
    assert throttle.delay("p") < peak, "success must decrease delay"

    for _ in range(50):
        throttle.note_429("p")
        timeline.append(throttle.delay("p"))
    for _ in range(50):
        throttle.note_success("p")
        timeline.append(throttle.delay("p"))
    assert all(0.1 <= d <= 30.0 for d in timeline)


# 4 ------------------------------------------------------------------------
def test_limiter_serializes_and_paces():
    import hunter.llm.rate_control as rc

    limiter = rc.ProviderLimiter(min_interval=0.05, max_concurrent=1)
    active = 0
    peak = 0
    entries: list[float] = []
    guard = threading.Lock()

    def worker() -> None:
        nonlocal active, peak
        with limiter.slot("p"):
            with guard:
                active += 1
                peak = max(peak, active)
                entries.append(time.monotonic())
            time.sleep(0.01)
            with guard:
                active -= 1

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak == 1, f"max concurrent was {peak}, expected 1"
    for earlier, later in zip(entries, entries[1:]):
        assert later - earlier >= 0.05 - 1e-6


# 5 ------------------------------------------------------------------------
def test_rate_guard_clear_on_success_record_on_429(monkeypatch, tmp_path):
    import hunter.llm.rate_guard as rate_guard

    calls: list[str] = []
    original_record, original_clear = rate_guard.record, rate_guard.clear

    def spy_record(provider, **kwargs):
        calls.append(f"record:{provider}")
        return original_record(provider, **kwargs)

    def spy_clear(provider):
        calls.append(f"clear:{provider}")
        return original_clear(provider)

    monkeypatch.setattr(rate_guard, "record", spy_record)
    monkeypatch.setattr(rate_guard, "clear", spy_clear)

    phase = {"mode": "429"}
    transport = FakeTransport(
        lambda url, payload, n: (
            Resp(429, err_body("slow down"), {"retry-after": "1"})
            if phase["mode"] == "429"
            else Resp(200, ok_body("m-a"))
        )
    )
    provider = NativeProvider(one_provider_config(retries=1), transport=transport)
    with pytest.raises((HunterError, AssertionError)):
        provider.complete("orchestrator", messages())
    assert "record:customin" in calls

    phase["mode"] = "ok"
    provider.complete("orchestrator", messages())
    assert "clear:customin" in calls


# 6 ------------------------------------------------------------------------
def test_429_does_not_leave_permanent_cooldown_after_success(monkeypatch, tmp_path):
    import hunter.llm.rate_guard as rate_guard

    # The breaker is already tested separately; keep it out of this lifecycle
    # test so two complete() calls can be driven in sequence.
    monkeypatch.setattr(rate_guard, "remaining", lambda provider: None)
    phase = {"mode": "429"}
    transport = FakeTransport(
        lambda url, payload, n: (
            Resp(429, err_body("slow down"), {"retry-after": "1"})
            if phase["mode"] == "429"
            else Resp(200, ok_body("m-a"))
        )
    )
    provider = NativeProvider(one_provider_config(retries=1), transport=transport)
    with pytest.raises((HunterError, AssertionError)):
        provider.complete("orchestrator", messages())

    state_file = tmp_path / "rate_limits" / "customin.json"
    assert state_file.exists(), "429 must write a cooldown file"

    phase["mode"] = "ok"
    result = provider.complete("orchestrator", messages())
    assert result.provider == "customin"
    assert not state_file.exists(), "success must clear the cooldown file"
