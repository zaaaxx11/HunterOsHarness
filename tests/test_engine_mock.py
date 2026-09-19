"""MockEngine + LLMEngine stub tests.

MockEngine must be fully offline: its HTTP transport is rigged to explode if
any request is ever attempted. LLMEngine must plan fine but refuse to run
until v0.2 wires litellm in.
"""

import httpx
import pytest

from hunter.engine.base import EngineContext, TargetSpec
from hunter.engine.llm import LLMEngine
from hunter.engine.mock import MockEngine
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope


def _rigged_client() -> ScopedHttpClient:
    """A client whose transport fails the test if ANY request goes out."""
    def deny(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("MockEngine attempted a network request")
    return ScopedHttpClient(localhost_scope(), transport=httpx.MockTransport(deny))


def _ctx_and_target(events: list[tuple[str, dict]]):
    client = _rigged_client()
    ctx = EngineContext(http=client, emit=lambda kind, payload: events.append((kind, dict(payload))))
    target = TargetSpec(url="http://127.0.0.1:1/", scope=localhost_scope())
    return client, ctx, target


def test_mock_engine_plan():
    engine = MockEngine()
    plan = engine.plan(TargetSpec(url="http://127.0.0.1:1/", scope=localhost_scope()))
    assert engine.name == "mock"
    assert plan.engine == "mock"
    assert len(plan.phases) == 1


def test_mock_engine_run_returns_canned_candidate_without_network():
    engine = MockEngine()
    events: list[tuple[str, dict]] = []
    client, ctx, target = _ctx_and_target(events)
    try:
        result = engine.run(target, ctx)
    finally:
        client.close()
    assert len(result.candidates) == 1
    canned = result.candidates[0]
    assert canned.key == "mock|GET|/mock|-"
    assert canned.severity.value == "low"
    assert len(canned.evidence) == 1
    assert canned.evidence[0].kind == "note"
    assert result.stats["requests"] == 0
    assert ("probe_started", {"check_id": "mock"}) in events
    assert ("probe_result", {"check_id": "mock", "candidates": 1, "hit": True}) in events


def test_mock_engine_replay_true_for_its_candidate():
    engine = MockEngine()
    events: list[tuple[str, dict]] = []
    client, ctx, target = _ctx_and_target(events)
    try:
        result = engine.run(target, ctx)
        assert engine.replay(target, ctx, result.candidates[0]) is True
    finally:
        client.close()


def test_llm_engine_plan_works():
    engine = LLMEngine()
    plan = engine.plan(TargetSpec(url="http://127.0.0.1:1/", scope=localhost_scope()))
    assert engine.name == "llm"
    assert plan.engine == "llm"
    assert plan.phases  # non-empty strategy


def test_llm_engine_run_refuses_until_v02():
    engine = LLMEngine()
    events: list[tuple[str, dict]] = []
    client, ctx, target = _ctx_and_target(events)
    try:
        with pytest.raises(RuntimeError, match="LLMEngine lands in v0.2"):
            engine.run(target, ctx)
        with pytest.raises(RuntimeError, match="litellm"):
            engine.replay(target, ctx, None)  # type: ignore[arg-type]
    finally:
        client.close()
