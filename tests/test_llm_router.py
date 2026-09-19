"""ProviderRouter — normalization, retries, failover, classification.

NO test in this file touches the network: LiteLLM is always the FakeLiteLLM
test seam (or absent entirely for the import-guard test).
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from hunter.errors import HunterError
from hunter.llm.base import ERROR_REASONS
from hunter.llm.budget import RunBudget
from hunter.llm.config import (
    AgentConfig,
    BudgetConfig,
    FallbackEntry,
    HunterConfig,
    ProviderConfig,
    TierConfig,
)
from hunter.llm.router import ProviderRouter, _wire_model, hunter_error_from_classified

USER_MSG = {"role": "user", "content": "find the bug"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Hermetic: no machine env vars leak into routing decisions."""
    for var in (
        "HUNTEROS_CONFIG", "HUNTEROS_MODEL", "HUNTEROS_TIER",
        "HUNTEROS_BUDGET_USD", "HUNTEROS_MAX_ITERATIONS",
    ):
        monkeypatch.delenv(var, raising=False)


# ------------------------------------------------------------------ fakes ---


class FakeProviderError(Exception):
    """Synthetic provider failure with an optional HTTP status code."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class FakeLiteLLM:
    """Duck-typed litellm module: a queue of responses/exceptions per call."""

    def __init__(self, queue: tuple[Any, ...] = (), cost: float = 0.012) -> None:
        self.calls: list[dict[str, Any]] = []
        self._queue = list(queue)
        self._cost = cost

    def completion(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if not self._queue:
            raise AssertionError("FakeLiteLLM queue exhausted — unexpected extra call")
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def completion_cost(self, response: Any) -> float:
        return self._cost


def make_response(
    text: str = "ok",
    tool_calls: tuple[Any, ...] = (),
    finish_reason: str = "stop",
    model: str = "fake/response-model",
    prompt_tokens: int = 11,
    completion_tokens: int = 7,
) -> Any:
    message = SimpleNamespace(content=text, tool_calls=list(tool_calls))
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason=finish_reason)],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
        model=model,
    )


def make_tool_call(call_id: str = "call_1", name: str = "http_request", arguments: str = '{"url": "http://x/"}'):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


def make_chunk(content: str, finish_reason: str | None = None, model: str = "fake/stream-model") -> Any:
    delta = SimpleNamespace(content=content, tool_calls=[])
    return SimpleNamespace(
        model=model,
        usage=None,
        choices=[SimpleNamespace(delta=delta, finish_reason=finish_reason)],
    )


def make_config(
    provider: str = "openai",
    model: str = "gpt-fake",
    base_url: str = "",
    timeout: int = 120,
    providers: dict[str, ProviderConfig] | None = None,
    fallback_providers: list[FallbackEntry] | None = None,
    api_max_retries: int = 3,
) -> HunterConfig:
    return HunterConfig(
        model_tiers={
            "orchestrator": TierConfig(provider=provider, model=model, base_url=base_url, timeout=timeout)
        },
        providers=providers or {},
        fallback_providers=fallback_providers or [],
        budget=BudgetConfig(),
        agent=AgentConfig(api_max_retries=api_max_retries),
    )


# ------------------------------------------------------------- success path --


def test_success_path_normalizes_turn_result():
    fake = FakeLiteLLM([make_response(text="hello there")])
    router = ProviderRouter(make_config(), litellm_module=fake)

    result = router.complete("orchestrator", [USER_MSG])

    assert result.text == "hello there"
    assert result.finish_reason == "stop"
    assert result.input_tokens == 11
    assert result.output_tokens == 7
    assert result.cost_usd == pytest.approx(0.012)
    assert result.model == "fake/response-model"
    assert result.provider == "openai"
    assert result.error_surface is None

    call = fake.calls[0]
    assert call["model"] == "openai/gpt-fake"  # provider prefix applied
    assert call["messages"] == [USER_MSG]
    assert call["api_key"] is None  # no provider block -> litellm env resolution
    assert call["timeout"] == 120
    assert call["stream"] is False
    assert "tools" not in call
    assert "base_url" not in call


def test_api_key_resolved_from_provider_block(monkeypatch):
    cfg = make_config(providers={"openai": ProviderConfig(key_env="FAKE_OPENAI_KEY")})
    monkeypatch.setenv("FAKE_OPENAI_KEY", "sk-fake-123456")
    fake = FakeLiteLLM([make_response()])

    ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert fake.calls[0]["api_key"] == "sk-fake-123456"


def test_base_url_and_tools_forwarded():
    cfg = make_config(base_url="https://gw.example.com/v1")
    fake = FakeLiteLLM([make_response()])
    tools = [{"type": "function", "function": {"name": "http_request"}}]

    ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG], tools=tools)

    call = fake.calls[0]
    assert call["base_url"] == "https://gw.example.com/v1"
    assert call["tools"] == tools


def test_reasoning_effort_forwarded_only_when_set():
    cfg = make_config()
    cfg.model_tiers["orchestrator"].reasoning_effort = "low"
    fake = FakeLiteLLM([make_response()])
    ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])
    assert fake.calls[0]["reasoning_effort"] == "low"

    plain = FakeLiteLLM([make_response()])
    ProviderRouter(make_config(), litellm_module=plain).complete("orchestrator", [USER_MSG])
    assert "reasoning_effort" not in plain.calls[0]


def test_tool_calls_parsed_into_turn_result():
    good = make_tool_call("call_1", "http_request", '{"url": "http://x/", "n": 2}')
    fake = FakeLiteLLM([make_response(text="", tool_calls=(good,), finish_reason="tool_calls")])

    result = ProviderRouter(make_config(), litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.finish_reason == "tool_calls"
    (call,) = result.tool_calls
    assert call.id == "call_1"
    assert call.name == "http_request"
    assert call.arguments == {"url": "http://x/", "n": 2}


def test_malformed_tool_json_tolerated():
    bad = make_tool_call("call_2", "bad_tool", "{not json")
    fake = FakeLiteLLM([make_response(text="", tool_calls=(bad,), finish_reason="tool_calls")])

    result = ProviderRouter(make_config(), litellm_module=fake).complete("orchestrator", [USER_MSG])

    # The turn keeps finish_reason "tool_calls" and an empty-arguments call:
    # the tool layer owns malformed-argument handling.
    (call,) = result.tool_calls
    assert call.name == "bad_tool"
    assert call.arguments == {}
    assert result.finish_reason == "tool_calls"


def test_empty_response_is_retried():
    fake = FakeLiteLLM([SimpleNamespace(choices=[]), make_response(text="got it")])

    result = ProviderRouter(make_config(), litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.text == "got it"
    assert len(fake.calls) == 2


# ------------------------------------------------------- retries + failover --


def test_retry_on_429_then_success(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("hunter.llm.router.time.sleep", sleeps.append)
    fake = FakeLiteLLM(
        [FakeProviderError("429 too many requests", 429), make_response(text="second try")]
    )
    cfg = make_config(api_max_retries=3)

    result = ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.text == "second try"
    assert len(fake.calls) == 2
    assert sleeps == [1.0]  # exponential backoff: 1s, then 2s, then 4s (cap 8s)


def test_backoff_sequence_is_exponential_and_capped(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("hunter.llm.router.time.sleep", sleeps.append)
    err = FakeProviderError("503 boom", 503)
    fake = FakeLiteLLM([err, err, err, err, make_response(text="finally")])
    cfg = make_config(api_max_retries=5)

    result = ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.text == "finally"
    assert sleeps == [1.0, 2.0, 4.0, 8.0]


def test_fallback_to_second_provider_on_auth_error(monkeypatch):
    monkeypatch.setenv("FB_KEY", "sk-fallback-9876")
    cfg = make_config(
        fallback_providers=[
            FallbackEntry(provider="openrouter", model="anthropic/claude-3", key_env="FB_KEY")
        ]
    )
    fake = FakeLiteLLM(
        [
            FakeProviderError("401 invalid api key", 401),
            make_response(text="fallback ok", model="openrouter/anthropic/claude-3"),
        ]
    )

    result = ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.text == "fallback ok"
    assert result.provider == "openrouter"
    assert result.model == "openrouter/anthropic/claude-3"
    assert fake.calls[0]["model"] == "openai/gpt-fake"
    assert fake.calls[1]["model"] == "openrouter/anthropic/claude-3"
    assert fake.calls[1]["api_key"] == "sk-fallback-9876"


def test_non_retryable_auth_raises_hunter_error_exit_4():
    fake = FakeLiteLLM([FakeProviderError("401 invalid api key", 401)])

    with pytest.raises(HunterError) as ei:
        ProviderRouter(make_config(), litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert ei.value.layer == "auth"
    assert ei.value.exit_code == 4
    assert "invalid api key" in ei.value.message
    assert len(fake.calls) == 1  # auth never retries the same provider


def test_all_attempts_exhausted_terminal_rate_limit(monkeypatch):
    monkeypatch.setattr("hunter.llm.router.time.sleep", lambda _s: None)
    err = FakeProviderError("429 slow down", 429)
    fake = FakeLiteLLM([err, err, err])  # 3 attempts, no fallbacks

    with pytest.raises(HunterError) as ei:
        ProviderRouter(make_config(api_max_retries=3), litellm_module=fake).complete(
            "orchestrator", [USER_MSG]
        )

    # "rate_limit" is not an errors.py layer — exit code 5 carries the signal.
    assert ei.value.exit_code == 5
    assert ei.value.code == "provider.rate_limit"
    assert "/model" in ei.value.hint and "fallback" in ei.value.hint
    assert len(fake.calls) == 3


def test_all_routes_exhausted_on_server_error_is_provider_error(monkeypatch):
    monkeypatch.setattr("hunter.llm.router.time.sleep", lambda _s: None)
    err = FakeProviderError("503 kaput", 503)
    fake = FakeLiteLLM([err, err])
    cfg = make_config(
        api_max_retries=1,
        fallback_providers=[FallbackEntry(provider="openai", model="gpt-backup")],
    )

    with pytest.raises(HunterError) as ei:
        ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert ei.value.layer == "provider"
    assert ei.value.exit_code == 1
    assert len(fake.calls) == 2  # primary + the one distinct fallback


def test_fallback_dedup_identical_route(monkeypatch):
    monkeypatch.setattr("hunter.llm.router.time.sleep", lambda _s: None)
    err = FakeProviderError("503 kaput", 503)
    fake = FakeLiteLLM([err, err, err])
    cfg = make_config(
        api_max_retries=1,
        # First entry duplicates the primary route; only the second is new.
        fallback_providers=[
            FallbackEntry(provider="openai", model="gpt-fake"),
            FallbackEntry(provider="openai", model="gpt-fake", base_url=""),
            FallbackEntry(provider="openai", model="gpt-fresh"),
        ],
    )

    with pytest.raises(HunterError):
        ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    models = [call["model"] for call in fake.calls]
    assert models == ["openai/gpt-fake", "openai/gpt-fresh"]


def test_context_overflow_raises_immediately_with_compact_hint():
    err = FakeProviderError("This model's maximum context length is 8192 tokens", 400)
    fake = FakeLiteLLM([err, err])

    with pytest.raises(HunterError) as ei:
        ProviderRouter(make_config(api_max_retries=3), litellm_module=fake).complete(
            "orchestrator", [USER_MSG]
        )

    assert ei.value.layer == "provider"
    assert ei.value.code == "provider.context_overflow"
    assert "compact or shorten the conversation" in ei.value.hint
    assert len(fake.calls) == 1  # deterministic rejection: no retry, no fallback


def test_unkeyed_fallback_link_is_skipped(monkeypatch):
    monkeypatch.delenv("ALSO_UNSET_XYZ", raising=False)
    err = FakeProviderError("401 nope", 401)
    fake = FakeLiteLLM([err])
    cfg = make_config(
        fallback_providers=[
            # Declares a key env that is not set -> unusable -> never dialed.
            FallbackEntry(provider="openai", model="gpt-fresh", key_env="ALSO_UNSET_XYZ"),
        ],
    )

    with pytest.raises(HunterError) as ei:
        ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert ei.value.exit_code == 4
    assert len(fake.calls) == 1  # primary only


def test_model_unresolved_errors_at_use_time():
    cfg = HunterConfig(model_tiers={}, providers={}, fallback_providers=[])
    fake = FakeLiteLLM(())

    with pytest.raises(HunterError) as ei:
        ProviderRouter(cfg, litellm_module=fake).complete("utility", [USER_MSG])

    assert ei.value.code == "config.model_unresolved"
    assert len(fake.calls) == 0


def test_litellm_missing_raises_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "litellm", None)  # forces the ImportError path

    with pytest.raises(HunterError) as ei:
        ProviderRouter(make_config())

    assert ei.value.layer == "config"
    assert ei.value.code == "config.llm_extra_missing"
    assert "hunteros-harness[llm]" in ei.value.hint
    assert ei.value.exit_code == 8


# -------------------------------------------------------------- streaming ----


def test_streaming_assembles_text_and_calls_cb():
    stream_chunks = [
        make_chunk("Hel", model="fake/stream-model"),
        make_chunk("lo"),
        make_chunk("", finish_reason="stop"),
    ]
    fake = FakeLiteLLM([stream_chunks])
    seen: list[str] = []

    result = ProviderRouter(make_config(), litellm_module=fake).complete(
        "orchestrator", [USER_MSG], stream_cb=seen.append
    )

    assert seen == ["Hel", "lo"]
    assert result.text == "Hello"
    assert result.finish_reason == "stop"
    assert result.model == "fake/stream-model"
    assert result.provider == "openai"
    assert fake.calls[0]["stream"] is True


def test_streaming_accumulates_tool_call_fragments():
    start = SimpleNamespace(
        model="m", usage=None,
        choices=[SimpleNamespace(
            delta=SimpleNamespace(
                content="",
                tool_calls=[SimpleNamespace(
                    index=0, id="call_9",
                    function=SimpleNamespace(name="http_request", arguments='{"u'),
                )],
            ),
            finish_reason=None,
        )],
    )
    end = SimpleNamespace(
        model="", usage=None,
        choices=[SimpleNamespace(
            delta=SimpleNamespace(
                content="",
                tool_calls=[SimpleNamespace(
                    index=0, id=None,
                    function=SimpleNamespace(name=None, arguments='rl": "http://x/"}'),
                )],
            ),
            finish_reason="tool_calls",
        )],
    )
    fake = FakeLiteLLM([[start, end]])
    seen: list[str] = []

    result = ProviderRouter(make_config(), litellm_module=fake).complete(
        "orchestrator", [USER_MSG], stream_cb=seen.append
    )

    assert seen == []  # no text deltas
    (call,) = result.tool_calls
    assert call.id == "call_9"
    assert call.name == "http_request"
    assert call.arguments == {"url": "http://x/"}
    assert result.finish_reason == "tool_calls"


# ----------------------------------------------------------------- budget ----


def test_budget_cost_added_and_exhaustion_raises_usage_error():
    budget = RunBudget(max_cost_usd=0.01)
    fake = FakeLiteLLM([make_response()])

    with pytest.raises(HunterError) as ei:
        ProviderRouter(make_config(), litellm_module=fake).complete("orchestrator", [USER_MSG], budget=budget)

    assert ei.value.layer == "usage"
    assert ei.value.code == "budget.exhausted"
    assert "config.yaml" in ei.value.hint
    assert budget.spent_usd == pytest.approx(0.012)  # the cost was still recorded


def test_budget_exhausted_before_any_call():
    budget = RunBudget(max_cost_usd=0.01)
    budget.add_cost(1.0)
    fake = FakeLiteLLM(())

    with pytest.raises(HunterError) as ei:
        ProviderRouter(make_config(), litellm_module=fake).complete("orchestrator", [USER_MSG], budget=budget)

    assert ei.value.code == "budget.exhausted"
    assert len(fake.calls) == 0


def test_budget_within_limits_passes_through():
    budget = RunBudget(max_cost_usd=10.0)
    fake = FakeLiteLLM([make_response()])

    result = ProviderRouter(make_config(), litellm_module=fake).complete(
        "orchestrator", [USER_MSG], budget=budget
    )

    assert result.text == "ok"
    assert budget.spent_usd == pytest.approx(0.012)
    assert budget.exhausted() is None


# ------------------------------------------------------------ classification --


_CLASSIFY_CASES: dict[str, BaseException] = {
    "auth": FakeProviderError("who goes there", 401),
    "auth_permanent": Exception("auth_permanent: key rejected after refresh"),
    "billing": FakeProviderError("payment required", 402),
    "rate_limit": FakeProviderError("429 too many requests", 429),
    "overloaded": Exception("the server is overloaded, at capacity"),
    "server_error": FakeProviderError("internal boom", 500),
    "timeout": Exception("request timed out"),
    "context_overflow": Exception("This model's maximum context length is 8192 tokens"),
    "model_not_found": FakeProviderError("model not found", 404),
    "content_policy_blocked": Exception("your request was flagged by our content filter"),
    "format_error": FakeProviderError("bad request shape", 400),
    "empty_response": Exception("provider returned an empty response"),
    "unknown": Exception("mysterious failure xyzzy"),
}


@pytest.mark.parametrize("reason", sorted(ERROR_REASONS))
def test_classify_maps_every_reason_in_the_vocabulary(reason):
    router = ProviderRouter(make_config(), litellm_module=FakeLiteLLM())

    classified = router.classify(_CLASSIFY_CASES[reason])

    assert classified.reason == reason, classified


@pytest.mark.parametrize(
    ("reason", "layer", "exit_code"),
    [
        ("auth", "auth", 4),
        ("auth_permanent", "auth", 4),
        ("billing", "billing", 4),
        # errors.LAYERS has no "rate_limit": layer falls back to "provider"
        # while the exit code stays pinned at 5 (the stable script contract).
        ("rate_limit", "provider", 5),
        ("model_not_found", "config", 8),
        ("context_overflow", "provider", 1),
        ("server_error", "provider", 1),
        ("unknown", "provider", 1),
    ],
)
def test_hunter_error_from_classified_layers_and_exit_codes(reason, layer, exit_code):
    from hunter.llm.base import ClassifiedError

    error = hunter_error_from_classified(ClassifiedError(reason=reason, message="detail here"))

    assert error.layer == layer
    assert error.exit_code == exit_code
    assert "detail here" in error.message
    assert error.hint  # every mapped error is user-actionable


def test_classify_preserves_status_code_and_retryability():
    router = ProviderRouter(make_config(), litellm_module=FakeLiteLLM())

    rate = router.classify(FakeProviderError("429", 429))
    assert (rate.status_code, rate.retryable, rate.should_fallback) == (429, True, False)

    auth = router.classify(FakeProviderError("401", 401))
    assert (auth.status_code, auth.retryable, auth.should_fallback) == (401, False, True)

    timeout = router.classify(TimeoutError("read timed out"))
    assert (timeout.reason, timeout.retryable) == ("timeout", True)


def test_classify_redacts_secrets():
    router = ProviderRouter(make_config(), litellm_module=FakeLiteLLM())

    classified = router.classify(Exception("bad key sk-abc123DEF456xyz with Bearer abcdef123456"))

    assert "sk-abc123DEF456xyz" not in classified.message
    assert "abcdef123456" not in classified.message
    assert "sk-***" in classified.message
    assert "Bearer ***" in classified.message


def test_classify_walks_cause_chain_for_status():
    router = ProviderRouter(make_config(), litellm_module=FakeLiteLLM())
    wrapped = None
    try:
        try:
            raise FakeProviderError("throttled upstream", 429)
        except FakeProviderError as inner:
            raise RuntimeError("litellm wrapper") from inner
    except RuntimeError as outer:
        wrapped = outer

    assert router.classify(wrapped).reason == "rate_limit"


# ------------------------------------------------------------ wire mapping ----


@pytest.mark.parametrize(
    ("provider", "model", "base_url", "expected"),
    [
        ("openai", "gpt-4o", "", "openai/gpt-4o"),
        ("openai", "openai/gpt-4o", "", "openai/gpt-4o"),  # never double-prefixed
        ("anthropic", "claude-3", "", "anthropic/claude-3"),
        ("openrouter", "anthropic/claude-3", "", "openrouter/anthropic/claude-3"),
        ("ollama", "llama3", "", "ollama_chat/llama3"),
        ("auto", "gpt-4o", "", "gpt-4o"),  # litellm infers
        ("auto", "openrouter/z/g", "", "openrouter/z/g"),
        ("mygateway", "m", "http://x/v1", "openai/m"),  # unknown + base_url -> openai-compat
        ("auto", "m", "http://x/v1", "openai/m"),  # auto + base_url -> openai-compat
        ("unknown-provider", "m", "", "m"),  # unknown, no base_url -> pass through
    ],
)
def test_wire_model_prefix_table(provider, model, base_url, expected):
    assert _wire_model(provider, model, base_url) == expected
