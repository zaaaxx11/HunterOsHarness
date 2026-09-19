"""Router `endpoint: responses` support — wire-model insertion, per-candidate
endpoint, terminal config errors, streaming passthrough, ping/CLI (M2 §4/§5).

P-tests are RED until the builder ships ``_wire_model(..., *, endpoint="")``,
``_Candidate.endpoint`` and ``ping_provider(endpoint=...)``. LiteLLM is ALWAYS
the FakeLiteLLM seam (test_llm_router convention) — zero network.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import hunter.cli.main as cli_main
from hunter.errors import HunterError
from hunter.llm.config import (
    AgentConfig,
    BudgetConfig,
    FallbackEntry,
    HunterConfig,
    ProviderConfig,
    TierConfig,
)
from hunter.llm.ping import ping_provider
from hunter.llm.router import ProviderRouter, _wire_model
from hunter.llm.writing import write_config

runner = CliRunner()
USER_MSG = {"role": "user", "content": "find the bug"}


class FakeProviderError(Exception):
    """Synthetic provider failure with an optional HTTP status code."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class FakeLiteLLM:
    """Duck-typed litellm module: a queue of responses/exceptions, calls kept.
    With an empty queue it returns a well-formed 1-choice response."""

    def __init__(self, queue: tuple[Any, ...] = ()) -> None:
        self.calls: list[dict[str, Any]] = []
        self._queue = list(queue)

    def completion(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if not self._queue:
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content="ok", tool_calls=[]),
                        finish_reason="stop",
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                model=kwargs.get("model", "fake/model"),
            )
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def completion_cost(self, response: Any) -> float:
        return 0.012


def make_response(text: str = "ok", model: str = "fake/response-model") -> Any:
    message = SimpleNamespace(content=text, tool_calls=[])
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7),
        model=model,
    )


def make_chunk(content: str, finish_reason: str | None = None, model: str = "fake/stream-model") -> Any:
    delta = SimpleNamespace(content=content, tool_calls=[])
    return SimpleNamespace(
        model=model,
        usage=None,
        choices=[SimpleNamespace(delta=delta, finish_reason=finish_reason)],
    )


def _config(
    model_tiers: dict[str, TierConfig] | None = None,
    providers: dict[str, ProviderConfig] | None = None,
    fallback_providers: list[FallbackEntry] | None = None,
    api_max_retries: int = 3,
) -> HunterConfig:
    return HunterConfig(
        model_tiers=model_tiers
        if model_tiers is not None
        else {"orchestrator": TierConfig(provider="openai", model="m1")},
        providers=providers or {},
        fallback_providers=fallback_providers or [],
        budget=BudgetConfig(),
        agent=AgentConfig(api_max_retries=api_max_retries),
    )


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Hermetic: no machine env vars leak into routing/key resolution."""
    for var in (
        "HUNTEROS_CONFIG", "HUNTEROS_MODEL", "HUNTEROS_TIER",
        "HUNTEROS_BUDGET_USD", "HUNTEROS_MAX_ITERATIONS",
    ):
        monkeypatch.delenv(var, raising=False)


# ------------------------------------------------------------------- P1/P2 --


# The M1 prefix table (test_llm_router.test_wire_model_prefix_table) — endpoint=""
# must reproduce it EXACTLY.
_PREFIX_TABLE = [
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
]

_RESPONSES_TABLE = [
    ("openai", "gpt-4o", "", "openai/responses/gpt-4o"),
    # The responses/ segment inserts once AFTER the head — an already-prefixed
    # model keeps its prefix path (never double-prefixed).
    ("openai", "openai/gpt-4o", "", "openai/responses/openai/gpt-4o"),
    ("openrouter", "anthropic/claude-3", "", "openrouter/responses/anthropic/claude-3"),
    ("azure", "gpt-4o-deployment", "", "azure/responses/gpt-4o-deployment"),
    ("mygateway", "m", "http://x/v1", "openai/responses/m"),  # unknown + base_url
    ("auto", "m", "http://x/v1", "openai/responses/m"),  # auto + base_url
]

_BARE_MODELS = [("auto", "m", ""), ("unknown-provider", "m", "")]


def test_wire_model_responses_insertion_table():
    """P1: endpoint="responses" inserts the segment after the provider prefix;
    a prefixless result is a terminal config.value error; endpoint="" is the M1 table."""
    for provider, model, base_url, expected in _RESPONSES_TABLE:
        assert _wire_model(provider, model, base_url, endpoint="responses") == expected, (
            provider, model, base_url,
        )

    for provider, model, base_url in _BARE_MODELS:
        with pytest.raises(HunterError) as ei:  # no prefix possible -> raise BEFORE any dial
            _wire_model(provider, model, base_url, endpoint="responses")
        assert ei.value.code == "config.value", (provider, model)

    for provider, model, base_url, expected in _PREFIX_TABLE:
        assert _wire_model(provider, model, base_url, endpoint="") == expected, (
            provider, model, base_url,
        )


def test_router_honors_provider_endpoint_responses():
    """P2: ProviderConfig(endpoint="responses") dials the responses wire model;
    a chat provider keeps the plain wire model (regression guard)."""
    cfg = _config(providers={"openai": ProviderConfig(endpoint="responses")})
    fake = FakeLiteLLM([make_response(text="hello")])
    result = ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.text == "hello"
    call = fake.calls[0]
    assert call["model"] == "openai/responses/m1"
    assert call["messages"] == [USER_MSG]  # otherwise identical kwargs
    assert call["timeout"] == 120
    assert call["stream"] is False
    assert "base_url" not in call

    chat_fake = FakeLiteLLM([make_response()])
    chat_cfg = _config(providers={"openai": ProviderConfig()})
    ProviderRouter(chat_cfg, litellm_module=chat_fake).complete("orchestrator", [USER_MSG])
    assert chat_fake.calls[0]["model"] == "openai/m1"


# ------------------------------------------------------------------- P3/P4 --


def test_fallback_candidate_inherits_provider_endpoint(monkeypatch):
    """P3: a fallback's endpoint comes from ITS provider block, with its own key."""
    monkeypatch.setenv("PRIMARY_KEY", "sk-primary-123")
    monkeypatch.setenv("FB_KEY", "sk-fallback-9876")
    cfg = _config(
        providers={
            "openai": ProviderConfig(key_env="PRIMARY_KEY"),
            "corp": ProviderConfig(base_url="http://corp/v1", endpoint="responses"),
        },
        fallback_providers=[FallbackEntry(provider="corp", model="m2", key_env="FB_KEY")],
    )
    fake = FakeLiteLLM(
        [
            FakeProviderError("401 invalid api key", 401),
            make_response(text="fallback ok"),
        ]
    )

    result = ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert result.text == "fallback ok"
    assert fake.calls[0]["model"] == "openai/m1"  # primary stays chat
    assert fake.calls[0]["api_key"] == "sk-primary-123"
    assert fake.calls[1]["model"] == "openai/responses/m2"  # corp: unknown + base_url + responses
    assert fake.calls[1]["api_key"] == "sk-fallback-9876"  # the fallback's resolved key


def test_prefixless_responses_is_terminal_config_error():
    """P4: responses on a provider with no prefix possible -> config.value, zero dials."""
    cfg = _config(
        model_tiers={"orchestrator": TierConfig(provider="auto", model="m1")},
        providers={"auto": ProviderConfig(endpoint="responses")},
        api_max_retries=1,
    )
    fake = FakeLiteLLM(())

    with pytest.raises(HunterError) as ei:
        ProviderRouter(cfg, litellm_module=fake).complete("orchestrator", [USER_MSG])

    assert ei.value.code == "config.value"
    assert len(fake.calls) == 0  # raised BEFORE litellm — no retries, no failover


# ------------------------------------------------------------------- P5-P7 --


def test_streaming_responses_passes_prefixed_model():
    """P5: streaming flows through the SAME stream=True path with the prefixed model."""
    cfg = _config(providers={"openai": ProviderConfig(endpoint="responses")})
    fake = FakeLiteLLM(
        [[make_chunk("Hel"), make_chunk("lo"), make_chunk("", finish_reason="stop")]]
    )
    seen: list[str] = []

    result = ProviderRouter(cfg, litellm_module=fake).complete(
        "orchestrator", [USER_MSG], stream_cb=seen.append
    )

    assert fake.calls[0]["model"] == "openai/responses/m1"
    assert fake.calls[0]["stream"] is True
    assert seen == ["Hel", "lo"]  # normalized into a TurnResult by _normalize_stream
    assert result.text == "Hello"
    assert result.finish_reason == "stop"


def test_ping_provider_endpoint_kwarg():
    """P6: ping_provider forwards endpoint to _wire_model; the default call is unchanged."""
    fake = FakeLiteLLM()
    result = ping_provider("openai", "m1", litellm_module=fake, endpoint="responses")
    assert result.ok is True
    assert fake.calls[0]["model"] == "openai/responses/m1"

    plain = FakeLiteLLM()
    result = ping_provider("openai", "m1", litellm_module=plain)
    assert result.ok is True
    assert plain.calls[0]["model"] == "openai/m1"  # default call unchanged


def test_provider_test_passes_stored_endpoint(monkeypatch, tmp_path):
    """P7: `provider test` honors providers.<n>.endpoint from the config file."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    target = tmp_path / "config.yaml"
    monkeypatch.setenv("HUNTEROS_CONFIG", str(target))
    write_config(
        {
            "providers": {"corp": {"base_url": "http://corp/v1", "endpoint": "responses"}},
            "model_tiers": {"orchestrator": {"provider": "corp", "model": "m1"}},
        },
        target,
        home=tmp_path,
    )
    fake = FakeLiteLLM()
    monkeypatch.setattr("hunter.llm.ping.load_litellm", lambda: fake)

    result = runner.invoke(cli_main.app, ["config", "provider", "test", "corp"])

    assert result.exit_code == 0, (result.output, result.exception)
    (call,) = fake.calls
    assert call["model"] == "openai/responses/m1"  # unknown name + base_url + stored endpoint
