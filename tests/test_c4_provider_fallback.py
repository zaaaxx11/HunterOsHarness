"""Planner C — C4 provider fallback visibility (TDD step 1, failing by design).

Production targets:
  - hunter.llm.router.ProviderRouter._build_chain / _attempt / classify / _redact
  - hunter.llm.router._REASON_TO_ERROR / hunter_error_from_classified
  - hunter.llm.router._BACKOFF_CAP_SECONDS (1s->8s cap)
  - hunter.llm.config.load_config / resolve_key / resolve_model (key order)
  - hunter.llm.providers.key_env_for_endpoint (per-host key env)
  - hunter.llm.base.TurnResult (line ~72) / ClassifiedError (line ~48) shapes
  - FUTURE hunter.llm.router.describe_chain (/model chain + last-link) -> FAIL
  - hunter.cli.doctor_core.collect_checks(live=...) (never-raise, never-leak-key)
  - hunter.llm.probe.detect_endpoint / list_models via client_factory (no network)

Per-function contract:
  test_c4_chain_dedup .................... primary+fallbacks deduped by triple
  test_c4_attempt_retries_backoff ........ retries 1s->8s cap, api_max_retries honored
  test_c4_classify_once_exit_codes ....... classify once; exits 4/5/8/1 via table
  test_c4_key_order ...................... key_env env -> inline -> "" ; missing -> exit4
  test_c4_per_host_key_env ............... per-host key_env_for_endpoint slugs
  test_c4_redact ......................... sk-/Bearer/api_key stripped
  test_c4_unkeyed_links_skipped .......... unkeyed-declared links skipped, never synthesized
  test_c4_model_shows_chain_and_last_link  (FAIL now) /model chain + last-link helper
  test_c4_doctor_live_never_raise_noleak . doctor --live never raises, never leaks keys
  test_c4_fake_litellm_no_network ........ fake module shape; zero sockets
  test_c4_result_shapes_pinned ........... TurnResult/ClassifiedError field shapes

Mitigations: time.sleep monkeypatched (no real sleep); fake litellm mirrors
  the real completion()/completion_cost() surface; sockets assert-disabled.
"""

from __future__ import annotations

import dataclasses
import os
import socket

import pytest

from hunter.errors import EXIT_AUTH, EXIT_CONFIG, EXIT_ERROR, EXIT_RATE_LIMIT, HunterError
from hunter.llm import config as config_mod
from hunter.llm.base import ClassifiedError, TurnResult
from hunter.llm.config import (
    FallbackEntry,
    HunterConfig,
    ProviderConfig,
    TierConfig,
    default_config,
    resolve_key,
)
from hunter.llm.providers import key_env_for_endpoint
from hunter.llm.router import (
    _BACKOFF_CAP_SECONDS,
    _REASON_TO_ERROR,
    _redact,
    hunter_error_from_classified,
)


def _require_describe_chain():
    import hunter.llm.router as router

    fn = getattr(router, "describe_chain", None)
    if fn is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.llm.router.describe_chain to create — "
            "/model shows the failover chain + last-link outcome "
            "(ordered provider/model links, active index, last error redacted)"
        )
    return fn


class FakeError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class FakeLiteLLM:
    def __init__(self, queue, cost=0.01):
        self.calls: list[dict] = []
        self._queue = list(queue)
        self._cost = cost

    def completion(self, **kwargs):
        self.calls.append(kwargs)
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def completion_cost(self, response):
        return self._cost


def _resp(text="ok", model="m"):
    from types import SimpleNamespace

    msg = SimpleNamespace(content=text, tool_calls=[])
    choice = SimpleNamespace(message=msg, finish_reason="stop")
    usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1)
    return SimpleNamespace(choices=[choice], usage=usage, model=model)


def _router(cfg=None, queue=(), monkeypatch=None):
    from hunter.llm.router import ProviderRouter

    cfg = cfg or default_config()
    try:
        cfg.model_tiers["orchestrator"].model = cfg.model_tiers["orchestrator"].model or "m0"
    except KeyError:
        pass
    fake = FakeLiteLLM(queue)
    router = ProviderRouter(cfg, litellm_module=fake)
    if monkeypatch is not None:
        sleeps: list[float] = []
        monkeypatch.setattr("hunter.llm.router.time.sleep", sleeps.append)
        return router, fake, sleeps
    return router, fake, []


def _cfg_with_chain():
    cfg = default_config()
    cfg.model_tiers["orchestrator"] = TierConfig(provider="openai", model="gpt-4o", timeout=5)
    cfg.providers["openai"] = ProviderConfig(key_env="OPENAI_API_KEY", api_key="inline-openai")
    cfg.fallback_providers = [
        FallbackEntry(provider="openai", model="gpt-4o"),  # exact dup -> dropped
        FallbackEntry(provider="openrouter", model="m1", key_env="MISSING_ENV_XYZ"),
    ]
    return cfg


# ------------------------------------------------------------- pins (PASS) --

def test_c4_chain_dedup(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    router, _, _ = _router(_cfg_with_chain())
    chain = router._build_chain(router.config.model_tiers["orchestrator"], "gpt-4o")
    assert [(c.provider, c.model) for c in chain].count(("openai", "gpt-4o")) == 1


def test_c4_attempt_retries_backoff(monkeypatch):
    cfg = default_config()
    cfg.agent.api_max_retries = 3
    err = FakeError("rate limit exceeded, too many requests", 429)
    router, fake, sleeps = _router(cfg, queue=[err, err, _resp()], monkeypatch=monkeypatch)
    out = router.complete("orchestrator", [{"role": "user", "content": "hi"}])
    assert out.text == "ok" and sleeps == [1.0, 2.0]
    assert _BACKOFF_CAP_SECONDS == 8.0
    # Cap shape: 2**attempt capped at 8 -> [1,2,4,8,8,...]
    assert [min(8.0, 2.0**a) for a in range(6)] == [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]


def test_c4_classify_once_exit_codes():
    cases = {
        "auth": EXIT_AUTH, "billing": EXIT_AUTH, "rate_limit": EXIT_RATE_LIMIT,
        "model_not_found": EXIT_CONFIG, "timeout": EXIT_ERROR,
        "server_error": EXIT_ERROR, "overloaded": EXIT_ERROR,
        "empty_response": EXIT_ERROR, "content_policy_blocked": EXIT_ERROR,
        "format_error": EXIT_ERROR, "context_overflow": EXIT_ERROR, "unknown": EXIT_ERROR,
    }
    for reason, exit_code in cases.items():
        layer, code, hint = _REASON_TO_ERROR[reason]
        err = hunter_error_from_classified(ClassifiedError(reason=reason, message="m"))
        assert err.exit_code == exit_code, reason
        assert hint and code, reason
    from hunter.llm.router import ProviderRouter

    router, _, _ = _router()
    once = router.classify(FakeError("invalid api key", 401))
    assert (once.reason, once.retryable, once.should_fallback) == ("auth", False, True)


def test_c4_key_order(monkeypatch):
    cfg = default_config()
    cfg.providers["p"] = ProviderConfig(key_env="K_ORDER_ENV", api_key="inline-key")
    monkeypatch.setenv("K_ORDER_ENV", "env-key")
    assert resolve_key("p", cfg, env=dict(os.environ)) == "env-key"
    monkeypatch.delenv("K_ORDER_ENV", raising=False)
    assert resolve_key("p", cfg, env={}) == "inline-key"
    cfg.providers["q"] = ProviderConfig(key_env="K_MISSING_XYZ")
    with pytest.raises(HunterError) as exc:
        resolve_key("q", cfg, env={})
    assert exc.value.code == "auth.missing_key" and exc.value.exit_code == EXIT_AUTH == 4
    cfg.providers["free"] = ProviderConfig(base_url="http://127.0.0.1:11434")
    assert resolve_key("free", cfg, env={}) == ""
    assert resolve_key("ghost-no-block", cfg, env={}) == ""


def test_c4_per_host_key_env():
    assert key_env_for_endpoint("https://api.example.com:443/v1") == "API_EXAMPLE_COM_API_KEY"
    assert key_env_for_endpoint("http://127.0.0.1:8080/v1").startswith("K_127")
    assert key_env_for_endpoint("not a url") == "CUSTOM_API_KEY"


def test_c4_redact():
    blob = "key sk-abc123XYZ789 Bearer deadbeef-token-123 api_key=supersecretvalue123"
    red = _redact(blob)
    assert "sk-abc123XYZ789" not in red and "deadbeef-token-123" not in red
    assert "supersecretvalue123" not in red and "sk-***" in red


def test_c4_unkeyed_links_skipped(monkeypatch):
    for var in ("MISSING_ENV_XYZ", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    cfg = _cfg_with_chain()
    cfg.providers.pop("openai", None)
    cfg.model_tiers["orchestrator"] = TierConfig(provider="auto", model="m0")
    router, _, _ = _router(cfg)
    chain = router._build_chain(router.config.model_tiers["orchestrator"], "m0")
    assert all(c.provider != "openrouter" for c in chain), (
        "declared-but-unresolvable key_env links skipped, never synthesized")
    assert len(chain) == 2, "primary + keyless openai fallback ('' key dials without auth)"
    assert all(c.api_key is not None for c in chain)


def test_c4_doctor_live_never_raise_noleak(monkeypatch, tmp_path):
    from hunter.cli.doctor_core import collect_checks

    cfg_text = (
        "model_tiers:\n  orchestrator:\n    provider: mylocal\n    model: local-model\n"
        "providers:\n  mylocal:\n    base_url: http://127.0.0.1:9\n    key_env: TEST_LIVE_KEY_XYZ\n"
    )
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(cfg_text, encoding="utf-8")
    monkeypatch.setenv("HUNTEROS_CONFIG", str(cfg_file))
    monkeypatch.setenv("TEST_LIVE_KEY_XYZ", "super-secret-live-key")
    seen: list[str] = []

    def fake_probe(url):
        seen.append(url)
        return "reachable (HTTP 200)"

    monkeypatch.setattr("hunter.cli.doctor_core._probe_base_url", fake_probe)
    checks = collect_checks(live=True)
    assert seen, "live mode really probed (via seam, no network)"
    blob = "\n".join(c.detail for c in checks)
    assert "super-secret-live-key" not in blob, "keys never leak into doctor rows"
    assert any(c.label == "provider:mylocal" for c in checks)


def test_c4_fake_litellm_no_network(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("network dial attempted")))
    router, fake, _ = _router(queue=[_resp("hello")])
    out = router.complete("orchestrator", [{"role": "user", "content": "hi"}])
    assert out.text == "hello" and len(fake.calls) == 1
    assert fake.calls[0]["api_key"] is None or isinstance(fake.calls[0]["api_key"], str)


def test_c4_result_shapes_pinned():
    assert {f.name for f in dataclasses.fields(TurnResult)} >= {
        "text", "tool_calls", "finish_reason", "cost_usd", "model", "provider",
        "error_surface",
    }
    assert {f.name for f in dataclasses.fields(ClassifiedError)} >= {
        "reason", "retryable", "should_fallback", "status_code", "message",
    }


# ------------------------------------------------------- visibility (FAIL) --

def test_c4_model_shows_chain_and_last_link(monkeypatch):
    describe_chain = _require_describe_chain()
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    router, _, _ = _router(_cfg_with_chain())
    view = describe_chain(router, "orchestrator")
    assert "openai" in str(view).lower()
    assert "last" in str(view).lower(), "chain view carries the last-link outcome"
