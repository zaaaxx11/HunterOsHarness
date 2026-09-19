"""Custom / third-party provider commands + config write-back.

NO network: litellm is always the fake seam (monkeypatched into
``hunter.llm.ping.load_litellm``), and the router tests inject the fake
module directly. Config writes land in tmp paths via $HUNTEROS_CONFIG.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from hunter.cli.main import app
from hunter.errors import HunterError
from hunter.llm.base import TurnResult
from hunter.llm.config import (
    AgentConfig,
    BudgetConfig,
    FallbackEntry,
    HunterConfig,
    ProviderConfig,
    TierConfig,
)
from hunter.llm.writing import render_config, write_config

runner = CliRunner()


class FakeProviderError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class FakeLiteLLM:
    """Duck-typed litellm module: a queue of responses/exceptions, calls kept.
    With an empty queue it returns a well-formed 1-choice response (the
    router normalizes it into a TurnResult)."""

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


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch, tmp_path):
    # CI on Linux puts pytest's tmp_path under /tmp — OUTSIDE the real home, so
    # the $HUNTEROS_CONFIG containment guard (writing.resolve_config_target)
    # would refuse every CLI write. Make the sandbox itself the home directory
    # (HOME on POSIX, USERPROFILE on Windows) so the env target is in-home on
    # every OS. The guard itself stays live and is tested separately.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    for var in ("OPENROUTER_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "HUNTEROS_VERBOSE"):
        monkeypatch.delenv(var, raising=False)


def _add(*args: str) -> Any:
    return runner.invoke(app, ["config", "provider", "add", *args])


# --------------------------------------------------------------- add / list --


def test_add_list_round_trip():
    result = _add("demo", "--base-url", "http://127.0.0.1:1/v1")
    assert result.exit_code == 0, (result.output, result.exception)

    listing = runner.invoke(app, ["config", "provider", "list"])
    assert listing.exit_code == 0
    assert "demo" in listing.output and "keyless" in listing.output
    assert "http://127.0.0.1:1/v1" in listing.output

    import os

    from hunter.llm.config import load_config

    cfg = load_config(os.environ["HUNTEROS_CONFIG"], env={})
    assert cfg.providers["demo"].base_url == "http://127.0.0.1:1/v1"


def test_add_unknown_name_without_base_url_exits_2():
    result = _add("mysterycorp")
    assert result.exit_code == 2, (result.output, result.exception)
    assert "--base-url" in result.output


def test_add_known_name_uses_table_key_env(monkeypatch):
    result = _add("groq")
    assert result.exit_code == 0, (result.output, result.exception)
    import os
    from pathlib import Path

    raw = yaml.safe_load(Path(os.environ["HUNTEROS_CONFIG"]).read_text(encoding="utf-8"))
    assert raw["providers"]["groq"]["key_env"] == "GROQ_API_KEY"


def test_add_duplicate_refuses_then_force_replaces():
    assert _add("demo", "--base-url", "http://one/v1").exit_code == 0
    duplicate = _add("demo", "--base-url", "http://two/v1")
    assert duplicate.exit_code == 2
    assert "--force" in duplicate.output
    forced = _add("demo", "--base-url", "http://two/v1", "--force")
    assert forced.exit_code == 0
    import os
    from pathlib import Path

    raw = yaml.safe_load(Path(os.environ["HUNTEROS_CONFIG"]).read_text(encoding="utf-8"))
    assert raw["providers"]["demo"]["base_url"] == "http://two/v1"


def test_add_default_model_pins_orchestrator():
    result = _add("demo", "--base-url", "http://x/v1", "--default-model", "my-model")
    assert result.exit_code == 0
    import os

    from hunter.llm.config import load_config

    cfg = load_config(os.environ["HUNTEROS_CONFIG"], env={})
    assert cfg.model_tiers["orchestrator"].model == "my-model"


# ------------------------------------------------------------------- remove --


def _write_raw(monkeypatch, tmp_path, raw: dict) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    monkeypatch.setenv("HUNTEROS_CONFIG", str(path))


def test_remove_referenced_provider_refuses_and_force_works(monkeypatch, tmp_path):
    _write_raw(
        monkeypatch,
        tmp_path,
        {
            "model_tiers": {"orchestrator": {"provider": "corp", "model": "m1"}},
            "providers": {"corp": {"base_url": "http://corp/v1"}},
            "fallback_providers": [{"provider": "corp", "model": "m2"}],
        },
    )
    refused = runner.invoke(app, ["config", "provider", "remove", "corp"])
    assert refused.exit_code == 2, (refused.output, refused.exception)
    assert "model_tiers.orchestrator.provider" in refused.output
    assert "fallback_providers[0].provider" in refused.output

    forced = runner.invoke(app, ["config", "provider", "remove", "corp", "--force"])
    assert forced.exit_code == 0
    import os
    from pathlib import Path

    raw = yaml.safe_load(Path(os.environ["HUNTEROS_CONFIG"]).read_text(encoding="utf-8"))
    assert "corp" not in (raw.get("providers") or {})
    assert raw["model_tiers"]["orchestrator"]["provider"] == "corp"  # left dangling by --force


def test_remove_unknown_provider_exits_1(monkeypatch, tmp_path):
    _write_raw(monkeypatch, tmp_path, {"providers": {"other": {"base_url": "http://x/v1"}}})
    result = runner.invoke(app, ["config", "provider", "remove", "ghost"])
    assert result.exit_code == 1


# --------------------------------------------------------------------- test --


def test_provider_test_ok_with_fake_litellm(monkeypatch):
    fake = FakeLiteLLM()
    monkeypatch.setattr("hunter.llm.ping.load_litellm", lambda: fake)
    assert _add("demo", "--base-url", "http://127.0.0.1:1/v1", "--default-model", "m1").exit_code == 0

    result = runner.invoke(app, ["config", "provider", "test", "demo"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "OK (" in result.output and "ms)" in result.output
    (call,) = fake.calls
    # unknown provider + base_url → OpenAI-compatible wire prefix; keyless → None
    assert call["model"] == "openai/m1"
    assert call["api_key"] is None
    assert call["max_tokens"] == 1
    assert call["base_url"] == "http://127.0.0.1:1/v1"


def test_provider_test_auth_fail_exits_4(monkeypatch):
    fake = FakeLiteLLM((FakeProviderError("invalid api key", status_code=401),))
    monkeypatch.setattr("hunter.llm.ping.load_litellm", lambda: fake)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake-000")
    assert _add("openrouter").exit_code == 0

    result = runner.invoke(app, ["config", "provider", "test", "openrouter"])
    assert result.exit_code == 4, (result.output, result.exception)
    assert "[ERROR auth]" in result.output


def test_provider_test_missing_key_exits_4_without_dialing(monkeypatch):
    dialled = FakeLiteLLM()
    monkeypatch.setattr("hunter.llm.ping.load_litellm", lambda: dialled)
    assert _add("openrouter").exit_code == 0

    result = runner.invoke(app, ["config", "provider", "test", "openrouter"])
    assert result.exit_code == 4, (result.output, result.exception)
    assert "key missing" in result.output and "OPENROUTER_API_KEY" in result.output
    assert dialled.calls == []  # never dialled without a key


# --------------------------------------------------- keyless routing (router) --


def _config(**overrides: Any) -> HunterConfig:
    return HunterConfig(
        model_tiers=overrides.get(
            "model_tiers", {"orchestrator": TierConfig(provider="corp", model="m1", base_url="http://x/v1")}
        ),
        providers=overrides.get("providers", {"corp": ProviderConfig(base_url="http://x/v1")}),
        fallback_providers=overrides.get("fallback_providers", []),
        budget=BudgetConfig(),
        agent=AgentConfig(),
    )


def test_keyless_block_routes_api_key_none():
    fake = FakeLiteLLM()
    from hunter.llm.router import ProviderRouter

    router = ProviderRouter(_config(), litellm_module=fake)
    turn = router.complete("orchestrator", [{"role": "user", "content": "hi"}])
    assert isinstance(turn, TurnResult)
    (call,) = fake.calls
    assert call["api_key"] is None  # a keyless block dials with NO key, no auth error
    assert call["base_url"] == "http://x/v1"


def test_fallback_with_keyless_custom_link_is_dialed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-primary")
    cfg = _config(
        model_tiers={"orchestrator": TierConfig(provider="openai", model="m1")},
        providers={
            "openai": ProviderConfig(key_env="OPENAI_API_KEY"),
            "corp": ProviderConfig(base_url="http://corp/v1"),  # keyless block
        },
        fallback_providers=[FallbackEntry(provider="corp", model="m2", base_url="http://corp/v1")],
    )
    fake = FakeLiteLLM((FakeProviderError("invalid api key", status_code=401),))
    from hunter.llm.router import ProviderRouter

    router = ProviderRouter(cfg, litellm_module=fake)
    router.complete("orchestrator", [{"role": "user", "content": "hi"}])
    assert len(fake.calls) == 2
    assert fake.calls[0]["api_key"] == "sk-primary"
    assert fake.calls[1]["model"] == "openai/m2"  # unknown name + base_url → openai/ prefix
    assert fake.calls[1]["api_key"] is None  # keyless fallback link dialed without a key


# ------------------------------------------------------------- write_config --


def test_write_config_preserves_template_comments_and_is_atomic(tmp_path):
    path = tmp_path / "deep" / "config.yaml"
    written = write_config({"providers": {"a": {"base_url": "http://a/v1"}}}, path)
    assert written == path
    text = path.read_text(encoding="utf-8")
    assert "# HunterOs LLM configuration" in text  # canonical template comments
    assert "credentials per provider name" in text
    assert not list(tmp_path.glob("*.tmp"))  # atomic: no temp leftovers

    # Second write merges (existing provider kept) and still parses.
    write_config({"budget": {"max_iterations": 9}}, path)
    import yaml as _yaml

    raw = _yaml.safe_load(path.read_text(encoding="utf-8"))
    assert raw["providers"]["a"]["base_url"] == "http://a/v1"
    assert raw["budget"]["max_iterations"] == 9


def test_write_config_none_value_deletes_and_never_invents_api_keys(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(
        {"providers": {"a": {"api_key": "sk-kept"}, "b": {"base_url": "http://b/v1"}}}, path
    )
    write_config({"providers": {"b": None}}, path)  # None deletes
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "b" not in raw["providers"]
    assert raw["providers"]["a"]["api_key"] == "sk-kept"  # round-trip preserves inline keys


def test_render_config_output_loads(tmp_path):
    from hunter.llm.config import load_config

    text = render_config({})
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    cfg = load_config(path, env={}, home=tmp_path)
    assert cfg.agent.tier == "basic" and cfg.providers == {}


def test_write_config_refuses_env_path_outside_home(monkeypatch, tmp_path):
    outside = tmp_path / "elsewhere" / "config.yaml"
    monkeypatch.setenv("HUNTEROS_CONFIG", str(outside))
    with pytest.raises(HunterError) as ei:
        write_config({"budget": {"max_iterations": 3}}, None, home=tmp_path / "home")
    assert "outside the home directory" in ei.value.message
    forced = write_config({"budget": {"max_iterations": 3}}, None, force=True, home=tmp_path / "home")
    assert forced == outside
