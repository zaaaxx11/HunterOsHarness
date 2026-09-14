"""Frozen regressions for config-aware LLM provider construction.

These tests exercise the registry and one-shot hunt seams only.  Providers are
constructor fakes and hunt execution is stubbed, so no LiteLLM call or network
request is possible.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from hunter.cli.main import app
from hunter.hunt import HuntOutcome
from hunter.kernel.ledger import Ledger
from hunter.llm.config import HunterConfig, default_config
from hunter.llm.router import ProviderRouter, hunter_error_from_classified
from hunter.tools import registry
from hunter.tools.scope import localhost_scope
from hunter.workflow.pipeline import run_scan

runner = CliRunner()

_CONFIG_YAML = """\
model_tiers:
  orchestrator:
    provider: sandbox
    model: sandbox-model
providers:
  sandbox:
    base_url: http://127.0.0.1:9/v1
agent:
  tier: advanced
"""


@pytest.fixture(autouse=True)
def _clean_llm_environment(monkeypatch):
    """Keep real user config, model, and tier settings out of wiring tests."""
    for var in (
        "HUNTEROS_CONFIG",
        "HUNTEROS_MODEL",
        "HUNTEROS_TIER",
        "HUNTEROS_BUDGET_USD",
        "HUNTEROS_MAX_ITERATIONS",
        "HUNTER_STATE_DIR",
    ):
        monkeypatch.delenv(var, raising=False)


def _sandbox_config(monkeypatch, tmp_path, text: str = _CONFIG_YAML):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("HUNTEROS_CONFIG", str(path))
    return path


def _quiet_cli_updates(monkeypatch) -> None:
    """Prevent the CLI's polite version check from doing work in these tests."""
    from hunter.cli import update_core

    monkeypatch.setattr(update_core, "start_background_check", lambda **_kwargs: None)
    monkeypatch.setattr(update_core, "emit_notice", lambda: None)


def _fake_hunt(*_args: Any, **_kwargs: Any) -> HuntOutcome:
    return HuntOutcome(
        run_id="R-WIRING",
        status="completed",
        findings=0,
        verified=0,
        candidates=0,
        report_path=None,
        exit_code=0,
        stats={},
        finding_rows=[],
    )


def test_registry_default_provider_receives_sandbox_hunter_config(monkeypatch, tmp_path):
    """The registry's canonical default factory must pass HunterConfig onward."""
    _sandbox_config(monkeypatch, tmp_path)
    captured: list[HunterConfig] = []

    class CapturingProvider:
        name = "sandbox"

        def __init__(self, config: HunterConfig) -> None:
            captured.append(config)
            self.config = config

    import hunter.llm.router as router_module

    monkeypatch.setattr(router_module, "ProviderRouter", CapturingProvider)

    provider = registry._default_llm_provider()

    assert provider is not None
    assert len(captured) == 1
    config = captured[0]
    assert isinstance(config, HunterConfig)
    assert config.model_tiers["orchestrator"].provider == "sandbox"
    assert config.model_tiers["orchestrator"].model == "sandbox-model"
    assert config.providers["sandbox"].base_url == "http://127.0.0.1:9/v1"


def test_get_engine_llm_keeps_configured_provider_instead_of_stub(monkeypatch, tmp_path):
    """A configured provider must survive registry construction on the engine."""
    _sandbox_config(monkeypatch, tmp_path)

    class ConfigOnlyProvider:
        name = "configured-sandbox"

        def __init__(self, config: HunterConfig) -> None:
            self.config = config

    import hunter.llm.router as router_module

    monkeypatch.setattr(router_module, "ProviderRouter", ConfigOnlyProvider)

    engine = registry.get_engine("llm")

    assert engine.name == "llm"
    assert isinstance(engine._provider, ConfigOnlyProvider)
    assert engine._provider.config.model_tiers["orchestrator"].model == "sandbox-model"
    assert engine.plan(None).notes["brain"] == "configured-sandbox"


def test_cli_hunt_constructs_llm_provider_with_config_not_from_env(monkeypatch, tmp_path):
    """Implicit hunt selection must use ProviderRouter(config), never from_env()."""
    _sandbox_config(monkeypatch, tmp_path)
    _quiet_cli_updates(monkeypatch)
    monkeypatch.setattr("hunter.hunt.run_hunt", _fake_hunt)
    captured: list[HunterConfig] = []

    class ConfigOnlyProvider:
        name = "configured-sandbox"

        def __init__(self, config: HunterConfig) -> None:
            captured.append(config)
            self.config = config

    import hunter.llm.router as router_module

    # Deliberately no from_env attribute: this is the regression guard.
    monkeypatch.setattr(router_module, "ProviderRouter", ConfigOnlyProvider)

    result = runner.invoke(
        app,
        ["hunt", "http://127.0.0.1:1/", "--json", "--state", str(tmp_path / "state")],
    )

    assert result.exit_code == 0, (result.stdout, result.stderr, result.exception)
    assert json.loads(result.stdout)["status"] == "completed"
    assert len(captured) == 1
    assert captured[0].model_tiers["orchestrator"].provider == "sandbox"


def test_missing_config_keeps_cli_deterministic_fallback(monkeypatch, tmp_path):
    """An explicitly missing config still falls back without running an LLM hunt."""
    _quiet_cli_updates(monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "missing.yaml"))
    seen: list[str] = []

    def fake_hunt(*_args: Any, engine_name: str, **_kwargs: Any) -> HuntOutcome:
        seen.append(engine_name)
        return _fake_hunt()

    monkeypatch.setattr("hunter.hunt.run_hunt", fake_hunt)

    result = runner.invoke(app, ["hunt", "http://127.0.0.1:1/"])

    assert result.exit_code == 0, (result.output, result.exception)
    assert seen == ["deterministic"]
    assert "no brain configured" in result.output


def test_missing_config_keeps_explicit_llm_failure_ledgered(monkeypatch, tmp_path):
    """An explicitly requested LLM with no config remains a clean failed run."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "missing.yaml"))

    engine = registry.get_engine("llm")
    assert engine._provider is None

    state_dir = tmp_path / "state"
    summary = run_scan(
        "http://127.0.0.1:1/",
        engine_name="llm",
        scope=localhost_scope(),
        state_dir=state_dir,
    )

    assert summary.status == "failed"
    ledger = Ledger(state_dir / "ledger.db")
    try:
        events = ledger.events(summary.run_id)
        assert any(event.kind_value() == "error" for event in events)
        assert any(event.kind_value() == "run_ended" for event in events)
        assert ledger.verify_chain(summary.run_id).ok
    finally:
        ledger.close()


def test_provider_error_surface_never_leaks_api_key_sentinel():
    """Classified provider errors and their user rendering must redact keys."""
    sentinel = "sk-regression-sentinel-123456"
    router = ProviderRouter(
        # The injected object is enough for classify(); no LiteLLM operation is called.
        config=default_config(),
        litellm_module=object(),
    )

    classified = router.classify(RuntimeError(f"invalid api key {sentinel}"))
    error = hunter_error_from_classified(classified)

    assert classified.reason == "auth"
    assert sentinel not in classified.message
    assert sentinel not in error.user_message()
    assert sentinel not in str(error)
    assert "sk-***" in error.user_message()
