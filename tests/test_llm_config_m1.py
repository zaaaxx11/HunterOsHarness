"""M1 schema additions — `providers.<n>.endpoint` and `agent.browser`.

Additive loader/renderer changes (design doc §6). Old configs must keep
loading byte-identically; the two new keys go from config.unknown_key to
first-class validated fields.
"""

from __future__ import annotations

import pytest

from hunter.errors import HunterError
from hunter.llm.config import load_config
from hunter.llm.writing import render_config

V03_YAML = """\
model_tiers:
  planner:
    provider: anthropic
    model: claude-sonnet-4-5
    timeout: 90
    reasoning_effort: medium
  exploit:
    provider: openai
    model: gpt-fake

providers:
  anthropic:
    key_env: ANTHROPIC_API_KEY
  openai:
    key_env: OPENAI_API_KEY
    api_key: sk-inline-fallback
  local:
    base_url: http://127.0.0.1:11434

fallback_providers:
  - provider: openrouter
    model: anthropic/claude-3
    key_env: OPENROUTER_API_KEY

budget:
  max_cost_usd: 12.5
  max_iterations: 90

agent:
  tier: verify
  api_max_retries: 5
"""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Hermetic: no machine env vars leak into the loader under test."""
    for var in (
        "HUNTEROS_CONFIG", "HUNTEROS_MODEL", "HUNTEROS_TIER",
        "HUNTEROS_BUDGET_USD", "HUNTEROS_MAX_ITERATIONS",
        "HUNTEROS_KEYS_FILE", "HUNTEROS_ONBOARD_DECLINED",
    ):
        monkeypatch.delenv(var, raising=False)


def _write(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_provider_endpoint_roundtrip_through_render(tmp_path):
    """A27: endpoint loads, renders, and re-loads to the same value."""
    cfg = load_config(
        _write(
            tmp_path,
            "providers:\n  corp:\n    key_env: CORP_KEY\n"
            "    base_url: https://llm.corp.example.com/v1\n    endpoint: chat\n",
        ),
        env={},
        home=tmp_path,
    )
    assert cfg.providers["corp"].endpoint == "chat"

    text = render_config(
        {
            "providers": {
                "corp": {
                    "key_env": "CORP_KEY",
                    "base_url": "https://llm.corp.example.com/v1",
                    "endpoint": "responses",
                }
            }
        }
    )
    assert "endpoint: responses" in text
    cfg2 = load_config(_write(tmp_path, text), env={}, home=tmp_path)
    assert cfg2.providers["corp"].endpoint == "responses"


def test_provider_endpoint_invalid_rejected(tmp_path):
    """A28: endpoint outside {chat, responses} is a config.value error."""
    with pytest.raises(HunterError) as excinfo:
        load_config(
            _write(tmp_path, "providers:\n  corp:\n    endpoint: grpc\n"),
            env={},
            home=tmp_path,
        )
    assert excinfo.value.code == "config.value"
    assert "providers.corp.endpoint" in excinfo.value.message


def test_agent_browser_loader_rules(tmp_path):
    """A29: agent.browser accepts bools and "true"/"false" strings only."""
    truthy = load_config(_write(tmp_path, "agent:\n  browser: true\n"), env={}, home=tmp_path)
    assert truthy.agent.browser is True

    quoted_false = load_config(
        _write(tmp_path, 'agent:\n  browser: "false"\n'), env={}, home=tmp_path
    )
    assert quoted_false.agent.browser is False

    absent = load_config(_write(tmp_path, "agent:\n  tier: basic\n"), env={}, home=tmp_path)
    assert absent.agent.browser is False

    with pytest.raises(HunterError) as excinfo:
        load_config(_write(tmp_path, "agent:\n  browser: 1\n"), env={}, home=tmp_path)
    assert excinfo.value.code == "config.type"
    assert "agent.browser" in excinfo.value.message


def test_render_config_browser_line_and_roundtrip(tmp_path):
    """A30: the renderer always emits the browser line; both values load."""
    default_text = render_config({})
    assert "browser: false" in default_text
    cfg = load_config(_write(tmp_path, default_text), env={}, home=tmp_path)
    assert cfg.agent.browser is False

    browser_text = render_config({"agent": {"tier": "advanced", "browser": True}})
    assert "browser: true" in browser_text
    cfg_on = load_config(_write(tmp_path, browser_text), env={}, home=tmp_path)
    assert cfg_on.agent.tier == "advanced"
    assert cfg_on.agent.browser is True


def test_v03_config_legacy_tiers_load_mapped(tmp_path):
    """A31: a full v0.3-style config (legacy tier names) still loads — the
    loader maps the old keys onto the canonical vocabulary."""
    cfg = load_config(_write(tmp_path, V03_YAML), env={}, home=tmp_path)
    assert cfg.agent.tier == "verifier"
    assert cfg.model_tiers["orchestrator"].model == "claude-sonnet-4-5"
    assert cfg.agent.api_max_retries == 5
    assert cfg.providers["anthropic"].key_env == "ANTHROPIC_API_KEY"
    assert cfg.providers["anthropic"].endpoint == ""
    assert cfg.providers["local"].endpoint == ""
    assert cfg.agent.browser is False
