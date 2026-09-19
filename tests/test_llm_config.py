"""HunterConfig — file search, YAML parsing, validation, env overrides, keys."""

from __future__ import annotations

import pytest

from hunter.errors import EXIT_AUTH, HunterError
from hunter.llm.base import TIERS
from hunter.llm.config import (
    AGENT_TIERS,
    ProviderConfig,
    config_example_yaml,
    find_config_path,
    load_config,
    resolve_key,
    resolve_model,
)

FULL_YAML = """\
model_tiers:
  orchestrator:
    provider: anthropic
    model: claude-sonnet-4-5
    timeout: 90
    reasoning_effort: medium
  hunter:
    provider: openai
    model: gpt-fake
    base_url: https://gateway.example.com/v1

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
  wall_seconds: 3600

agent:
  tier: verifier
  api_max_retries: 5
"""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Hermetic: no machine env vars leak into config tests."""
    for var in (
        "HUNTEROS_CONFIG", "HUNTEROS_MODEL", "HUNTEROS_TIER",
        "HUNTEROS_BUDGET_USD", "HUNTEROS_MAX_ITERATIONS",
    ):
        monkeypatch.delenv(var, raising=False)


def test_defaults_without_file(tmp_path):
    cfg = load_config(env={}, home=tmp_path)
    assert cfg.source_path is None
    assert set(cfg.model_tiers) == set(TIERS)
    for tier_cfg in cfg.model_tiers.values():
        assert tier_cfg.provider == "auto"
        assert tier_cfg.model == ""
        assert tier_cfg.base_url == ""
        assert tier_cfg.key_env == ""
        assert tier_cfg.timeout == 120
        assert tier_cfg.reasoning_effort == ""
    assert cfg.providers == {}
    assert cfg.fallback_providers == []
    assert cfg.budget.max_cost_usd == 5.0
    assert cfg.budget.max_iterations == 60
    assert cfg.budget.wall_seconds == 1800.0
    assert cfg.agent.tier == "basic"
    assert cfg.agent.api_max_retries == 3


def test_full_yaml_parse(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(FULL_YAML, encoding="utf-8")

    cfg = load_config(path, env={}, home=tmp_path)

    assert cfg.source_path == str(path)
    orchestrator = cfg.model_tiers["orchestrator"]
    assert (
        orchestrator.provider, orchestrator.model, orchestrator.timeout, orchestrator.reasoning_effort
    ) == ("anthropic", "claude-sonnet-4-5", 90, "medium")
    hunter = cfg.model_tiers["hunter"]
    assert (hunter.provider, hunter.model, hunter.base_url) == (
        "openai", "gpt-fake", "https://gateway.example.com/v1",
    )
    # Untouched tiers keep defaults.
    assert cfg.model_tiers["utility"].model == ""
    assert cfg.providers["anthropic"].key_env == "ANTHROPIC_API_KEY"
    assert cfg.providers["openai"].api_key == "sk-inline-fallback"
    assert cfg.providers["local"].base_url == "http://127.0.0.1:11434"
    (fb,) = cfg.fallback_providers
    assert (fb.provider, fb.model, fb.key_env) == ("openrouter", "anthropic/claude-3", "OPENROUTER_API_KEY")
    assert (cfg.budget.max_cost_usd, cfg.budget.max_iterations, cfg.budget.wall_seconds) == (12.5, 90, 3600.0)
    assert (cfg.agent.tier, cfg.agent.api_max_retries) == ("verifier", 5)


def test_find_config_path_search_order(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("budget: {max_iterations: 5}", encoding="utf-8")
    from_env = tmp_path / "from-env.yaml"
    from_env.write_text("budget: {max_iterations: 6}", encoding="utf-8")
    home = tmp_path / "home"
    home_file = home / ".hunter" / "config.yaml"  # M11 M1: the unified home
    home_file.parent.mkdir(parents=True)
    home_file.write_text("budget: {max_iterations: 7}", encoding="utf-8")

    # 1. explicit path wins.
    assert find_config_path(explicit, env={}, home=home) == explicit
    # 2. then $HUNTEROS_CONFIG.
    assert find_config_path(None, env={"HUNTEROS_CONFIG": str(from_env)}, home=home) == from_env
    # 3. then ~/.hunter/config.yaml (M11 moved the home).
    assert find_config_path(None, env={}, home=home) == home_file
    # 4. then None (defaults) when the home file is absent.
    assert find_config_path(None, env={}, home=tmp_path / "nope") is None
    # The env path is honored by load_config too.
    from_env_cfg = load_config(env={"HUNTEROS_CONFIG": str(from_env)}, home=tmp_path / "nope")
    assert from_env_cfg.budget.max_iterations == 6


def test_explicit_path_missing_is_an_error(tmp_path):
    with pytest.raises(HunterError) as ei:
        load_config(tmp_path / "nope.yaml", env={}, home=tmp_path)
    assert ei.value.layer == "config"
    assert ei.value.code == "config.not_found"


def test_unknown_top_level_key_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("budget:\n  max_iterations: 5\nbogus_key: 1\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.layer == "config"
    assert ei.value.code == "config.unknown_key"
    assert "bogus_key" in ei.value.message
    for valid in ("model_tiers", "providers", "fallback_providers", "budget", "agent"):
        assert valid in ei.value.hint


def test_unknown_tier_and_nested_keys_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("model_tiers:\n  boss:\n    model: x\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.code == "config.unknown_key"
    assert "boss" in ei.value.message

    path.write_text("budget:\n  max_iterations: 5\n  nope: 1\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert "nope" in ei.value.message
    assert "max_iterations" in ei.value.hint


def test_invalid_yaml_is_a_parse_error(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("budget: [unclosed\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.code == "config.parse"

    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.code == "config.parse"


def test_type_violation_hint_names_key_and_type(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('budget:\n  max_cost_usd: "ten"\n', encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.layer == "config"
    assert "budget.max_cost_usd" in ei.value.message
    assert "number" in ei.value.message

    path.write_text("agent:\n  api_max_retries: 0\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert "agent.api_max_retries" in ei.value.message


def test_env_overrides_win_over_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "budget:\n  max_cost_usd: 12.5\n  max_iterations: 90\nagent:\n  tier: verifier\n",
        encoding="utf-8",
    )
    env = {
        "HUNTEROS_TIER": "hunter",
        "HUNTEROS_BUDGET_USD": "2.5",
        "HUNTEROS_MAX_ITERATIONS": "7",
    }
    cfg = load_config(path, env=env, home=tmp_path)
    assert cfg.agent.tier == "hunter"
    assert cfg.budget.max_cost_usd == 2.5
    assert cfg.budget.max_iterations == 7
    # Untouched by env: wall_seconds stays from YAML/defaults.
    assert cfg.budget.wall_seconds == 1800.0


def test_env_overrides_work_without_file(tmp_path):
    cfg = load_config(env={"HUNTEROS_TIER": "utility", "HUNTEROS_MAX_ITERATIONS": "11"}, home=tmp_path)
    assert cfg.agent.tier == "utility"
    assert cfg.budget.max_iterations == 11


def test_invalid_env_overrides_are_config_errors(tmp_path):
    for env, expected in (
        ({"HUNTEROS_TIER": "boss"}, "HUNTEROS_TIER"),
        ({"HUNTEROS_BUDGET_USD": "lots"}, "HUNTEROS_BUDGET_USD"),
        ({"HUNTEROS_MAX_ITERATIONS": "many"}, "HUNTEROS_MAX_ITERATIONS"),
        # M8 F4 drift: "0" is now ACCEPTED for max_iterations (0 = unlimited);
        # only negatives stay refused.
        ({"HUNTEROS_MAX_ITERATIONS": "-1"}, "HUNTEROS_MAX_ITERATIONS"),
    ):
        with pytest.raises(HunterError) as ei:
            load_config(env=env, home=tmp_path)
        assert ei.value.layer == "config"
        assert expected in ei.value.message


def test_env_zero_iterations_accepted_means_unlimited(tmp_path):
    """M8 F4: HUNTEROS_MAX_ITERATIONS=0 loads and means unlimited."""
    cfg = load_config(env={"HUNTEROS_MAX_ITERATIONS": "0"}, home=tmp_path)
    assert cfg.budget.max_iterations == 0


def test_agent_tier_vocabulary():
    assert "basic" in AGENT_TIERS
    for tier in TIERS:
        assert tier in AGENT_TIERS


def test_model_resolution_chain(tmp_path):
    cfg = load_config(env={}, home=tmp_path)  # nothing configured anywhere

    # tier.model wins over everything.
    cfg.model_tiers["hunter"].model = "hunter-model"
    env = {"HUNTEROS_MODEL": "env-model"}
    assert resolve_model("hunter", cfg, env=env) == "hunter-model"

    # Empty/"auto" tiers take $HUNTEROS_MODEL.
    assert resolve_model("verifier", cfg, env=env) == "env-model"

    # ... then the orchestrator (top default) model for other tiers.
    cfg.model_tiers["orchestrator"].model = "orchestrator-model"
    assert resolve_model("utility", cfg, env={}) == "orchestrator-model"
    assert resolve_model("verifier", cfg, env={}) == "orchestrator-model"
    # ... but env still beats the orchestrator default.
    assert resolve_model("utility", cfg, env=env) == "env-model"

    # Nothing anywhere -> error at use time.
    empty = load_config(env={}, home=tmp_path)
    with pytest.raises(HunterError) as ei:
        resolve_model("orchestrator", empty, env={})
    assert ei.value.code == "config.model_unresolved"
    assert "HUNTEROS_MODEL" in ei.value.hint


def test_resolve_key_env_beats_inline(tmp_path):
    cfg = load_config(env={}, home=tmp_path)
    cfg.providers["openai"] = ProviderConfig(key_env="OPENAI_API_KEY", api_key="sk-inline")
    assert resolve_key("openai", cfg, env={"OPENAI_API_KEY": "sk-from-env"}) == "sk-from-env"
    # Inline api_key is the fallback when the env var is absent.
    assert resolve_key("openai", cfg, env={}) == "sk-inline"


def test_resolve_key_missing_raises_auth_exit_4(tmp_path):
    cfg = load_config(env={}, home=tmp_path)
    cfg.providers["openai"] = ProviderConfig(key_env="OPENAI_API_KEY")
    with pytest.raises(HunterError) as ei:
        resolve_key("openai", cfg, env={})
    assert ei.value.layer == "auth"
    assert ei.value.code == "auth.missing_key"
    assert ei.value.exit_code == EXIT_AUTH
    assert "OPENAI_API_KEY" in ei.value.hint


def test_resolve_key_keyless_block_returns_empty(tmp_path):
    """A provider block with NEITHER key_env NOR api_key is KEYLESS — no auth
    error, LiteLLM dials it without a key (local/corp endpoints)."""
    cfg = load_config(env={}, home=tmp_path)
    cfg.providers["local"] = ProviderConfig(base_url="http://x/v1")
    assert resolve_key("local", cfg, env={}) == ""
    # Providers with NO block at all delegate to litellm's own resolution.
    assert resolve_key("openai", cfg, env={}) == ""


def test_example_yaml_parses(tmp_path):
    path = tmp_path / "example.yaml"
    path.write_text(config_example_yaml(), encoding="utf-8")
    cfg = load_config(path, env={}, home=tmp_path)
    assert set(cfg.model_tiers) == set(TIERS)
    assert cfg.model_tiers["orchestrator"].model == "claude-sonnet-4-5"
    assert cfg.providers["anthropic"].key_env == "ANTHROPIC_API_KEY"
    assert cfg.agent.tier == "basic"
    assert cfg.budget.max_cost_usd == 5.0
