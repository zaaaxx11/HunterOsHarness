"""M2 tier rename + migration — canonical vocabulary, loader/writer migration,
/model + config show + doctor surfaces, static scans (design doc §2/§3/§6).

RED until the builder ships the new vocabulary: ``LEGACY_TIERS``,
``LEGACY_TIER_ALIASES`` and ``normalize_tier`` are imported INSIDE the test
bodies (M1 precedent — a missing symbol must fail one test, not collection).
Static tests (R16, D1/D2) read repo files with pathlib — no execution, no
network. Every loader/writer test is hermetic: explicit ``env={}``,
``home=tmp_path``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import hunter.cli.main as cli_main
from hunter.chat.commands import CommandContext, safe_execute
from hunter.chat.sessions import ChatStore
from hunter.errors import HunterError
from hunter.kernel.ledger import Ledger
from hunter.llm.base import TIERS
from hunter.llm.config import AGENT_TIERS, config_example_yaml, default_config, load_config
from hunter.llm.writing import render_config, write_config

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[1]

LEGACY_YAML = """\
model_tiers:
  planner:
    provider: anthropic
    model: claude-sonnet-4-5
  exploit:
    provider: openai
    model: gpt-fake
  verify:
    provider: openai
    model: gpt-mini
"""

CANONICAL_YAML = """\
model_tiers:
  orchestrator:
    provider: anthropic
    model: claude-sonnet-4-5
  hunter:
    provider: openai
    model: gpt-fake
"""

_LEGACY_NOTE_SUFFIX = "(old names are accepted; update your config)"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Hermetic: no machine env vars leak into the loader/surfaces under test."""
    for var in (
        "HUNTEROS_CONFIG", "HUNTEROS_MODEL", "HUNTEROS_TIER",
        "HUNTEROS_BUDGET_USD", "HUNTEROS_MAX_ITERATIONS",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def store(tmp_path):
    s = ChatStore(tmp_path / "chat.db")
    yield s
    s.close()


@pytest.fixture
def ctx(store, tmp_path):
    """A chat command context bound to a fresh session (test_chat_commands convention)."""
    sid = store.create_session()
    return CommandContext(
        store=store,
        config=default_config(),
        ledger_factory=lambda: Ledger(tmp_path / "ledger.db"),
        args="",
        options={"session_id": sid, "state_dir": str(tmp_path)},
    )


# ------------------------------------------------------------------- R1-R6 --


def test_tier_vocabulary_and_normalize():
    """R1: canonical vocabulary + alias table + normalize_tier contract."""
    from hunter.llm.base import LEGACY_TIER_ALIASES, LEGACY_TIERS, normalize_tier

    assert TIERS == ("orchestrator", "hunter", "verifier", "utility")
    assert LEGACY_TIERS == ("planner", "exploit", "verify")
    assert LEGACY_TIER_ALIASES == {
        "planner": "orchestrator",
        "exploit": "hunter",
        "verify": "verifier",
    }
    assert normalize_tier("planner") == "orchestrator"
    assert normalize_tier("exploit") == "hunter"
    assert normalize_tier("verify") == "verifier"
    for tier in TIERS:
        assert normalize_tier(tier) == tier
    assert normalize_tier("boss") == "boss"  # unknown names pass through unchanged
    for tier in ("basic", "advanced", *TIERS):
        assert tier in AGENT_TIERS

    # hunter.llm re-exports the rename surface additively (§2.1).
    import hunter.llm as llm_pkg

    assert llm_pkg.LEGACY_TIERS == LEGACY_TIERS
    assert llm_pkg.LEGACY_TIER_ALIASES == LEGACY_TIER_ALIASES
    assert llm_pkg.normalize_tier is normalize_tier


def test_legacy_model_tiers_load_mapped_with_notes(tmp_path):
    """R2: a legacy model_tiers file loads mapped, with one note per rename."""
    path = tmp_path / "legacy.yaml"
    path.write_text(LEGACY_YAML, encoding="utf-8")

    cfg = load_config(path, env={}, home=tmp_path)

    assert set(cfg.model_tiers) == set(TIERS)
    assert (cfg.model_tiers["orchestrator"].provider, cfg.model_tiers["orchestrator"].model) == (
        "anthropic", "claude-sonnet-4-5",
    )
    assert cfg.model_tiers["hunter"].model == "gpt-fake"
    assert cfg.model_tiers["verifier"].model == "gpt-mini"
    assert tuple(cfg.legacy_notes) == (
        f"model_tiers.planner renamed to model_tiers.orchestrator {_LEGACY_NOTE_SUFFIX}",
        f"model_tiers.exploit renamed to model_tiers.hunter {_LEGACY_NOTE_SUFFIX}",
        f"model_tiers.verify renamed to model_tiers.verifier {_LEGACY_NOTE_SUFFIX}",
    )


def test_new_name_config_loads_without_notes(tmp_path):
    """R3: a canonical config loads with legacy_notes == ()."""
    path = tmp_path / "canonical.yaml"
    path.write_text(CANONICAL_YAML, encoding="utf-8")

    cfg = load_config(path, env={}, home=tmp_path)

    assert cfg.legacy_notes == ()
    assert cfg.model_tiers["orchestrator"].model == "claude-sonnet-4-5"


def test_both_legacy_and_canonical_tier_rejected(tmp_path):
    """R4: legacy + canonical twin in one model_tiers fails closed."""
    path = tmp_path / "conflict.yaml"
    path.write_text(
        "model_tiers:\n"
        "  planner:\n    provider: anthropic\n    model: old-value\n"
        "  orchestrator:\n    provider: anthropic\n    model: new-value\n",
        encoding="utf-8",
    )
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.code == "config.value"
    assert "planner" in ei.value.message
    assert "orchestrator" in ei.value.message
    assert "both" in ei.value.message  # no silent merge precedence


def test_agent_tier_and_env_legacy_aliases_map(tmp_path):
    """R5: agent.tier and $HUNTEROS_TIER legacy values normalize + note."""
    path = tmp_path / "agent-tier.yaml"
    path.write_text("agent:\n  tier: exploit\n", encoding="utf-8")
    cfg = load_config(path, env={}, home=tmp_path)
    assert cfg.agent.tier == "hunter"
    assert tuple(cfg.legacy_notes) == (
        f"agent.tier 'exploit' renamed to 'hunter' {_LEGACY_NOTE_SUFFIX}",
    )

    env_cfg = load_config(env={"HUNTEROS_TIER": "planner"}, home=tmp_path)
    assert env_cfg.agent.tier == "orchestrator"
    assert tuple(env_cfg.legacy_notes) == (
        f"$HUNTEROS_TIER 'planner' renamed to 'orchestrator' {_LEGACY_NOTE_SUFFIX}",
    )


def test_garbage_tier_inputs_still_rejected(tmp_path):
    """R6: garbage fails closed with the canonical vocabulary in the message."""
    from hunter.llm.base import LEGACY_TIERS

    with pytest.raises(HunterError) as ei:
        load_config(env={"HUNTEROS_TIER": "boss"}, home=tmp_path)
    assert ei.value.code == "config.value"
    assert "HUNTEROS_TIER" in ei.value.message

    path = tmp_path / "boss.yaml"
    path.write_text("model_tiers:\n  boss:\n    model: x\n", encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        load_config(path, env={}, home=tmp_path)
    assert ei.value.code == "config.unknown_key"
    assert "boss" in ei.value.message
    # The hint lists the NEW names and the legacy-accepted sentence (built from
    # TIERS + LEGACY_TIERS, never literals).
    assert ei.value.hint == (
        f"valid tier names: {', '.join(TIERS)} "
        f"(legacy names {', '.join(LEGACY_TIERS)} are accepted)"
    )


# ------------------------------------------------------------------ R7-R10 --


def test_write_config_renders_only_new_names(tmp_path):
    """R7: the writer migrates legacy model_tiers keys — old names never render."""
    path = tmp_path / "config.yaml"
    write_config({"model_tiers": {"planner": {"provider": "anthropic", "model": "keep-me"}}}, path)

    text = path.read_text(encoding="utf-8")
    assert "orchestrator:" in text
    assert "planner:" not in text
    cfg = load_config(path, env={}, home=tmp_path)
    assert (cfg.model_tiers["orchestrator"].provider, cfg.model_tiers["orchestrator"].model) == (
        "anthropic", "keep-me",
    )


def test_write_config_both_names_conflict_untouched_disk(tmp_path):
    """R8: writer legacy+canonical twin fails closed with bytes untouched."""
    path = tmp_path / "config.yaml"
    write_config({"model_tiers": {"orchestrator": {"provider": "anthropic", "model": "keep"}}}, path)
    before = path.read_bytes()

    with pytest.raises(HunterError) as ei:
        write_config({"model_tiers": {"planner": {"provider": "anthropic", "model": "twin"}}}, path)

    assert ei.value.code == "config.write_failed"
    assert "planner" in ei.value.message and "orchestrator" in ei.value.message
    assert path.read_bytes() == before


def test_write_config_migrates_agent_tier_value(tmp_path):
    """R9: writer maps a legacy agent.tier VALUE to the canonical name."""
    path = tmp_path / "config.yaml"
    write_config({"agent": {"tier": "verify"}}, path)

    text = path.read_text(encoding="utf-8")
    assert re.search(r"tier: verifier\b", text)
    assert not re.search(r"tier: verify\b", text)
    cfg = load_config(path, env={}, home=tmp_path)
    assert cfg.agent.tier == "verifier"


def test_render_and_example_yaml_new_vocabulary(tmp_path):
    """R10: renderer + example yaml speak only the canonical vocabulary."""
    text = render_config({})
    for tier in TIERS:
        assert f"\n  {tier}:" in text
    assert "payload/craft tier — inherits orchestrator unless set" in text
    assert "inherits planner" not in text
    assert "basic | advanced | orchestrator | hunter | verifier | utility" in text
    path = tmp_path / "rendered.yaml"
    path.write_text(text, encoding="utf-8")
    assert set(load_config(path, env={}, home=tmp_path).model_tiers) == set(TIERS)

    example = config_example_yaml()
    assert "planner" not in example and "exploit" not in example
    example_path = tmp_path / "example.yaml"
    example_path.write_text(example, encoding="utf-8")
    example_cfg = load_config(example_path, env={}, home=tmp_path)
    assert example_cfg.model_tiers["orchestrator"].model == "claude-sonnet-4-5"


# ------------------------------------------------------------------ R11-R14 --


def test_model_command_legacy_alias_persists_orchestrator(ctx, tmp_path):
    """R11: /model with a legacy name mutates + persists the CANONICAL key."""
    ctx.args = "planner m-x"
    reply = safe_execute("model", ctx)
    assert reply.data["global"] is False
    assert ctx.config.model_tiers["orchestrator"].model == "m-x"
    assert "orchestrator" in reply.text  # the reply names the canonical tier
    ctx.args = ""
    assert "m-x" in safe_execute("model", ctx).text

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("model_tiers:\n  orchestrator:\n    model: old\n", encoding="utf-8")
    ctx.config.source_path = str(cfg_file)
    ctx.args = "planner m-x --global"
    reply = safe_execute("model", ctx)
    assert reply.data["global"] is True
    data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    assert data["model_tiers"]["orchestrator"]["model"] == "m-x"
    assert "planner:" not in cfg_file.read_text(encoding="utf-8")  # never regains an old key


def test_model_command_unknown_tier_still_blocked(ctx):
    """R12: /model turbo m-x still fails — with the new vocabulary hint."""
    ctx.args = "turbo m-x"
    reply = safe_execute("model", ctx)
    assert "[ERROR config]" in reply.text
    assert "orchestrator" in reply.text and "verifier" in reply.text


def test_config_show_new_rows_and_legacy_note(monkeypatch, tmp_path):
    """R13: config show renders the canonical rows; legacy configs get a note row."""
    legacy = tmp_path / "legacy.yaml"
    legacy.write_text(
        "model_tiers:\n"
        "  planner:\n    provider: anthropic\n    model: claude-sonnet-4-5\n"
        "  exploit:\n    provider: openai\n    model: gpt-fake\n"
        "  verify:\n    provider: openai\n    model: gpt-mini\n"
        "providers:\n  anthropic:\n    key_env: ANTHROPIC_API_KEY\n"
        "agent:\n  tier: exploit\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(legacy))

    result = runner.invoke(cli_main.app, ["config", "show"])
    assert result.exit_code == 0, (result.output, result.exception)
    for row in (
        "model_tiers.orchestrator", "model_tiers.hunter",
        "model_tiers.verifier", "model_tiers.utility",
    ):
        assert row in result.output
    assert "legacy names" in result.output
    assert "renamed to" in result.output

    # A canonical (default) config has every canonical row and no legacy row.
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "missing.yaml"))
    fresh = runner.invoke(cli_main.app, ["config", "show"])
    assert fresh.exit_code == 0, (fresh.output, fresh.exception)
    assert "model_tiers.orchestrator" in fresh.output
    assert "model_tiers.planner" not in fresh.output
    assert "legacy names" not in fresh.output


def test_doctor_maps_legacy_config_and_notes(monkeypatch, tmp_path):
    """R14: doctor resolves the orchestrator tier from a legacy config + notes it."""
    legacy = tmp_path / "legacy.yaml"
    legacy.write_text(
        "model_tiers:\n"
        "  planner:\n    provider: anthropic\n    model: claude-sonnet-4-5\n"
        "providers:\n  anthropic:\n    key_env: ANTHROPIC_API_KEY\n"
        "agent:\n  tier: exploit\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HUNTEROS_CHAT_DB", str(tmp_path / "chat.db"))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(legacy))

    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    rows = {c["label"]: c for c in json.loads(result.output)["checks"]}
    assert rows["llm-model"]["status"] == "ok"
    assert rows["llm-model"]["detail"].startswith("orchestrator: claude-sonnet-4-5")
    assert "renamed to" in rows["llm-config"]["detail"]


# ------------------------------------------------------------------ R16 + D1/D2


def test_no_stale_old_name_literals_outside_base():
    """R16: the literals "planner"/"exploit" (any quoting) live ONLY in llm/base.py."""
    src = ROOT / "src" / "hunter"
    allowed = src / "llm" / "base.py"
    needles = ('"planner"', "'planner'", '"exploit"', "'exploit'")
    offenders: list[str] = []
    for path in sorted(src.rglob("*.py")):
        if path == allowed:
            continue
        text = path.read_text(encoding="utf-8")
        hits = [needle for needle in needles if needle in text]
        if hits:
            offenders.append(f"{path.relative_to(ROOT)}: {', '.join(hits)}")
    assert not offenders, (
        "stale old-name literals outside hunter/llm/base.py:\n" + "\n".join(offenders)
    )


def test_example_yaml_and_docs_vocabulary(tmp_path):
    """D1+D2: example config + docs speak the canonical vocabulary."""
    example_path = ROOT / "examples" / "config.example.yaml"
    example = example_path.read_text(encoding="utf-8")
    for tier in TIERS:
        assert f"{tier}:" in example
    assert "planner" not in example and "exploit" not in example
    cfg = load_config(example_path, env={}, home=tmp_path)
    assert cfg.model_tiers["orchestrator"].provider == "anthropic"

    assert "(orchestrator/hunter/verifier/utility)" in (ROOT / "README.md").read_text(encoding="utf-8")

    llm_md = (ROOT / "docs" / "LLM.md").read_text(encoding="utf-8")
    assert "orchestrator" in llm_md
    assert "planner/exploit/verify" in llm_md  # the legacy-accepted sentence
    assert "still load" in llm_md and "auto-renamed" in llm_md

    assert "orchestrator" in (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "orchestrator" in (ROOT / "QUICKSTART.md").read_text(encoding="utf-8")
