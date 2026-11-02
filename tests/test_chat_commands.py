"""Slash-command tests: resolution, scope gate, scan/findings/report, config."""

from __future__ import annotations

import pytest
import yaml

from hunter.chat.commands import (
    COMMAND_REGISTRY,
    CommandContext,
    resolve_command,
    safe_execute,
)
from hunter.chat.sessions import ChatStore
from hunter.kernel.ledger import Ledger
from hunter.llm.config import default_config
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server
from hunter.workflow.pipeline import run_scan


@pytest.fixture
def store(tmp_path):
    s = ChatStore(tmp_path / "chat.db")
    yield s
    s.close()


@pytest.fixture
def ctx(store, tmp_path):
    """A context bound to a fresh session with a tmp ledger."""
    sid = store.create_session()
    return CommandContext(
        store=store,
        config=default_config(),
        ledger_factory=lambda: Ledger(tmp_path / "ledger.db"),
        args="",
        options={"session_id": sid, "state_dir": str(tmp_path)},
    )


# -- resolution ----------------------------------------------------------------


def test_resolve_command_basic_and_alias():
    cmd, args = resolve_command("/scan http://x --engine mock")
    assert cmd.name == "scan" and args == "http://x --engine mock"
    cmd, args = resolve_command("/finds R-1")
    assert cmd.name == "findings" and args == "R-1"
    cmd, args = resolve_command("/q")
    assert cmd.name == "quit"


def test_resolve_command_mention_suffix_and_case():
    cmd, args = resolve_command("/SCAN@HunterBot http://x")
    assert cmd.name == "scan" and args == "http://x"


def test_resolve_command_rejects_non_commands():
    assert resolve_command("hello there") is None
    assert resolve_command("/") is None
    assert resolve_command("/nope") is None
    assert resolve_command("") is None


def test_registry_has_required_commands():
    names = {c.name for c in COMMAND_REGISTRY}
    assert {
        "help", "new", "sessions", "resume", "title", "scan", "findings",
        "report", "skills", "model", "scope", "usage", "undo", "clear",
        "verbose", "quit",
    } <= names


# -- help / session commands ------------------------------------------------------


def test_help_lists_commands(ctx):
    reply = safe_execute("help", ctx)
    assert "/scan" in reply.text and "/undo" in reply.text
    assert reply.format == "markdown"


def test_help_detail_for_one_command(ctx):
    ctx.args = "scan"
    reply = safe_execute("help", ctx)
    assert "--scope" in reply.text


def test_unknown_executor_name(ctx):
    assert safe_execute("definitely-not-a-command", ctx).text == "unknown command — /help"


def test_new_sessions_resume_quit(store, ctx):
    reply = safe_execute("new", ctx)
    new_sid = reply.data["session_id"]
    assert new_sid and store.get_session(new_sid) is not None

    ctx.options["session_id"] = new_sid
    ctx.store.set_title(new_sid, "named")
    reply = safe_execute("sessions", ctx)
    assert "named" in reply.text

    ctx.args = new_sid
    assert safe_execute("resume", ctx).data["session_id"] == new_sid
    ctx.args = "latest"
    assert safe_execute("resume", ctx).data["session_id"]

    ctx.args = ""
    reply = safe_execute("quit", ctx)
    assert reply.data.get("quit") is True


def test_title_get_and_set(ctx):
    sid = ctx.options["session_id"]
    ctx.args = "my audit thread"
    assert safe_execute("title", ctx).text.startswith("title set")
    assert ctx.store.get_session(sid)["title"] == "my audit thread"


def test_undo_command(ctx):
    sid = ctx.options["session_id"]
    ctx.store.append_message(sid, "user", "one")
    ctx.store.append_message(sid, "assistant", "two")
    ctx.args = "2"
    reply = safe_execute("undo", ctx)
    assert reply.text.startswith("removed")
    assert ctx.store.messages(sid) == []


def test_verbose_cycles(ctx):
    seen = []
    for _ in range(3):
        seen.append(safe_execute("verbose", ctx).data["verbosity"])
    assert seen == ["verbose", "quiet", "normal"]


def test_usage_accumulates(ctx):
    sid = ctx.options["session_id"]
    ctx.store.append_message(sid, "user", "hi")
    ctx.store.append_message(sid, "assistant", "ho", cost_usd=0.25)
    ctx.store.append_message(sid, "assistant", "ho", cost_usd=0.75)
    reply = safe_execute("usage", ctx)
    assert "$1.0000" in reply.text
    assert reply.data["cost_usd"] == 1.0


# -- scope-gated scanning ------------------------------------------------------------


def test_scan_blocked_without_scope_manifest(ctx):
    ctx.args = "http://example.com/"
    reply = safe_execute("scan", ctx)
    assert "[BLOCKED]" in reply.text
    assert reply.data["error"]["blocked"] is True


def test_scan_blocked_invalid_manifest(ctx, tmp_path):
    bad = tmp_path / "scope.json"
    bad.write_text("{}", encoding="utf-8")
    ctx.args = f"http://example.com/ --scope {bad}"
    reply = safe_execute("scan", ctx)
    assert "[BLOCKED]" in reply.text


def test_scan_localhost_live_vault(ctx):
    handle, port = start_server()
    try:
        ctx.args = f"http://127.0.0.1:{port}/"
        reply = safe_execute("scan", ctx)
    finally:
        handle.shutdown()
    assert reply.data["status"] == "completed"
    run_id = reply.data["run_id"]
    assert run_id.startswith("R-")
    assert "verified" in reply.text and run_id in reply.text
    assert reply.data["verified"] >= 1
    ledger = ctx.ledger_factory()
    try:
        assert len(ledger.findings(run_id)) == reply.data["verified"] + reply.data["candidates"]
    finally:
        ledger.close()


# -- findings / report ----------------------------------------------------------------


@pytest.fixture
def scanned_run(ctx):
    handle, port = start_server()
    try:
        summary = run_scan(
            f"http://127.0.0.1:{port}/", scope=localhost_scope(), state_dir=ctx.options["state_dir"]
        )
    finally:
        handle.shutdown()
    assert summary.status == "completed"
    return summary.run_id


def test_findings_lists_run(ctx, scanned_run):
    ctx.args = scanned_run
    reply = safe_execute("findings", ctx)
    assert scanned_run in reply.text
    assert "| severity" in reply.text


def test_findings_latest_and_unknown(ctx, scanned_run):
    ctx.args = ""
    assert safe_execute("findings", ctx).data["run_id"] == scanned_run
    ctx.args = "R-nope"
    assert "[ERROR ledger]" in safe_execute("findings", ctx).text


def test_report_markdown_and_sarif(ctx, scanned_run):
    ctx.args = f"{scanned_run} --fmt markdown"
    reply = safe_execute("report", ctx)
    assert reply.format == "markdown"
    assert f"run {scanned_run}" in reply.text
    assert "Chain verification: OK" in reply.text

    ctx.args = f"{scanned_run} --fmt sarif"
    reply = safe_execute("report", ctx)
    assert '"version": "2.1.0"' in reply.text
    assert reply.data["fmt"] == "sarif"


def test_report_rejects_unknown_format(ctx, scanned_run):
    ctx.args = f"{scanned_run} --fmt xml"
    assert "[ERROR engine]" in safe_execute("report", ctx).text


# -- model / scope / skills ------------------------------------------------------------


def test_model_show_when_unset(ctx):
    ctx.args = ""
    reply = safe_execute("model", ctx)
    assert "orchestrator" in reply.text and "(unset)" in reply.text


def test_model_in_session_mutation(ctx):
    ctx.args = "orchestrator gpt-x"
    reply = safe_execute("model", ctx)
    assert reply.data["global"] is False
    assert ctx.config.model_tiers["orchestrator"].model == "gpt-x"
    ctx.args = ""
    assert "gpt-x" in safe_execute("model", ctx).text


def test_model_unknown_tier_blocked(ctx):
    ctx.args = "turbo gpt-x"
    reply = safe_execute("model", ctx)
    assert "[ERROR config]" in reply.text


def test_model_global_persists_yaml(ctx, tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("model_tiers:\n  orchestrator:\n    model: old\n", encoding="utf-8")
    ctx.config.source_path = str(cfg_file)
    ctx.args = "orchestrator new-model --global"
    reply = safe_execute("model", ctx)
    assert reply.data["global"] is True
    data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    assert data["model_tiers"]["orchestrator"]["model"] == "new-model"


def test_model_global_without_file_hints_env(ctx):
    ctx.config.source_path = None
    ctx.args = "orchestrator new-model --global"
    reply = safe_execute("model", ctx)
    assert "HUNTEROS_MODEL" in reply.text


def test_scope_defaults_to_localhost_only(ctx):
    reply = safe_execute("scope", ctx)
    assert "localhost" in reply.text


def test_scope_shows_last_scan_scope(ctx):
    # The surface's state bag carries the active scope after a governed scan.
    ctx.options["scope_summary"] = {"name": "client-x", "hosts": ["example.com"]}
    reply = safe_execute("scope", ctx)
    assert "client-x" in reply.text and "example.com" in reply.text


def test_skills_lists_bundled(ctx):
    reply = safe_execute("skills", ctx)
    assert "recon-basics" in reply.text


# ------------------------------------------- /model --list and --providers


def test_model_providers_lists_configured_providers_without_leaking_keys(ctx):
    """Multi-provider is only useful if you can see it without opening the YAML.

    Key PRESENCE is reported; the key VALUE never is — a slash command that
    echoes a secret into a scrollback is a leak, not a feature.
    """
    from hunter.chat.commands import _model_providers

    from hunter.llm.config import ProviderConfig

    ctx.config.providers["mygate"] = ProviderConfig(
        key_env="SOME_KEY_ENV", api_key="", base_url="https://gw.example.com/v1", endpoint=""
    )
    reply = _model_providers(ctx.config)
    assert "mygate" in reply.text
    assert "https://gw.example.com/v1" in reply.text
    assert "SOME_KEY_ENV" in reply.text
    assert "NOT SET" in reply.text
    assert "mygate" in reply.data["providers"]


def test_model_providers_reports_the_fallback_chain(ctx):
    from hunter.chat.commands import _model_providers

    reply = _model_providers(ctx.config)
    assert "fallback chain" in reply.text


def test_model_list_reads_base_url_from_the_provider_block(ctx, monkeypatch):
    """base_url lives on the provider block, not the tier.

    `hunter config provider` writes it there, so reading only the tier finds
    nothing on every normally-configured install and --list reports "nothing
    to list" against a live endpoint.
    """
    from hunter.chat import commands as cmd_mod

    seen = {}

    def fake_list(base_url, api_key="", **kwargs):
        seen["base_url"] = base_url
        seen["api_key"] = api_key
        return ["model-a", "model-b"]

    monkeypatch.setattr(cmd_mod, "_split_options", cmd_mod._split_options)
    import hunter.llm.probe as probe_mod
    monkeypatch.setattr(probe_mod, "list_models", fake_list)

    ctx.config.model_tiers["orchestrator"].provider = "jerouter"
    ctx.config.model_tiers["orchestrator"].base_url = ""
    from hunter.llm.config import ProviderConfig

    ctx.config.providers["jerouter"] = ProviderConfig(
        key_env="JEROUTER_API_KEY", api_key="", base_url="https://je.jerouter.web.id/v1", endpoint=""
    )
    monkeypatch.setenv("JEROUTER_API_KEY", "secret-value")

    reply = cmd_mod._model_list(ctx.config)

    assert seen["base_url"] == "https://je.jerouter.web.id/v1"
    assert seen["api_key"] == "secret-value"
    assert "model-a" in reply.text and "model-b" in reply.text
    assert reply.data["models"] == ["model-a", "model-b"]


def test_model_list_without_a_base_url_says_so_instead_of_probing(ctx):
    """A tier with no base_url has nothing to dial.

    Probing a blank URL returns [] on any failure, which reads as "the
    provider has no models" — a misleading answer when the real cause is a
    missing base_url.
    """
    from hunter.chat.commands import _model_list

    ctx.config.model_tiers["orchestrator"].provider = "jerouter"
    ctx.config.model_tiers["orchestrator"].base_url = ""
    ctx.config.providers.pop("jerouter", None)

    reply = _model_list(ctx.config)

    assert "no base_url" in reply.text
    assert reply.data["models"] == []


def test_model_list_survives_a_dead_endpoint(ctx, monkeypatch):
    """A dead provider must not kill the REPL."""
    import hunter.llm.probe as probe_mod
    from hunter.chat.commands import _model_list

    def boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(probe_mod, "list_models", boom)
    ctx.config.model_tiers["orchestrator"].provider = "jerouter"
    ctx.config.model_tiers["orchestrator"].base_url = "https://dead.example.com/v1"

    reply = _model_list(ctx.config)

    assert "could not list models" in reply.text
    assert reply.data.get("error")


# ------------------------------------- /model interactive provider -> model picker


def _ctx_with_ask(ctx, answers):
    """A ctx whose ask_fn replays ``answers`` in order (scripted operator)."""
    remaining = list(answers)

    def ask(prompt, default=""):
        return remaining.pop(0) if remaining else default

    ctx.options["ask_fn"] = ask
    return ctx


def test_bare_model_picks_provider_then_model(ctx, monkeypatch):
    """`/model` with no args must run the provider -> model flow.

    Before this, the REPL could APPLY a model but could not show which
    providers or models existed — switching meant leaving the session.
    """
    import hunter.chat.commands as cmd_mod
    from hunter.chat.commands import _model_pick

    # _model_pick imports list_models inside the function body, so the patch
    # has to land on the calling module — patching hunter.llm.probe does
    # nothing and the probe silently returns the real (empty) list.
    monkeypatch.setattr(cmd_mod, "_probe_models", lambda *a, **k: ["model-a", "model-b"])
    # Pick by NAME, not row number: the first known row (openai) has no
    # base_url, so the picker cannot probe it and falls back to manual entry.
    # A provider with a URL is the one that exercises the model menu.
    _ctx_with_ask(ctx, ["openrouter", "2"])

    reply = _model_pick(ctx)

    assert reply.data["model"] == "model-b"
    assert reply.data["provider"] == "openrouter"
    # the rendered menu must reach the reply, not vanish into a buffer
    assert "model-a" in reply.text


def test_bare_model_accepts_a_provider_name_not_just_a_number(ctx, monkeypatch):
    import hunter.chat.commands as cmd_mod
    from hunter.chat.commands import _model_pick

    monkeypatch.setattr(cmd_mod, "_probe_models", lambda *a, **k: ["only-model"])
    _ctx_with_ask(ctx, ["openrouter", "1"])

    reply = _model_pick(ctx)

    assert reply.data["provider"] == "openrouter"
    # One model detected: the picker offers it as the default, so a blank or
    # "1" both keep it.
    assert reply.data["model"] == "only-model"


def test_bare_model_rejects_an_unknown_provider(ctx):
    from hunter.chat.commands import _model_pick

    _ctx_with_ask(ctx, ["not-a-provider"])
    reply = _model_pick(ctx)

    assert "unknown provider" in reply.text
    assert reply.data.get("unknown_provider") == "not-a-provider"


def test_bare_model_blank_answer_cancels(ctx):
    from hunter.chat.commands import _model_pick

    _ctx_with_ask(ctx, [""])
    reply = _model_pick(ctx)

    assert reply.data.get("cancelled") is True


def test_bare_model_without_an_input_channel_shows_the_map(ctx):
    """A piped or scripted surface must not hang on stdin.

    The picker degrades to the tier map instead of blocking — a `/model`
    delivered over a pipe has nobody to answer the prompt.
    """
    from hunter.chat.commands import _model_pick

    ctx.options.pop("ask_fn", None)
    reply = _model_pick(ctx)

    assert "model tiers:" in reply.text
    assert "models" in reply.data


def test_bare_model_survives_a_dead_endpoint(ctx, monkeypatch):
    """A dead provider must not kill the REPL — manual entry instead."""
    import hunter.chat.commands as cmd_mod
    from hunter.chat.commands import _model_pick

    def boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(cmd_mod, "_probe_models", boom)
    _ctx_with_ask(ctx, ["openrouter", "my-manual-model"])

    reply = _model_pick(ctx)

    assert reply.data["model"] == "my-manual-model"


def test_bare_model_global_persists_provider_and_model(ctx, monkeypatch, tmp_path):
    """--global must write BOTH provider and model.

    A model id only means something against the provider that serves it;
    persisting one without the other leaves a config that resolves to a
    different brain than the operator picked.
    """
    import hunter.chat.commands as cmd_mod
    from hunter.chat.commands import _model_pick

    monkeypatch.setattr(cmd_mod, "_probe_models", lambda *a, **k: ["pinned-model"])
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("model_tiers:\n  orchestrator:\n    model: old\n")
    ctx.config.source_path = str(cfg_file)
    ctx.options["model_global"] = True
    _ctx_with_ask(ctx, ["openrouter", "1"])

    reply = _model_pick(ctx)

    assert "persisted" in reply.text
    import yaml

    parsed = yaml.safe_load(cfg_file.read_text())
    tier_block = parsed["model_tiers"]["orchestrator"]
    assert tier_block["model"] == "pinned-model"
    assert tier_block["provider"] == "openrouter"
