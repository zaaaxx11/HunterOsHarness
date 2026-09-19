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
