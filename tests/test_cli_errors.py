"""Error doctrine — every failure NOTIFIED with a location, zero tracebacks.

Covers: the per-command HunterError wrap (exit 8 + ``where:`` line), the
``main()`` backstop (one-liner + issue URL, --verbose traceback, interrupt →
130, HUNTEROS_VERBOSE=1), the chat safe_execute catch-all, and the REPL loop
surviving an unexpected exception (scripted-console pattern).
"""

from __future__ import annotations

import importlib.util

import pytest
from typer.testing import CliRunner

import hunter.cli.main as cli_main
from hunter.chat.commands import EXECUTORS, CommandContext, safe_execute
from hunter.cli.handle import (
    ISSUE_URL,
    handle_cli_error,
    is_verbose,
    set_verbose,
)
from hunter.errors import HunterError

runner = CliRunner()


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    set_verbose(False)


def _bad_config(tmp_path) -> None:
    (tmp_path / "config.yaml").write_text("budget: [unclosed\n", encoding="utf-8")


def test_config_show_bad_config_exit_8_with_where_line(monkeypatch, tmp_path):
    _bad_config(tmp_path)
    result = runner.invoke(cli_main.app, ["config", "show"])
    assert result.exit_code == 8, (result.output, result.exception)
    assert "[ERROR config]" in result.output
    assert "where: hunter/" in result.output  # location line, no traceback
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_provider_list_bad_config_exits_8(monkeypatch, tmp_path):
    _bad_config(tmp_path)
    result = runner.invoke(cli_main.app, ["config", "provider", "list"])
    assert result.exit_code == 8
    assert "[ERROR config]" in result.output and "where:" in result.output
    assert "Traceback" not in result.output


def test_unexpected_command_error_escapes_raw_under_clirunner(monkeypatch, tmp_path):
    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli_main, "_open_ledger", boom)
    result = runner.invoke(cli_main.app, ["runs"])
    assert result.exit_code == 1
    assert not isinstance(result.exception, SystemExit)  # escaped raw under CliRunner


def _assert_backstop(monkeypatch, capsys, argv: list[str], *, expect_traceback: bool) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("boom from the backstop test")

    monkeypatch.setattr(cli_main, "_open_ledger", boom)
    monkeypatch.setattr("sys.argv", ["hunter", *argv])
    with pytest.raises(SystemExit) as ei:
        cli_main.main()
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "[ERROR engine] unexpected RuntimeError: boom from the backstop test" in err
    assert ISSUE_URL in err
    assert ("Traceback" in err) == expect_traceback


def test_main_backstop_one_liner_and_issue_url(monkeypatch, tmp_path, capsys):
    _assert_backstop(monkeypatch, capsys, ["runs"], expect_traceback=False)


def test_main_backstop_verbose_prints_traceback_to_stderr(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HUNTEROS_VERBOSE", "1")
    _assert_backstop(monkeypatch, capsys, ["runs"], expect_traceback=True)


def test_hunteros_verbose_env_is_honored(monkeypatch):
    assert not is_verbose()
    monkeypatch.setenv("HUNTEROS_VERBOSE", "1")
    assert is_verbose()


def test_keyboard_interrupt_maps_to_130(capsys):
    code = handle_cli_error(KeyboardInterrupt(), verbose=False)
    assert code == 130
    assert "[interrupted]" in capsys.readouterr().err


def test_handle_cli_error_hunter_error_has_where_line(capsys, tmp_path):
    # Raise through a REAL hunter call so the traceback carries hunter frames.
    (tmp_path / "broken.yaml").write_text("budget: [unclosed\n", encoding="utf-8")
    from hunter.llm.config import load_config

    try:
        load_config(tmp_path / "broken.yaml", env={}, home=tmp_path)
        raise AssertionError("load_config should have raised")  # pragma: no cover
    except HunterError as exc:
        code = handle_cli_error(exc, verbose=False)
    err = capsys.readouterr().err
    assert code == 8
    assert "[ERROR config]" in err
    assert "where: hunter/llm/config.py" in err
    assert err.count("Hint:") == 1


def test_safe_execute_catch_all_returns_engine_reply():
    def boom(_ctx):
        raise ValueError("kaboom")

    ctx = CommandContext(store=None, config=None)
    try:
        EXECUTORS["boom"] = boom
        reply = safe_execute("boom", ctx)
    finally:
        del EXECUTORS["boom"]
    assert reply.text.startswith("[ERROR engine] unexpected ValueError: kaboom")
    assert "Hint:" in reply.text
    assert reply.data["error"]["layer"] == "engine"


def test_repl_loop_survives_store_exception():
    """Scripted-console pattern (tests/test_chat_repl.py): an unexpected
    exception mid-turn prints [ERROR engine] and the session keeps working."""
    from hunter.chat.repl import ChatEngine, run_repl
    from hunter.chat.sessions import ChatStore

    class ExplodingStore(ChatStore):
        def append_message(self, *args, **kwargs):
            import sqlite3

            raise sqlite3.OperationalError("disk I/O error (simulated)")

    class BoomProvider:
        name = "boom"

        def complete(self, *_args, **_kwargs):  # pragma: no cover — never reached
            raise AssertionError("the store explodes before the provider is dialed")

    class FakeConsole:
        is_terminal = False

        def __init__(self, inputs) -> None:
            self._inputs = list(inputs)
            self.printed: list[str] = []

        def print(self, *args, **kwargs) -> None:
            for arg in args:
                self.printed.append(str(getattr(arg, "plain", arg)))

        def input(self, prompt: str = "") -> str:
            item = self._inputs.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

    store = ExplodingStore(":memory:")
    engine = ChatEngine(store=store, config=None, provider=BoomProvider())
    console = FakeConsole(["hello", "/quit"])
    run_repl(engine=engine, console=console)  # returns — session survived
    text = "\n".join(console.printed)
    assert "[ERROR engine] unexpected OperationalError" in text
    assert "session saved" in text  # /quit still worked after the failure
    store.close()


def test_gateway_surfaces_hint_in_error_reply():
    import asyncio

    from hunter.gateway.app import GatewayApp
    from hunter.llm.config import default_config

    class Transport:
        name = "fake"

    class _Gateway(GatewayApp):
        def engine_for(self, session_key):
            class Engine:
                def handle_text(self, _text):
                    raise ValueError("no key configured — set OPENROUTER_API_KEY")

            return Engine()

    gateway = _Gateway(default_config(), [Transport()])
    import types

    msg = types.SimpleNamespace(chat_id="1", text="hi")
    reply = asyncio.run(gateway.handle_message(Transport(), msg))
    assert reply.startswith("[ERROR engine]")
    assert "Hint:" in reply
    assert "no key configured" in reply


# ===========================================================================
# Phase surfacing — B9's contract consumed lazily (each test skips itself if
# the phase engine is not importable in a mid-flight checkout)
# ===========================================================================

_HAS_PHASES = importlib.util.find_spec("hunter.phases") is not None
needs_phases = pytest.mark.skipif(not _HAS_PHASES, reason="phase engine (B9) not landed yet")


class YieldProvider:
    """Provider that immediately ends an audit via respond_to_user."""

    name = "fake-yield"

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        from hunter.llm.base import ToolCall, TurnResult

        return TurnResult(
            text="",
            tool_calls=(ToolCall(id="1", name="respond_to_user", arguments={"message": "yield"}),),
            cost_usd=0.01,
        )


@needs_phases
def test_audit_lifecycle_records_phase_events(tmp_path):
    """/audit mounts the PhaseState machine: score opens+closes, the run lives
    in recon, and finish closes the open phase with its honest ledger gate.
    (M3 rewrite: arming goes through the hunt-intent path with an auto-YES
    confirm — the auto-drive turn IS the old "go" turn.)"""
    from hunter.chat.repl import ChatEngine
    from hunter.chat.sessions import ChatStore
    from hunter.kernel.ledger import Ledger

    store = ChatStore(tmp_path / "chat.db")
    engine = ChatEngine(
        store=store,
        config=None,
        provider=YieldProvider(),
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
        confirm_fn=lambda _prompt: True,
    )
    out = engine.handle_text("audit http://127.0.0.1:8941/")
    run_id = out.data["hunt"]["run_id"]
    engine.close()  # honest finish: closes the open phase, ends the run
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        kinds = [e.kind_value() for e in ledger.events(run_id)]
        assert kinds.count("phase_started") == 2  # score + recon
        assert kinds.count("phase_ended") == 2  # score closed; recon closed honestly
        assert "run_ended" in kinds
        assert "report_rendered" not in kinds  # /report is the only reporter
    finally:
        ledger.close()
    store.close()


@needs_phases
def test_hunter_retro_renders_and_records(tmp_path):
    from hunter.kernel.ledger import Ledger
    from hunter.phases import PhaseState

    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run("R-retro1", "http://127.0.0.1:1/", "deterministic", "localhost-only")
    machine = PhaseState(ledger, "R-retro1")
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    machine.close_current()
    ledger.finish_run("R-retro1", "completed")
    ledger.close()

    shown = runner.invoke(cli_main.app, ["retro", "--run", "R-retro1", "--state", str(tmp_path)])
    assert shown.exit_code == 0, (shown.output, shown.exception)
    assert "Retro" in shown.output and "coverage" in shown.output

    recorded = runner.invoke(
        cli_main.app, ["retro", "--run", "R-retro1", "--record", "--state", str(tmp_path)]
    )
    assert recorded.exit_code == 0, (recorded.output, recorded.exception)


@needs_phases
def test_report_digest_stamps_report_rendered(tmp_path):
    from hunter.kernel.ledger import Ledger

    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run("R-report1", "http://127.0.0.1:1/", "deterministic", "localhost-only")
    ledger.finish_run("R-report1", "completed")
    ledger.close()

    rendered = runner.invoke(
        cli_main.app, ["report", "--run", "R-report1", "--state", str(tmp_path)]
    )
    assert rendered.exit_code == 0, (rendered.output, rendered.exception)

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        events = [e for e in ledger.events("R-report1") if e.kind_value() == "report_rendered"]
        assert len(events) == 1
        payload = events[0].payload
        assert payload["fmt"] == "markdown"
        assert len(payload["sha256"]) == 64  # digest-stamped
        assert payload["chars"] > 0
    finally:
        ledger.close()
