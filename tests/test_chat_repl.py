"""REPL tests — scripted input, no tty: banner, turns, interrupts, quit."""

from __future__ import annotations

import pytest

from hunter.chat.repl import ChatEngine, run_repl
from hunter.chat.sessions import ChatStore
from hunter.llm.base import TurnResult
from hunter.llm.config import default_config


class FakeProvider:
    """Deterministic ChatProvider: records history, answers 'ok'."""

    name = "fake"

    def __init__(self, *, stream: bool = False, interrupt: bool = False) -> None:
        self.stream = stream
        self.interrupt = interrupt
        self.calls: list[list[dict]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append(list(messages))
        if self.interrupt:
            raise KeyboardInterrupt
        if self.stream and stream_cb is not None:
            stream_cb("ok")
        return TurnResult(text="ok", cost_usd=0.01)


class FakeConsole:
    """Scripted rich.Console stand-in: pops inputs, records prints."""

    is_terminal = False

    def __init__(self, inputs: list) -> None:
        self._inputs = list(inputs)
        self.printed: list[str] = []

    def print(self, *args, **kwargs) -> None:
        for arg in args:
            self.printed.append(_stringify(arg))

    def input(self, prompt: str = "") -> str:
        item = self._inputs.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def text(self) -> str:
        return "\n".join(self.printed)


def _stringify(renderable) -> str:
    """Pull plain text out of the rich renderables the REPL prints."""
    if hasattr(renderable, "plain"):  # rich.text.Text
        return renderable.plain
    if hasattr(renderable, "markup"):  # rich.markdown.Markdown
        return renderable.markup
    if hasattr(renderable, "renderable"):  # rich.panel.Panel etc.
        return _stringify(renderable.renderable)
    return str(renderable)


@pytest.fixture
def store(tmp_path):
    s = ChatStore(tmp_path / "chat.db")
    yield s
    s.close()


def _engine(store, provider=None) -> ChatEngine:
    return ChatEngine(
        store=store,
        config=default_config(),
        provider=provider if provider is not None else FakeProvider(),
    )


def test_banner_prints_and_quit_exits(store):
    console = FakeConsole(["/quit"])
    run_repl(engine=_engine(store), console=console)
    text = console.text()
    assert "HUNTEROS" in text and "Evidence or Nothing" in text
    assert "session:" in text


def test_free_text_persists_turn(store):
    console = FakeConsole(["hello there", "/quit"])
    provider = FakeProvider()
    run_repl(engine=_engine(store, provider), console=console)
    assert "ok" in console.text()
    roles = [m["role"] for m in store.messages(_engine_session(store))]
    contents = [m["content"] for m in store.messages(_engine_session(store))]
    assert "user" in roles and "assistant" in roles
    assert "hello there" in contents and "ok" in contents
    # The provider saw the persisted history.
    assert any(m["role"] == "user" and m["content"] == "hello there" for m in provider.calls[0])


def _engine_session(store: ChatStore) -> str:
    # The engine created exactly one session; find it.
    sessions = store.list_sessions()
    assert len(sessions) == 1
    return sessions[0]["session_id"]


def test_unknown_command_replies_help_hint(store):
    console = FakeConsole(["/frobnicate", "/quit"])
    run_repl(engine=_engine(store), console=console)
    assert "unknown command — /help" in console.text()


def test_streamed_turn_renders_and_persists(store):
    console = FakeConsole(["hi", "/quit"])
    run_repl(engine=_engine(store, FakeProvider(stream=True)), console=console)
    assert "ok" in console.text()


def test_interrupt_at_prompt_once_stays_alive_twice_exits(store):
    console = FakeConsole([KeyboardInterrupt(), "/quit"])
    run_repl(engine=_engine(store), console=console)
    assert "nothing is running" in console.text()

    console = FakeConsole([KeyboardInterrupt(), KeyboardInterrupt()])
    run_repl(engine=_engine(store), console=console)
    assert "bye" in console.text()


def test_interrupt_during_turn_marks_partial_and_survives(store):
    console = FakeConsole(["explain the plan", "/quit"])
    run_repl(engine=_engine(store, FakeProvider(interrupt=True)), console=console)
    assert "[interrupted]" in console.text()
    # The user turn was kept; no assistant prose was fabricated.
    contents = [m["content"] for m in store.messages(_engine_session(store))]
    assert "explain the plan" in contents
    assert "ok" not in contents


def test_eof_exits_cleanly(store):
    console = FakeConsole([EOFError()])
    run_repl(engine=_engine(store), console=console)  # returns without raising


def test_provider_error_keeps_repl_alive(store, monkeypatch):
    # Deterministically simulate "no provider configured" without touching
    # any real user config: load_config always fails inside this test.
    from hunter.errors import HunterError

    def boom(*_args, **_kwargs):
        raise HunterError(
            code="config.not_found", layer="config",
            message="no config in tests", hint="set HUNTEROS_MODEL",
        )

    monkeypatch.setattr("hunter.chat.repl.load_config", boom)
    engine = ChatEngine(store=store, config=None, provider=None)
    console = FakeConsole(["hello", "/quit"])
    run_repl(engine=engine, console=console)
    text = console.text()
    assert "ERROR config" in text and "no config in tests" in text
    assert "slash commands still work" in text


def test_audit_conversational_turns_are_governed(store, tmp_path):
    """Stretch check: /audit opens a ledger run; chat text drives the loop."""
    from hunter.kernel.ledger import Ledger
    from hunter.llm.base import ToolCall

    class AuditProvider:
        name = "fake-audit"

        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            # respond_to_user yields control back to the chat layer, ending
            # the run with a yield_message (the /audit attach semantics).
            return TurnResult(
                text="",
                tool_calls=(
                    ToolCall(id="1", name="respond_to_user", arguments={"message": "yield"}),
                ),
                cost_usd=0.02,
            )

    engine = ChatEngine(
        store=store,
        config=default_config(),
        provider=AuditProvider(),
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
    )
    out = engine.handle_text("/audit http://127.0.0.1:8941/")
    run_id = out.data["audit_start_run_id"]
    assert run_id.startswith("R-")
    reply = engine.handle_text("what did you find?")
    assert "yield" in reply.text

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        runs = ledger.runs()
        assert runs and runs[-1]["run_id"] == run_id
        events = ledger.events(run_id)
        assert any(e.kind_value() == "run_started" for e in events)
    finally:
        ledger.close()
    # Transcript carries the governed turn with its cost and run binding.
    assistant = [m for m in store.messages(engine.session_id) if m["role"] == "assistant"]
    assert assistant and assistant[-1]["run_id"] == run_id
    engine.close()
