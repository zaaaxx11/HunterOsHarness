"""M11 M3 — chat works: one-shot, resume, friendly failures (§6 test plan).

Spec: docs/plans/m11-ux.md §2.2 Q3/Q14, §6. The CLI gains a one-shot
prompt argument, --resume/--continue/--list, a single no-provider panel, and
the free-text intent hint. The engine is injected through the module-level
``hunter.cli.main._build_engine`` seam (monkeypatched with raising=False so
pre-M3 runs fail on BEHAVIOR, not on the seam). Zero network: FakeProvider
scripts only; no real config exists (isolated home).
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hunter.chat.repl import ChatEngine, run_repl
from hunter.chat.sessions import ChatStore
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ToolCall, TurnResult
from hunter.llm.config import default_config
from hunter.cli.main import app

runner = CliRunner()

TARGET = "http://example.com"
FREE_TEXT = f"scan {TARGET} for vulnerabilities"
HINT_FRAGMENT = "💡 to hunt this target explicitly: /audit http://example.com --scope <manifest>"
HINT_SHELL = "or from the shell: hunter hunt http://example.com"
PANEL_FIX_LINES = (
    "💡 Fix it in under a minute:",
    "hunter init",
    "hunter model",
    "hunter config provider add custom --base-url https://your-endpoint/v1",
    "hunter config key set CUSTOM_API_KEY",
)
SHORT_NO_PROVIDER = "💡 no brain configured — run hunter init (the setup panel is above)"


class FakeProvider:
    """Deterministic ChatProvider (test_chat_repl convention)."""

    name = "fake"

    def __init__(self, script=(), interrupt: bool = False) -> None:
        self.script = list(script)
        self.interrupt = interrupt
        self.calls: list[list[dict]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append([dict(m) for m in messages])
        if self.interrupt:
            raise KeyboardInterrupt
        index = len(self.calls) - 1
        if self.script:
            return self.script[min(index, len(self.script) - 1)]
        return TurnResult(text="ok", cost_usd=0.01)


def chat_turn(text: str = "ok") -> TurnResult:
    return TurnResult(text=text, cost_usd=0.01)


def yield_turn(message: str = "yield") -> TurnResult:
    return TurnResult(
        text="",
        tool_calls=(ToolCall(id="y", name="respond_to_user", arguments={"message": message}),),
        cost_usd=0.01,
    )


def _patch_build_engine(monkeypatch, build) -> None:
    """Swap the CLI's engine factory (the seam M3 introduces). ``build`` takes
    the CLI's keyword arguments and returns a ChatEngine."""
    monkeypatch.setattr("hunter.cli.main._build_engine", build, raising=False)


def _engine_builder(store: ChatStore, provider=None, recorder: list | None = None):
    """A _build_engine double that builds a REAL engine around the given store."""

    def build(**kwargs):
        if recorder is not None:
            recorder.append(kwargs.get("session_id"))
        return ChatEngine(
            store=store,
            config=default_config(),
            provider=provider if provider is not None else FakeProvider(),
            session_id=kwargs.get("session_id"),
            options={"verbosity": "normal"},
        )

    return build


def _no_provider_engine(monkeypatch, store: ChatStore, code: str = "config.not_found") -> ChatEngine:
    """A REAL engine in the no-provider state (load_config always fails here)."""
    from hunter.errors import HunterError

    def boom(*_args, **_kwargs):
        raise HunterError(
            code=code, layer="config", message="no config in tests", hint="set HUNTEROS_MODEL"
        )

    monkeypatch.setattr("hunter.chat.repl.load_config", boom)
    return ChatEngine(store=store, config=None, provider=None)


@pytest.fixture
def store():
    s = ChatStore()
    yield s
    s.close()


# -- 1 --------------------------------------------------------------------------


def test_one_shot_prints_reply_and_exits_zero(store, monkeypatch):
    """`hunter chat "text"` answers once, persists, and never opens the REPL."""
    engine = _engine_builder(store)()
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", "hello there"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "ok" in result.output
    assert "session:" not in result.output  # the REPL banner never printed
    contents = [m["content"] for m in store.messages(engine.session_id)]
    assert "hello there" in contents and "ok" in contents  # message persisted


# -- 2 --------------------------------------------------------------------------


def test_one_shot_persists_to_named_session(store, monkeypatch):
    sid = store.create_session("existing session")
    seen: list = []
    _patch_build_engine(monkeypatch, _engine_builder(store, recorder=seen))
    result = runner.invoke(app=app, args=["chat", "append to me", "--resume", sid])
    assert result.exit_code == 0, (result.output, result.exception)
    assert seen == [sid]  # the named session was resolved and used
    contents = [m["content"] for m in store.messages(sid)]
    assert "append to me" in contents


# -- 3 --------------------------------------------------------------------------


def test_one_shot_provider_missing_prints_panel_once_exit_8(store, monkeypatch):
    """No provider: ONE setup panel with the pinned fix commands, exit 8."""
    engine = _no_provider_engine(monkeypatch, store)
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", "hello"])
    assert result.exit_code == 8, (result.output, result.exception)
    text = result.output
    assert "ERROR config" in text
    for line in PANEL_FIX_LINES:
        assert line in text, line
    assert text.count("Fix it in under a minute") == 1  # the panel appears ONCE

    # The hospitality panel text itself is pinned byte-exact (error=None shape).
    from hunter.hospitality import no_provider_message

    pinned = (
        "[ERROR config] no provider configured — chat needs a brain\n"
        "💡 Fix it in under a minute:\n"
        "   hunter init                  — the guided wizard (recommended)\n"
        "   hunter model                 — pick a provider + model (key already set?)\n"
        "   hunter config provider add custom --base-url https://your-endpoint/v1\n"
        "   hunter config key set CUSTOM_API_KEY"
    )
    assert no_provider_message(None) == pinned


# -- 4 --------------------------------------------------------------------------


def test_one_shot_slash_command_runs_without_repl(store, monkeypatch):
    engine = _engine_builder(store)()
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", "/help"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "/scan" in result.output  # the command listing
    assert "session:" not in result.output  # no REPL opened


# -- 5 --------------------------------------------------------------------------


def test_list_flag_renders_sessions_without_provider(store):
    store.create_session("alpha title")
    store.create_session("beta title")
    result = runner.invoke(app=app, args=["chat", "--list"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "alpha title" in result.output and "beta title" in result.output
    assert "no brain configured yet" not in result.output  # no onboarding offer


# -- 6 --------------------------------------------------------------------------


def test_list_empty_store_prints_hint(store):
    result = runner.invoke(app=app, args=["chat", "--list"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "no sessions yet" in result.output


# -- 7 --------------------------------------------------------------------------


def test_resume_last_picks_most_recent(store, monkeypatch):
    sids = []
    for title in ("first", "second", "third"):
        sid = store.create_session(title)
        store.append_message(sid, "user", f"seed {title}")
        sids.append(sid)
        time.sleep(0.02)  # keep last_active_at strictly increasing

    seen: list = []
    _patch_build_engine(monkeypatch, _engine_builder(store, recorder=seen))
    result = runner.invoke(app=app, args=["chat", "ping last", "--resume", "last"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert seen == [sids[-1]]  # the newest session won
    contents = [m["content"] for m in store.messages(sids[-1])]
    assert "ping last" in contents


# -- 8 --------------------------------------------------------------------------


def test_continue_equals_resume_last(store, monkeypatch):
    sids = []
    for title in ("first", "second"):
        sid = store.create_session(title)
        store.append_message(sid, "user", f"seed {title}")
        sids.append(sid)
        time.sleep(0.02)

    seen: list = []
    _patch_build_engine(monkeypatch, _engine_builder(store, recorder=seen))
    result = runner.invoke(app=app, args=["chat", "again", "--continue"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert seen == [sids[-1]]


# -- 9 --------------------------------------------------------------------------


def test_resume_unknown_id_friendly_error_exit_2(store):
    store.create_session("kept session")
    result = runner.invoke(app=app, args=["chat", "hi", "--resume", "nope-123"])
    assert result.exit_code == 2, (result.output, result.exception)
    text = result.output
    assert "no session 'nope-123'" in text
    assert "kept session" in text  # recent sessions are listed
    assert "💡 resume one: hunter chat --resume" in text

    # The hospitality string itself is pinned (§6 shape contract).
    from hunter.hospitality import unknown_session_message

    sessions = [{"session_id": "S-1", "title": "", "last_active_at": 0.0}]
    message = unknown_session_message("nope-123", sessions)
    assert message.startswith("no session 'nope-123'.")
    assert "sessions:" in message
    assert "S-1" in message and "(untitled)" in message
    assert "💡 resume one: hunter chat --resume nope-123 — or start fresh: hunter chat" in message


# -- 10 -------------------------------------------------------------------------


def test_resume_last_with_no_sessions_starts_fresh(store, monkeypatch):
    engine = _engine_builder(store)()
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", "fresh start", "--resume", "last"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "ok" in result.output
    assert len(store.list_sessions()) == 1  # a fresh session, no error


# -- 11 -------------------------------------------------------------------------


def test_repl_path_still_works_scripted(store, monkeypatch):
    """No prompt argument -> the REPL (regression guard), via the same seam."""
    home = Path(os.environ["USERPROFILE"])
    config_path = home / ".hunter" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("agent:\n  tier: basic\n", encoding="utf-8")
    # The first-run offer must stay out of the way on both sides of the M1
    # home move (pre-M1 the seeded ~/.hunter config is not the legacy path).
    monkeypatch.setenv("HUNTEROS_ONBOARD_DECLINED", "1")

    engine = _engine_builder(store)()
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat"], input="hello\n/quit\n")
    assert result.exit_code == 0, (result.output, result.exception)
    assert "HUNTEROS" in result.output  # the banner
    assert "ok" in result.output  # the scripted provider answered


# -- 12 (Q3: free text is NEVER an audit) ----------------------------------------


def test_free_text_with_url_gets_reply_plus_hint_no_audit(store, monkeypatch, tmp_path):
    state = tmp_path / "state"
    provider = FakeProvider([chat_turn("plain reply")])
    engine = _engine_builder(store, provider=provider)()
    engine.options["state_dir"] = str(state)
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", FREE_TEXT, "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    text = result.output
    assert "plain reply" in text  # a NORMAL conversational reply
    assert HINT_FRAGMENT in text and HINT_SHELL in text  # + the pinned hint
    ledger = Ledger(state / "ledger.db")
    try:
        assert ledger.runs() == []  # NO audit opened
    finally:
        ledger.close()


# -- 13 --------------------------------------------------------------------------


def test_free_text_intent_with_no_provider_shows_panel_plus_hint(store, monkeypatch, tmp_path):
    state = tmp_path / "state"
    engine = _no_provider_engine(monkeypatch, store)
    engine.options["state_dir"] = str(state)
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", FREE_TEXT, "--state", str(state)])
    assert result.exit_code == 8, (result.output, result.exception)
    text = result.output
    assert "Fix it in under a minute" in text  # the panel
    assert HINT_FRAGMENT in text  # + the same hint
    ledger = Ledger(state / "ledger.db")
    try:
        assert ledger.runs() == []
    finally:
        ledger.close()


# -- 14 (regression guard: explicit mode still intercepts) ------------------------


def test_hunt_mode_still_intercepts_free_text(store, tmp_path):
    def forbidden(_prompt: str) -> bool:
        raise AssertionError("hunt mode must not prompt")

    provider = FakeProvider([yield_turn("driven")])
    engine = ChatEngine(
        store=store, config=default_config(), provider=provider,
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
        confirm_fn=forbidden,
    )
    engine.handle_text("/hunt on")
    out = engine.handle_text("audit http://127.0.0.1:8941/")
    assert out.data["hunt"]["action"] in ("closed", "started")
    assert len(provider.calls) == 1  # the agent was driven, no prompt fired


# -- 15 (adversarial: no-provider spam) ------------------------------------------


def test_no_provider_spam_fixed_in_repl(store, monkeypatch):
    """Two user lines, no provider: the panel ONCE, then the short line."""
    engine = _no_provider_engine(monkeypatch, store)
    lines = ["hello", "and again", "/quit"]

    printed: list[str] = []

    def _stringify(renderable) -> str:
        if hasattr(renderable, "plain"):
            return renderable.plain
        if hasattr(renderable, "markup"):
            return renderable.markup
        if hasattr(renderable, "renderable"):
            return _stringify(renderable.renderable)
        return str(renderable)

    class RecordingConsole:
        is_terminal = False

        def print(self, *args, **kwargs) -> None:
            for arg in args:
                printed.append(_stringify(arg))

        def input(self, prompt: str = "") -> str:
            printed.append(prompt)
            item = lines.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

        def text(self) -> str:
            return "\n".join(printed)

    run_repl(engine=engine, console=RecordingConsole())
    text = "\n".join(printed)
    assert text.count("Fix it in under a minute") == 1  # panel exactly once
    assert text.count(SHORT_NO_PROVIDER) == 1  # short line on the second turn


# -- 16 --------------------------------------------------------------------------


def test_one_shot_interrupt_exit_130(store, monkeypatch):
    provider = FakeProvider(interrupt=True)
    engine = _engine_builder(store, provider=provider)()
    _patch_build_engine(monkeypatch, lambda **kwargs: engine)
    result = runner.invoke(app=app, args=["chat", "explain the plan"])
    assert result.exit_code == 130, (result.output, result.exception)
    assert "[interrupted]" in result.output
