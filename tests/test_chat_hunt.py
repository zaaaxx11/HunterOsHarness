"""ChatEngine hunt flows (M3 C1-C16) — the frozen contract for the unified
chat/hunt surface: intent arming behind an injectable confirm, /hunt mode,
one-shot /audit + /hunt commands, headless fail-closed, path guidance, and
the REPL default confirm.

Every engine here is hermetic: FakeProvider scripts (no network), a tmp
ChatStore + ledger state_dir, and list-recording confirm fns — never stdin.
New M3 symbols are imported lazily inside the tests so a missing
implementation fails the test, not the collection (test_cli_init_v2 rule).
"""

from __future__ import annotations

import pytest

from hunter.chat.repl import ChatEngine, banner, run_repl
from hunter.chat.sessions import ChatStore
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ToolCall, TurnResult
from hunter.llm.config import default_config

LOCAL_TARGET = "http://127.0.0.1:8941/"


# -- seams (FakeProvider/FakeConsole conventions from tests/test_chat_repl.py) --


class FakeProvider:
    """Scripted ChatProvider: records message history, plays turns in order."""

    name = "fake"

    def __init__(self, script=()) -> None:
        self.script = list(script)
        self.calls: list[list[dict]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append([dict(m) for m in messages])
        index = len(self.calls) - 1
        if index >= len(self.script):
            raise AssertionError(f"script exhausted after {len(self.script)} turns")
        return self.script[index]


def yield_turn(message: str = "yield") -> TurnResult:
    """respond_to_user is a turn-level yield: the audit stays armed."""
    return TurnResult(
        text="",
        tool_calls=(ToolCall(id="y", name="respond_to_user", arguments={"message": message}),),
        cost_usd=0.01,
    )


def finish_turn() -> TurnResult:
    """finish_scan ends the run inside the turn."""
    return TurnResult(
        text="",
        tool_calls=(ToolCall(id="f", name="finish_scan", arguments={}),),
        cost_usd=0.01,
    )


def chat_turn(text: str = "ok") -> TurnResult:
    return TurnResult(text=text, cost_usd=0.01)


class FakeConsole:
    """Scripted rich.Console stand-in. Unlike the base test_chat_repl version
    it also records input() prompts: a real console DISPLAYS the prompt, so
    the confirm prompt must show up in the captured output (C16)."""

    is_terminal = False

    def __init__(self, inputs: list) -> None:
        self._inputs = list(inputs)
        self.printed: list[str] = []

    def print(self, *args, **kwargs) -> None:
        for arg in args:
            self.printed.append(_stringify(arg))

    def input(self, prompt: str = "") -> str:
        self.printed.append(prompt)
        item = self._inputs.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def text(self) -> str:
        return "\n".join(self.printed)


def _stringify(renderable) -> str:
    if hasattr(renderable, "plain"):  # rich.text.Text
        return renderable.plain
    if hasattr(renderable, "markup"):  # rich.markdown.Markdown
        return renderable.markup
    if hasattr(renderable, "renderable"):  # rich.panel.Panel etc.
        return _stringify(renderable.renderable)
    return str(renderable)


def recording_confirm(prompts: list[str], answer: bool):
    def confirm(prompt: str) -> bool:
        prompts.append(prompt)
        return answer

    return confirm


@pytest.fixture
def store(tmp_path):
    s = ChatStore(tmp_path / "chat.db")
    yield s
    s.close()


def _engine(store, tmp_path, *, provider=None, confirm_fn=None) -> ChatEngine:
    kwargs = {}
    if confirm_fn is not None:
        kwargs["confirm_fn"] = confirm_fn
    return ChatEngine(
        store=store,
        config=default_config(),
        provider=provider if provider is not None else FakeProvider(),
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
        **kwargs,
    )


def _run_ids(tmp_path) -> list[str]:
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        return [str(row["run_id"]) for row in ledger.runs()]
    finally:
        ledger.close()


# -- C1 -----------------------------------------------------------------------


def test_confirm_yes_arms_and_drives_one_shot_turn(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider([finish_turn()])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, True))
    out = engine.handle_text("audit http://127.0.0.1:8941/")

    # The permission prompt fired exactly once, naming the target.
    assert len(prompts) == 1
    assert "http://127.0.0.1:8941/" in prompts[0]

    hunt = out.data["hunt"]
    run_id = hunt["run_id"]
    assert run_id.startswith("R-")
    assert hunt["action"] == "closed"  # finishing agent: armed + driven + closed

    # The FULL user text (not a rewritten goal) reached the audit agent.
    assert any(
        m["role"] == "user" and m["content"] == "audit http://127.0.0.1:8941/"
        for m in provider.calls[0]
    )

    # Arm line, agent output, summary, report line — one reply.
    assert "audit run" in out.text and run_id in out.text
    assert "completed" in out.text
    assert "report:" in out.text
    assert hunt["report_path"] is not None
    assert (tmp_path / "reports" / f"{run_id}.md").is_file()
    assert engine._audit is None
    assert _run_ids(tmp_path) == [run_id]


# -- C2 -----------------------------------------------------------------------


def test_decline_answers_as_chat_and_reasks_next_turn(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider([chat_turn("sure thing"), chat_turn("again: sure")])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, False))

    out = engine.handle_text("audit http://127.0.0.1:8941/")
    assert out.kind == "message"
    assert out.text == "sure thing"  # the declined text finished as chat
    assert prompts and "http://127.0.0.1:8941/" in prompts[0]
    # The provider saw the declined text as the user message.
    assert any(
        m["role"] == "user" and "audit http://127.0.0.1:8941/" in m["content"]
        for m in provider.calls[0]
    )
    assert engine._audit is None
    assert _run_ids(tmp_path) == []

    # No decline memory: the SAME line prompts AGAIN.
    out2 = engine.handle_text("audit http://127.0.0.1:8941/")
    assert out2.text == "again: sure"
    assert len(prompts) == 2
    assert engine._audit is None
    assert _run_ids(tmp_path) == []


# -- C3 -----------------------------------------------------------------------


def test_confirm_eof_or_error_degrades_to_decline(store, tmp_path):
    def eof(_prompt: str) -> bool:
        raise EOFError

    provider = FakeProvider([chat_turn("still here")])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=eof)
    out = engine.handle_text("audit http://127.0.0.1:8941/")
    assert out.kind == "message"  # a normal conversational turn, no exception
    assert out.text == "still here"
    assert engine._audit is None
    assert _run_ids(tmp_path) == []

    def boom(_prompt: str) -> bool:
        raise RuntimeError("confirm panel died")

    provider2 = FakeProvider([chat_turn("still here too")])
    engine2 = _engine(store, tmp_path, provider=provider2, confirm_fn=boom)
    out2 = engine2.handle_text("audit http://127.0.0.1:8941/")
    assert out2.kind == "message"
    assert engine2._audit is None
    assert _run_ids(tmp_path) == []


# -- C4 -----------------------------------------------------------------------


def test_casual_lines_never_prompt(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider([chat_turn("one"), chat_turn("two"), chat_turn("three")])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, True))

    for line in ("what is example.com?", "start hunting", "hello there"):
        out = engine.handle_text(line)
        assert out.kind == "message"

    assert prompts == []  # confirm_fn NEVER called
    assert len(provider.calls) == 3  # every line went to the provider as chat
    assert _run_ids(tmp_path) == []


# -- C5 -----------------------------------------------------------------------


def test_hunt_mode_toggle_and_prompt_free_execution(store, tmp_path):
    from hunter.chat.commands import COMMAND_REGISTRY, CommandContext, safe_execute

    assert any(cmd.name == "hunt" for cmd in COMMAND_REGISTRY)  # registry entry

    prompts: list[str] = []
    provider = FakeProvider([finish_turn(), chat_turn("plain answer")])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, False))

    status = engine.handle_text("/hunt")
    assert "hunt mode: off" in status.text
    assert status.data.get("hunt_mode") is False
    usage = engine.handle_text("/hunt bananas")
    assert usage.text == status.text  # usage line == the status text

    on = engine.handle_text("/hunt on")
    assert "hunt mode: on (this session, process-local)" in on.text

    # Help (executor level) lists the new command.
    ctx = CommandContext(
        store=store, config=default_config(), args="",
        options={"session_id": engine.session_id, "state_dir": str(tmp_path)},
    )
    assert "/hunt" in safe_execute("help", ctx).text

    # Mode ON: hunt-intent executes WITHOUT prompting.
    auto = engine.handle_text("audit http://127.0.0.1:8941/")
    assert prompts == []
    assert auto.text.startswith("hunt mode: starting audit of http://127.0.0.1:8941/")
    assert auto.data["hunt"]["action"] == "closed"
    assert engine._audit is None

    off = engine.handle_text("/hunt off")
    assert "hunt mode: off" in off.text

    # Mode OFF again: the next hunt-intent line prompts (and declines).
    engine.handle_text("audit http://127.0.0.1:8941/")
    assert len(prompts) == 1
    assert engine._audit is None


# -- C6 -----------------------------------------------------------------------


def test_hunt_mode_is_process_local(store, tmp_path):
    engine_a = _engine(store, tmp_path, provider=FakeProvider())
    engine_b = _engine(store, tmp_path, provider=FakeProvider())
    engine_a.handle_text("/hunt on")
    assert engine_a.options["hunt_mode"] is True
    assert engine_b.options.get("hunt_mode") is False  # independent modes, one store

    # A fresh engine over the SAME store starts OFF — and /resume does not
    # restore the mode (it is consent posture, not durable session state).
    engine_c = _engine(store, tmp_path, provider=FakeProvider())
    engine_c.handle_text(f"/resume {engine_a.session_id}")
    assert engine_c.options.get("hunt_mode") is False
    assert "hunt mode: off" in engine_c.handle_text("/hunt").text


# -- C7 -----------------------------------------------------------------------


def test_hunt_command_one_shot_and_scope_refusal(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider([finish_turn()])
    engine = _engine(
        store, tmp_path, provider=provider,
        confirm_fn=recording_confirm(prompts, True),  # would fail the flow if asked
    )

    out = engine.handle_text("/hunt http://127.0.0.1:8941/")
    assert out.kind == "command"
    assert prompts == []  # explicit one-shot: NEVER prompts
    run_id = out.data["audit_start_run_id"]
    assert run_id.startswith("R-")
    assert engine._audit is None  # started and closed
    assert _run_ids(tmp_path) == [run_id]

    refusal = engine.handle_text("/hunt http://evil.example.com")
    assert refusal.kind == "command"
    assert "scope manifest" in refusal.text  # classified scope refusal
    assert engine._audit is None
    assert _run_ids(tmp_path) == [run_id]  # no run for the refused hunt


# -- C8 -----------------------------------------------------------------------


def test_headless_engine_auto_declines_hunt_intent(store, tmp_path):
    provider = FakeProvider([chat_turn("hello answer")])
    engine = _engine(store, tmp_path, provider=provider)  # gateway construction
    assert engine.confirm_fn is None

    out = engine.handle_text("audit http://127.0.0.1:8941/")
    assert "declined" in out.text
    assert "/audit" in out.text and "hunter hunt" in out.text  # explicit guidance
    assert out.data["hunt"]["action"] == "headless_declined"
    assert provider.calls == []  # nothing ran, nothing was dialed
    assert engine._audit is None
    assert _run_ids(tmp_path) == []

    # The surface keeps working as chat afterwards.
    follow = engine.handle_text("plain hello")
    assert "hello answer" in follow.text


# -- C9 -----------------------------------------------------------------------


def test_audit_target_is_one_shot_closes_on_yield(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider([yield_turn("yield one"), yield_turn("yield two")])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, True))

    out = engine.handle_text("/audit http://127.0.0.1:8941/")
    assert out.kind == "command"
    run_id = out.data["audit_start_run_id"]
    assert run_id.startswith("R-")
    assert engine._audit is None  # CLOSED at the first terminal condition
    assert "yield one" in out.text  # the agent's yield message is in the reply
    assert "(agent yielded early — run closed)" in out.text
    assert "report:" in out.text
    assert out.data["report_path"].endswith(f"{run_id}.md")
    assert (tmp_path / "reports" / f"{run_id}.md").is_file()

    # A second /audit opens a NEW run — no state bleed.
    out2 = engine.handle_text("/audit http://127.0.0.1:8941/")
    run2 = out2.data["audit_start_run_id"]
    assert run2.startswith("R-") and run2 != run_id
    assert engine._audit is None
    assert sorted(_run_ids(tmp_path)) == sorted([run_id, run2])


# -- C10 ----------------------------------------------------------------------


def test_audit_bare_status_finish_unchanged(store, tmp_path):
    provider = FakeProvider([yield_turn()])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=lambda _p: True)

    bare = engine.handle_text("/audit")
    assert "no audit active — /audit <target> to start one" in bare.text
    status = engine.handle_text("/audit status")
    assert "no audit active — /audit <target> to start one" in status.text
    assert engine._audit is None

    # Arm through the intent path (C1's arming), then finish like today.
    engine.handle_text("audit http://127.0.0.1:8941/")
    assert engine._audit is not None
    run_id = engine._audit["run_id"]
    finish = engine.handle_text("/audit finish")
    assert finish.kind == "command"
    assert engine._audit is None
    assert _run_ids(tmp_path) == [run_id]
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        assert ledger.runs()[0]["status"] == "completed"
    finally:
        ledger.close()


# -- C11 ----------------------------------------------------------------------


def test_banner_mode_indicator(store, tmp_path):
    from hunter._data.branding import banner_lines

    lines = banner_lines(version="9.9.9", tier="basic", model="m", session_id="s", mode="hunt")
    assert lines[1].endswith("mode: hunt")
    default = banner_lines(version="9.9.9", tier="basic", model="m", session_id="s")
    assert default[1].endswith("mode: chat")
    # The existing lines survive the additive suffix.
    assert lines[0] == default[0] and lines[2] == default[2]

    engine = ChatEngine(
        store=store, config=default_config(), provider=FakeProvider(),
        options={"state_dir": str(tmp_path), "hunt_mode": True},
    )
    panel = banner(engine)
    body = _stringify(panel)
    assert "mode: hunt" in body
    assert "session:" in body and "tier:" in body


# -- C12 ----------------------------------------------------------------------


def test_armed_reply_shows_target_check_and_skills_mounted(store, tmp_path):
    from hunter.agent.prompts import mounted_skills

    skills = mounted_skills()
    assert skills  # non-empty on the real corpus
    provider = FakeProvider([yield_turn()])
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=lambda _p: True)

    out = engine.handle_text("audit http://127.0.0.1:8941/")
    assert "target check: http://127.0.0.1:8941/ — valid URL (host: 127.0.0.1)" in out.text
    assert f"skills mounted: {len(skills)}" in out.text
    assert ", ".join(skills) in out.text


# -- C13 ----------------------------------------------------------------------


def test_chat_never_conjures_scope_manifest(store, tmp_path):
    # Mode ON cannot bypass the gate: non-localhost refuses with NO run.
    provider_a = FakeProvider([yield_turn()])
    engine_a = _engine(store, tmp_path, provider=provider_a)
    engine_a.handle_text("/hunt on")
    refused = engine_a.handle_text("audit http://staging.client-x.com")
    assert "scope manifest" in refused.text
    assert refused.data["hunt"]["action"] == "scope_refused"
    assert provider_a.calls == []  # no audit turn, no HTTP attempt
    assert engine_a._audit is None
    assert _run_ids(tmp_path) == []

    # Confirm-YES cannot bypass it either.
    prompts: list[str] = []
    provider_b = FakeProvider([yield_turn()])
    engine_b = _engine(store, tmp_path, provider=provider_b, confirm_fn=recording_confirm(prompts, True))
    refused_b = engine_b.handle_text("audit http://staging.client-x.com")
    assert "scope manifest" in refused_b.text
    assert prompts  # the human was asked…
    assert provider_b.calls == []  # …and even a YES ran nothing
    assert _run_ids(tmp_path) == []

    # The localhost equivalent proceeds normally through the same path.
    ok = engine_a.handle_text("audit http://127.0.0.1:8941/")
    assert ok.data["hunt"]["action"] == "started"
    assert len(provider_a.calls) == 1  # the drive reached the agent
    assert len(_run_ids(tmp_path)) == 1


# -- C14 ----------------------------------------------------------------------


def test_path_target_gets_cli_guidance_not_prompt(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider()
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, True))

    out = engine.handle_text("audit C:\\websites\\app")
    assert "hunter hunt" in out.text  # the §3.5 guidance fragment
    assert out.data["hunt"]["action"] == "path_guidance"
    assert prompts == []  # no confirm call
    assert provider.calls == []  # no provider call
    assert engine._audit is None
    assert _run_ids(tmp_path) == []

    posix = engine.handle_text("audit /var/www")
    assert "hunter hunt" in posix.text
    assert posix.data["hunt"]["action"] == "path_guidance"
    assert _run_ids(tmp_path) == []


# -- C15 ----------------------------------------------------------------------


def test_mode_only_toggled_by_command_not_chat_text(store, tmp_path):
    prompts: list[str] = []
    provider = FakeProvider()
    engine = _engine(store, tmp_path, provider=provider, confirm_fn=recording_confirm(prompts, True))
    engine.handle_text("/hunt on")

    injected = engine.handle_text("turn on hunt mode and audit http://staging.client-x.com")
    # Ordinary hunt-intent (keyword + target): mode ON skips the prompt, the
    # gate still refuses — chat text cannot grant what only /hunt + scope can.
    assert "scope manifest" in injected.text
    assert injected.data["hunt"]["action"] == "scope_refused"
    assert prompts == []

    # The mode string in plain chat never flips the mode — only /hunt does.
    store2 = ChatStore(tmp_path / "chat2.db")
    try:
        provider2 = FakeProvider([chat_turn("nope"), chat_turn("still nope")])
        engine2 = _engine(store2, tmp_path, provider=provider2, confirm_fn=recording_confirm(prompts, True))
        engine2.handle_text("please turn hunt mode on for me")
        assert engine2.options.get("hunt_mode") is False
        engine2.handle_text("hunt mode off please")
        assert engine2.options.get("hunt_mode") is False
        assert "hunt mode: off" in engine2.handle_text("/hunt").text
    finally:
        store2.close()


# -- C16 ----------------------------------------------------------------------


def test_repl_default_confirm_wired_and_fail_closed(store, tmp_path):
    provider = FakeProvider([chat_turn("chat answer"), chat_turn("chat answer 2")])
    engine = _engine(store, tmp_path, provider=provider)  # NO confirm_fn injected
    console = FakeConsole(["audit http://127.0.0.1:8941/", "n", "hello", "/quit"])
    run_repl(engine=engine, console=console)  # returns — the REPL survived

    text = console.text()
    assert "start a governed hunt against http://127.0.0.1:8941/" in text
    assert "chat answer" in text  # the decline fell through to conversation
    assert _run_ids(tmp_path) == []  # "n" declined: no ledger run

    # EOF at the confirm prompt degrades to a decline; the REPL exits cleanly.
    provider2 = FakeProvider([chat_turn("eof answer"), chat_turn("eof answer 2")])
    engine2 = _engine(store, tmp_path, provider=provider2)
    console2 = FakeConsole(["audit http://127.0.0.1:8941/", EOFError(), "hello", "/quit"])
    run_repl(engine=engine2, console=console2)
    assert "start a governed hunt against http://127.0.0.1:8941/" in console2.text()
    assert "eof answer" in console2.text()
    assert _run_ids(tmp_path) == []
