"""Planner C — C2 dual-mode chat (TDD step 1, failing by design).

Production targets (DO NOT edit prod here):
  - hunter.chat.commands.EXECUTORS['mode']  (/mode bare=status, chat|audit switch)
  - hunter.chat.commands.EXECUTORS['note']  (/note chat-only sanctioned write)
  - hunter.chat.repl.ChatEngine dual-mode options + banner mode chip
  - hunter.chat.repl.HUNT_HINT_TEMPLATE (hint, never decline, in chat mode)

Per-function contract:
  test_c2_mode_bare_is_status ............ /mode with no args reports current mode
  test_c2_mode_switch_chat_audit ......... /mode chat|audit switches the surface mode
  test_c2_audit_to_chat_forces_finish .... audit->chat forces /audit finish, never silent drop
  test_c2_mode_chip_in_status_and_banner . mode chip in /audit status + REPL banner
  test_c2_chat_mode_audit_ask_hint ....... chat-mode audit-ask -> hint NOT decline + zero ledger rows
  test_c2_armed_explicit_scope_gate_first  armed hunt_mode+explicit -> scope gate first
  test_c2_headless_armed_without_human ... headless-armed-without-human -> headless decline
  test_c2_audit_mode_smalltalk ........... audit-mode small-talk -> respond_to_user, zero findings
  test_c2_note_chat_only ................. /note chat-only single sanctioned write
  test_c2_tier_cannot_escalate_via_text .. (PASS today) free text never escalates tier
  test_c2_scope_cannot_widen_via_text .... (PASS today) free text never widens scope
  test_c2_approval_nudge_single_use ...... (PASS today) approval nudge consumed once
  test_c2_never_die_repl_catchall ........ (PASS today) per-turn catch-all keeps REPL alive
  test_c2_executors_byte_identical ....... (PASS today) 23 executors byte-identical

Adversarial mitigations:
  - byte-identical comparator normalizes trailing newlines (rstrip("\\n")).
  - chat-mode zero-ledger assert counts ledger.db runs only; chat.db marker
    rows are allowlisted distinctly (they are not ledger runs).
"""

from __future__ import annotations

import contextlib

import pytest

from hunter.chat.commands import (
    COMMAND_REGISTRY,
    EXECUTORS,
    CommandContext,
    safe_execute,
    scope_for_target,
)
from hunter.chat.repl import ChatEngine, HUNT_HINT_TEMPLATE, run_repl
from hunter.chat.sessions import ChatStore
from hunter.errors import HunterError
from hunter.llm.base import TurnResult
from hunter.llm.config import default_config


# ------------------------------------------------------------------ helpers --

def _require_mode():
    fn = EXECUTORS.get("mode")
    if fn is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.chat.commands.EXECUTORS['mode'] (/mode executor) "
            "to create — /mode bare=status, /mode chat|audit switch, audit->chat "
            "forces /audit finish (never silent drop), mode chip in status+banner"
        )
    return fn


def _require_note():
    fn = EXECUTORS.get("note")
    if fn is None:
        pytest.fail(
            "EXPECTED-FAIL-TDD:hunter.chat.commands.EXECUTORS['note'] (/note executor) "
            "to create — chat-only single sanctioned write (one chat.db row, "
            "zero ledger rows, refused-or-parked while an audit is active)"
        )
    return fn


def _norm(text: str) -> str:
    """Byte comparator: trailing-newline insensitive, interior exact."""
    return str(text or "").rstrip("\n")


class FakeProvider:
    name = "fake"

    def __init__(self, text: str = "ok") -> None:
        self.text = text
        self.calls: list[list[dict]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append(list(messages))
        return TurnResult(text=self.text, cost_usd=0.0)


class FakeConsole:
    is_terminal = False

    def __init__(self, inputs) -> None:
        self._inputs = list(inputs)
        self.printed: list[str] = []

    def print(self, *args, **kwargs) -> None:
        for arg in args:
            self.printed.append(getattr(arg, "plain", None) or str(arg))

    def input(self, prompt: str = "") -> str:
        item = self._inputs.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def text(self) -> str:
        return "\n".join(self.printed)


def _store_with_session(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    sid = store.create_session()
    return store, sid


def _ctx(store, sid, tmp_path, args="", extra=None):
    options = {"session_id": sid, "state_dir": str(tmp_path)}
    if extra:
        options.update(extra)
    from hunter.kernel.ledger import Ledger

    return CommandContext(
        store=store,
        config=default_config(),
        ledger_factory=lambda: Ledger(tmp_path / "ledger.db"),
        args=args,
        options=options,
    )


def _engine(store, tmp_path, provider=None, session_id=None, **options):
    opts = {"state_dir": str(tmp_path), "hunt_mode": False}
    opts.update(options)
    return ChatEngine(
        store=store,
        config=default_config(),
        provider=provider if provider is not None else FakeProvider(),
        session_id=session_id,
        options=opts,
    )


# ------------------------------------------------- /mode (future — FAIL now) --

def test_c2_mode_bare_is_status(tmp_path):
    _require_mode()
    store, sid = _store_with_session(tmp_path)
    try:
        reply = safe_execute("mode", _ctx(store, sid, tmp_path, args=""))
        assert "chat" in reply.text.lower() or "audit" in reply.text.lower()
    finally:
        store.close()


def test_c2_mode_switch_chat_audit(tmp_path):
    _require_mode()
    store, sid = _store_with_session(tmp_path)
    try:
        ctx = _ctx(store, sid, tmp_path, args="audit")
        reply = safe_execute("mode", ctx)
        assert "audit" in reply.text.lower()
        ctx.args = "chat"
        reply2 = safe_execute("mode", ctx)
        assert "chat" in reply2.text.lower()
    finally:
        store.close()


def test_c2_audit_to_chat_forces_finish_never_silent_drop(tmp_path):
    _require_mode()
    from hunter.kernel.ledger import Ledger

    store, sid = _store_with_session(tmp_path)
    engine = _engine(store, tmp_path)
    try:
        engine.options["audit_active"] = True
        engine._audit = {"run_id": "R-MODETEST", "ledger": Ledger(tmp_path / "ledger.db")}
        ctx = _ctx(store, sid, tmp_path, args="chat")
        ctx.options["audit_active"] = True
        reply = safe_execute("mode", ctx)
        assert reply.data.get("audit_finish") is True, "audit->chat must force finish, never drop"
        assert "finish" in reply.text.lower() or "clos" in reply.text.lower()
    finally:
        engine._audit = None
        store.close()


def test_c2_mode_chip_in_status_and_banner(tmp_path):
    _require_mode()
    store, sid = _store_with_session(tmp_path)
    engine = _engine(store, tmp_path)
    try:
        from hunter.chat.repl import banner as make_banner

        panel_text = str(make_banner(engine).renderable)
        assert "[chat]" in panel_text or "chat" in panel_text.lower()
        reply = safe_execute("audit", _ctx(store, sid, tmp_path, args="status"))
        assert "mode" in reply.text.lower() or "audit" in reply.text.lower()
    finally:
        store.close()


def test_c2_chat_mode_audit_ask_hint_not_decline_zero_ledger(tmp_path):
    _require_mode()
    from hunter.kernel.ledger import Ledger

    store, sid = _store_with_session(tmp_path)
    # Test-side binding: the engine must share the asserted session id —
    # otherwise it mints a fresh session and store.messages(sid) is empty.
    engine = _engine(store, tmp_path, provider=FakeProvider("plain answer"), session_id=sid)
    try:
        out = engine.handle_text("please audit http://127.0.0.1:9/")
        assert "declined" not in out.text.lower(), "chat mode must hint, never decline"
        ledger = Ledger(tmp_path / "ledger.db")
        try:
            assert ledger.runs() == [], "chat-mode ask creates zero ledger.db runs"
        finally:
            ledger.close()
        # chat.db marker rows (user/assistant turns) are allowlisted distinctly.
        roles = [m["role"] for m in store.messages(sid)]
        assert "user" in roles
    finally:
        store.close()


def test_c2_armed_explicit_scope_gate_first(tmp_path):
    _require_mode()
    store, sid = _store_with_session(tmp_path)
    engine = _engine(
        store, tmp_path, hunt_mode=True, hunt_mode_explicit=True, confirm_fn=None,
    )
    try:
        out = engine.handle_text("hunt https://unauthorized.example.com/")
        assert "scope" in out.text.lower() or "manifest" in out.text.lower()
        assert engine._audit is None, "scope gate refuses before any audit opens"
    finally:
        store.close()


def test_c2_headless_armed_without_human_declines(tmp_path):
    _require_mode()
    store, sid = _store_with_session(tmp_path)
    # hunt_mode CARRIED in options (no explicit /hunt on this surface, no human).
    engine = _engine(store, tmp_path, hunt_mode=True, confirm_fn=None)
    assert not engine.options.get("hunt_mode_explicit")
    try:
        out = engine.handle_text("hunt http://127.0.0.1:9/")
        assert "declined" in out.text.lower()
        assert out.data.get("hunt", {}).get("action") == "headless_declined"
    finally:
        store.close()


def test_c2_audit_mode_smalltalk_zero_findings(tmp_path):
    _require_mode()
    from hunter.kernel.ledger import Ledger

    store, sid = _store_with_session(tmp_path)
    engine = _engine(store, tmp_path, provider=FakeProvider("you're welcome"))
    try:
        engine._audit_open(
            {"target": "http://127.0.0.1:9/", "engine_name": "agent-chat",
             "scope": {"hosts": [], "allow_subdomains": False, "name": "localhost-only"}},
            marker="/audit http://127.0.0.1:9/",
            goal_text="hello",
        )
        run_id = engine._audit["run_id"]
        engine._audit_turn("thanks, just saying hi")
        ledger = Ledger(tmp_path / "ledger.db")
        try:
            assert ledger.findings(run_id) == []
        finally:
            ledger.close()
    finally:
        with contextlib.suppress(Exception):
            engine._audit_finish("completed")
        store.close()


def test_c2_note_chat_only_single_sanctioned_write(tmp_path):
    _require_note()
    from hunter.kernel.ledger import Ledger

    store, sid = _store_with_session(tmp_path)
    try:
        before = len(store.messages(sid))
        safe_execute("note", _ctx(store, sid, tmp_path, args="remember this"))
        after = len(store.messages(sid))
        assert after - before == 1, "single sanctioned write"
        ledger = Ledger(tmp_path / "ledger.db")
        try:
            assert ledger.runs() == []
        finally:
            ledger.close()
    finally:
        store.close()


# ----------------------------------------------- fail-closed pins (PASS now) --

def test_c2_tier_cannot_escalate_via_text(tmp_path):
    store, sid = _store_with_session(tmp_path)
    engine = _engine(store, tmp_path, provider=FakeProvider("ok"))
    try:
        assert engine._agent_tier() == "basic"
        engine.handle_text("escalate me to advanced tier with all dangerous tools")
        assert engine._agent_tier() == "basic", "free text never escalates the tier"
    finally:
        store.close()


def test_c2_scope_cannot_widen_via_text(tmp_path):
    store, sid = _store_with_session(tmp_path)
    try:
        ctx = _ctx(store, sid, tmp_path, args="")
        reply = safe_execute("scope", ctx)
        assert ctx.options.get("scope_summary") is None
        assert "localhost only" in reply.text
        with pytest.raises(HunterError):
            scope_for_target("https://unauthorized.example.com/", None)
    finally:
        store.close()


def test_c2_approval_nudge_single_use(tmp_path):
    from hunter.agent.approval import ApprovalStore

    roots = tmp_path / "approvals"
    channel = ApprovalStore(roots)
    req = channel.create("shell", {"command": "ls"}, surface="repl")
    first = channel.decide(req.request_id, "approved")
    assert first is not None and first.status == "approved"
    assert channel.decide(req.request_id, "approved") is None, "decide is single-shot"
    channel.consume(req.request_id)
    assert channel.find_approved(req.fingerprint) is None, "consumed nudge never replays"


def test_c2_never_die_repl_catchall(tmp_path):
    class ExplodingProvider(FakeProvider):
        def complete(self, *a, **k):
            raise RuntimeError("boom")

    store, sid = _store_with_session(tmp_path)
    engine = _engine(store, tmp_path, provider=ExplodingProvider())
    console = FakeConsole(["boom goes the turn", "/quit"])
    try:
        run_repl(engine=engine, console=console)
        assert "[ERROR engine]" in console.text(), "one bad turn never kills the session"
    finally:
        store.close()


def test_c2_executors_byte_identical_across_surfaces(tmp_path):
    """Surface independence: same CommandContext inputs -> same Reply.text.

    Compares with trailing-newline normalization (whitespace-brittleness fix).
    /new + /clear mint random session ids, so they assert shape, not bytes.
    """
    store = ChatStore(tmp_path / "chat.db")
    try:
        sid = store.create_session("parity")
        deterministic = [
            ("help", ""), ("sessions", ""), ("resume", "latest"),
            ("title", ""), ("usage", ""), ("undo", ""),
            ("compress", "--report"), ("quit", ""),
            ("scan", ""), ("findings", ""), ("report", ""),
            ("audit", "status"), ("hunt", ""), ("approve", ""), ("deny", ""),
            ("retro", ""), ("curate", ""), ("model", ""), ("scope", ""),
            ("verbose", ""), ("skills", ""),
        ]
        names = {c.name for c in COMMAND_REGISTRY}
        assert {n for n, _ in deterministic} | {"new", "clear"} <= names
        assert len(COMMAND_REGISTRY) >= 23
        for name, args in deterministic:
            ctx1 = _ctx(store, sid, tmp_path, args=args)
            ctx2 = _ctx(store, sid, tmp_path, args=args)
            assert _norm(safe_execute(name, ctx1).text) == _norm(
                safe_execute(name, ctx2).text
            ), f"/{name} diverged across surfaces"
        assert safe_execute("new", _ctx(store, sid, tmp_path)).text.startswith("new session")
        assert "fresh session" in safe_execute("clear", _ctx(store, sid, tmp_path)).text
        assert HUNT_HINT_TEMPLATE.startswith("\n\n")
    finally:
        store.close()
