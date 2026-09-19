"""R2-C /note queue (TDD RED — EXPECTED-FAIL-R2C).

Prod targets (READ ONLY, do NOT edit):
- hunter.chat.notes (NEW): park_note / flush_notes / NOTE_CAP / RENAME_NOTE
- hunter.chat.commands.EXECUTORS['note'] queue path (parked while audit active)
- hunter.chat.repl.ChatEngine._audit_turn_result / _audit_finish flush hook
- per-fn -> prod:
  parked run_id None never audit_turn -> hunter.chat.notes.park_note
  flush finish announces N ledger unchanged + EV sweep -> hunter.chat.notes.flush_notes
  cap 20 -> hunter.chat.notes.NOTE_CAP
  refused no-session -> hunter.chat.commands._exec_note (no-session branch)
  rename documented -> hunter.chat.notes.RENAME_NOTE (doc string)

TDD red: every test fails via EXPECTED-FAIL-R2C until the queue lands.
Mock only: tmp ChatStore/Ledger, no sockets/sleep/TUI loop.
Adversarial: rstrip comparator; ledger.db runs counted only (chat.db rows
allowlisted distinctly); seeded content (no randomness).
"""
from __future__ import annotations

import pytest

R2C = "EXPECTED-FAIL-R2C:/note queue (R2-C note)"
NOTE_CAP_EXPECTED = 20


def _require_notes():
    try:
        import hunter.chat.notes as notes  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{R2C} — hunter.chat.notes missing (park/flush/cap/rename)")
    return notes


def _norm(text: str) -> str:
    return str(text or "").rstrip("\n").rstrip()


def _store_with_session(tmp_path):
    from hunter.chat.sessions import ChatStore

    store = ChatStore(tmp_path / "chat.db")
    sid = store.create_session("r2c-note")
    return store, sid


def _ctx(store, sid, tmp_path, args="", extra=None):
    from hunter.chat.commands import CommandContext
    from hunter.kernel.ledger import Ledger
    from hunter.llm.config import default_config

    options = {"session_id": sid, "state_dir": str(tmp_path)}
    if extra:
        options.update(extra)
    return CommandContext(
        store=store,
        config=default_config(),
        ledger_factory=lambda: Ledger(tmp_path / "ledger.db"),
        args=args,
        options=options,
    )


def test_r2c_note_parked_run_id_none_never_audit_turn(tmp_path, monkeypatch):
    """Parked note carries run_id None and never drives an audit turn."""
    notes = _require_notes()
    park = getattr(notes, "park_note", None)
    if park is None:
        pytest.fail(f"{R2C} — hunter.chat.notes.park_note missing")
    from hunter.chat.repl import ChatEngine
    from hunter.llm.base import TurnResult

    store, sid = _store_with_session(tmp_path)
    try:
        from hunter.llm.config import default_config

        class _P:
            name = "fake"

            def complete(self, *a, **k):
                return TurnResult(text="ok")

        engine = ChatEngine(store=store, config=default_config(),
                            provider=_P(), session_id=sid,
                            options={"state_dir": str(tmp_path)})
        calls: list[str] = []
        monkeypatch.setattr(engine, "_audit_turn", lambda *a, **k: calls.append("audit_turn") or "x")
        engine.options["audit_active"] = True
        parked = park(engine, "remember parked thought")
        assert parked is not None
        assert getattr(parked, "run_id", None) is None, "parked note run_id must be None"
        assert calls == [], "parked note must never drive _audit_turn"
    finally:
        store.close()


def test_r2c_note_flush_finish_announces_n_ledger_unchanged_ev_sweep(tmp_path):
    """Flush on /audit finish announces N, leaves ledger runs unchanged, sweeps EV ids."""
    notes = _require_notes()
    flush = getattr(notes, "flush_notes", None)
    if flush is None:
        pytest.fail(f"{R2C} — hunter.chat.notes.flush_notes missing")
    from hunter.kernel.ledger import Ledger

    store, sid = _store_with_session(tmp_path)
    try:
        for i in range(3):
            store.append_message(sid, "user", f"note: parked-{i} EV-00ab R-abcdef123456")
        ledger = Ledger(tmp_path / "ledger.db")
        try:
            before = list(ledger.runs())
        finally:
            ledger.close()
        text = flush(store, sid)
        assert "3" in _norm(text), "finish must announce N flushed"
        ledger2 = Ledger(tmp_path / "ledger.db")
        try:
            assert ledger2.runs() == before, "flush never writes ledger.db runs"
        finally:
            ledger2.close()
        blob = "\n".join(m["content"] for m in store.messages(sid))
        assert "EV-00ab" in blob, "EV ids sweep into the flushed view"
    finally:
        store.close()


def test_r2c_note_cap_20(tmp_path):
    """Queue cap is exactly 20; the 21st park is refused (single sanctioned bound)."""
    notes = _require_notes()
    cap = getattr(notes, "NOTE_CAP", None)
    park = getattr(notes, "park_note", None)
    if cap is None or park is None:
        pytest.fail(f"{R2C} — hunter.chat.notes.NOTE_CAP/park_note missing")
    assert cap == NOTE_CAP_EXPECTED == 20
    store, sid = _store_with_session(tmp_path)
    try:
        from hunter.chat.repl import ChatEngine
        from hunter.llm.base import TurnResult
        from hunter.llm.config import default_config

        class _P:
            name = "fake"

            def complete(self, *a, **k):
                return TurnResult(text="ok")

        engine = ChatEngine(store=store, config=default_config(),
                            provider=_P(), session_id=sid,
                            options={"state_dir": str(tmp_path), "audit_active": True})
        for i in range(20):
            park(engine, f"thought-{i:02d}")
        with pytest.raises(ValueError):
            park(engine, "thought-21-overflow")
    finally:
        store.close()


def test_r2c_note_refused_no_session(tmp_path):
    """No active session -> 'no active session' refusal (never a traceback)."""
    _require_notes()
    from hunter.chat.commands import safe_execute

    store, _ = _store_with_session(tmp_path)
    try:
        ctx = _ctx(store, None, tmp_path, args="hello without session")
        ctx.options.pop("session_id", None)
        reply = safe_execute("note", ctx)
        assert "no active session" in _norm(reply.text).lower()
    finally:
        store.close()


def test_r2c_note_rename_documented():
    """Rename path is documented in the NEW module (no silent /note drift)."""
    notes = _require_notes()
    doc = getattr(notes, "RENAME_NOTE", "") or (notes.__doc__ or "")
    assert "rename" in str(doc).lower(), f"{R2C} — rename documentation missing"
