"""M8 F8 — context compression (test-first): extractive compaction for the
chat surface. The audit loop (AgentLoop) is NOT touched by this feature.

Pins: the 24k threshold, extractive-only bullets (every bullet is a prefix of
a real message), verbatim head/tail, evidence-id preservation, the polish
hook scoped to the summary block, and that compaction never mutates the
ChatStore (append-only chain stays intact).
"""

from __future__ import annotations

from typing import Any

from hunter.chat.compression import (
    COMPACT_MARKER,
    MAX_BULLET_CHARS,
    MAX_SUMMARY_BULLETS,
    compact_history,
    estimate_tokens,
    history_chars,
    should_compact,
)
from hunter.chat.sessions import ChatStore
from hunter.llm.base import TurnResult
from hunter.llm.config import default_config


class RecordingProvider:
    """Deterministic ChatProvider that records each turn's messages."""

    name = "fake"

    def __init__(self) -> None:
        self.calls: list[list[dict[str, Any]]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append([dict(m) for m in messages])
        return TurnResult(text="ok", cost_usd=0.01)


def _long_history(count: int) -> list[dict[str, str]]:
    history = [{"role": "system", "content": "You are the HunterOs chat agent."}]
    for index in range(count):
        role = "user" if index % 2 == 0 else "assistant"
        history.append({"role": role, "content": f"message-{index:02d} " + "detail " * 8})
    return history


def test_should_compact_threshold_and_estimate_tokens():
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("") == 1
    assert estimate_tokens("x" * 9) == 2
    below = [{"role": "user", "content": "a" * 23_999}]
    above = [{"role": "user", "content": "a" * 24_001}]
    assert history_chars(below) == 23_999
    assert should_compact(below) is False
    assert should_compact(above) is True


def test_compact_keeps_head_and_tail_extractively():
    history = _long_history(60)  # first + 59 middle + ... (59 = tail 12 + 47 middle)
    compacted, stats = compact_history(history)
    assert stats["messages_in"] == 60
    assert stats["messages_out"] == 1 + 1 + 12
    assert compacted[0] == history[0]  # first message verbatim
    assert compacted[-12:] == history[-12:]  # tail verbatim
    block = compacted[1]
    assert block["role"] == "system"
    assert block["content"].startswith(COMPACT_MARKER)
    bullet_lines = [line for line in block["content"].splitlines() if line.startswith("- ")]
    assert bullet_lines
    assert len(bullet_lines) <= MAX_SUMMARY_BULLETS  # 47 middle messages -> capped at 40
    for line in bullet_lines:
        head, _, body = line[2:].partition(": ")
        assert head in {"user", "assistant", "system"}
        assert len(body) <= MAX_BULLET_CHARS
        # EXTRACTIVE ONLY: the bullet is a prefix of a real message's first line
        assert any(
            message["role"] == head and message["content"].startswith(body)
            for message in history
        ), line


def test_compact_preserves_evidence_and_run_ids():
    middle = [
        {"role": "user", "content": "check EV-00ff12 shows reflected xss in /search"},
        {"role": "assistant", "content": "run R-abcdef123456 recorded; approval A-abcdef01 pending"},
        {"role": "user", "content": "finding F-0007 shipped with evidence EV-00ff12"},
    ]
    history = [{"role": "system", "content": "system prompt"}]
    history += middle * 10  # 30 middle messages, all compacted away
    history += [{"role": "user", "content": f"tail-{i}"} for i in range(12)]
    compacted, _stats = compact_history(history)
    block = compacted[1]["content"]
    for evidence_id in ("EV-00ff12", "R-abcdef123456", "A-abcdef01", "F-0007"):
        assert evidence_id in block  # ids survive verbatim, never dropped
    assert "EV-deadbeef" not in block  # and none are invented


def test_compact_never_writes_store(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    session_id = store.create_session()
    for index in range(20):
        role = "user" if index % 2 == 0 else "assistant"
        store.append_message(session_id, role, f"row {index:02d} evidence EV-000{index % 10}")
    rows_before = store.messages(session_id)
    chain_before = store.verify_chain(session_id)
    history = [{"role": m["role"], "content": m["content"]} for m in rows_before]
    compacted, _stats = compact_history(history)
    assert len(compacted) < len(history)
    assert len(store.messages(session_id)) == len(rows_before)
    assert store.verify_chain(session_id) == chain_before


def test_engine_auto_compacts_history_over_threshold(tmp_path):
    from hunter.chat.repl import ChatEngine

    store = ChatStore(tmp_path / "chat.db")
    provider = RecordingProvider()
    engine = ChatEngine(store=store, config=default_config(), provider=provider)
    session_id = engine.session_id
    try:
        store.append_message(session_id, "user", "x" * 25_000)
        engine.handle_text("ping")
        seen = provider.calls[0]
        assert seen[-1]["content"] == "ping"  # newest turn verbatim
        assert any(COMPACT_MARKER in m.get("content", "") for m in seen)
        # tail kept: at least the newest 12 rows survive verbatim
        tail_contents = [m["content"] for m in seen[-13:]]
        assert "ping" in tail_contents
    finally:
        engine.close()


def test_compress_command_persists_marker_and_truncates_view(tmp_path):
    from hunter.chat.repl import ChatEngine

    store = ChatStore(tmp_path / "chat.db")
    provider = RecordingProvider()
    engine = ChatEngine(
        store=store, config=default_config(), provider=provider, options={"state_dir": str(tmp_path)}
    )
    session_id = engine.session_id
    try:
        for index in range(15):
            role = "user" if index % 2 == 0 else "assistant"
            store.append_message(session_id, role, f"seed-{index:02d} evidence EV-0001")
        rows_before = store.messages(session_id)
        max_seq_before = max(m["seq"] for m in rows_before)

        out = engine.handle_text("/compress")
        assert out.text.startswith("compacted:")
        assert "store untouched" in out.text
        assert engine.options.get("compact_from_seq") == max_seq_before

        rows_after = store.messages(session_id)
        assert len(rows_after) == len(rows_before) + 1  # exactly one appended row
        marker_rows = [m for m in rows_after if COMPACT_MARKER in m["content"]]
        assert len(marker_rows) == 1
        assert marker_rows[0]["role"] == "assistant"
        assert marker_rows[0]["seq"] == max_seq_before + 1
        chain_ok, _checked, _broken = store.verify_chain(session_id)
        assert chain_ok

        # subsequent history excludes pre-compaction rows but keeps the marker
        provider.calls.clear()
        engine.handle_text("next question")
        seen = provider.calls[0]
        assert any(COMPACT_MARKER in m.get("content", "") for m in seen)
        assert not any(m.get("content") == "seed-00 evidence EV-0001" for m in seen)
        assert seen[-1]["content"] == "next question"
    finally:
        engine.close()


def test_summary_polish_hook_scoped_to_summary():
    history = _long_history(30)
    base, _base_stats = compact_history(history)
    polished, _polished_stats = compact_history(
        history, summary_polish=lambda summary: summary + " [polished]"
    )
    assert polished[0] == base[0]
    assert polished[-12:] == base[-12:]  # head/tail bytes identical
    assert base[1]["content"] + " [polished]" == polished[1]["content"]  # only the block changed
    assert "[polished]" in polished[1]["content"]
