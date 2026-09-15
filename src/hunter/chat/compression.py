"""Extractive context compression for the chat surface (M8 F8).

The chat brain is the orchestrator tier with a bounded context window. Long
sessions are compacted EXTRACTIVELY — every bullet is a prefix of a real
message, evidence ids are retained verbatim (never dropped, never invented),
and nothing is ever summarized INTO existence. The ChatStore is append-only
and is NEVER mutated by compaction: the view is rebuilt per turn.

Contract (pinned in docs/plans/v0.5/M8-ninja.md):
- the first message and the last ``TAIL_KEEP_MESSAGES`` stay verbatim;
- the middle span becomes ONE ``{"role": "system"}`` block starting with
  ``COMPACT_MARKER``, holding extractive bullets (``- role: <first 120 chars
  of first line>``, capped at ``MAX_SUMMARY_BULLETS``) PLUS every original
  line matching ``EVIDENCE_ID_RE`` in full (deduped, <=60 lines);
- ``summary_polish`` (optional LLM hook) may rewrite ONLY the block.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

__all__ = [
    "COMPACT_MARKER",
    "COMPACT_THRESHOLD_CHARS",
    "EVIDENCE_ID_RE",
    "MAX_BULLET_CHARS",
    "MAX_SUMMARY_BULLETS",
    "TAIL_KEEP_MESSAGES",
    "compact_history",
    "estimate_tokens",
    "history_chars",
    "should_compact",
]

COMPACT_THRESHOLD_CHARS = 24_000  # ~6k tokens at the 4-chars/token heuristic
TAIL_KEEP_MESSAGES = 12
MAX_SUMMARY_BULLETS = 40
MAX_BULLET_CHARS = 120
MAX_EVIDENCE_LINES = 60
COMPACT_MARKER = "[compacted history]"

# Evidence ids must never be dropped or invented: EV-<hex>, R-<12 hex>,
# A-<8 hex>, F-<digits> (approval requests carry the same A- shape).
EVIDENCE_ID_RE = re.compile(r"\b(?:EV-[0-9a-f]+|R-[0-9a-f]{12}|A-[0-9a-f]{8}|F-\d+)\b")


def estimate_tokens(text: str) -> int:
    """Cheap 4-chars/token heuristic; never returns less than 1."""
    return max(1, len(str(text or "")) // 4)


def history_chars(history: Iterable[dict[str, Any]]) -> int:
    """Total content characters across the history (roles excluded)."""
    return sum(len(str(message.get("content", ""))) for message in history)


def should_compact(
    history: Iterable[dict[str, Any]], *, threshold_chars: int = COMPACT_THRESHOLD_CHARS
) -> bool:
    """True when the history's content size crosses ``threshold_chars``."""
    return history_chars(history) >= threshold_chars


def _bullet(role: str, content: str) -> str:
    """``- role: <first 120 chars of the first line>`` — extractive only."""
    first_line = str(content or "").splitlines()[0] if str(content or "").strip() else ""
    body = first_line[:MAX_BULLET_CHARS]
    return f"- {role}: {body}"


def _evidence_lines(messages: list[dict[str, Any]]) -> list[str]:
    """Every original line carrying an evidence id, in first-seen order,
    deduped, capped at MAX_EVIDENCE_LINES — ids survive verbatim."""
    seen: set[str] = set()
    lines: list[str] = []
    for message in messages:
        for line in str(message.get("content", "")).splitlines():
            if not EVIDENCE_ID_RE.search(line):
                continue
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)
            if len(lines) >= MAX_EVIDENCE_LINES:
                return lines
    return lines


def _summary_block(
    messages: list[dict[str, Any]], *, summary_polish: Callable[[str], str] | None
) -> dict[str, str]:
    lines = [
        COMPACT_MARKER,
        f"Summary of {len(messages)} earlier messages (extractive — nothing added):",
    ]
    lines.extend(
        _bullet(str(m.get("role", "")), str(m.get("content", ""))) for m in messages[:MAX_SUMMARY_BULLETS]
    )
    lines.extend(_evidence_lines(messages))
    content = "\n".join(lines)
    if summary_polish is not None:
        # The polish hook may rewrite ONLY this block — never the verbatim
        # head/tail messages around it.
        content = str(summary_polish(content))
    return {"role": "system", "content": content}


def compact_history(
    history: list[dict[str, Any]], *, summary_polish: Callable[[str], str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Fold the middle span of ``history`` into one extractive system block.

    Returns ``(compacted, stats)`` with
    ``stats = {"messages_in", "messages_out", "chars_in", "chars_out"}``.
    ``messages_in`` counts the compaction INPUT — every message after the
    verbatim head (the head is passed through untouched, never folded);
    ``messages_out`` counts the rows of the resulting view (head + block +
    tail). The input list is never mutated; the first message and the last
    ``TAIL_KEEP_MESSAGES`` messages are kept verbatim. Short histories
    (<= TAIL_KEEP_MESSAGES + 1) have no middle span, so the block is simply
    prepended without duplicating the head.
    """
    messages = [dict(message) for message in history]
    chars_in = history_chars(messages)
    block = _summary_block(messages[1 : len(messages) - TAIL_KEEP_MESSAGES], summary_polish=summary_polish)
    if len(messages) <= TAIL_KEEP_MESSAGES + 1:
        compacted = [block, *messages]
    else:
        compacted = [messages[0], block, *messages[-TAIL_KEEP_MESSAGES:]]
    stats = {
        "messages_in": max(0, len(messages) - 1),
        "messages_out": len(compacted),
        "chars_in": chars_in,
        "chars_out": history_chars(compacted),
    }
    return compacted, stats
