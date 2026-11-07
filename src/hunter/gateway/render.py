"""Telegram rendering: agent markdown in, valid MarkdownV2 out.

Adapted from hermes-agent's Telegram platform adapter. Telegram rejects an entire
message when its MarkdownV2 is malformed, so the rules are:

* stash code first — text inside ``` or `` is never escaped as prose;
* convert the constructs MarkdownV2 spells differently (**bold** -> *bold*,
  *italic* -> _italic_, ## Title -> *Title*, ~~x~~ -> ~x~);
* escape every remaining special character;
* restore the stashed code last, in reverse order so nesting resolves.

Anything that fails still has to arrive, so :func:`strip_mdv2` produces the
plain-text fallback the transport retries with.
"""

from __future__ import annotations

import re

#: Every character MarkdownV2 requires backslash-escaped outside code spans.
_MDV2_ESCAPE_RE = re.compile(r"([_*\[\]()~`>#+\-=|{}.!\\])")

#: A fenced block or an inline span — the two regions never escaped as prose.
_CODE_SPAN_RE = re.compile(r"(```[\s\S]*?```|`[^`\n]+`)")

#: A pipe-table separator row (| --- | :--: |).
_TABLE_RULE_RE = re.compile(r"^[\s|:\-]+$")


def escape_mdv2(text: str) -> str:
    """Escape Telegram MarkdownV2 special characters."""
    return _MDV2_ESCAPE_RE.sub(lambda m: "\\" + m.group(1), text)


def strip_mdv2(text: str) -> str:
    """Undo MarkdownV2 for the plain-text fallback (never send broken markup)."""
    out = re.sub(r"\\([_*\[\]()~`>#+\-=|{}.!\\])", r"\1", text)
    out = re.sub(r"\*\*([^*]+)\*\*", r"\1", out)  # **bold** before *MarkdownV2 bold*
    out = re.sub(r"\*([^*\n]+)\*", r"\1", out)
    out = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"\1", out)  # keep snake_case intact
    out = re.sub(r"~([^~\n]+)~", r"\1", out)
    out = re.sub(r"\|\|([^|\n]+)\|\|", r"\1", out)
    return out


def tables_to_bullets(text: str) -> str:
    """Turn GFM pipe tables into bullet groups — MarkdownV2 has no table syntax."""
    lines = text.split("\n")
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        is_header = (
            line.lstrip().startswith("|")
            and index + 1 < len(lines)
            and _TABLE_RULE_RE.match(lines[index + 1])
            and "|" in lines[index + 1]
        )
        if not is_header:
            out.append(line)
            index += 1
            continue
        header = [cell.strip() for cell in line.strip().strip("|").split("|")]
        cursor = index + 2
        while cursor < len(lines) and lines[cursor].lstrip().startswith("|"):
            row = [cell.strip() for cell in lines[cursor].strip().strip("|").split("|")]
            cells = [f"{h}: {v}" for h, v in zip(header, row) if v]
            if cells:
                out.append("- " + " · ".join(cells))
            cursor += 1
        index = cursor
    return "\n".join(out)


def to_markdown_v2(content: str) -> str:
    """Convert ordinary agent markdown into valid Telegram MarkdownV2."""
    if not content:
        return content

    placeholders: dict[str, str] = {}
    counter = [0]

    def stash(value: str) -> str:
        key = f"\x00H{len(placeholders)}\x00"
        counter[0] += 1
        placeholders[key] = value
        return key

    def stash_wrapped(open_: str, close: str):
        return lambda m: stash(f"{open_}{escape_mdv2(m.group(1))}{close}")

    text = tables_to_bullets(content)

    # 1) Fenced blocks. Per spec \ and ` must be escaped inside pre/code.
    def protect_fenced(m: re.Match) -> str:
        raw = m.group(0)
        # opening fence plus an optional language tag, up to the first newline
        open_end = raw.index("\n") + 1 if "\n" in raw[3:] else 3
        body = raw[open_end:][:-3].replace("\\", "\\\\").replace("`", "\\`")
        return stash(raw[:open_end] + body + "```")

    text = re.sub(r"(```(?:[^\n]*\n)?[\s\S]*?```)", protect_fenced, text)
    # 2) Inline code.
    text = re.sub(r"(`[^`]+`)", lambda m: stash(m.group(0).replace("\\", "\\\\")), text)
    # 3) Links: escape the label; only ')' and '\' need escaping inside the URL.
    def convert_link(m: re.Match) -> str:
        url = m.group(2).replace("\\", "\\\\").replace(")", "\\)")
        return stash(f"[{escape_mdv2(m.group(1))}]({url})")

    text = re.sub(r"\[([^\]]+)\]\(([^()]*(?:\([^()]*\)[^()]*)*)\)", convert_link, text)
    # 4) Headings -> bold, with redundant ** inside the heading removed.
    def convert_header(m: re.Match) -> str:
        inner = re.sub(r"\*\*(.+?)\*\*", r"\1", m.group(1).strip())
        return stash(f"*{escape_mdv2(inner)}*")

    text = re.sub(r"^#{1,6}\s+(.+)$", convert_header, text, flags=re.MULTILINE)
    # 5-8) emphasis. [^*\n] keeps a match on one line so * bullets stay bullets.
    text = re.sub(r"\*\*(.+?)\*\*", stash_wrapped("*", "*"), text)
    text = re.sub(r"\*([^*\n]+)\*", stash_wrapped("_", "_"), text)
    text = re.sub(r"~~(.+?)~~", stash_wrapped("~", "~"), text)
    text = re.sub(r"\|\|(.+?)\|\|", stash_wrapped("||", "||"), text)
    # 9) Blockquotes: keep the > marker, escape only the body.
    text = re.sub(
        r"^((?:\*\*)?>{1,3}) (.+)$",
        lambda m: stash(f"{m.group(1)} {escape_mdv2(m.group(2))}"),
        text,
        flags=re.MULTILINE,
    )
    # 10) Everything left is prose: escape it.
    text = escape_mdv2(text)
    # 11) Restore, reverse order so nested placeholders resolve.
    for key in reversed(list(placeholders)):
        text = text.replace(key, placeholders[key])
    return text


def chunk_text(text: str, limit: int = 4096) -> list[str]:
    """Split ``text`` into Telegram-sized parts without breaking code fences.

    A part that would end mid-fence closes it; the next part reopens it, so each
    message renders on its own.
    """
    if not text.strip():
        return []
    if len(text) <= limit:
        return [text]

    # The (N/M) marker appended to every part is real payload: reserve room for
    # it, or a part sized exactly at the limit overflows once the marker lands.
    limit = max(64, limit - 12)

    parts: list[str] = []
    current: list[str] = []
    size = 0
    fence: str | None = None

    def flush() -> None:
        nonlocal current, size, fence
        body = "\n".join(current)
        if fence is not None:
            body += "\n```"  # close the fence so this message is valid
        parts.append(body)
        # reopen it for the continuation
        current = [fence] if fence is not None else []
        size = len(fence) + 1 if fence is not None else 0

    for line in text.split("\n"):
        stripped = line.lstrip()
        opening = stripped.startswith("```")
        if opening and fence is None:
            fence = "```" + stripped[3:].strip()
        line_len = len(line) + 1
        if size + line_len > limit and current:
            flush()
        # a single line longer than the limit is hard-split
        while len(line) + 1 > limit:
            if current and size:
                flush()
            parts.append(line[: limit - 1])
            line = line[limit - 1 :]
            size = 0
            current = [fence] if fence is not None else []
        current.append(line)
        size += len(line) + 1
        if opening and fence is not None and stripped.rstrip() == fence.rstrip() and len(current) > 1:
            fence = None

    if current:
        parts.append("\n".join(current))

    if len(parts) > 1:
        total = len(parts)
        # The marker is appended to already-rendered MarkdownV2, so its
        # parentheses must be escaped or Telegram rejects the whole message.
        parts = [f"{part}\n\\({i}/{total}\\)" for i, part in enumerate(parts, 1)]
    return [p for p in parts if p.strip()]


def render(content: str) -> str:
    """Entry point: agent markdown -> one MarkdownV2 document."""
    return to_markdown_v2(content or "")
