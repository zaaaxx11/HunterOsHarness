#!/usr/bin/env python3
"""compress_session — extractive compaction report for one chat session.

Prints what a `/compress`-style compaction of the session's live history
would look like: head and tail kept verbatim, the middle summarized
EXTRACTIVELY (every bullet is a prefix of a real message; evidence ids are
never dropped or invented). Nothing is written unless ``--apply`` is passed,
and ``--apply`` only APPENDS the summary block as a normal assistant row —
the store stays append-only and the hash chain intact.

Exit codes: 0 ok, 1 error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from hunter.chat.sessions import ChatStore  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="compress_session", description=__doc__)
    parser.add_argument("--session", required=True, help="chat session id")
    parser.add_argument("--state", default=".hunter", help="state directory (default ./.hunter)")
    parser.add_argument("--apply", action="store_true", help="append the summary block (append-only)")
    return parser


def _load_compression():
    try:
        from hunter.chat import compression
    except ImportError as exc:
        print(
            "[ERROR config] hunter.chat.compression is unavailable — "
            f"update the harness install ({exc})",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_ERROR) from exc
    return compression


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    compression = _load_compression()
    db_path = Path(args.state) / "chat.db"
    store = ChatStore(db_path)
    try:
        if store.get_session(args.session) is None:
            print(f"[ERROR engine] session '{args.session}' not found in {db_path}", file=sys.stderr)
            return EXIT_ERROR
        history = [
            {"role": str(row["role"]), "content": str(row["content"])}
            for row in store.messages(args.session)
        ]
        if not compression.should_compact(history):
            print(
                f"no compaction needed: {len(history)} messages / "
                f"{compression.history_chars(history)} chars "
                f"(threshold {compression.COMPACT_THRESHOLD_CHARS} chars)"
            )
            return EXIT_OK
        compacted, stats = compression.compact_history(history)
        if not args.apply:
            print("compaction report (nothing written — pass --apply):")
        else:
            block = next(
                (m["content"] for m in compacted if m.get("role") == "system"),
                "",
            )
            if not block:
                print("[ERROR engine] compaction produced no summary block", file=sys.stderr)
                return EXIT_ERROR
            store.append_message(args.session, "assistant", block)
            ok, count, broken_at = store.verify_chain(args.session)
            if not ok:
                print(f"[ERROR ledger] chat chain broken at {broken_at}", file=sys.stderr)
                return EXIT_ERROR
            print(f"summary appended as an assistant row (chain ok, {count} rows)")
        print(
            f"compacted: {stats['messages_in']} messages / {stats['chars_in']} chars "
            f"-> {stats['chars_out']} chars (store untouched)"
        )
        return EXIT_OK
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
