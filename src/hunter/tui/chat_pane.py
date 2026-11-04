"""Chat pane — embed HunterOs ChatEngine inside a Textual widget.

Yields a :class:`ChatPane` that plugs the full conversational REPL
(``hunter.chat.repl.ChatEngine``) into a Textual ``RichLog`` area with
an ``Input`` bar at the bottom. Every turn is asynchronous; the TUI
stays responsive. /scan and /audit create ledger runs; everything else
is a chat turn.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.containers import Vertical
from textual.widgets import Input, RichLog


class ChatPane(Vertical, can_focus=True):
    """A single chat surface wrapping the ChatEngine."""

    def __init__(
        self,
        *,
        state_dir: str | Path | None = None,
        provider_name: str = "",
        session_name: str = "tui-chat",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._state_dir = str(Path(state_dir or "~/.hunter").expanduser())
        self._provider_name = provider_name
        self._session_name = session_name
        self._engine: Any = None

    def compose(self) -> Any:
        from textual.containers import Vertical
        from textual.widgets import Input, RichLog

        yield RichLog(id="chat-log", markup=True, highlight=True, wrap=True, max_lines=5000, auto_scroll=True)
        yield Input(placeholder="Chat with HunterOs…  ( /help for commands )", id="chat-input")

    def on_mount(self) -> None:
        self._init_engine()
        log = self.query_one("#chat-log", RichLog)
        log.write(Text("HunterOs Chat — type /help for commands, /scan URL to hunt", style="dim italic"))
        self.query_one("#chat-input", Input).focus()

    def _init_engine(self) -> None:
        with contextlib.suppress(Exception):
            from hunter.chat.repl import ChatEngine
            self._engine = ChatEngine(
                state_dir=self._state_dir,
                session=self._session_name,
                provider_name=self._provider_name or "",
            )

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        log = self.query_one("#chat-log", RichLog)
        log.write(Text(f"│ {text}", style="bold"))
        await self._do_turn(text, log)

    @worker(exclusive=True, group="chat", exit_on_error=False)
    async def _do_turn(self, text: str, log: RichLog) -> None:
        if self._engine is None:
            self._init_engine()
        if self._engine is None:
            log.write(Text("Chat engine not available — check your LLM config.", style="red"))
            return
        try:
            output = await asyncio.to_thread(self._engine.handle_text, text)
            for line in output.get("lines", []) or []:
                log.write(Text(line))
            # Also check for fallback keys
            reply = output.get("reply") or ""
            if reply:
                log.write(Text(reply))
        except Exception as exc:
            log.write(Text(f"└ Error: {type(exc).__name__}: {exc}", style="red"))