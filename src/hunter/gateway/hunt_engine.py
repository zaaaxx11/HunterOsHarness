"""Gateway engine backed by the hunteros session + chunked hunt loop.

The messaging gateway (Telegram, Discord, ...) keeps one engine per chat. This
engine routes a chat line the same way the ``hunteros`` shell does:

    "/..."  -> the slash-command registry (32 commands) against a HuntSession
    text    -> plain chat with the model

and the hunt itself runs through ``hunter.workflow.loop_v3`` (chunked units,
tool-choice enforcement, 4-layer verification) — not the legacy audit path.

Progress is pushed back to the chat through an injected ``notify`` callable so a
long hunt is not a single silent reply.
"""
from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from hunter.cli.spinner import ProgressLine


@dataclass
class TurnOutput:
    """The shape ``GatewayApp.handle_message`` reads (``out.text``)."""

    text: str = ""
    kind: str = "text"
    meta: dict = field(default_factory=dict)


class HuntGatewayEngine:
    """One hunt session, reachable from a chat transport."""

    def __init__(
        self,
        *,
        session_key: str = "gateway",
        state_dir: str | None = None,
        config: Any = None,
        options: dict | None = None,
        notify: Any = None,
    ) -> None:
        # imports are local so the gateway keeps working without the CLI extras
        from hunter.cli.commands import core as _core  # noqa: F401 - registers
        from hunter.cli.commands import registry as _registry
        from hunter.cli.shell import LLMAdapter, build_provider
        from hunter.session import HuntSession
        import hunter.verify as _verify

        self._registry = _registry
        self._verify = _verify
        self._notify = notify
        self.session_key = session_key
        self.options = dict(options or {})

        self.session = HuntSession(name=session_key)
        self.session._chat = self._chat

        self._llm = None
        self._llm_tiers: dict = {}
        self._ensure_llm()
        self.session._engine = self._run_hunt

    def _ensure_llm(self) -> Any:
        """(Re)build the model client whenever /model or /set changed the tiers.

        Without this a mid-chat /model only edited session state: the provider
        was built once at construction, so the change never reached the wire.
        """
        from hunter.cli.shell import LLMAdapter, build_provider

        tiers = dict(self.session.model_tiers or {})
        if self._llm is not None and tiers == self._llm_tiers:
            return self._llm
        provider = build_provider(tiers)
        self._llm = LLMAdapter(provider, tier="hunter") if provider is not None else None
        self._llm_tiers = tiers
        return self._llm

    # -- helpers -----------------------------------------------------------
    @property
    def notify(self) -> Any:
        """Out-of-band push hook (set by the gateway once a transport exists)."""
        return self._notify

    @notify.setter
    def notify(self, fn: Any) -> None:
        self._notify = fn

    @property
    def session_id(self) -> str:
        return self.session.id

    def _say(self, text: str) -> None:
        """Push an out-of-band progress line to the chat, when wired."""
        if text and callable(self._notify):
            try:
                self._notify(text)
            except Exception:  # noqa: BLE001 - a push failure must not stop a hunt
                pass

    def _chat(self, text: str) -> str:
        self._ensure_llm()
        if self._llm is None:
            return ("(no model configured) set a provider with /model or "
                    "~/.hunter/config.yaml")
        from hunter.cli.shell import CHAT_SYSTEM

        try:
            return str(self._llm.complete(CHAT_SYSTEM, text) or "")
        except Exception as exc:  # noqa: BLE001
            # Self-repair: a broken shell.py (malformed CHAT_SYSTEM) kills
            # every chat turn. Feed the traceback back so a follow-up message
            # can trigger a patch through the model and the next turn works.
            import traceback as _tb
            tb = _tb.format_exc()[-1200:]
            try:
                self.session.log(f"[crash] chat — {type(exc).__name__}: {str(exc)[:80]}")
                self.session._last_crash = tb
            except Exception:  # noqa: BLE001
                pass
            return (
                f"[crash] {type(exc).__name__}: {str(exc)[:120]}\\n\\n"
                "The harness broke — the LLM can self-repair. Reply with "
                "'fix it' to attempt an automatic patch.\\n\\n"
                f"```\\n{tb[:600]}\\n```"
            )

    def _run_hunt(self, active: Any) -> None:
        """Body of a hunt, executed on a worker thread."""
        from pathlib import Path

        from hunter.workflow.loop_v3 import HuntLoop

        self._ensure_llm()
        if self._llm is None:
            self._say("[hunt] no model configured — cannot hunt")
            return

        state_path = Path(
            os.path.expanduser(f"~/.hunter/sessions/{active.name}/hunt_state.json")
        )

        # A live status line redrawn each round. HuntLoop._log is called
        # after every cycle with the round stats; we parse that line into
        # the progress bar so Telegram sees "round 2/10 · 3 findings" instead
        # of a stack of log lines.
        prog = ProgressLine(total_rounds=None)
        walls = active.wall_seconds

        def _log(message: str) -> None:
            active.log(message)
            self._say(message)
            text_line = str(message)
            _R = None
            try:
                # Round status from the loop: "[R4] round: findings=5 verified=1 ..."
                if text_line.startswith("[R"):
                    import re as _re

                    _m = _re.search(r"\[(R\d+)].*?findings=(\d+).*?verified=(\d+)",
                                    text_line)
                    if _m:
                        _R = int(_m.group(1)[1:])
                        prog.update(round=_R, findings=int(_m.group(2)),
                                    verified=int(_m.group(3)))
                    if walls:
                        _rem = _re.search(r"(?:left|remaining)[= ]*([\d.]+)s?", text_line)
                        if _rem:
                            prog.update(remaining=float(_rem.group(1)))
                if "tool call" in text_line.lower():
                    tool_call = getattr(sys.modules.get("hunter.cli.spinner", None),
                                        "tool_call", None)
                    if tool_call:
                        tool_call("hunt", text_line.strip())
                elif _R:
                    prog.draw()
            except Exception:  # noqa: BLE001 - a cosmetic line must not break the hunt
                pass

        try:
            loop = HuntLoop(
                llm=self._llm,
                verify_claim=self._verify.verify_claim,
                target=active.target,
                goals=active.goals,
                wall_seconds=active.wall_seconds,
                idle_seconds=active.idle_seconds,
                budget_usd=active.budget,
                state_path=state_path,
                model_tiers=active.model_tiers,
                log=_log,
            )
            state = loop.run()
        except Exception as exc:  # noqa: BLE001 - report, never crash the gateway
            active.log(f"[hunt] failed: {type(exc).__name__}: {exc}")
            self._say(f"[hunt] failed: {type(exc).__name__}: {exc}")
            return

        active.round = getattr(state, "round", active.round)
        active.findings = list(getattr(state, "findings", active.findings) or [])
        active.completion_reason = getattr(state, "completion_reason", None)

        verified = [f for f in active.findings if f.get("status") == "verified"]
        lines = [
            f"hunt finished — {getattr(state, 'completion_reason', '?')}",
            f"findings: {len(active.findings)}  verified: {len(verified)}",
        ]
        for f in active.findings[:12]:
            lines.append(
                f"  [{f.get('status', '?')}] {f.get('severity', '?')} "
                f"{str(f.get('title', ''))[:70]}"
            )
        lines.append("/findings verified  ·  /claim <id>  ·  /report")
        self._say("\n".join(lines))

    # -- engine contract ---------------------------------------------------
    def handle_text(self, text: str, *, stream_cb: Any = None) -> TurnOutput:
        raw = (text or "").strip()
        if not raw:
            return TurnOutput(text="", kind="noop")
        if raw.startswith("/"):
            _before = dict(self.session.model_tiers or {})
            try:
                out = self._registry.dispatch(raw, self.session)
            except Exception as exc:  # noqa: BLE001 - a bad command never kills chat
                out = f"[error] {type(exc).__name__}: {exc}"
            # a model change takes effect on the next call, not on restart
            if dict(self.session.model_tiers or {}) != _before:
                self._ensure_llm()
                out = str(out) + f"\n(active: hunter={self.session.model_tiers.get('hunter')})"
            return TurnOutput(text=str(out or ""), kind="command")
        return TurnOutput(text=self._chat(raw), kind="text")

    def close(self) -> None:
        """Eviction/shutdown hook: persist the session, leave the hunt running."""
        try:
            self.session.save()
        except Exception:  # noqa: BLE001
            pass
