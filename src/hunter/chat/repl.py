"""HunterOs chat — the conversational REPL and the shared ChatEngine.

ONE code path for both surfaces (the gateway is a thin client of it):

- :class:`ChatEngine` owns the session, the provider, and the audit state.
  ``handle_text`` routes a line to the slash registry (``hunter.chat.commands``)
  or to a conversational LLM turn; both surfaces (REPL, Telegram, webhook)
  consume the same :class:`TurnOutput`.
- :func:`run_repl` is the human-facing rich REPL: banner, ``hunter>``
  prompt, streaming markdown rendering, and the two-stage Ctrl-C contract
  (first press cancels the in-flight turn and prints ``[interrupted]``;
  a second press within the same prompt exits).

Conversational turns create NO ledger runs — only /scan and /audit do. The
chat brain is the planner tier; history is rebuilt from the hash-chained
ChatStore every turn, so what the model sees is exactly what was persisted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.markdown import Markdown as RichMarkdown
from rich.panel import Panel
from rich.text import Text

from hunter import __version__
from hunter.chat.commands import CommandContext, CommandReply, resolve_command, safe_execute
from hunter.chat.sessions import ChatStore
from hunter.errors import HunterError
from hunter.llm.base import StreamCb, TurnResult
from hunter.llm.config import default_model, load_config

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.llm.base import ChatProvider
    from hunter.llm.config import HunterConfig

__all__ = ["ChatEngine", "TurnOutput", "banner", "run_repl"]

PROMPT = "[bold cyan]hunter>[/bold cyan] "
_SESSION_TITLE_MAX = 60


@dataclass
class TurnOutput:
    """What one handled line produces. ``kind``: command | message | error |
    interrupted | noop. ``quit`` asks the surface to exit."""

    text: str
    kind: str = "message"
    format: str = "plain"
    data: dict[str, Any] = field(default_factory=dict)
    quit: bool = False


class ChatEngine:
    """The shared conversational brain: sessions + provider + audit state."""

    def __init__(
        self,
        *,
        session_id: str | None = None,
        state_dir: str | None = None,
        store: ChatStore | None = None,
        config: HunterConfig | None = None,
        provider: ChatProvider | None = None,
        ledger_factory: Any = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self._owns_store = store is None
        self.store = store if store is not None else ChatStore()
        self.config = config
        self.provider = provider
        self._provider_error: HunterError | None = None
        if provider is None:
            if config is None:
                try:
                    config = load_config()
                    self.config = config
                except HunterError as exc:
                    self._provider_error = exc
            if self.config is not None:
                try:
                    from hunter.llm.router import ProviderRouter

                    self.provider = ProviderRouter(self.config)
                except HunterError as exc:
                    self._provider_error = exc
        if session_id is not None and self.store.get_session(session_id) is None:
            session_id = None  # unknown id — fall through to a fresh session
        self.session_id = session_id or self.store.create_session()
        self.options: dict[str, Any] = options if options is not None else {}
        self.options.setdefault("verbosity", "normal")
        self.options.setdefault("state_dir", state_dir)
        self.options["session_id"] = self.session_id
        self._ledger_factory = ledger_factory
        self._audit: Any | None = None
        self._stream_buffer: list[str] = []

    # -- public API ------------------------------------------------------------

    def handle_text(self, text: str, *, stream_cb: StreamCb | None = None) -> TurnOutput:
        """Route one line: slash command or conversational turn."""
        stripped = (text or "").strip()
        if not stripped:
            return TurnOutput(text="", kind="noop")
        if stripped.startswith("/"):
            return self._run_slash(stripped)
        return self._run_conversational(stripped, stream_cb=stream_cb)

    def close(self) -> None:
        self._audit_finish("aborted")
        if self._owns_store:
            self.store.close()

    # -- slash handling ----------------------------------------------------------

    def _run_slash(self, line: str) -> TurnOutput:
        resolved = resolve_command(line)
        if resolved is None:
            return TurnOutput(
                "unknown command — /help", kind="command", data={"unknown": True}
            )
        cmd, args = resolved
        ctx = CommandContext(
            store=self.store,
            config=self.config,
            ledger_factory=self._ledger_factory,
            args=args,
            options=self.options,
        )
        reply = safe_execute(cmd.name, ctx)
        self._absorb_reply(reply)
        return TurnOutput(
            reply.text,
            kind="command",
            format=reply.format,
            data=reply.data,
            quit=bool(reply.data.get("quit")),
        )

    def _absorb_reply(self, reply: CommandReply) -> None:
        """Act on the side-effects a reply declares (surfaces stay stateless)."""
        new_sid = reply.data.get("session_id")
        if isinstance(new_sid, str) and self.store.get_session(new_sid) is not None:
            self.session_id = new_sid
            self.options["session_id"] = new_sid
        if reply.data.get("audit_start"):
            self._audit_open(reply.data["audit_start"])
            if self._audit is not None:
                reply.data["audit_start_run_id"] = self._audit["run_id"]
            else:
                # QA red-audit v0.2: the executor promised an armed audit, but
                # the engine refused to open one (no provider / no model).
                # Never leave the user with a false "audit armed" reply.
                reply.text = self._no_provider_text()
                reply.data["audit_refused"] = True
        if reply.data.get("audit_finish"):
            self._audit_finish("completed")

    # -- conversational turns ------------------------------------------------------

    def _run_conversational(self, text: str, *, stream_cb: StreamCb | None) -> TurnOutput:
        self._autotitle(text)
        if self._audit is not None:
            return TurnOutput(self._audit_turn(text, stream_cb=stream_cb), kind="message")
        if self.provider is None:
            return TurnOutput(self._no_provider_text(), kind="error")
        self.store.append_message(self.session_id, "user", text)
        history = [
            {"role": m["role"], "content": m["content"]}
            for m in self.store.messages(self.session_id)
            if m["role"] in ("user", "assistant")
        ]
        self._stream_buffer = []
        wrapped_cb = self._wrap_stream(stream_cb)
        try:
            turn = self.provider.complete("planner", history, stream_cb=wrapped_cb)
        except HunterError as exc:
            return TurnOutput(exc.user_message(), kind="error")
        except KeyboardInterrupt:
            return self._interrupted_output()
        return self._persist_assistant_turn(turn)

    def _wrap_stream(self, stream_cb: StreamCb | None) -> StreamCb | None:
        if stream_cb is None:
            return None

        def cb(chunk: str) -> None:
            self._stream_buffer.append(chunk)
            stream_cb(chunk)

        return cb

    def _persist_assistant_turn(self, turn: TurnResult) -> TurnOutput:
        text = (turn.text or "").strip()
        if turn.error_surface is not None:
            # Provider failure already normalized by the router: surface it,
            # do NOT persist it as assistant prose.
            surface = turn.error_surface
            message = (
                f"[ERROR {surface.get('layer', 'provider')}] {surface.get('message', '')}"
            )
            hint = surface.get("hint") or ""
            if hint:
                message += f"\nHint: {hint}"
            return TurnOutput(message, kind="error")
        if not text:
            return TurnOutput("(empty response)", kind="error")
        self.store.append_message(
            self.session_id, "assistant", text, cost_usd=turn.cost_usd
        )
        return TurnOutput(text, kind="message")

    def _interrupted_output(self) -> TurnOutput:
        """Ctrl-C mid-turn: keep the partial (if any) and report the cancel."""
        partial = "".join(self._stream_buffer).strip()
        if partial:
            self.store.append_message(self.session_id, "assistant", partial + "\n[interrupted]")
        return TurnOutput("[interrupted]", kind="interrupted")

    def _no_provider_text(self) -> str:
        if self._provider_error is not None:
            return (
                f"{self._provider_error.user_message()}\n"
                "(slash commands still work; only model replies are unavailable)"
            )
        return (
            "[ERROR config] no provider configured\n"
            "Hint: set HUNTEROS_MODEL or create ~/.hunteros/config.yaml "
            "(`hunter config example` shows a full file)."
        )

    def _autotitle(self, first_line: str) -> None:
        session = self.store.get_session(self.session_id)
        if session is not None and not (session.get("title") or "").strip():
            self.store.set_title(self.session_id, first_line.strip()[:_SESSION_TITLE_MAX])

    # -- interactive audit (/audit) ----------------------------------------------

    def _audit_open(self, spec: dict[str, Any]) -> str:
        """Open a governed audit run: ledger run + scoped ToolContext + budget."""
        if self.provider is None:
            return self._no_provider_text()
        from hunter.kernel.events import EventKind
        from hunter.kernel.ledger import Ledger
        from hunter.tools.http_client import ScopedHttpClient
        from hunter.tools.scope import ScopeSet

        if self._audit is not None:
            self._audit_finish("aborted")
        state_dir = self.options.get("state_dir")
        ledger = Ledger(f"{state_dir}/ledger.db" if state_dir else None)
        run_id = f"R-{uuid.uuid4().hex[:12]}"
        scope = ScopeSet(
            frozenset(spec.get("scope", {}).get("hosts") or ()),
            allow_subdomains=bool(spec.get("scope", {}).get("allow_subdomains")),
            name=str(spec.get("scope", {}).get("name", "chat-audit")),
        )
        target = str(spec.get("target", ""))
        engine_name = str(spec.get("engine_name", "agent-chat"))
        ledger.create_run(run_id, target, engine_name, scope.name)
        ledger.append(
            run_id,
            EventKind.RUN_STARTED,
            {"target": target, "engine": engine_name, "scope": scope.summary(),
             "surface": "chat", "harness_version": __version__},
        )
        http = ScopedHttpClient(scope)
        budget = self._build_budget()
        tier = self._agent_tier()
        from hunter.agent.tools_base import ToolContext

        tool_ctx = ToolContext(
            run_id=run_id,
            ledger=ledger,
            http=http,
            scope=scope,
            target_url=target,
            emit=lambda kind, payload: ledger.append(run_id, kind, payload),
            config={"tier": tier},
        )
        self._audit = {
            "run_id": run_id,
            "ledger": ledger,
            "http": http,
            "ctx": tool_ctx,
            "budget": budget,
            "tier": tier,
            "target": target,
        }
        self.options["audit_active"] = True
        self.options["audit_status"] = (
            f"audit active: run {run_id} on {target} — free text drives the agent; "
            "/audit finish closes the run"
        )
        self.store.append_message(self.session_id, "user", f"/audit {target}")
        self.store.append_message(
            self.session_id,
            "assistant",
            f"audit run {run_id} opened against {target} (scope: {scope.name}). "
            "Every probe is scope-gated and every finding is claim-gated: evidence or nothing.",
            run_id=run_id,
        )
        return f"audit run {run_id} opened — free text now drives the audit agent"

    def _audit_turn(self, text: str, *, stream_cb: StreamCb | None = None) -> str:
        """One user message against the audit agent loop."""
        audit = self._audit
        if audit is None:  # pragma: no cover — guarded by caller
            return "no audit active"
        from hunter.agent.loop import AgentLoop
        from hunter.agent.tools import build_registry

        self.store.append_message(self.session_id, "user", text)
        loop = AgentLoop(
            self.provider,
            build_registry(audit["tier"]),
            tier=audit["tier"],
            budget=audit["budget"],
        )
        try:
            result = loop.run(audit["ctx"], text, stream_cb=stream_cb)
        except HunterError as exc:
            # QA red-audit v0.2: a config/provider failure mid-audit (e.g. no
            # model resolved) must surface as a readable error, never kill the
            # REPL with a traceback. The audit stays armed; the run is closed
            # by close() if the user gives up.
            return exc.user_message()
        out_text = result.yield_message or result.summary or "(no output)"
        self.store.append_message(
            self.session_id,
            "assistant",
            out_text,
            run_id=audit["run_id"],
            cost_usd=float(result.stats.get("cost_usd", 0.0)),
        )
        if result.finished:
            status = "interrupted" if result.interrupted else "completed"
            summary = self._audit_finish(status)
            return f"{out_text}\n\n{summary}"
        return out_text

    def _audit_finish(self, status: str) -> str:
        audit = self._audit
        if audit is None:
            return "no audit active"
        self._audit = None
        self.options["audit_active"] = False
        self.options["audit_status"] = None
        from hunter.kernel.events import EventKind

        ledger: Any = audit["ledger"]
        run_id = audit["run_id"]
        try:
            ledger.append(
                run_id, EventKind.RUN_ENDED, {"status": status, "surface": "chat"}
            )
            ledger.finish_run(run_id, status)
            findings = ledger.findings(run_id)
        finally:
            try:
                audit["http"].close()
            finally:
                ledger.close()
        return (
            f"audit run {run_id} {status}: {len(findings)} finding(s) "
            f"(all claim-gated) — /report {run_id} renders the report"
        )

    def _build_budget(self) -> Any:
        from hunter.llm.budget import RunBudget

        cfg = self.config
        if cfg is not None:
            return RunBudget(
                max_cost_usd=cfg.budget.max_cost_usd,
                max_iterations=cfg.budget.max_iterations,
                wall_seconds=cfg.budget.wall_seconds,
            )
        return RunBudget()

    def _agent_tier(self) -> str:
        """Map config agent.tier (basic|planner|...) onto loop tiers
        (basic|advanced): anything pinned above basic is an active audit."""
        tier = self.config.agent.tier if self.config is not None else "basic"
        return "basic" if tier == "basic" else "advanced"


# --------------------------------------------------------------------------
# REPL surface
# --------------------------------------------------------------------------


def banner(engine: ChatEngine) -> Panel:
    """The chat welcome panel (text from hunter._data.branding)."""
    from hunter._data.branding import banner_lines

    cfg = engine.config
    lines = banner_lines(
        version=__version__,
        tier=cfg.agent.tier if cfg is not None else "basic",
        model=default_model(cfg) if cfg is not None else "",
        session_id=engine.session_id,
    )
    body = Text("\n".join(lines))
    return Panel(body, title="hunter chat", border_style="cyan", subtitle="Evidence or Nothing")


def _print_output(console: Console, out: TurnOutput) -> None:
    if not out.text:
        return
    if out.format == "markdown":
        console.print(RichMarkdown(out.text))
    else:
        console.print(out.text, markup=False, highlight=False)


def _stream_turn(console: Console, engine: ChatEngine, text: str) -> TurnOutput:
    """Conversational turn with live markdown rendering while streaming."""
    if not getattr(console, "is_terminal", False):
        out = engine.handle_text(text)
        _print_output(console, out)
        return out
    from rich.live import Live

    chunks: list[str] = []

    def cb(chunk: str) -> None:
        chunks.append(chunk)

    with Live(console=console, refresh_per_second=10, transient=True) as live:
        out = engine.handle_text(text, stream_cb=cb)
        shown = "".join(chunks) or out.text
        live.update(RichMarkdown(shown))
    if out.kind in ("command", "message") and out.text:
        console.print(RichMarkdown(out.text))
    else:
        _print_output(console, out)
    return out


def run_repl(
    session_id: str | None = None,
    state_dir: str | None = None,
    *,
    engine: ChatEngine | None = None,
    console: Console | None = None,
) -> None:
    """Interactive chat REPL. Importable without a tty (tests inject a
    scripted console via the keyword-only hooks)."""
    console = console if console is not None else Console()
    engine = engine if engine is not None else ChatEngine(session_id=session_id, state_dir=state_dir)
    console.print(banner(engine))
    armed = 0  # Ctrl-C stage within the current prompt cycle
    while True:
        try:
            line = console.input(PROMPT)
        except KeyboardInterrupt:
            armed += 1
            if armed >= 2:
                console.print("\n[dim]bye — evidence or nothing.[/dim]", markup=True)
                break
            console.print(
                "\n[dim](Ctrl-C again to exit — nothing is running)[/dim]", markup=True
            )
            continue
        except EOFError:
            break
        armed = 0
        if not line.strip():
            continue
        try:
            if line.strip().startswith("/"):
                out = engine.handle_text(line)
                _print_output(console, out)
            else:
                out = _stream_turn(console, engine, line)
        except KeyboardInterrupt:
            out = TurnOutput("[interrupted]", kind="interrupted")
            _print_output(console, out)
        if out.kind == "interrupted":
            armed = 1  # the next Ctrl-C in this prompt cycle exits
        if out.quit:
            break
    engine.close()
