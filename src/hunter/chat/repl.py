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
chat brain is the orchestrator tier; history is rebuilt from the hash-chained
ChatStore every turn, so what the model sees is exactly what was persisted.
"""

from __future__ import annotations

import contextlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.markdown import Markdown as RichMarkdown
from rich.panel import Panel
from rich.text import Text

from hunter import __version__
from hunter.chat.commands import (
    CommandContext,
    CommandReply,
    default_state_dir,
    resolve_command,
    safe_execute,
    scope_for_target,
)
from hunter.chat.compression import COMPACT_MARKER, compact_history, should_compact
from hunter.chat.intent import HuntIntent, IntentRouter
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


def _open_phase_machine(ledger: Any, run_id: str) -> Any:
    """B9 phase contract, consumed LAZILY: a chat audit opens ``score`` and
    closes it immediately (chat has no scoring pass), then spends its life in
    ``recon``. Returns None whenever the phase engine is absent or disagrees —
    phase surfacing is cosmetic and must never break an audit."""
    try:
        from hunter.phases import PhaseState
    except Exception:  # noqa: BLE001 — ImportError or a half-landed module
        return None
    try:
        machine = PhaseState(ledger, run_id)
        start = getattr(machine, "start", None)
        close = getattr(machine, "close_current", None)
        if callable(start):
            start("score")
        if callable(close):
            close()
        if callable(start):
            start("recon")
        return machine
    except Exception:  # noqa: BLE001 — best-effort bookkeeping
        return None


def _close_phase_machine(machine: Any) -> None:
    """P2 tail contract, LAZY: close the open phase with its honest ledger
    gate. Chat has no debunk pass, so verify/report/retro stay PENDING —
    /report digest-stamps the report phase, `hunter retro --record` records
    the retro. The machine never skips ahead (phase.out_of_order), so the
    honest tail is exactly one close."""
    if machine is None:
        return
    close = getattr(machine, "close_current", None)
    if not callable(close):
        return
    with contextlib.suppress(Exception):  # best-effort bookkeeping
        close()


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
        confirm_fn: Any = None,
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
                    from hunter.llm.router import provider_from_config

                    self.provider = provider_from_config(self.config)
                except HunterError as exc:
                    self._provider_error = exc
        if session_id is not None and self.store.get_session(session_id) is None:
            session_id = None  # unknown id — fall through to a fresh session
        self.session_id = session_id or self.store.create_session()
        self.options: dict[str, Any] = options if options is not None else {}
        self.options.setdefault("verbosity", "normal")
        self.options.setdefault("state_dir", state_dir)
        self.options.setdefault("hunt_mode", False)
        self.options["session_id"] = self.session_id
        self.confirm_fn = confirm_fn
        self._intent = IntentRouter()
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
            spec = reply.data["audit_start"]
            goal = ""
            if reply.data.get("audit_auto"):
                from hunter.agent.prompts import build_goal
                from hunter.engine.base import TargetSpec
                from hunter.tools.scope import ScopeSet

                scope_data = spec.get("scope", {})
                goal = build_goal(
                    TargetSpec(
                        url=spec["target"],
                        scope=ScopeSet(
                            frozenset(scope_data.get("hosts") or ()),
                            allow_subdomains=bool(scope_data.get("allow_subdomains")),
                            name=str(scope_data.get("name", "chat-audit")),
                        ),
                        notes={},
                    ),
                    self._agent_tier(),
                )
            opening = self._audit_open(spec, goal_text=goal)

            if self._audit is not None:
                run_id = self._audit["run_id"]
                reply.data["audit_start_run_id"] = run_id
                if reply.data.get("audit_auto"):
                    from hunter.agent.prompts import build_goal
                    from hunter.engine.base import TargetSpec

                    goal = build_goal(
                        TargetSpec(url=spec["target"], scope=self._audit["ctx"].scope, notes={}),
                        self._audit["tier"],
                    )
                    out_text, result = self._audit_turn_result(goal)
                    parts = [opening, out_text]
                    if not result.finished:
                        status = "interrupted" if result.interrupted else "completed"
                        summary = self._audit_finish(status)
                        summary += " (agent yielded early — run closed)"
                    else:
                        summary = self._audit_finish(
                            "interrupted" if result.interrupted else "completed"
                        ) if self._audit is not None else ""
                    if summary:
                        parts.append(summary)
                    report = self._write_report(run_id)
                    parts.append(
                        f"report: {report}" if report else "report unavailable — chain blocked"
                    )
                    reply.text = "\n\n".join(parts)
                    reply.data["report_path"] = str(report) if report else None
            else:
                # Never leave the user with a false "audit armed" reply.
                reply.text = self._no_provider_text()
                reply.data["audit_refused"] = True
        if reply.data.get("audit_finish"):
            self._audit_finish("completed")
        granted = reply.data.get("approval_granted")
        if isinstance(granted, str) and self._audit is not None:
            # M8 F1: the gateway/REPL rides this path too — the nudge reaches
            # the audit agent as a user turn and it retries the blocked call.
            self._audit_turn(
                f"Approval {granted} granted — retry the exact tool call that required it."
            )
        denied = reply.data.get("approval_denied")
        if isinstance(denied, str) and self._audit is not None:
            self._audit_turn(
                f"Approval {denied} denied by the user — continue without that tool."
            )

    # -- conversational turns ------------------------------------------------------

    def _build_history(self) -> list[dict[str, Any]]:
        """The conversational view of the session (M8 F8):

        1. rows with ``seq <= options["compact_from_seq"]`` are dropped —
           EXCEPT the stored compaction marker row (so the model keeps the
           extractive summary);
        2. when the view crosses the compression threshold, ``compact_history``
           folds the middle span into ONE extractive system block (head and
           last 12 messages stay verbatim);
        3. the soul persona (F7) is prepended as a system message when the
           module is importable and non-empty — the guarded import means a
           missing/broken soul module can never break chat startup.
        """
        cutoff = int(self.options.get("compact_from_seq", 0) or 0)
        history: list[dict[str, Any]] = []
        for row in self.store.messages(self.session_id):
            if row["role"] not in ("user", "assistant"):
                continue
            if row["seq"] <= cutoff and COMPACT_MARKER not in str(row["content"]):
                continue
            history.append({"role": row["role"], "content": str(row["content"])})
        if should_compact(history):
            history, _stats = compact_history(history)
        soul = ""
        try:
            from hunter.agent.soul import soul_block  # noqa: PLC0415 — optional module

            soul = soul_block()
        except ImportError:
            soul = ""
        if soul:
            history.insert(
                0, {"role": "system", "content": "You are the HunterOs chat agent. " + soul}
            )
        return history

    def _run_conversational(self, text: str, *, stream_cb: StreamCb | None) -> TurnOutput:
        self._autotitle(text)
        if self._audit is not None:
            return TurnOutput(self._audit_turn(text, stream_cb=stream_cb), kind="message")
        intent = self._intent.classify(text)
        if intent.is_hunt:
            handled = self._handle_hunt_intent(intent, text, stream_cb=stream_cb)
            if handled is not None:
                return handled
        if self.provider is None:
            return TurnOutput(self._no_provider_text(), kind="error")
        self.store.append_message(self.session_id, "user", text)
        history = self._build_history()
        self._stream_buffer = []
        wrapped_cb = self._wrap_stream(stream_cb)
        try:
            turn = self.provider.complete("orchestrator", history, stream_cb=wrapped_cb)
        except HunterError as exc:
            return TurnOutput(exc.user_message(), kind="error")
        except KeyboardInterrupt:
            return self._interrupted_output()
        return self._persist_assistant_turn(turn)

    def _handle_hunt_intent(
        self, intent: HuntIntent, text: str, *, stream_cb: StreamCb | None
    ) -> TurnOutput | None:
        target = intent.target or ""
        if intent.kind == "path":
            return TurnOutput(
                f"'{target}' looks like a local path — the chat audit surface handles URLs only.\n"
                f'Hunt it with: hunter hunt "{target}"',
                data={
                    "hunt": {
                        "target": target,
                        "action": "path_guidance",
                        "run_id": None,
                        "report_path": None,
                    }
                },
            )
        if self.provider is None:
            return TurnOutput(
                self._no_provider_text(),
                kind="error",
                data={
                    "hunt": {
                        "target": target,
                        "action": "headless_declined",
                        "run_id": None,
                        "report_path": None,
                    }
                },
            )

        mode = bool(self.options.get("hunt_mode"))
        if not mode:
            if self.confirm_fn is None:
                return TurnOutput(
                    self._headless_decline_text(target),
                    data={
                        "hunt": {
                            "target": target,
                            "action": "headless_declined",
                            "run_id": None,
                            "report_path": None,
                        }
                    },
                )
            try:
                confirmed = bool(
                    self.confirm_fn(
                        f"start a governed hunt against {target}? [y/N] "
                    )
                )
            except Exception:  # noqa: BLE001 — confirmation is fail-closed
                confirmed = False
            if not confirmed:
                return None

        try:
            scope = scope_for_target(target, None)
        except HunterError as exc:
            return TurnOutput(
                exc.user_message(),
                data={
                    "hunt": {
                        "target": target,
                        "action": "scope_refused",
                        "run_id": None,
                        "report_path": None,
                    }
                },
            )
        spec = {
            "target": target,
            "engine_name": "agent-chat",
            "scope": scope.summary(),
        }
        opening = self._audit_open(spec, marker=f"/audit {target}", goal_text=text)
        if self._audit is None:
            return TurnOutput(
                self._no_provider_text(),
                kind="error",
                data={
                    "hunt": {
                        "target": target,
                        "action": "headless_declined",
                        "run_id": None,
                        "report_path": None,
                    }
                },
            )
        run_id = self._audit["run_id"]
        out_text, result = self._audit_turn_result(text, stream_cb=stream_cb)
        action = "closed" if result.finished else "started"
        parts = [opening, out_text]
        report_path = None
        if result.finished:
            report_path = self._write_report(run_id)
            parts.append(
                f"report: {report_path}"
                if report_path
                else "report unavailable — chain blocked"
            )
        response = "\n\n".join(part for part in parts if part)
        if mode:
            response = f"hunt mode: starting audit of {target}\n\n{response}"
        return TurnOutput(
            response,
            kind="message",
            data={
                "hunt": {
                    "target": target,
                    "action": action,
                    "run_id": run_id,
                    "report_path": str(report_path) if report_path else None,
                }
            },
        )

    @staticmethod
    def _headless_decline_text(target: str) -> str:
        return (
            f"hunt request detected for {target} — declined: no interactive confirmation is "
            "available on this surface. Start explicitly with /audit <target> --scope "
            "<manifest> or `hunter hunt <target>` (which can generate a minimal manifest "
            "after confirmation)."
        )

    def _write_report(self, run_id: str):
        from hunter.hunt import write_hunt_report

        return write_hunt_report(run_id, state_dir=self.options.get("state_dir"))

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

    def _audit_open(self, spec: dict[str, Any], *, marker: str | None = None, goal_text: str = "") -> str:
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
        # The audit tier follows the configured agent.tier (M3 invariant: free
        # text can never escalate it) — an operator must explicitly opt into
        # "advanced" for approval-danger tools. When they are in tier, the
        # approval gate below mediates every call; they are reachable exactly
        # through that gate, never around it.
        tier = self._agent_tier()
        from hunter.agent.approval import ApprovalStore, make_approval_gate
        from hunter.agent.tools_base import ToolContext

        # Same resolution the Ledger default convention uses (M8 F1): an
        # explicit state_dir wins; otherwise env HUNTER_STATE_DIR or ./.hunter.
        resolved_state_dir = str(state_dir) if state_dir else str(default_state_dir())
        approval_store = ApprovalStore(Path(resolved_state_dir) / "approvals")
        gate_kwargs: dict[str, Any] = {"auto_allow": bool(self.options.get("hunt_mode"))}
        if self.confirm_fn is not None:
            confirm = self.confirm_fn

            def _confirm_request(request: Any) -> bool:
                return bool(confirm(f"approve {request.tool}: {request.summary} [y/N] "))

            gate_kwargs["confirm_fn"] = _confirm_request
        tool_ctx = ToolContext(
            run_id=run_id,
            ledger=ledger,
            http=http,
            scope=scope,
            target_url=target,
            emit=lambda kind, payload: ledger.append(run_id, kind, payload),
            config={
                "tier": tier,
                "browser_enabled": bool(getattr(getattr(self.config, "agent", None), "browser", False)),
                "browser_cloak": bool(
                    getattr(getattr(self.config, "agent", None), "browser_cloak", True)
                ),
                "hunt_permission": True,
                "state_dir": resolved_state_dir,
                "approval_gate": make_approval_gate(
                    approval_store,
                    ledger=ledger,
                    run_id=run_id,
                    surface=str(self.session_id or ""),
                    **gate_kwargs,
                ),
            },
        )
        seed = self.options.get("browser_cloak_seed")
        if seed is not None:
            tool_ctx.config["browser_cloak_seed"] = seed
        phase_machine = _open_phase_machine(ledger, run_id)
        if phase_machine is not None:
            tool_ctx.config["phase_machine"] = phase_machine  # B9: tools observe phases
        self._audit = {
            "run_id": run_id,
            "ledger": ledger,
            "http": http,
            "ctx": tool_ctx,
            "budget": budget,
            "tier": tier,
            "target": target,
            "phase_machine": phase_machine,
        }
        self.options["audit_active"] = True
        self.options["audit_status"] = (
            f"audit active: run {run_id} on {target} — free text drives the agent; "
            "/audit finish closes the run"
        )
        self.store.append_message(self.session_id, "user", marker or f"/audit {target}")
        from urllib.parse import urlparse

        from hunter.agent.skills import selected_skill_names

        host = urlparse(target).hostname or ""
        selected = selected_skill_names(goal_text or target, goal_text or target)
        skills_line = f"skills mounted: {len(selected)}"
        if selected:
            skills_line += f" ({', '.join(f'{name} [{source}]' for name, source in selected)})"
        # Keep the pre-M5 corpus line as a secondary compatibility breadcrumb;
        # the first mounted line above is the authoritative selected set.
        from hunter.agent.prompts import mounted_skills

        legacy = mounted_skills()
        legacy_line = (
            f"skills mounted: {len(legacy)} ({', '.join(legacy)})" if legacy else "skills mounted: 0"
        )
        opening = (
            f"audit run {run_id} opened against {target} (scope: {scope.name})\n"
            f"target check: {target} — valid URL (host: {host})\n"
            f"{skills_line}\n{legacy_line}\n"
            "Every probe is scope-gated and every finding is claim-gated: evidence or nothing."
        )
        self.store.append_message(
            self.session_id,
            "assistant",
            opening,
            run_id=run_id,
        )
        return f"audit run {run_id} opened — free text now drives the audit agent\n{opening}"

    def _audit_turn(self, text: str, *, stream_cb: StreamCb | None = None) -> str:
        """One user message against the audit agent loop."""
        return self._audit_turn_result(text, stream_cb=stream_cb)[0]

    def _audit_turn_result(
        self, text: str, *, stream_cb: StreamCb | None = None
    ) -> tuple[str, Any]:
        """Drive one audit turn and return rendered text plus its result."""
        audit = self._audit
        if audit is None:  # pragma: no cover — guarded by caller
            return "no audit active", type("Result", (), {"finished": False, "interrupted": False})()
        from hunter.agent.loop import AgentLoop
        from hunter.agent.tools import build_registry

        self.store.append_message(self.session_id, "user", text)
        loop = AgentLoop(
            self.provider,
            build_registry(
                audit["tier"],
                browser_enabled=bool(audit["ctx"].config.get("browser_enabled", False)),
            ),
            tier=audit["tier"],
            budget=audit["budget"],
        )
        try:
            result = loop.run(audit["ctx"], text, stream_cb=stream_cb)
        except HunterError as exc:
            return exc.user_message(), type("Result", (), {"finished": False, "interrupted": False})()
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
            return f"{out_text}\n\n{summary}", result
        return out_text, result

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
            # The phase close lands BEFORE run_ended: replaying the chain must
            # never show a phase outliving its run. A completed audit closes
            # with its honest ledger gate; an interrupted/aborted audit was
            # abandoned, not gate-failed — it closes with {"aborted": true}.
            machine = audit.get("phase_machine")
            if status == "completed":
                _close_phase_machine(machine)
            else:
                abort = getattr(machine, "abort", None)
                if callable(abort):
                    with contextlib.suppress(Exception):
                        abort()
            findings = ledger.findings(run_id)
            ledger.append(
                run_id, EventKind.RUN_ENDED, {"status": status, "surface": "chat"}
            )
            ledger.finish_run(run_id, status)
        finally:
            try:
                audit["ctx"].close_browser()
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
                min_wall_seconds=getattr(cfg.budget, "min_wall_seconds", 0.0),
            )
        return RunBudget()

    def _agent_tier(self) -> str:
        """Map config agent.tier (basic|orchestrator|...) onto loop tiers
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
        mode="hunt" if engine.options.get("hunt_mode") else "chat",
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
    if engine.confirm_fn is None:
        def _console_confirm(prompt: str) -> bool:
            try:
                answer = console.input(prompt).strip().lower()
            except (EOFError, KeyboardInterrupt):
                return False
            return answer in ("y", "yes")
        engine.confirm_fn = _console_confirm
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
        except Exception as exc:  # noqa: BLE001 — one bad turn must never kill the session
            out = TurnOutput(
                f"[ERROR engine] unexpected {type(exc).__name__}: {str(exc)[:200]}\n"
                "Hint: the session stays alive — try again, or check `hunter doctor`.",
                kind="error",
            )
            _print_output(console, out)
        if out.kind == "interrupted":
            armed = 1  # the next Ctrl-C in this prompt cycle exits
        if out.quit:
            break
    engine.close()
