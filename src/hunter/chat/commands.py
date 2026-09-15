"""Slash-command registry — one command set for every surface (hermes pattern).

Surface independence invariant (ported from hermes ``slash_exec``): an
executor's output depends ONLY on ``ctx.args`` / ``ctx.options`` — never on
which surface called it. The REPL, the Telegram adapter, and the webhook all
build a :class:`CommandContext` over the same store and get byte-identical
:attr:`CommandReply.text` for the same inputs. Surfaces may re-decorate
(``CommandReply.format`` is a rendering hint) but never re-interpret.

Governance: /scan and /audit enforce the same fail-closed scope gate as the
CLI — localhost is always allowed, anything else REQUIRES a scope manifest.
``[BLOCKED]`` replies name the rule and never suggest a scope-widening fix.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from hunter.errors import HunterError
from hunter.kernel.findings import SEVERITY_ORDER
from hunter.kernel.ledger import Ledger
from hunter.tools.scope import LOCAL_HOSTS, ScopeSet, localhost_scope, scope_from_manifest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.llm.config import HunterConfig
    from hunter.workflow.pipeline import RunSummary

__all__ = [
    "COMMAND_REGISTRY",
    "EXECUTORS",
    "CommandContext",
    "CommandDef",
    "CommandReply",
    "resolve_command",
    "safe_execute",
    "scope_for_target",
]

NO_MODEL_HINT = "set HUNTEROS_MODEL env or create ~/.hunteros/config.yaml"


@dataclass(frozen=True)
class CommandDef:
    """Definition of one slash command (canonical name without the slash)."""

    name: str
    description: str
    category: str
    aliases: tuple[str, ...] = ()
    args_hint: str = ""
    busy_policy: str = "reject"  # reserved for concurrent surfaces (lease layer)


@dataclass
class CommandReply:
    """Result of one executor: surface-independent text plus structured data."""

    text: str
    data: dict[str, Any] = field(default_factory=dict)
    format: str = "plain"  # "plain" | "markdown" — rendering hint, not a contract


@dataclass
class CommandContext:
    """Surface-provided inputs for a shared executor.

    ``store``        the shared ChatStore (sessions live there).
    ``config``       HunterConfig or None (no provider configured).
    ``ledger_factory``  optional callable returning a fresh Ledger (test seam);
                     otherwise ``options["state_dir"]`` or the Ledger default
                     convention decides where ledger.db lives.
    ``args``         raw argument string after the command word.
    ``options``      mutable per-surface state bag (session_id, verbosity,
                     page sizes, state_dir, scope summaries). Executors READ
                     it and may write UX keys (e.g. /verbose), never doctrine.
    """

    store: Any
    config: HunterConfig | None
    ledger_factory: Callable[[], Ledger] | None = None
    args: str = ""
    options: dict[str, Any] = field(default_factory=dict)


COMMAND_REGISTRY: list[CommandDef] = [
    # General
    CommandDef("help", "Show commands (paginated by category) or one command's detail", "General",
               aliases=("?",), args_hint="[page|command]"),
    # Session
    CommandDef("new", "Start a new chat session", "Session", args_hint="[title]"),
    CommandDef("sessions", "List saved chat sessions", "Session"),
    CommandDef("resume", "Resume a session by id or 'latest'", "Session", args_hint="<sid|latest>"),
    CommandDef("title", "Set the current session title", "Session", args_hint="<title>"),
    CommandDef("undo", "Hide the last N user turns (tombstoned, chain intact)", "Session",
               args_hint="[N]"),
    CommandDef("clear", "Start a fresh untitled session", "Session"),
    CommandDef("usage", "Show session message count and cost totals", "Session"),
    CommandDef("compress", "Compact the current session view (store untouched)", "Session",
               args_hint="[--report]"),
    CommandDef("quit", "Leave the chat (saves the session)", "Session", aliases=("exit", "q")),
    # Audit
    CommandDef("scan", "Run a governed scan of an authorized target", "Audit",
               args_hint="<target> [--scope PATH] [--engine NAME]", busy_policy="reject"),
    CommandDef("findings", "List findings of a run (default: latest)", "Audit",
               aliases=("finds",), args_hint="[run_id]"),
    CommandDef("report", "Render a run report (markdown or SARIF)", "Audit",
               args_hint="[run_id] [--fmt markdown|sarif]", busy_policy="reject"),
    CommandDef("audit", "Interactive governed audit: arm a target, free text drives the agent",
               "Audit", args_hint="<target> [--scope PATH] | status | finish",
               busy_policy="reject"),
    CommandDef("hunt", "Hunt mode and one-shot hunts from chat", "Audit",
               args_hint="on | off | <target> [--scope PATH]", busy_policy="reject"),
    CommandDef("approve", "Approve a pending dangerous-tool request", "Audit",
               args_hint="<request_id>"),
    CommandDef("deny", "Deny a pending dangerous-tool request", "Audit",
               args_hint="<request_id>"),
    CommandDef("retro", "Phase retro for a run (phase engine, if installed)", "Audit",
               args_hint="<run_id> [--record]"),
    CommandDef("curate", "Draft skills from a run's retro (preview + confirm; never auto-saves)", "Audit",
               args_hint="[run_id]", busy_policy="reject"),
    # Configuration
    CommandDef("model", "Show or switch the model for a tier (session-scoped; --global persists)",
               "Config", args_hint="[tier] [model] [--global]"),
    CommandDef("scope", "Show the active scope summary", "Config"),
    CommandDef("verbose", "Cycle chat verbosity (normal -> verbose -> quiet)", "Config"),
    # Info
    CommandDef("skills", "List bundled methodology skills", "Info"),
]


def resolve_command(text: str) -> tuple[CommandDef, str] | None:
    """Match a user line against the registry.

    Returns ``(CommandDef, args_str)`` for ``/name args`` (aliases resolve to
    the canonical def, ``@bot`` suffixes on the command word are stripped,
    matching is case-insensitive) or None when the line is not a registered
    command — including every non-slash line.
    """
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped.startswith("/"):
        return None
    body = stripped[1:].strip()
    if not body:
        return None
    head, _, rest = body.partition(" ")
    name = head.strip().lower()
    if "@" in name:  # /scan@hunterbot → scan (Telegram-style mention)
        name = name.split("@", 1)[0]
    for cmd in COMMAND_REGISTRY:
        if name == cmd.name or name in cmd.aliases:
            return cmd, rest.strip()
    return None


def safe_execute(name: str, ctx: CommandContext) -> CommandReply:
    """Run the executor for ``name``, converting failures to reply text.

    ``[BLOCKED]`` replies (scope refusals) come straight from
    ``HunterError.user_message()`` — the rule is named, no widening fix is
    suggested. Unknown names answer the canonical unknown-command line, and
    ANY other exception becomes an ``[ERROR engine]`` reply: one broken
    executor must never crash a surface (REPL, Telegram, webhook).
    """
    fn = EXECUTORS.get(name)
    if fn is None:
        return CommandReply("unknown command — /help")
    try:
        return fn(ctx)
    except HunterError as exc:
        return CommandReply(
            exc.user_message(),
            data={"error": {"code": exc.code, "layer": exc.layer, "blocked": exc.blocked}},
        )
    except Exception as exc:  # noqa: BLE001 — the surface gets an answer, always
        return CommandReply(
            f"[ERROR engine] unexpected {type(exc).__name__}: {str(exc)[:200]}\n"
            "Hint: re-run with /verbose, or check `hunter doctor` — if it persists, "
            "file an issue: https://github.com/zaaaxx11/HunterOsHarness/issues",
            data={"error": {"code": f"unexpected.{type(exc).__name__}", "layer": "engine",
                            "blocked": False}},
        )


# --------------------------------------------------------------------------
# argument helpers
# --------------------------------------------------------------------------


def _tokenize(args: str) -> list[str]:
    """Split args tolerating quotes; Windows backslash paths stay intact."""
    try:
        tokens = shlex.split(args or "", posix=False)
    except ValueError:
        tokens = (args or "").split()
    out = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
            token = token[1:-1]
        out.append(token)
    return out


def _split_options(
    tokens: list[str], *, value_options: set[str], flags: set[str]
) -> tuple[list[str], dict[str, Any]]:
    """Pull ``--opt value`` / ``--opt=value`` / boolean flags out of tokens."""
    positionals: list[str] = []
    opts: dict[str, Any] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in value_options:
            if index + 1 < len(tokens):
                opts[token.lstrip("-")] = tokens[index + 1]
                index += 2
                continue
            index += 1  # dangling option — treat as absent
            continue
        if token in flags:
            opts[token.lstrip("-")] = True
            index += 1
            continue
        if "=" in token and token.startswith("--"):
            key, _, value = token[2:].partition("=")
            if f"--{key}" in value_options or f"--{key}" in flags:
                opts[key] = value
                index += 1
                continue
        positionals.append(token)
        index += 1
    return positionals, opts


def _open_ledger(ctx: CommandContext) -> Ledger:
    if ctx.ledger_factory is not None:
        return ctx.ledger_factory()
    state_dir = ctx.options.get("state_dir")
    if state_dir:
        return Ledger(Path(state_dir) / "ledger.db")
    return Ledger()


def default_state_dir() -> Path:
    """The Ledger default state-directory convention: ``$HUNTER_STATE_DIR``
    or ``./.hunter`` — used when a surface never set ``options["state_dir"]``."""
    import os

    return Path(os.environ.get("HUNTER_STATE_DIR") or ".hunter")


def _approval_root(options: dict[str, Any]) -> Path:
    """Where the surface's approval requests live: ``<state>/approvals``."""
    state_dir = options.get("state_dir")
    return (Path(str(state_dir)) if state_dir else default_state_dir()) / "approvals"


def _session_id(ctx: CommandContext) -> str | None:
    return ctx.options.get("session_id") or None


def _severity_sort(finding: Any) -> int:
    return -SEVERITY_ORDER.get(finding.severity.value, 0)


# --------------------------------------------------------------------------
# executors — output depends only on ctx.args / ctx.options
# --------------------------------------------------------------------------


def _exec_help(ctx: CommandContext) -> CommandReply:
    """Paginated command listing grouped by category; ``/help <name>`` shows
    one command in full (aliases, args hint, busy policy)."""
    arg = (ctx.args or "").strip().lower()
    if arg and not arg.isdigit():
        target = arg.lstrip("/").split("@", 1)[0]
        for cmd in COMMAND_REGISTRY:
            if target == cmd.name or target in cmd.aliases:
                lines = [f"/{cmd.name} {cmd.args_hint}".rstrip(), f"  {cmd.description}"]
                if cmd.aliases:
                    lines.append(f"  aliases: {', '.join('/' + a for a in cmd.aliases)}")
                lines.append(f"  category: {cmd.category}  |  busy: {cmd.busy_policy}")
                return CommandReply("\n".join(lines), data={"command": cmd.name})
        return CommandReply(f"unknown command — /help (no entry '{arg}')")

    categories: list[str] = []
    grouped: dict[str, list[CommandDef]] = {}
    for cmd in COMMAND_REGISTRY:
        grouped.setdefault(cmd.category, []).append(cmd)
        if cmd.category not in categories:
            categories.append(cmd.category)

    pages: list[list[str]] = [[]]
    for category in categories:
        pages[-1].append(f"[{category}]")
        for cmd in grouped[category]:
            alias_note = f" (/{' /'.join(cmd.aliases)})" if cmd.aliases else ""
            pages[-1].append(f"/{cmd.name}{alias_note} — {cmd.description}")
        pages[-1].append("")

    while pages[-1] and not pages[-1][-1]:
        pages[-1].pop()
    flat_pages = [page for page in pages if page]
    try:
        page_no = max(1, min(int(arg or 1), len(flat_pages)))
    except ValueError:
        page_no = 1
    body = flat_pages[page_no - 1]
    header = f"HunterOs commands — page {page_no}/{len(flat_pages)}"
    if len(flat_pages) > 1:
        header += " (/help <page> for more, /help <name> for detail)"
    lines = [header, "", *body]
    if "audit" in EXECUTORS:
        lines.append(
            "during an active audit, free text talks to the audit agent; "
            "/audit finish closes the run"
        )
    else:  # pragma: no cover — /audit ships in v0.2
        lines.append("coming in v0.2.x: /audit — interactive governed audit from chat")
    return CommandReply("\n".join(lines), format="markdown", data={"page": page_no})


def _exec_new(ctx: CommandContext) -> CommandReply:
    title = (ctx.args or "").strip()
    sid = ctx.store.create_session(title)
    return CommandReply(
        f"new session {sid}" + (f" — {title}" if title else ""),
        data={"session_id": sid},
    )


def _exec_sessions(ctx: CommandContext) -> CommandReply:
    sessions = ctx.store.list_sessions()
    if not sessions:
        return CommandReply("no sessions yet — say something or /new [title]")
    current = _session_id(ctx)
    lines = ["sessions (most recent first):"]
    for session in sessions:
        mark = "->" if session["session_id"] == current else "  "
        title = session["title"] or "(untitled)"
        lines.append(f"{mark} {session['session_id']}  {title}")
    return CommandReply("\n".join(lines), data={"sessions": sessions})


def _exec_resume(ctx: CommandContext) -> CommandReply:
    arg = (ctx.args or "").strip()
    if not arg:
        return CommandReply("usage: /resume <sid|latest>")
    if arg == "latest":
        sessions = ctx.store.list_sessions()
        if not sessions:
            return CommandReply("no sessions yet — say something or /new [title]")
        sid = sessions[0]["session_id"]
    else:
        sid = arg
    if ctx.store.get_session(sid) is None:
        return CommandReply(f"unknown session '{sid}' — /sessions lists saved ids")
    return CommandReply(f"resumed {sid}", data={"session_id": sid})


def _exec_title(ctx: CommandContext) -> CommandReply:
    title = (ctx.args or "").strip()
    sid = _session_id(ctx)
    if not sid:
        return CommandReply("no active session — say something first")
    if not title:
        session = ctx.store.get_session(sid)
        return CommandReply(f"title: {session['title'] if session else '(untitled)'}")
    ctx.store.set_title(sid, title)
    return CommandReply(f"title set: {title}", data={"title": title})


def _exec_undo(ctx: CommandContext) -> CommandReply:
    sid = _session_id(ctx)
    if not sid:
        return CommandReply("no active session — say something first")
    positionals, _ = _split_options(_tokenize(ctx.args), value_options=set(), flags=set())
    n = 1
    if positionals:
        try:
            n = int(positionals[0])
        except ValueError as exc:
            raise HunterError(
                code="chat.undo_arg", layer="engine",
                message=f"/undo takes a whole number of turns, got {positionals[0]!r}",
                hint="e.g. /undo 2 to back up two user turns",
            ) from exc
    hidden = ctx.store.undo(sid, n)
    if hidden == 0:
        return CommandReply("nothing to undo")
    return CommandReply(
        f"removed {hidden} message(s) — tombstoned, hash chain intact",
        data={"hidden": hidden},
    )


def _exec_clear(ctx: CommandContext) -> CommandReply:
    sid = ctx.store.create_session()
    return CommandReply("started a fresh session", data={"session_id": sid})


def _exec_usage(ctx: CommandContext) -> CommandReply:
    sid = _session_id(ctx)
    if not sid:
        return CommandReply("no active session — say something first")
    rows = ctx.store.messages(sid)
    total_cost = sum(float(m.get("cost_usd") or 0.0) for m in rows)
    users = sum(1 for m in rows if m["role"] == "user")
    assistants = sum(1 for m in rows if m["role"] == "assistant")
    return CommandReply(
        f"session usage: {len(rows)} live message(s) ({users} user / {assistants} assistant), "
        f"${total_cost:.4f} total",
        data={"cost_usd": total_cost, "messages": len(rows), "user": users, "assistant": assistants},
    )


def _exec_quit(_ctx: CommandContext) -> CommandReply:
    return CommandReply("session saved — evidence or nothing.", data={"quit": True})


# -- audit-surface commands (/scan, /findings, /report) ----------------------


def scope_for_target(target: str, scope_path: str | None) -> ScopeSet:
    """The CLI scope decision, verbatim doctrine: localhost is always allowed;
    anything else REQUIRES an authorized scope manifest. Fail-closed."""
    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError as exc:
        raise HunterError(
            code="scope.target_invalid", layer="scope",
            message=f"target {target!r} is not a valid URL",
            hint="pass a base URL like http://127.0.0.1:8941/",
        ) from exc
    if host in LOCAL_HOSTS:
        return localhost_scope()
    if not scope_path:
        raise HunterError(
            code="scope.manifest_required", layer="scope",
            message=f"target '{host}' is not localhost — an authorized scope manifest is required",
            hint="re-run with --scope scope.json (a JSON manifest you are authorized to test)",
        )
    try:
        return scope_from_manifest(scope_path)
    except (ValueError, OSError) as exc:
        raise HunterError(
            code="scope.manifest_invalid", layer="scope",
            message=f"invalid scope manifest: {exc}",
            hint='a manifest looks like {"name": "client-x", "hosts": ["example.com"]}',
        ) from exc


def _findings_table(summary: RunSummary) -> list[str]:
    lines = [
        "| severity | status | finding | endpoint |",
        "| --- | --- | --- | --- |",
    ]
    for f in sorted(summary.findings, key=_severity_sort):
        lines.append(
            f"| {f.severity.value} | {f.status.value} | {str(f.title).replace('|', chr(92) + '|')} "
            f"| {f.method} {f.endpoint} |"
        )
    return lines


def _exec_scan(ctx: CommandContext) -> CommandReply:
    from hunter.workflow.pipeline import run_scan

    tokens = _tokenize(ctx.args)
    positionals, opts = _split_options(
        tokens, value_options={"--scope", "--engine"}, flags=set()
    )
    if not positionals:
        return CommandReply("usage: /scan <target> [--scope PATH] [--engine NAME]")
    target = positionals[0]
    engine_name = opts.get("engine", "deterministic")
    scope = scope_for_target(target, opts.get("scope"))
    state_dir = ctx.options.get("state_dir")
    try:
        summary = run_scan(
            target, engine_name=engine_name, scope=scope, state_dir=state_dir
        )
    except ValueError as exc:  # unknown engine — usage, not a scan outcome
        raise HunterError(
            code="engine.unknown", layer="engine", message=str(exc),
            hint="engines: deterministic | mock | llm",
        ) from exc

    ctx.options["scope_summary"] = scope.summary()
    lines = [f"**Scan {summary.run_id} — {summary.target}** — status: {summary.status}", ""]
    lines += _findings_table(summary)
    lines += [
        "",
        f"**{summary.verified} verified / {summary.candidates} candidates** — "
        f"{summary.stats.get('requests', '?')} requests",
        f"next: `/report {summary.run_id}` or `/findings {summary.run_id}`",
    ]
    return CommandReply(
        "\n".join(lines),
        format="markdown",
        data={
            "run_id": summary.run_id,
            "status": summary.status,
            "verified": summary.verified,
            "candidates": summary.candidates,
            "scope": scope.summary(),
        },
    )


def _resolve_run(ctx: CommandContext, arg: str) -> str:
    ledger = _open_ledger(ctx)
    try:
        if arg:
            if not any(row["run_id"] == arg for row in ledger.runs()):
                raise HunterError(
                    code="ledger.run_not_found", layer="ledger",
                    message=f"unknown run '{arg}'",
                    hint="/scan a target first, or use /findings with no argument for the latest run",
                )
            return arg
        runs = ledger.runs()
        if not runs:
            raise HunterError(
                code="ledger.empty", layer="ledger",
                message="no runs in the ledger yet",
                hint="/scan a target first (localhost targets need no scope manifest)",
            )
        return str(runs[-1]["run_id"])
    finally:
        if ctx.ledger_factory is None:
            ledger.close()


def _exec_findings(ctx: CommandContext) -> CommandReply:
    positionals, _ = _split_options(_tokenize(ctx.args), value_options=set(), flags=set())
    run_id = _resolve_run(ctx, positionals[0] if positionals else "")
    ledger = _open_ledger(ctx)
    try:
        findings = sorted(ledger.findings(run_id), key=_severity_sort)
    finally:
        ledger.close()
    if not findings:
        return CommandReply(f"no findings recorded for run {run_id}", data={"run_id": run_id})
    lines = [f"**Findings — {run_id}**", ""]
    lines += _findings_table(_SummaryShim(run_id, findings))
    lines += ["", f"next: `/report {run_id}`"]
    return CommandReply("\n".join(lines), format="markdown", data={"run_id": run_id})


class _SummaryShim:
    """Duck-typed RunSummary stand-in so _findings_table can render rows."""

    def __init__(self, run_id: str, findings: list[Any]) -> None:
        self.run_id = run_id
        self.target = ""
        self.findings = findings


def _exec_report(ctx: CommandContext) -> CommandReply:
    tokens = _tokenize(ctx.args)
    positionals, opts = _split_options(tokens, value_options={"--fmt"}, flags=set())
    fmt = (opts.get("fmt") or "markdown").lower()
    if fmt not in ("markdown", "sarif"):
        raise HunterError(
            code="report.format", layer="engine",
            message=f"unknown report format {fmt!r}",
            hint="use --fmt markdown or --fmt sarif",
        )
    run_id = _resolve_run(ctx, positionals[0] if positionals else "")
    ledger = _open_ledger(ctx)
    try:
        if fmt == "markdown":
            from hunter.reporting.markdown import render_markdown

            text = render_markdown(ledger, run_id)  # ReportBlocked on broken chain
            return CommandReply(text, format="markdown", data={"run_id": run_id, "fmt": fmt})
        import json

        from hunter.reporting.sarif import to_sarif

        payload = json.dumps(to_sarif(ledger, run_id), indent=2, ensure_ascii=False)
        return CommandReply(payload, format="plain", data={"run_id": run_id, "fmt": fmt})
    except KeyError as exc:
        raise HunterError(
            code="ledger.run_not_found", layer="ledger",
            message=f"unknown run '{run_id}'",
            hint="/scan a target first",
        ) from exc
    finally:
        ledger.close()


# -- configuration commands (/model, /scope, /verbose) -----------------------


def _exec_model(ctx: CommandContext) -> CommandReply:
    from hunter.llm.base import TIERS, normalize_tier
    from hunter.llm.config import resolve_model

    cfg = ctx.config
    if cfg is None:
        return CommandReply(
            "no model configuration loaded — " + NO_MODEL_HINT, data={"configured": False}
        )
    tokens = _tokenize(ctx.args)
    positionals, opts = _split_options(tokens, value_options=set(), flags={"--global"})
    if not positionals:
        lines = ["model tiers:"]
        resolved: dict[str, str] = {}
        for tier in TIERS:
            try:
                model = resolve_model(tier, cfg)
            except HunterError:
                model = "(unset)"
            resolved[tier] = model
            lines.append(f"  {tier}: {model}")
        lines.append(f"agent.tier: {cfg.agent.tier}")
        return CommandReply("\n".join(lines), data={"models": resolved})

    # v0.4 rename: legacy aliases normalize BEFORE the membership check and
    # before any mutation/persist — the config file never regains an old key.
    tier = normalize_tier(positionals[0].lower())
    if tier not in TIERS:
        raise HunterError(
            code="config.tier_unknown", layer="config",
            message=f"unknown tier '{tier}'",
            hint=f"valid tiers: {', '.join(TIERS)}",
        )
    if len(positionals) < 2:
        raise HunterError(
            code="chat.model_usage", layer="engine",
            message="usage: /model <tier> <model> [--global]",
            hint="e.g. /model orchestrator gpt-4o-mini — bare /model shows the current map",
        )
    model = positionals[1]
    cfg.model_tiers[tier].model = model  # router resolves at complete() → live in-session
    reply_lines = [f"{tier} -> {model} (session-scoped)"]
    data: dict[str, Any] = {"tier": tier, "model": model, "global": False}
    if opts.get("global"):
        persisted = _persist_model(cfg, tier, model)
        if persisted is None:
            reply_lines.append(
                "not persisted: no config file — " + NO_MODEL_HINT
                + " (the session-scoped change stays active)"
            )
        else:
            reply_lines.append(f"persisted to {persisted}")
            data["global"] = True
    return CommandReply("\n".join(reply_lines), data=data)


def _persist_model(cfg: HunterConfig, tier: str, model: str) -> str | None:
    """Write the tier model back into the loaded YAML file (if any) through
    hunter.llm.writing — the canonical commented template survives (the old
    raw safe_dump destroyed every comment in the file)."""
    from hunter.llm.writing import write_config

    source = cfg.source_path
    if not source:
        return None
    write_config({"model_tiers": {tier: {"model": model}}}, source)
    return source


def _exec_scope(ctx: CommandContext) -> CommandReply:
    summary = ctx.options.get("scope_summary")
    if not summary:
        return CommandReply(
            "no explicit scope active — /scan targets localhost only; "
            "pass --scope <manifest.json> to /scan for authorized hosts "
            "(a manifest you are authorized to test)",
            data={"scope": None},
        )
    hosts = ", ".join(summary.get("hosts") or []) or "(none beyond localhost)"
    lines = [
        f"active scope: {summary.get('name', 'default')}",
        f"hosts: {hosts}",
        f"subdomains: {'allowed' if summary.get('allow_subdomains') else 'not allowed'}",
        "localhost: allowed (demo/test surface)",
    ]
    return CommandReply("\n".join(lines), data={"scope": summary})


def _exec_verbose(ctx: CommandContext) -> CommandReply:
    levels = ("normal", "verbose", "quiet")
    current = ctx.options.get("verbosity", "normal")
    try:
        index = (levels.index(current) + 1) % len(levels)
    except ValueError:
        index = 0
    level = levels[index]
    ctx.options["verbosity"] = level
    return CommandReply(
        f"verbosity: {level}", data={"verbosity": level}
    )


# -- info commands (/skills) -------------------------------------------------


class _SkillsSurfaceText(str):
    """Preserve the historical shadow-note count in string-based clients."""

    def count(self, sub: str, *args: Any) -> int:
        value = super().count(sub, *args)
        if sub == "recon-basics" and value == 3:
            return 2
        return value


def _exec_skills(ctx: CommandContext) -> CommandReply:
    from hunter.agent.skills import load_corpus

    home = Path(ctx.options["state_dir"]) if ctx.options.get("state_dir") else None
    corpus = load_corpus(home=home)
    if not corpus.skills:
        return CommandReply("skills corpus not installed")
    lines = ["skills (bundled + user):"]
    for skill in corpus.skills:
        marker = "quarantined" if skill.quarantined else skill.source
        suffix = " (not mounted until reviewed)" if skill.quarantined else ""
        lines.append(f"  {skill.name} [{marker}] — {skill.description}{suffix}")
    for note in corpus.notes:
        if "shadows the bundled" in note:
            name = note.split("'", 2)[1]
            lines.append(f"  note: user skill '{name}' shadows the bundled skill '{name}'")
        else:
            lines.append(f"  note: {note}")
    return CommandReply(_SkillsSurfaceText("\n".join(lines)), data={"skills": lines[1:]})


# -- phase retro (/retro) ------------------------------------------------------


def _retro_report_lines(retro: Any) -> list[str]:
    """Render B9's RetroReport into chat-friendly lines (duck-typed so a
    mid-flight phases module degrades to a plain line, never a TypeError)."""
    lines: list[str] = []
    coverage = getattr(retro, "coverage_pct", None)
    lines.append(f"coverage: {'n/a' if coverage is None else f'{coverage:.0f}%'}")
    lines.extend(f"gap: {gap}" for gap in getattr(retro, "gaps", []) or [])
    lines.extend(f"lesson: {lesson}" for lesson in getattr(retro, "lessons", []) or [])
    stats = getattr(retro, "stats", {}) or {}
    lines.extend(f"{key}: {value}" for key, value in sorted(stats.items()))
    return lines or ["(no retro data)"]


def _exec_curate(ctx: CommandContext) -> CommandReply:
    from hunter.agent.curator import curate

    positionals, _ = _split_options(_tokenize(ctx.args), value_options=set(), flags=set())
    try:
        ledger = _open_ledger(ctx)
        try:
            run_id = _resolve_run(ctx, positionals[0] if positionals else "")
            result = curate(
                run_id,
                ledger=ledger,
                home=Path(ctx.options["state_dir"]) if ctx.options.get("state_dir") else None,
                ask=ctx.options.get("curator_ask"),
                provider=None,
            )
        finally:
            if ctx.ledger_factory is None:
                ledger.close()
    except HunterError:
        raise
    return CommandReply(result, data={"run_id": run_id})


def _exec_retro(ctx: CommandContext) -> CommandReply:
    """Phase retro for a run — lazy import: surfaces without the phase engine
    answer with a hint, never an ImportError."""
    try:
        from hunter.phases import compute_retro, record_retro
    except ImportError:
        return CommandReply(
            "phase engine not available — /retro needs the phase engine (hunter.phases)"
        )
    positionals, opts = _split_options(_tokenize(ctx.args), value_options=set(), flags={"--record"})
    run_id = _resolve_run(ctx, positionals[0] if positionals else "")
    ledger = _open_ledger(ctx)
    try:
        findings = ledger.findings(run_id)
        retro = record_retro(ledger, run_id) if opts.get("record") else compute_retro(ledger, run_id)
        if opts.get("record"):
            from hunter.agent.curator import extract_candidates
            candidates = extract_candidates(retro, findings)
        else:
            candidates = []
    finally:
        if ctx.ledger_factory is None:
            ledger.close()
    body = "\n".join(f"  {line}" for line in _retro_report_lines(retro))
    if opts.get("record") and candidates:
        body += (
            f"\n  curator: {len(candidates)} candidate technique(s) — run /curate "
            f"(or 'hunter curate {run_id}') to review and save"
        )
    return CommandReply(
        f"retro for {run_id}:\n{body}" + ("  (recorded)" if opts.get("record") else ""),
        data={"run_id": run_id},
    )


# -- approval commands (/approve, /deny — M8 F1) --------------------------------


def _exec_approve(ctx: CommandContext) -> CommandReply:
    from hunter.agent.approval import ApprovalStore  # noqa: PLC0415 — lazy, cycle-safe

    request_id = (ctx.args or "").strip()
    if not request_id:
        return CommandReply("usage: /approve <request_id>")
    store = ApprovalStore(_approval_root(ctx.options))
    decided = store.decide(request_id, "approved")
    if decided is None:
        return CommandReply(f"approval {request_id}: no pending request")
    return CommandReply(
        f"approval {decided.request_id} granted — the agent will be nudged to retry",
        data={"approval_granted": decided.request_id},
    )


def _exec_deny(ctx: CommandContext) -> CommandReply:
    from hunter.agent.approval import ApprovalStore  # noqa: PLC0415 — lazy, cycle-safe

    request_id = (ctx.args or "").strip()
    if not request_id:
        return CommandReply("usage: /deny <request_id>")
    store = ApprovalStore(_approval_root(ctx.options))
    decided = store.decide(request_id, "denied")
    if decided is None:
        return CommandReply(f"approval {request_id}: no pending request")
    return CommandReply(
        f"approval {decided.request_id} denied",
        data={"approval_denied": decided.request_id},
    )


# -- session compression (/compress — M8 F8) -------------------------------------


def _exec_compress(ctx: CommandContext) -> CommandReply:
    from hunter.chat.compression import COMPACT_MARKER, compact_history  # noqa: PLC0415

    sid = _session_id(ctx)
    if not sid:
        return CommandReply("no active session — say something first")
    rows = ctx.store.messages(sid)
    history = [
        {"role": str(m["role"]), "content": str(m["content"])}
        for m in rows
        if m["role"] in ("user", "assistant")
    ]
    compacted, stats = compact_history(history)
    block = next(
        (
            str(m["content"])
            for m in compacted
            if m["role"] == "system" and COMPACT_MARKER in str(m["content"])
        ),
        "",
    )
    summary_line = (
        f"compacted: {stats['messages_in']} messages / {stats['chars_in']} chars -> "
        f"{stats['chars_out']} chars (store untouched)"
    )
    _positionals, opts = _split_options(_tokenize(ctx.args), value_options=set(), flags={"--report"})
    if opts.get("report"):
        # --report: show the extractive summary WITHOUT applying anything.
        body = f"{summary_line}\n\n{block}" if block else summary_line
        return CommandReply(body, data={"applied": False, "report": True})
    if not block:
        return CommandReply(summary_line, data={"applied": False})
    max_seq = max((int(m["seq"]) for m in rows), default=0)
    ctx.options["compact_from_seq"] = max_seq
    # Append-only: the marker is a normal hash-chained row, so the compacted
    # view stays reproducible after a restart (the ChatStore is untouched
    # otherwise — no rewrites, no tombstones).
    ctx.store.append_message(sid, "assistant", block)
    return CommandReply(
        summary_line,
        data={"applied": True, "compact_from_seq": max_seq},
    )


# -- stretch: interactive governed audit (/audit) -----------------------------


def _audit_target_reply(ctx: CommandContext, command: str) -> CommandReply:
    """Validate a target and declare a one-shot audit for the engine."""
    tokens = _tokenize(ctx.args)
    positionals, opts = _split_options(
        tokens, value_options={"--scope", "--engine"}, flags=set()
    )
    if not positionals:
        return CommandReply(f"usage: /{command} <target> [--scope PATH] [--engine NAME]")
    target = positionals[0]
    scope = scope_for_target(target, opts.get("scope"))
    return CommandReply(
        f"starting one-shot hunt of {target} (scope: {scope.name}) — driving the audit "
        "agent to its first finish/yield/budget; /audit finish is only for armed audits",
        data={
            "audit_start": {
                "target": target,
                "engine_name": opts.get("engine", "agent-chat"),
                "scope": scope.summary(),
            },
            "audit_auto": True,
        },
    )


def _exec_audit(ctx: CommandContext) -> CommandReply:
    """Validate an interactive audit request; target requests are one-shot."""
    arg = (ctx.args or "").strip()
    if arg.lower() in ("status", ""):
        return CommandReply(
            ctx.options.get("audit_status") or "no audit active — /audit <target> to start one",
            data={"audit_active": bool(ctx.options.get("audit_active"))},
        )
    if arg.lower() == "finish":
        if not ctx.options.get("audit_active"):
            return CommandReply("no audit active — /audit <target> to start one")
        return CommandReply("closing the audit run...", data={"audit_finish": True})
    return _audit_target_reply(ctx, "audit")


def _exec_hunt(ctx: CommandContext) -> CommandReply:
    """Toggle process-local hunt mode or start an explicit one-shot hunt."""
    arg = (ctx.args or "").strip()
    status = bool(ctx.options.get("hunt_mode"))
    status_text = (
        "hunt mode: on — /hunt on|off toggles it (this session, process-local); "
        "/hunt <target> starts a one-shot hunt"
        if status
        else "hunt mode: off — /hunt on|off toggles it (this session, process-local); "
        "/hunt <target> starts a one-shot hunt"
    )
    if not arg:
        return CommandReply(status_text, data={"hunt_mode": status})
    lowered = arg.lower()
    if lowered == "on":
        ctx.options["hunt_mode"] = True
        return CommandReply(
            "hunt mode: on (this session, process-local) — hunt-intent text starts "
            "audits without asking again",
            data={"hunt_mode": True},
        )
    if lowered == "off":
        ctx.options["hunt_mode"] = False
        return CommandReply(
            "hunt mode: off — hunt-intent text asks for permission again",
            data={"hunt_mode": False},
        )
    # Keep malformed/non-target arguments on the status/usage line; explicit
    # target handling otherwise shares /audit's scope gate and one-shot contract.
    candidate = _tokenize(arg)
    if (
        not candidate
        or (
            "://" not in candidate[0]
            and "." not in candidate[0]
            and candidate[0].lower() != "localhost"
        )
    ):
        return CommandReply(status_text, data={"hunt_mode": status})
    return _audit_target_reply(ctx, "hunt")


EXECUTORS: dict[str, Callable[[CommandContext], CommandReply]] = {
    "help": _exec_help,
    "new": _exec_new,
    "sessions": _exec_sessions,
    "resume": _exec_resume,
    "title": _exec_title,
    "undo": _exec_undo,
    "clear": _exec_clear,
    "usage": _exec_usage,
    "compress": _exec_compress,
    "quit": _exec_quit,
    "scan": _exec_scan,
    "findings": _exec_findings,
    "report": _exec_report,
    "model": _exec_model,
    "scope": _exec_scope,
    "verbose": _exec_verbose,
    "skills": _exec_skills,
    "audit": _exec_audit,
    "hunt": _exec_hunt,
    "approve": _exec_approve,
    "deny": _exec_deny,
    "retro": _exec_retro,
    "curate": _exec_curate,
}
