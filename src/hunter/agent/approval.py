"""Approval gate — the human checkpoint for dangerous agent tools (M8 F1).

Doctrine: catastrophic commands NEVER run in any mode; every other
``danger="approval"`` tool needs a user decision (``/approve <id>``) before it
executes — a pending request is a BLOCKED outcome, never a side effect.
Fail-closed everywhere: a surface without a configured gate refuses the tool
(``approval.unavailable``), a gateway without a confirm callback creates a
pending request and blocks (``approval.required``).

Persistence: one JSON file per request under ``<state>/approvals/<id>.json``.
Expiry is COMPUTED (never stored); decisions are single-use (``used_ts`` is
set when a decision is consumed, so an approval cannot be replayed).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from hunter.kernel.events import canonical_json, sha256_hex
from hunter.kernel.redaction import redact_text

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.agent.tools_base import ToolContext, ToolOutcome
    from hunter.kernel.ledger import Ledger

__all__ = [
    "APPROVAL_FILE_KEYS",
    "APPROVAL_TTL_SECONDS",
    "ApprovalRequest",
    "ApprovalStore",
    "CATASTROPHIC_PATTERNS_SOURCE",
    "CommandClass",
    "GateCallback",
    "READONLY_EXECUTABLES",
    "READONLY_GIT_SUBCOMMANDS",
    "classify_command",
    "classify_shell_command",
    "effective_status",
    "is_catastrophic",
    "make_approval_gate",
]

CommandClass = Literal["readonly", "mutating", "catastrophic"]

# This tuple is a public policy contract. Keep its order stable; additions to
# the effective allowlist below are deliberately separate for compatibility
# with the original M8 constants.
READONLY_EXECUTABLES: tuple[str, ...] = (
    "cat", "cd", "dir", "echo", "find", "grep", "head", "hostname",
    "id", "ls", "pwd", "rg", "stat", "tail", "type", "uname", "ver",
    "where", "which", "whoami", "git",
)
READONLY_GIT_SUBCOMMANDS: tuple[str, ...] = (
    "status", "diff", "log", "show", "branch", "rev-parse", "ls-files",
)
# Recon utilities are read-only from the local-system perspective. Network
# access and scope remain governed by their individual tools and the scope gate.
_READONLY_RECON_EXECUTABLES = {
    "curl", "wget", "nmap", "sqlmap", "nuclei", "ffuf", "dig", "nslookup",
    "whois", "whatweb", "gobuster", "masscan", "testssl", "openssl", "http",
}
_WRITE_FLAGS = {
    "-o", "--output", "--write", "--upload", "--delete", "--remove", "--append",
    "--in-place", "/a", "/s", "/q", "/f",
}

# (regex, reason) — matched against the RAW command and a normalized form
# (lowercased, "^"/"\" replaced by space, quotes removed, whitespace
# collapsed) so quoting/caret/backslash games cannot slip through.
CATASTROPHIC_PATTERNS_SOURCE: tuple[tuple[str, str], ...] = (
    (r"\brm\b[^;\n|&]*\s-\w*r\w*f", "recursive force delete"),
    (r"\brm\b[^;\n|&]*\s+(?:/|~/|~\b|\*)", "rm of root/home/glob"),
    (r"\bdel\b\s+/[sq]", "windows recursive delete"),
    (r"\brd\b\s+/s", "windows recursive delete"),
    (r"\bremove-item\b[^;\n]*\s-(?:recurse|force)\b", "powershell recursive delete"),
    (r"\bformat\b(?:\.com)?\b", "disk format"),
    (r"\bdiskpart\b", "disk partitioning"),
    (r"\bmkfs(?:\.\w+)?\b", "filesystem creation"),
    (r"\bdd\b[^;\n]*\bof=/dev/", "raw disk write"),
    (r">\s*/dev/(?:sd|nvme|hd)", "raw disk redirect"),
    (r"\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b", "machine power control"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", "fork bomb"),
)

_CATASTROPHIC_COMPILED: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in CATASTROPHIC_PATTERNS_SOURCE
)

_QUOTE_CHARS_RE = re.compile(r"[\'\"`]")
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_command(command: str) -> str:
    """Lowercase, neutralize caret/backslash escapes and quotes, collapse
    whitespace — the form denylist matching cannot be quoted around."""
    text = str(command or "")
    text = text.replace("^", " ").replace("\\", " ")
    text = _QUOTE_CHARS_RE.sub("", text)
    return _WHITESPACE_RE.sub(" ", text).strip().lower()


def is_catastrophic(command: str) -> str | None:
    """Reason string when ``command`` matches the catastrophic denylist,
    checked against BOTH the raw text and the normalized form; else None."""
    raw = str(command or "")
    normalized = normalize_command(raw)
    for pattern, reason in _CATASTROPHIC_COMPILED:
        if pattern.search(raw) or pattern.search(normalized):
            return reason
    return None


def _has_write_flag(argv: list[str]) -> bool:
    for token in argv[1:]:
        lowered = token.lower()
        if lowered in _WRITE_FLAGS:
            return True
        if any(lowered.startswith(flag + "=") for flag in ("-o", "--output", "--write")):
            return True
    return False


def classify_shell_command(command: str) -> CommandClass:
    """Classify a local command conservatively without granting execution.

    Catastrophic patterns are checked before parsing so quoting and escape
    variants cannot evade the safety boundary. Everything not in the small
    explicit read-only policy is mutating, including malformed shell syntax.
    """
    raw = str(command or "")
    if is_catastrophic(raw) is not None:
        return "catastrophic"
    if not raw.strip() or any(char in raw for char in ";|&<>"):
        return "mutating"
    try:
        argv = shlex.split(raw, posix=True)
    except ValueError:
        return "mutating"
    if not argv or any("=" in token for token in argv[:1]):
        return "mutating"
    executable = argv[0].lower()
    # Do not treat arbitrary paths/interpreters as safe aliases.
    if executable not in READONLY_EXECUTABLES and executable not in _READONLY_RECON_EXECUTABLES:
        return "mutating"
    if _has_write_flag(argv):
        return "mutating"
    if executable == "git":
        subcommand = next((token.lower() for token in argv[1:] if not token.startswith("-")), "")
        if subcommand not in READONLY_GIT_SUBCOMMANDS:
            return "mutating"
    return "readonly"


# Short public spelling used by newer callers while preserving the pinned M8
# name used by existing integrations and tests.
classify_command = classify_shell_command


APPROVAL_TTL_SECONDS = 300

APPROVAL_FILE_KEYS: tuple[str, ...] = (
    "request_id",
    "tool",
    "fingerprint",
    "summary",
    "args",
    "status",
    "surface",
    "created_ts",
    "expires_ts",
    "decided_ts",
    "used_ts",
)


@dataclass
class ApprovalRequest:
    """One pending/decided dangerous-tool request (mirrors the JSON file)."""

    request_id: str  # "A-" + uuid4().hex[:8]
    tool: str
    fingerprint: str  # sha256_hex(canonical_json({"tool": tool, "args": args}))
    summary: str  # <=200 chars, redact_text()'d one-line arg summary
    args: dict[str, Any]
    status: str  # stored: "pending" | "approved" | "denied"
    surface: str  # e.g. "telegram:12345" | "repl" | ""
    created_ts: float
    expires_ts: float
    decided_ts: float | None
    used_ts: float | None  # set when a decision is consumed (single-use)
    scope: str = "once"  # §10 Q2/Q3: "once" | "session" | "always"
    run_id: str = ""  # session binding (Q2); "" = unbound/legacy
    command_class: str | None = None  # Q2 always key: tool + command_class
    scope_id: str = ""  # informational key (always: tool:class; session: run:fp)


def _summary_for(tool: str, args: dict[str, Any]) -> str:
    """One-line, redacted, bounded arg summary for humans and the model."""
    joined = " ".join(f"{key}={args[key]}" for key in args) if isinstance(args, dict) and args else str(tool)
    text = redact_text(str(joined))
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:200]


def _write_json_atomic(path: Path, obj: Any) -> None:
    """tmp file + os.replace — atomic-enough on win32 and POSIX."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def effective_status(record: ApprovalRequest, *, now: float | None = None) -> str:
    """``"expired"`` when pending and ``now >= expires_ts``, else
    ``record.status``. Expiry is COMPUTED, never stored."""
    moment = time.time() if now is None else now
    if record.status == "pending" and moment >= record.expires_ts:
        return "expired"
    return record.status


class ApprovalStore:
    """File-backed approval requests under ``root`` (thread-safe)."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- internals -----------------------------------------------------------

    def _path(self, request_id: str) -> Path:
        return self.root / f"{request_id}.json"

    def _path_for(self, request: ApprovalRequest) -> Path:
        if (request.scope or "once") == "always":
            return self.root / "always" / f"{request.request_id}.json"
        return self._path(request.request_id)

    @staticmethod
    def _decode(data: Any) -> ApprovalRequest | None:
        """Corrupt/foreign/partial files decode to None — id forgery and
        garbage JSON must never raise. Legacy files without scope fields
        decode tolerantly as ``scope="once"``."""
        if not isinstance(data, dict):
            return None
        if not set(APPROVAL_FILE_KEYS) <= set(data):
            return None
        try:
            raw_scope = data.get("scope", "once") or "once"
            scope = str(raw_scope) if str(raw_scope) in ("once", "session", "always") else "once"
            raw_cc = data.get("command_class")
            cc = str(raw_cc) if str(raw_cc) in ("readonly", "mutating", "catastrophic") else None
            return ApprovalRequest(
                request_id=str(data["request_id"]),
                tool=str(data["tool"]),
                fingerprint=str(data["fingerprint"]),
                summary=str(data["summary"]),
                args=data["args"] if isinstance(data["args"], dict) else {},
                status=str(data["status"]),
                surface=str(data["surface"]),
                created_ts=float(data["created_ts"]),
                expires_ts=float(data["expires_ts"]),
                decided_ts=(None if data["decided_ts"] is None else float(data["decided_ts"])),
                used_ts=(None if data["used_ts"] is None else float(data["used_ts"])),
                scope=scope,
                run_id=str(data.get("run_id") or ""),
                command_class=cc,
                scope_id=str(data.get("scope_id") or ""),
            )
        except (TypeError, ValueError, KeyError):
            return None

    def _read_file(self, path: Path) -> ApprovalRequest | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        return self._decode(data)

    def _load(self, request_id: str | None) -> ApprovalRequest | None:
        if not request_id or not isinstance(request_id, str):
            return None
        for path in (self._path(request_id), self.root / "always" / f"{request_id}.json"):
            if path.is_file():
                record = self._read_file(path)
                if record is not None:
                    return record
        return None

    def _iter_files(self) -> Any:
        yield from self.root.glob("*.json")
        always_dir = self.root / "always"
        if always_dir.is_dir():
            yield from always_dir.glob("*.json")

    def _store(self, request: ApprovalRequest) -> None:
        # Pinned M8 format: default once requests persist exactly the 11
        # APPROVAL_FILE_KEYS (old test_approval.py pin). Scope extras live
        # only on session/always files, which tolerate legacy reads as once.
        payload = {key: asdict(request)[key] for key in APPROVAL_FILE_KEYS}
        if (request.scope or "once") != "once":
            payload["scope"] = request.scope or "once"
            payload["run_id"] = request.run_id or ""
            payload["command_class"] = request.command_class
            payload["scope_id"] = request.scope_id or ""
        _write_json_atomic(self._path_for(request), payload)

    # -- public API ------------------------------------------------------------

    def create(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        ttl_seconds: int = APPROVAL_TTL_SECONDS,
        surface: str = "",
        scope: str = "once",
        run_id: str = "",
        command_class: str | None = None,
    ) -> ApprovalRequest:
        """Create a pending request. §10 Q2/Q3/Q4: ``scope`` is one of
        once|session|always; ``always`` is keyed tool+command_class and local
        per state-dir; catastrophic+always is forced back to once."""
        scope = str(scope or "once")
        if scope not in ("once", "session", "always"):
            scope = "once"
        tool_name = str(tool)
        run = str(run_id or "")
        cc: str | None = None
        if command_class in ("readonly", "mutating", "catastrophic"):
            cc = str(command_class)
        elif tool_name == "shell_exec" and isinstance(args, dict):
            try:
                cc = classify_shell_command(str(args.get("command", "")))
            except Exception:  # noqa: BLE001 — inference never blocks creation
                cc = None
        if scope == "always" and cc == "catastrophic":
            scope = "once"  # Q3: catastrophic NEVER always
        fingerprint = sha256_hex(canonical_json({"tool": tool_name, "args": args}))
        if scope == "always":
            scope_id = f"{tool_name}:{cc or ''}"
        elif scope == "session":
            scope_id = f"{run}:{fingerprint}"
        else:
            scope_id = fingerprint
        with self._lock:
            now = time.time()
            request = ApprovalRequest(
                request_id=f"A-{uuid.uuid4().hex[:8]}",
                tool=tool_name,
                fingerprint=fingerprint,
                summary=_summary_for(tool_name, args),
                args=dict(args) if isinstance(args, dict) else {},
                status="pending",
                surface=str(surface or ""),
                created_ts=now,
                expires_ts=now + float(ttl_seconds),
                decided_ts=None,
                used_ts=None,
                scope=scope,
                run_id=run,
                command_class=cc,
                scope_id=scope_id,
            )
            self._store(request)
            return request

    def get(self, request_id: str | None) -> ApprovalRequest | None:
        with self._lock:
            return self._load(request_id)

    def decide(self, request_id: str, decision: str) -> ApprovalRequest | None:
        """Apply ``"approved"``/``"denied"`` once; None when the request is
        missing, already decided, TTL-expired, or the decision is invalid."""
        if decision not in ("approved", "denied"):
            return None
        with self._lock:
            record = self._load(request_id)
            if record is None:
                return None
            if record.status != "pending" or effective_status(record) == "expired":
                return None
            record.status = decision
            record.decided_ts = time.time()
            self._store(record)
            return record

    def find_approved(
        self,
        fingerprint: str,
        *,
        run_id: str | None = None,
        tool: str | None = None,
        command_class: str | None = None,
    ) -> ApprovalRequest | None:
        """Scope-aware approved lookup; does NOT consume.

        once: exact fingerprint (legacy, run-agnostic). session: fingerprint
        bound to ``run_id``. always (Q2): tool + command_class, fingerprint
        ignored, local to this state-dir. Exact matches win over always.
        """
        with self._lock:
            best_exact: ApprovalRequest | None = None
            best_always: ApprovalRequest | None = None
            for path in self._iter_files():
                record = self._read_file(path)
                if record is None or record.status != "approved":
                    continue
                if record.used_ts is not None or effective_status(record) == "expired":
                    continue
                scope = record.scope or "once"
                if scope == "always":
                    if tool is None:
                        continue
                    if record.tool != str(tool):
                        continue
                    if (record.command_class or None) != (command_class or None):
                        continue
                    if best_always is None or record.created_ts > best_always.created_ts:
                        best_always = record
                    continue
                if record.fingerprint != fingerprint:
                    continue
                if scope == "session" and run_id is not None and record.run_id != run_id:
                    continue
                if best_exact is None or record.created_ts > best_exact.created_ts:
                    best_exact = record
            return best_exact if best_exact is not None else best_always

    def find_decided(self, fingerprint: str) -> ApprovalRequest | None:
        """Newest DECIDED (approved or denied) record for ``fingerprint``.

        The gate uses this to ask the interactive ``confirm_fn`` at most once
        per exact call: once a decision exists, a retry falls through to a NEW
        pending request (``approval.required``) so the user can still approve
        asynchronously via ``/approve <id>`` — the recorded denial itself is
        never silently reused to auto-deny."""
        with self._lock:
            best: ApprovalRequest | None = None
            for path in self._iter_files():
                record = self._read_file(path)
                if record is None or record.fingerprint != fingerprint:
                    continue
                if record.status not in ("approved", "denied"):
                    continue
                if best is None or record.created_ts > best.created_ts:
                    best = record
            return best

    def consume(self, request_id: str) -> None:
        """Mark a once decision used (single-use). Session/always approvals
        stay reusable; missing ids are a no-op."""
        with self._lock:
            record = self._load(request_id)
            if record is None or record.used_ts is not None:
                return
            if (record.scope or "once") != "once":
                return
            record.used_ts = time.time()
            self._store(record)


GateCallback = Callable[[str, dict[str, Any], "ToolContext"], "ToolOutcome | None"]


def _gate_event(ledger: Ledger, run_id: str, payload: dict[str, Any]) -> None:
    """Ledger the approval decision directly (engine_event) — the gate is
    invoked from dispatch paths that may not have an emit callback."""
    with contextlib.suppress(Exception):  # bookkeeping must never block a tool
        ledger.append(run_id, "engine_event", payload)


def _blocked_outcome(code: str, message: str) -> ToolOutcome:
    from hunter.agent.tools_base import ToolOutcome  # noqa: PLC0415 — lazy, cycle-safe

    return ToolOutcome(ok=False, blocked=True, code=code, result_for_model=message)


def make_approval_gate(
    store: ApprovalStore,
    *,
    ledger: Ledger,
    run_id: str,
    auto_allow: bool = False,
    confirm_fn: Callable[[ApprovalRequest], bool] | None = None,
    surface: str = "",
) -> GateCallback:
    """Build the fail-closed, class-aware approval gate.

    Shell commands are classified before any approval shortcut. An approval
    decision is always fingerprinted and single-use; ``auto_allow`` applies to
    readonly shell commands only (generic approval tools retain M8 behavior).
    """

    def gate(tool: str, args: dict[str, Any], ctx: ToolContext) -> ToolOutcome | None:
        command_class: CommandClass | None = None
        reason: str | None = None
        if tool == "shell_exec":
            command = str(args.get("command", ""))
            command_class = classify_shell_command(command)
            reason = is_catastrophic(command)
        fingerprint = sha256_hex(canonical_json({"tool": str(tool), "args": args}))
        approved = store.find_approved(
            fingerprint, run_id=run_id, tool=str(tool), command_class=command_class
        )
        if approved is not None:
            if (approved.scope or "once") == "once":
                store.consume(approved.request_id)
            payload = {
                "tool": str(tool),
                "approval": f"consumed:{approved.request_id}",
                "fingerprint": fingerprint,
            }
            if command_class is not None:
                payload["command_class"] = command_class
            _gate_event(ledger, run_id, payload)
            if ctx is not None:
                ctx.config["approval_id"] = approved.request_id
                if command_class is not None:
                    ctx.config["approval_class"] = command_class
            return None

        # Catastrophic commands are not permanently denied, but they never
        # consult either auto_allow or an interactive callback.
        if command_class == "catastrophic":
            request = store.create(
                str(tool), args, surface=surface, scope="once",
                run_id=run_id, command_class=command_class,
            )
            _gate_event(
                ledger,
                run_id,
                {
                    "tool": "shell_exec",
                    "command_class": "catastrophic",
                    "approval": f"catastrophic:{request.request_id}",
                    "fingerprint": fingerprint,
                    "reason": reason or "catastrophic command",
                },
            )
            return _blocked_outcome(
                "approval.catastrophic",
                "BLOCKED: catastrophic shell command requires explicit approval. "
                f"Request id: {request.request_id} (expires in {APPROVAL_TTL_SECONDS}s). "
                f"Reply /approve {request.request_id} to permit exactly one execution.",
            )

        # Q1 BOLEH AUTO: readonly + auto_allow -> gate None, even for
        # outside paths. Never hard-block readonly on argv location.
        can_auto_allow = bool(auto_allow) and (tool != "shell_exec" or command_class == "readonly")
        if can_auto_allow:
            payload = {"tool": str(tool), "approval": "auto_allowed", "fingerprint": fingerprint}
            if command_class is not None:
                payload["command_class"] = command_class
                if ctx is not None:
                    ctx.config["approval_class"] = command_class
            _gate_event(ledger, run_id, payload)
            return None

        if confirm_fn is not None and store.find_decided(fingerprint) is None:
            request = store.create(
                str(tool), args, surface=surface, scope="once",
                run_id=run_id, command_class=command_class,
            )
            payload = {
                "tool": str(tool),
                "approval": f"requested:{request.request_id}",
                "fingerprint": fingerprint,
            }
            if command_class is not None:
                payload["command_class"] = command_class
            _gate_event(ledger, run_id, payload)
            try:
                allowed = bool(confirm_fn(request))
            except Exception:  # noqa: BLE001 — a broken confirm is a denial
                allowed = False
            if allowed:
                store.decide(request.request_id, "approved")
                store.consume(request.request_id)
                payload = {
                    "tool": str(tool),
                    "approval": f"granted:{request.request_id}",
                    "fingerprint": fingerprint,
                }
                if command_class is not None:
                    payload["command_class"] = command_class
                _gate_event(ledger, run_id, payload)
                if ctx is not None:
                    ctx.config["approval_id"] = request.request_id
                    if command_class is not None:
                        ctx.config["approval_class"] = command_class
                return None
            store.decide(request.request_id, "denied")
            payload = {
                "tool": str(tool),
                "approval": f"denied:{request.request_id}",
                "fingerprint": fingerprint,
            }
            if command_class is not None:
                payload["command_class"] = command_class
            _gate_event(ledger, run_id, payload)
            return _blocked_outcome(
                "approval.denied",
                f"BLOCKED: tool '{tool}' was denied by the user "
                f"(request {request.request_id}). Do not retry the same call.",
            )

        request = store.create(
            str(tool), args, surface=surface, scope="once",
            run_id=run_id, command_class=command_class,
        )
        payload = {
            "tool": str(tool),
            "approval": f"requested:{request.request_id}",
            "fingerprint": fingerprint,
        }
        if command_class is not None:
            payload["command_class"] = command_class
        _gate_event(ledger, run_id, payload)
        class_text = (
            f" shell command class '{command_class}'" if command_class is not None else ""
        )
        return _blocked_outcome(
            "approval.required",
            f"BLOCKED:{class_text} requires user approval. Request id: {request.request_id} "
            f"(expires in {APPROVAL_TTL_SECONDS}s). Ask the user to reply /approve "
            f"{request.request_id} — do not retry before approval.",
        )

    return gate
