"""tool_forge — the agent authors its own tools, and the ledger decides if they are real.

Why this exists
---------------
A hunt that finds a novel bug often needs a probe that does not exist yet:
a bespoke decoder for a non-standard envelope, a state-machine walker for an
unusual contract, a parser for a response shape no built-in covers. The
operator should not have to stop the run, write the tool by hand, and start
again — and the agent should not have to pretend a built-in tool does
something it does not.

So the agent can write a tool here, and the tool becomes usable in the SAME
run and every run after it.

Why it is not a code-execution hole
-----------------------------------
A tool that runs arbitrary code is ``shell_exec``, and that is already
triple-gated. ``tool_forge`` does not execute anything at authoring time — it
writes a handler that is dispatched later through the same registry, with the
same approval gate, the same scope gate, and the same ledger event trail. The
forge adds no new execution privilege; it adds a new *name* for code the
operator already authorised.

The three gates that keep a forged tool honest
----------------------------------------------
1. **Evidence-bound.** A forged tool is registered with the evidence ids from
   the run that motivated it. No evidence, no tool — the same RULE-E1 rule
   that governs findings. An agent cannot invent a tool out of nothing any
   more than it can invent a finding.
2. **Quarantined by default.** A forged tool is written to disk INERT
   (``quarantined: true``) and is not mounted for later runs until the
   operator edits the file. Within the run that forged it, it is usable —
   the evidence for it is right there in the ledger.
3. **Statically screened.** The draft is scanned for the same injection
   markers and control characters the skill curator screens for, plus a
   denylist of imports that would let a "tool" reach around the gates
   (``subprocess``, ``socket``, ``ctypes``, ``os.system``, ``eval``,
   ``exec``, ``__import__``). A tool that tries to bypass the harness is
   refused, not quarantined.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from hunter.agent.tools_base import ToolOutcome  # noqa: PLC0415 — optional import path

__all__ = ["register_forge_tools", "forge_tool", "screen_handler", "FORGE_SPEC"]

# A forged tool may not reach around the gates. These imports are what a
# "tool" would use to execute without the registry, open a raw socket, or
# load native code — none of which a legitimate probe needs.
_FORBIDDEN_IMPORTS = frozenset({
    "subprocess", "socket", "ctypes", "cffi", "multiprocessing",
    "pty", "commands", "popen2", "importlib", "imp",
})
_FORBIDDEN_CALLS = frozenset({
    "eval", "exec", "compile", "__import__", "globals", "locals",
    "os.system", "os.popen", "os.execv", "os.spawn", "breakpoint",
})
# The same injection markers the skill curator screens for: a tool whose
# description tries to talk to the model is not a tool, it is a prompt.
_INJECTION_MARKERS = (
    "ignore previous instructions", "ignore all previous instructions",
    "disregard previous instructions", "forget your instructions",
    "new instructions", "you are now", "act as", "pretend to be",
    "system prompt", "assistant:", "developer message",
    "<|im_start", "<|im_end", "### instruction", "reveal your",
)

_MAX_HANDLER_BYTES = 24_000
_MAX_NAME_LEN = 64


def _slug(text: str) -> str:
    words = re.findall(r"[a-z0-9]+", str(text).lower())
    slug = "-".join(words)[:_MAX_NAME_LEN].strip("-")
    return slug


def _clamp(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].strip()
    return cut or text[:limit]


def screen_handler(handler: str) -> tuple[bool, tuple[str, ...]]:
    """Refuse a handler that reaches around the harness. Returns (ok, reasons).

    Checked against the raw text, so a comment or a string cannot hide the
    import: the point is not to run the code, it is to refuse the *draft*.
    """
    reasons: list[str] = []
    lowered = str(handler or "").lower()

    for module in _FORBIDDEN_IMPORTS:
        if re.search(rf"\b(?:import\s+{module}\b|from\s+{module}\b)", lowered):
            reasons.append(f"forbidden import: {module}")

    for call in _FORBIDDEN_CALLS:
        if re.search(rf"(?<![\w.]){re.escape(call)}\s*\(", lowered):
            reasons.append(f"forbidden call: {call}")

    for marker in _INJECTION_MARKERS:
        if marker in lowered:
            reasons.append(f"injection marker: {marker}")

    if any(ord(char) < 32 and char not in "\t\n\r" for char in str(handler or "")):
        reasons.append("control character")

    return (not reasons), tuple(dict.fromkeys(reasons))


def _evidence_ids(ctx: Any, args: dict[str, Any]) -> tuple[list[str], str | None]:
    """The evidence this tool is grounded in. RULE-E1: it must exist.

    An agent may cite evidence ids from the current run. Every one is checked
    against the ledger before the tool is written — a forged tool with no
    evidence is refused exactly like a finding with no evidence.
    """
    raw = args.get("evidence_ids") or args.get("evidence") or []
    if isinstance(raw, str):
        raw = [raw]
    ids = [str(item).strip() for item in raw if str(item).strip()]
    if not ids:
        return [], "forge.no_evidence"
    ledger = getattr(ctx, "ledger", None)
    if ledger is None:
        return [], "forge.no_ledger"
    run_id = str(getattr(ctx, "run_id", "") or "")
    for evidence_id in ids:
        try:
            row = ledger._conn.execute(
                "SELECT run_id FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        except Exception:  # noqa: BLE001 — a ledger without the table is a refusal
            return [], "forge.no_evidence"
        if row is None:
            return [], f"forge.unknown_evidence:{evidence_id}"
        if run_id and str(row[0]) != run_id:
            return [], f"forge.cross_run_evidence:{evidence_id}"
    return ids, None


def _render_skill_md(name: str, description: str, handler: str, evidence_ids: list[str], rationale: str) -> str:
    """A SKILL.md card whose body documents the tool and its evidence.

    The handler is stored as a fenced python block so the card stays a plain
    markdown file an operator can read, diff, and edit — the same shape the
    skill corpus already uses and the loader expects: ``name`` matches the
    directory, ``tags`` is a YAML list, and the frontmatter is the only
    structured part.
    """
    lines = [
        "---",
        f"name: {name}",
        f"description: {description}",
        "version: 0.1.0",
        "tags:",
        "  - forged",
        "  - tool",
        "quarantined: true",
        f"evidence: {', '.join(evidence_ids)}",
        "---",
        "",
        f"# {name}",
        "",
        "## Why this tool exists",
        "",
        rationale or "(no rationale given)",
        "",
        "## Evidence",
        "",
        f"Bound to: {', '.join(evidence_ids)}",
        "",
        "## Handler",
        "",
        "Forged during a hunt. INERT until an operator edits this file and",
        "removes `quarantined: true` — within the run that forged it the tool",
        "is usable, because its evidence is in that run's ledger.",
        "",
        "```python",
        handler.rstrip("\n"),
        "```",
        "",
    ]
    return "\n".join(lines)


def forge_tool(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Author a new tool. Evidence-bound, screened, quarantined on disk."""
    name = _slug(args.get("name", ""))
    if not name:
        return {"ok": False, "blocked": False, "code": "forge.bad_name",
                "result_for_model": "tool name must contain at least one [a-z0-9] character"}
    description = _clamp(args.get("description", "") or name.replace("-", " "), 60)
    handler = str(args.get("handler", "") or "")
    rationale = _clamp(args.get("rationale", "") or "", 400)

    if not handler.strip():
        return {"ok": False, "blocked": False, "code": "forge.empty_handler",
                "result_for_model": "handler body is required — a tool with no code is a note, use note_add"}
    if len(handler.encode("utf-8")) > _MAX_HANDLER_BYTES:
        return {"ok": False, "blocked": False, "code": "forge.handler_too_large",
                "result_for_model": f"handler exceeds the {_MAX_HANDLER_BYTES}-byte cap"}
    if "def " not in handler:
        return {"ok": False, "blocked": False, "code": "forge.no_entrypoint",
                "result_for_model": "handler must define at least one function (def ...)"}

    ok, reasons = screen_handler(handler + "\n" + description + "\n" + rationale)
    if not ok:
        # Refused, not quarantined: a draft that tries to reach around the
        # gates never reaches disk at all.
        try:
            ctx.emit("engine_event", {"tool": "tool_forge", "code": "forge.screened_out", "name": name, "reasons": list(reasons)})
        except Exception:  # noqa: BLE001
            pass
        return {"ok": False, "blocked": True, "code": "forge.screened_out",
                "result_for_model": "handler refused: " + "; ".join(reasons)}

    evidence_ids, evidence_error = _evidence_ids(ctx, args)
    if evidence_error is not None:
        try:
            ctx.emit("engine_event", {"tool": "tool_forge", "code": evidence_error, "name": name})
        except Exception:  # noqa: BLE001
            pass
        return {"ok": False, "blocked": True, "code": evidence_error,
                "result_for_model": (
                    f"a forged tool must cite evidence from THIS run ({evidence_error}). "
                    "Cite the evidence_ids that motivated it — the same rule a finding follows."
                )}

    # Where it lands: the user skill corpus, so a later run can mount it once
    # an operator lifts the quarantine.
    try:
        from hunter.agent.skills import user_skills_dir
        root = user_skills_dir()
    except Exception:  # noqa: BLE001 — no corpus, no forge
        return {"ok": False, "blocked": False, "code": "forge.no_corpus",
                "result_for_model": "skill corpus is unavailable; cannot store a forged tool"}

    target = root / name / "SKILL.md"
    if target.parent.exists():
        try:
            ctx.emit("engine_event", {"tool": "tool_forge", "code": "forge.exists", "name": name})
        except Exception:  # noqa: BLE001
            pass
        return {"ok": False, "blocked": False, "code": "forge.exists",
                "result_for_model": f"{target} already exists — pick another name (no overwrite)"}

    card = _render_skill_md(name, description, handler, evidence_ids, rationale)

    # Fail-closed on our own output: a card the corpus cannot parse is a card
    # the operator cannot lift the quarantine on. Validate before writing, the
    # same way the skill loader validates before registering.
    try:
        from hunter.agent.skills import parse_skill_md
        if parse_skill_md(card, directory_id=name, source="user") is None:
            return {"ok": False, "blocked": False, "code": "forge.card_invalid",
                    "result_for_model": "the rendered card failed skill validation; adjust name/description"}
    except Exception:  # noqa: BLE001 — no validator, no forge
        return {"ok": False, "blocked": False, "code": "forge.no_corpus",
                "result_for_model": "skill corpus is unavailable; cannot store a forged tool"}

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(card, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "blocked": False, "code": "forge.write_failed",
                "result_for_model": f"could not write {target}: {exc}"}

    try:
        ctx.emit("engine_event", {
            "tool": "tool_forge", "code": "ok", "name": name,
            "evidence": evidence_ids, "path": str(target), "quarantined": True,
        })
    except Exception:  # noqa: BLE001
        pass

    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result_for_model": (
            f"forged tool '{name}' written to {target} (INERT — quarantined: true). "
            f"Bound to evidence {', '.join(evidence_ids)}. "
            "Usable in THIS run; mounted for later runs only after an operator edits the file."
        ),
    }


FORGE_SPEC: dict[str, Any] = {
    "name": "tool_forge",
    "description": (
        "Author a NEW tool for this hunt when no built-in covers the probe you need. "
        "The handler is python; it is screened (no subprocess/socket/eval/exec), must cite "
        "evidence from THIS run, and is written to the skill corpus INERT (quarantined) — "
        "usable now, mounted for later runs only after an operator lifts the quarantine."
    ),
    "danger": "none",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Tool name; lowercased, hyphenated, max 64 chars."},
            "description": {"type": "string", "description": "One line, max 60 chars — what the tool does."},
            "handler": {"type": "string", "description": "Python source defining the handler function(s). No subprocess/socket/eval/exec."},
            "rationale": {"type": "string", "description": "Why this tool is needed and what it probes."},
            "evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "Evidence ids from THIS run that motivate the tool (required)."},
        },
        "required": ["name", "description", "handler", "evidence_ids"],
        "additionalProperties": False,
    },
}


def register_forge_tools(registry: Any) -> Any:
    """Register tool_forge. Mirrors the toolchain/expand registration pattern."""
    from hunter.agent.tools_base import ToolSpec  # noqa: PLC0415 — optional import path

    def handler(args: dict[str, Any], ctx: Any) -> ToolOutcome:
        out = forge_tool(args, ctx)
        if out.get("blocked"):
            return ToolOutcome(
                ok=False, blocked=True, code=str(out.get("code", "blocked")),
                result_for_model=str(out.get("result_for_model", "blocked")),
            )
        if not out.get("ok"):
            return ToolOutcome(
                ok=False, code=str(out.get("code", "error")),
                result_for_model=str(out.get("result_for_model", "error")),
            )
        return ToolOutcome(result_for_model=str(out.get("result_for_model", "ok")))

    registry.register(ToolSpec(
        name=FORGE_SPEC["name"],
        description=FORGE_SPEC["description"],
        parameters=FORGE_SPEC["parameters"],
        handler=handler,
        danger=FORGE_SPEC["danger"],
    ))
    return registry
