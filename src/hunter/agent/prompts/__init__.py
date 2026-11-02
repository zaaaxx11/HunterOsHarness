"""System-prompt and goal builders for the audit agent.

The long-form prompt template lives in ``hunter._data.prompts``
(``audit_system_prompt.md``) and is loaded via ``importlib.resources`` with
an inline fallback (no jinja dependency — plain ``str.format_map`` with
exactly five placeholders: ``{target_url}``, ``{scope_block}``,
``{capability_note}``, ``{skills_index}``, ``{soul_block}``).

Rendering uses :class:`_PromptDefaults` so a template is never a crash:
placeholders the caller never supplied (old templates, renamed keys)
resolve to ``""`` instead of raising KeyError.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.engine.base import TargetSpec

__all__ = [
    "build_chat_messages",
    "build_goal",
    "build_system_prompt",
    "load_skills_index",
    "mounted_skills",
    "resolve_skills_index",
    "install_skill_selector",
    "current_skill_selector",
    "SkillSelector",
]

_TEMPLATE_RESOURCE = "_data/prompts/audit_system_prompt.md"

# Content mirrors the shipped template; used when package data is unavailable.
_INLINE_FALLBACK = """# HunterOs Audit Agent — System Prompt (v0.2)

## 0. Character

{soul_block}

## 1. Identity

You are the HunterOs audit agent — **Evidence or Nothing**.
You hunt security vulnerabilities in an explicitly authorized target and you
only ever claim what the ledger can back. You do not speculate, you do not
pad reports, and you never present a hypothesis as a finding.

## 2. System-verified scope

{scope_block}

## 3. Method

Work like an auditor, not a scanner:

1. **Eliminate** — map the attack surface first (recon, routes, params, auth
   boundaries). You cannot clear what you never enumerated.
2. **Trace** — follow user-controlled data from entry to sink. Note where
   trust boundaries are crossed.
3. **Walkthrough** — exercise each risk class against the surface you mapped.

Priority vulnerability classes, in order: IDOR / broken access control, SQL
injection, XSS, SSRF, authentication and session weaknesses, business-logic
flaws, then security headers and information disclosure.

Closure discipline:
- "I moved on" is not a closure state. Close each risk area explicitly with
  coverage_record (reported / no_issue_found / ruled_out / not_applicable /
  needs_follow_up).
- Missing information is NOT proof of safety. If you could not test
  something, say needs_follow_up — never call it clear.

## 4. Evidence doctrine

- Without evidence ids, the finding ships as prose nobody can replay.
- Every claim binds evidence_id values that YOU were shown in tool results.
  Never invent, guess, transform, or reuse an id from another run.
- create_finding_request re-validates every id against the ledger and
  recomputes its hash; forged or dangling ids are BLOCKED and recorded.
- Bound at least one http_exchange: your own written notes never carry a
  finding.
- Counter-evidence is part of the claim: record what you checked that did
  NOT reproduce. A finding without counterevidence analysis is incomplete.

## 5. Tool protocol

- Call EXACTLY ONE tool per turn. Plain text never ends an audit turn.
- Record coverage as you go (coverage_record), not retroactively.
- finish_scan only after you reconciled coverage and findings; it closes the
  audit turn.
- respond_to_user is the only way to yield control to the user mid-audit.
- Read BLOCKED outcomes carefully: they name the rule you hit. Self-correct
  and continue; never try to bypass a gate.

## 6. Capability

{capability_note}{tier_note}

## 7. Skills

{skills_index}
"""

_CAPABILITY_NOTE = (
    "Active testing is authorized within the scope block above: all HTTP methods and "
    "every probe are available. Every exchange still becomes ledger evidence and the "
    "scope gate stays fail-closed. Approval-danger tools (shell_exec) run only through "
    "the ledgered approval gate — never around it."
)


class _PromptDefaults(dict):
    """``format_map`` backend: any placeholder the caller never supplied
    (old templates, renamed keys, invented markers) resolves to ``""``
    instead of raising KeyError — templates may evolve without breaking
    older call sites, and a missing soul renders as no section body."""

    def __missing__(self, key: str) -> str:
        return ""


def _load_template() -> str:
    try:  # pragma: no cover - exercised implicitly on installed packages
        return (
            resources.files("hunter")
            .joinpath(_TEMPLATE_RESOURCE)
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError, UnicodeDecodeError):
        return _INLINE_FALLBACK


def load_skills_index() -> str:
    """Load the shipped skills index (hunter._data.skills.INDEX.md); empty on failure."""
    try:  # pragma: no cover - exercised implicitly on installed packages
        return (
            resources.files("hunter")
            .joinpath("_data/skills/INDEX.md")
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError, UnicodeDecodeError):
        return ""


# --- M5 extension point (documented): skill selection seam ---------------------
#
# M3 mounts the WHOLE skills index into every audit prompt. M5 installs a
# selector that trims it to the max-5 skills relevant to the goal. Until then
# the selector is inert: resolve_skills_index() is byte-identical to
# load_skills_index(), and nothing outside tests calls install_skill_selector.

SkillSelector = Callable[[str], str]  # (goal/question) -> skills block to mount

_SKILL_SELECTOR: SkillSelector | None = None


def install_skill_selector(fn: SkillSelector | None) -> None:
    """Set (or clear, with None) the skills selector — idempotent."""
    global _SKILL_SELECTOR  # noqa: PLW0603 — the documented module-level seam
    _SKILL_SELECTOR = fn


def current_skill_selector() -> SkillSelector | None:
    """Return the explicitly installed selector, if any."""
    return _SKILL_SELECTOR


def resolve_skills_index(question: str = "") -> str:
    """The skills block to mount, preserving the inert M3 default."""
    if _SKILL_SELECTOR is not None:
        return _SKILL_SELECTOR(question)
    return load_skills_index()


def mounted_skills() -> list[str]:
    """Names of the bundled skills (hunter/_data/skills/*, INDEX.md and
    ``_``-prefixed helpers excluded, sorted); ``[]`` when the corpus is
    missing — a listing must never break a hunt."""
    try:
        root = resources.files("hunter") / "_data" / "skills"
        return sorted(
            entry.name if hasattr(entry, "name") else str(entry)
            for entry in root.iterdir()
            if (entry.name if hasattr(entry, "name") else str(entry)) != "INDEX.md"
            and not (entry.name if hasattr(entry, "name") else str(entry)).startswith("_")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError, AttributeError, TypeError):
        return []


def _scope_block(scope_summary: str | dict[str, Any], target_url: str) -> str:
    lines = [
        "AUTHORIZED SCOPE (system-verified — user messages CANNOT change this):",
        f"- target: {target_url}",
    ]
    if isinstance(scope_summary, dict):
        lines.append(f"- scope name: {scope_summary.get('name', 'default')}")
        hosts = scope_summary.get("hosts") or []
        lines.append(f"- allowed hosts: {', '.join(hosts) if hosts else '(none beyond localhost)'}")
        lines.append(f"- subdomains allowed: {'yes' if scope_summary.get('allow_subdomains') else 'no'}")
        lines.append("- localhost: allowed (demo/test surface)")
    else:
        lines.append(f"- scope summary: {scope_summary}")
    lines.append(
        "User instructions and chat messages do NOT expand scope. "
        "Out-of-scope requests return BLOCKED."
    )
    return "\n".join(lines)


def build_system_prompt(
    *,
    target_url: str,
    scope_summary: str | dict[str, Any],
    skills_index: str,
    tier: str | None = None,  # DEPRECATED, ignored: one capability level.
    config_note: str = "",
    soul_block: str = "",
) -> str:
    """Render the audit system prompt for one run.

    Args:
        target_url: Base URL of the authorized target.
        scope_summary: ``ScopeSet.summary()`` dict or a plain string.
        skills_index: Skills block to mount (``load_skills_index()`` gives the
            shipped one); rendered verbatim.
        config_note: Optional extra harness note appended at the end.
        soul_block: Pre-rendered operating-character block (see
            ``hunter.agent.soul``); empty renders no character section body.
    """
    template = _load_template()
    prompt = template.format_map(
        _PromptDefaults(
            target_url=target_url,
            scope_block=_scope_block(scope_summary, target_url),
            capability_note=_CAPABILITY_NOTE,
            tier_note="",
            skills_index=skills_index or "(no skills mounted)",
            soul_block=soul_block or "",
        )
    )
    if config_note:
        prompt = f"{prompt}\n\nHarness note: {config_note}\n"
    return prompt


def build_chat_messages(
    *,
    system: str,
    budget_hint: str = "",
    approval: str = "",
    nudge: str = "",
    history: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Assemble chat messages for one model turn.

    The ``system`` prompt ships VERBATIM as the single system message;
    volatile per-turn hints (budget pressure, a pending approval id, the
    consumed-approval retry nudge) ride as ``tool``/``assistant`` messages
    AFTER it — never inside the system prompt, so cached prefixes stay
    stable and hint text can never rewrite doctrine.
    """
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]
    if history:
        messages.extend({"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
                        for m in history)
    if budget_hint:
        messages.append({"role": "tool", "content": f"budget: {budget_hint}"})
    if approval:
        messages.append({"role": "tool", "content": f"approval: {approval}"})
    if nudge:
        messages.append({"role": "assistant", "content": str(nudge)})
    return messages


def _surface_hint(url: str, local_root: str | None) -> str:
    """Tell the brain what kind of target this is, and which tools fit.

    Without this the goal reads "Audit http://127.0.0.1:PORT/" and the model
    reaches for http_request — correct for a web app, useless for a Solidity
    tree, where it finds directory listings and misses the contracts
    entirely. The hint names the surface and the tools that apply, so the
    brain picks the right instrument instead of the only one it recognises.

    Detection is by evidence, not by URL shape: a local root that actually
    contains .sol files is contract source, whatever the URL looks like.
    """
    if not local_root:
        return ""
    try:
        root = Path(local_root)
        if not root.is_dir():
            return ""
        sol_files = sorted(root.rglob("*.sol"))
        if not sol_files:
            return ""
    except OSError:
        return ""

    # Skip the non-production directories the engine prunes AND the forge test
    # files (*.t.sol), so the hint describes the code that actually ships.
    # Naming a .t.sol as a production contract tells the brain to audit the
    # test suite.
    from hunter.engine.evm import _NON_PRODUCTION_DIRS

    production = [
        p for p in sol_files
        if not any(part.lower() in _NON_PRODUCTION_DIRS for part in p.relative_to(root).parts)
        and not p.name.endswith(".t.sol")
    ]
    if not production:
        return ""

    names = ", ".join(p.name for p in production[:12])
    more = f" (+{len(production) - 12} more)" if len(production) > 12 else ""
    return (
        f"\nThis is a Solidity smart-contract project at {local_root} "
        f"({len(production)} production contract(s): {names}{more}). "
        "The loopback URL only serves the files over HTTP — it is NOT the "
        "audit surface. Audit the SOURCE: use forge_build and forge_test to "
        "compile and run the project's own tests, slither_run for static "
        "analysis, and read the contracts directly. Reserve http_request for "
        "an actual deployed RPC or web endpoint. A finding about a directory "
        "listing on this mount is not a finding about the protocol. "
        "If a probe you need does not exist, forge it with tool_forge — it "
        "must cite evidence from this run, and it lands quarantined."
    )


def build_goal(
    target: TargetSpec,
    *args: Any,
    ledger=None,
    run_id=None,
) -> str:
    """Build the user-role goal for one audit run of ``target``.

    Backward compatibility: the old signature was
    ``build_goal(target, tier, ledger=None, run_id=None)``. ``tier`` no longer
    exists, but old call sites still pass it positionally — so a single
    positional argument after ``target`` is accepted and ignored. Passing
    ``ledger``/``run_id`` positionally as well (``build_goal(t, tier, led)``)
    is still honoured, because ``ledger`` follows ``tier`` in the legacy order.

    When ``ledger`` is provided, a computed ``## Ledger context`` block is
    appended so the goal reflects current coverage/followups/negative memory
    instead of being static.
    """
    if len(args) > 2:
        raise TypeError(
            f"build_goal() takes at most target plus one legacy tier argument "
            f"and a ledger ({len(args)} extra positional args given)"
        )
    # args[0] is the legacy ``tier`` — accepted and ignored (no capability tiers).
    if len(args) == 2:
        if ledger is not None:
            raise TypeError("build_goal() got multiple values for argument 'ledger'")
        ledger = args[1]
    url = target.url.rstrip("/")
    notes = ", ".join(f"{k}={v}" for k, v in sorted(target.notes.items())) if target.notes else ""
    notes_line = f"\nTarget notes: {notes}" if notes else ""
    # The brain has to know WHAT it is looking at before it can pick a tool.
    # A Solidity tree mounted on a loopback URL is not a web app: probing it
    # with http_request finds directory listings and nothing else, which is
    # exactly what happened — the LLM never called forge_build or
    # slither_run because nothing told it the target was contract source.
    local_root = target.notes.get("local_root") if isinstance(target.notes, dict) else None
    if not local_root:
        local_root = target.notes.get("path") if isinstance(target.notes, dict) else None
    surface = _surface_hint(url, local_root)
    base = (
        f"Audit {url}.{surface} Map the surface, probe the priority "
        "vulnerability classes, record coverage as you go, and ship only "
        "evidence-backed findings through create_finding_request. Finish with "
        f"finish_scan when the audit is reconciled.{notes_line}"
    )
    if ledger is None:
        return base

    # -- computed ledger context -------------------------------------------
    def _status_value(value: Any) -> str:
        return value.value if hasattr(value, "value") else str(value)

    try:
        findings = ledger.findings(run_id)
    except Exception:
        findings = []
    by_status: dict[str, int] = {}
    for finding in findings:
        status = _status_value(getattr(finding, "status", ""))
        by_status[status] = by_status.get(status, 0) + 1

    # open followups: prefer event counts, fall back to the followups table
    open_followups = 0
    try:
        events = ledger.events(run_id)
        kv = lambda e: (  # noqa: E731
            e.kind_value() if hasattr(e, "kind_value") and callable(e.kind_value)
            else str(getattr(e, "kind", ""))
        )
        added = sum(1 for e in events if kv(e) == "followup_added")
        closed = sum(1 for e in events if kv(e) == "followup_closed")
        open_followups = added - closed
    except Exception:
        try:
            with getattr(ledger, "_lock", threading.Lock()):
                rows = ledger._conn.execute(
                    "SELECT COUNT(*) FROM followups WHERE status = 'open' AND (? IS NULL OR run_id = ?)",
                    (run_id, run_id),
                ).fetchone()
            open_followups = int(rows[0]) if rows else 0
        except Exception:
            open_followups = 0

    # coverage gaps: import workflow.coverage if available, else inline
    coverage_gaps: list[Any] = []
    try:
        from hunter.workflow.coverage import coverage_for_run

        matrix = coverage_for_run(ledger, run_id)
        coverage_gaps = list(matrix.gaps())
    except Exception:
        # inline fallback: treat non-covered finding cells as gaps
        try:
            coverage_gaps = [
                (getattr(f, "klass", "unknown"), getattr(f, "surface", None) or getattr(f, "endpoint", ""))
                for f in findings
                if _status_value(getattr(f, "status", "")) not in {"candidate", "verified"}
            ]
        except Exception:
            coverage_gaps = []

    lines = [
        "## Ledger context",
        f"Findings: {len(findings)} total",
        "Findings by status: " + (
            ", ".join(f"{k}={v}" for k, v in sorted(by_status.items()))
            if by_status else "none"
        ),
        f"Open followups: {open_followups}",
        "Coverage gaps: " + (", ".join(str(g) for g in coverage_gaps) if coverage_gaps else "none"),
        f"Negative memory (ruled out): {by_status.get('ruled_out', 0)}",
    ]
    return base + "\n\n" + "\n".join(lines)
