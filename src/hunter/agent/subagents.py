"""Sub-agents — real delegated hunt workers, not prompt personas.

WHY
---
The four "agents" in the brief (Architect → Red-Teamer → Fuzzer → Chainer) used
to be one model wearing four hats in one conversation: one memory, one bias,
nobody to disagree with.  A hypothesis the orchestrator gets attached to is
never independently falsified.

This module gives the orchestrator actual workers.  A sub-agent is:

* its **own** :class:`AgentLoop` — separate message history, so it does not
  inherit the parent's confirmation bias;
* **soul-injected** — it renders the same ``soul_block()`` the parent does, so
  the operating character is consistent across the whole operation;
* **tool-restricted** — it gets a narrow registry (read/probe tools only by
  default); it can never call ``create_finding_request``, because a sub-agent
  must not be able to file claims.  Only the orchestrator files findings, after
  review — that is what keeps the evidence ladder honest when work is
  delegated;
* **budget-bounded** — a hard turn ceiling and its own cost cap, so a runaway
  or looping child cannot drain the run.

CONTAINMENT LAW
---------------
A child shares the parent's :class:`ToolContext`: same ledger (same run id),
same :class:`ScopeSet`, same ``ScopedHttpClient``.  So evidence it produces is
real, in-scope, and chained into the parent run — and any attempt to leave
scope still dies at the scope gate, not at the child.

The child returns a *report*, never a finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SubagentSpec",
    "SubagentResult",
    "SUBAGENT_ROLES",
    "run_subagent",
    "build_subagent_registry",
]

# Tools a sub-agent may hold.  Deliberately excludes create_finding_request,
# finish_scan, respond_to_user and threat_model_amend: children gather evidence,
# they do not make claims and cannot end the parent's run.
SUBAGENT_TOOL_ALLOWLIST: tuple[str, ...] = (
    "think",
    "note_add",
    "note_get",
    "note_list",
    "http_request",
    "run_probe",
    "ledger_search",
    "coverage_record",
    "coverage_list",
    "threat_model_get",
    "browser_navigate",
    "browser_snapshot",
    "browser_click",
    "browser_type",
    "shell_exec",
)

# Role presets: the specialty each worker is spawned for.  ``focus`` lands in
# the child's goal text; ``tools`` narrows the allowlist further.
SUBAGENT_ROLES: dict[str, dict[str, Any]] = {
    "architect": {
        "focus": (
            "Decide what is worth testing before anything is tested. Turn the "
            "target into a ranked set of testable hypotheses. For each one name "
            "the exact surface, the precondition that must hold, and the "
            "observation that would falsify it. Never claim a vulnerability — "
            "you produce the ranked questions the other workers will spend "
            "budget on."
        ),
        "tools": (
            "think",
            "http_request",
            "run_probe",
            "ledger_search",
            "coverage_list",
            "note_add",
            "note_list",
            "note_get",
            "threat_model_get",
            "shell_exec",
        ),
    },
    "recon": {
        "focus": (
            "Map the attack surface only. Enumerate hosts, endpoints, parameters, "
            "auth requirements and response shapes. Record coverage. Do NOT form "
            "vulnerability claims."
        ),
        "tools": (
            "think",
            "http_request",
            "run_probe",
            "browser_navigate",
            "browser_snapshot",
            "coverage_record",
            "coverage_list",
            "note_add",
            "note_list",
            "shell_exec",
        ),
    },
    "redteam": {
        "focus": (
            "Try to break the specific hypothesis you were given. Be adversarial: "
            "assume the target is defended and hunt for the seam. Report what held "
            "and what broke, with the exact request/response that shows it."
        ),
        "tools": (
            "think",
            "http_request",
            "run_probe",
            "browser_navigate",
            "browser_snapshot",
            "browser_click",
            "browser_type",
            "note_add",
            "note_get",
            "ledger_search",
            "shell_exec",
        ),
    },
    "fuzzer": {
        "focus": (
            "Mutate one variable at a time across a parameter you were given. "
            "Prefer differential evidence (what changed between two requests) over "
            "volume. Stop when a mutation produces a state change worth reporting."
        ),
        "tools": (
            "think",
            "http_request",
            "run_probe",
            "note_add",
            "note_list",
            "shell_exec",
        ),
    },
    "chainer": {
        "focus": (
            "Look ONLY for how individual observations could chain into a single "
            "exploit path. State preconditions, the handoff between steps, and the "
            "first step that would fail in reality."
        ),
        "tools": (
            "think",
            "ledger_search",
            "note_list",
            "note_get",
            "http_request",
            "coverage_list",
        ),
    },
    "verifier": {
        "focus": (
            "Judge whether a claim is actually proven. Demand the artifact: a "
            "transcript, a hash, a rendered page, a program output that can be "
            "re-run. Label anything short of that UNPROVEN, BLOCKED or "
            "INCONCLUSIVE. You are the one who says no."
        ),
        "tools": (
            "think",
            "ledger_search",
            "note_add",
            "note_list",
            "note_get",
            "http_request",
            "run_probe",
        ),
    },
}


@dataclass
class SubagentSpec:
    """One delegation request."""

    role: str = "redteam"
    goal: str = ""
    context: str = ""
    max_turns: int = 12
    max_cost_usd: float = 0.0  # 0 = inherit / unbounded
    tools: tuple[str, ...] | None = None


@dataclass
class SubagentResult:
    """What a child reports back — evidence and observations, never a finding."""

    role: str
    ok: bool
    summary: str
    notes: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def render(self) -> str:
        head = f"[subagent:{self.role}] {'OK' if self.ok else 'FAILED'}"
        turns = self.stats.get("turns")
        tools = self.stats.get("tool_calls")
        meta = f" (turns={turns}, tool_calls={tools})" if turns is not None else ""
        body = self.summary.strip() or "(no summary)"
        out = f"{head}{meta}\n{body}"
        if self.error:
            out += f"\nERROR: {self.error}"
        if not self.ok:
            out += (
                "\nNOTE: this delegation failed — the absence of a result is NOT "
                "evidence that the hypothesis is false."
            )
        return out


def build_subagent_registry(
    parent_registry: Any,
    *,
    role: str = "redteam",
    extra_tools: tuple[str, ...] | None = None,
) -> Any:
    """A narrowed registry: only allowlisted specs, rebuilt into a fresh one."""
    from .tools_base import ToolRegistry

    preset = SUBAGENT_ROLES.get(role, SUBAGENT_ROLES["redteam"])
    allowed = set(extra_tools or preset["tools"])
    child = ToolRegistry()
    child.built_for_tier = getattr(parent_registry, "built_for_tier", "basic")  # type: ignore[attr-defined]
    for name, spec in parent_registry._specs.items():
        if name in allowed and name in SUBAGENT_TOOL_ALLOWLIST:
            child.register(spec)
    return child


def _child_goal(spec: SubagentSpec, parent_target: str) -> str:
    preset = SUBAGENT_ROLES.get(spec.role, {})
    focus = preset.get("focus", "")
    parts = [
        f"You are a delegated {spec.role} worker on {parent_target}.",
        "",
        f"## Your specialty\n{focus}",
        "",
        f"## Assignment\n{spec.goal}",
    ]
    if spec.context:
        parts += ["", f"## Context handed to you by the orchestrator\n{spec.context}"]
    parts += [
        "",
        "## Rules",
        "- Every claim needs a real request/response you actually made this session.",
        "- You cannot file findings. Report observations for the orchestrator to judge.",
        "- Stay inside scope. A blocked request is a finding about the target, not a reason to widen scope.",
        "- If you learn nothing, say so plainly — a clean negative result is a real result.",
        f"- You have at most {spec.max_turns} turns. Spend them on evidence, not narration.",
    ]
    return "\n".join(parts)


def run_subagent(
    spec: SubagentSpec,
    ctx: Any,
    *,
    provider: Any,
    parent_registry: Any,
    tier: str = "basic",
    budget: Any = None,
) -> SubagentResult:
    """Spawn one child loop against the SAME context (same ledger, same scope)."""
    role = spec.role if spec.role in SUBAGENT_ROLES else "redteam"
    spec = SubagentSpec(
        role=role,
        goal=spec.goal,
        context=spec.context,
        max_turns=max(2, int(spec.max_turns or 12)),
        max_cost_usd=spec.max_cost_usd,
        tools=spec.tools,
    )
    try:
        from .loop import AgentLoop

        registry = build_subagent_registry(
            parent_registry, role=role, extra_tools=spec.tools
        )
        if not registry._specs:
            return SubagentResult(
                role=role,
                ok=False,
                summary="",
                error="no tools available to the child after restriction",
            )

        # Reserve one turn for the wrap-up: a child that spends every turn
        # probing returns nothing useful, which is the same as not delegating.
        working_turns = max(1, spec.max_turns - 1)
        child_budget = budget if budget is not None else _child_budget(spec, working_turns)
        loop = AgentLoop(
            provider,
            registry,
            tier=tier if tier in ("basic", "advanced") else "basic",
            budget=child_budget,
            # The child runs under its own soul card, so its character matches
            # its job instead of inheriting the orchestrator's.
            role=role,
        )
        # The child writes into the parent's ledger/scope; the run id is the
        # parent's, so its evidence is chained into the same run.
        result = loop.run(ctx, _child_goal(spec, getattr(ctx, "target_url", "the target")))
        stats = dict(getattr(result, "stats", {}) or {})
        report = str(getattr(result, "summary", "") or "").strip()

        # If the child burned its budget without concluding, ask it once more
        # with tools REMOVED so it can only narrate what it already found.
        if not report or report.startswith("stopped: budget exhausted"):
            report = _force_summary(
                provider=provider, spec=spec, ctx=ctx, stats=stats
            ) or report

        return SubagentResult(
            role=role,
            ok=not bool(getattr(result, "interrupted", False)),
            summary=report,
            notes=[],
            stats=stats,
        )
    except Exception as exc:
        return SubagentResult(
            role=role,
            ok=False,
            summary="",
            error=f"{type(exc).__name__}: {exc}",
        )


def _force_summary(*, provider: Any, spec: SubagentSpec, ctx: Any, stats: dict[str, Any]) -> str:
    """One final tool-free call: turn the child's own work into a report."""
    try:
        from .soul import role_soul_block

        evidence = _evidence_digest(ctx)
        prompt = "\n".join(
            [
                f"You are the {spec.role} worker. Your probing budget is spent.",
                "",
                f"## Your assignment\n{spec.goal}",
                "",
                "## Evidence you actually collected this session",
                evidence or "(none recorded)",
                "",
                "## Task",
                "Write the report the orchestrator needs. Use ONLY the evidence above.",
                "State: what you established, what remains unknown, and the exact "
                "request/response reference for each claim. No speculation. No tool "
                "calls are available — this is a final report.",
                "Keep it under 250 words.",
            ]
        )
        turn = provider.complete(
            "orchestrator",
            [
                {"role": "system", "content": str(role_soul_block(spec.role) or "")},
                {"role": "user", "content": prompt},
            ],
        )
        stats["wrapup_tokens_in"] = getattr(turn, "tokens_in", 0)
        stats["wrapup_tokens_out"] = getattr(turn, "tokens_out", 0)
        return str(getattr(turn, "text", "") or "").strip()
    except Exception as exc:
        return f"(wrap-up failed: {type(exc).__name__}: {exc})"


def _evidence_digest(ctx: Any, limit: int = 12) -> str:
    """Compact list of this run's stored evidence, for the wrap-up prompt.

    ``Ledger.evidence()`` returns plain dicts, not objects — reading them with
    ``getattr`` silently produced ``[?] ?:`` for every row, which starved the
    wrap-up of the very evidence it was supposed to summarise.
    """
    try:
        evidence = ctx.ledger.evidence(ctx.run_id)  # type: ignore[attr-defined]
    except Exception:
        return ""
    rows: list[str] = []
    for item in list(evidence)[-limit:]:
        if isinstance(item, dict):
            ref = item.get("id", "?")
            kind = item.get("kind", "?")
            data = item.get("data") or {}
            if not isinstance(data, dict):
                rows.append(f"- [{ref}] {kind}: {str(data)[:220]}")
                continue
            # http_exchange rows carry the substance we need: status, method,
            # the request body the model sent and the head of what came back.
            bits: list[str] = []
            if data.get("method"):
                bits.append(str(data["method"]))
            url = data.get("url") or data.get("request_line") or ""
            if url:
                bits.append(str(url)[:160])
            if data.get("status") is not None:
                bits.append(f"-> {data['status']}")
            line = " ".join(bits) if bits else str(data.get("summary") or data.get("note") or "")
            body = data.get("response_body") or data.get("response_excerpt") or ""
            if body:
                line += f"\n    response: {str(body)[:260]}"
            rows.append(f"- [{ref}] {kind}: {line[:420]}")
        else:
            ref = getattr(item, "id", "?")
            kind = getattr(item, "kind", "?")
            detail = str(getattr(item, "summary", "") or getattr(item, "request_line", ""))
            rows.append(f"- [{ref}] {kind}: {detail[:220]}")
    return "\n".join(rows)


def _child_budget(spec: SubagentSpec, working_turns: int | None = None) -> Any:
    """A concrete, bounded budget so a looping child cannot drain the run."""
    try:
        from hunter.llm.budget import RunBudget

        iterations = working_turns if working_turns is not None else spec.max_turns
        kwargs: dict[str, Any] = {"max_iterations": max(1, int(iterations))}
        if spec.max_cost_usd and spec.max_cost_usd > 0:
            kwargs["max_cost_usd"] = float(spec.max_cost_usd)
        return RunBudget(**kwargs)
    except Exception:
        return None
