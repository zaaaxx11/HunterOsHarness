"""Per-state output formats for the audit agent.

The system prompt carries ONE canonical finding format (section 7 of
``audit_system_prompt.md``). That format is written for the worker that
SHIPS a finding — the hunter. It is the wrong shape for a verifier, who
reports a verdict on someone else's claim, and wrong again for an
orchestrator, who reports a plan and a routing decision rather than a
vulnerability.

So the format is a function of state, not a constant. Each state gets a
block that replaces the generic one, rendered by
:func:`output_format_block` and injected into the template's
``{output_format_block}`` placeholder.

The states map onto the shipped souls (``_data/prompts/souls/``) plus the
orchestrator role the operator drives from the REPL:

- ``hunter``    — redteam / fuzzer / chainer: ships findings and chains
- ``verifier``  — verifier: adjudicates a claim, never authors one
- ``architect`` — architect / recon: maps surface, ranks hypotheses
- ``orchestrator`` — the operator-facing brain: plans, routes, reports

Adding a state is adding a key here; nothing else needs to change.
"""

from __future__ import annotations

__all__ = [
    "OUTPUT_FORMATS",
    "STATES",
    "output_format_block",
    "resolve_state",
]

# -- the canonical finding format, shared by every state that can ship one ---

_FINDING_FORMAT = """\
VULNERABILITY: [Class/Type]
ENTRY: [Pre-auth / Post-auth / Unauth]
CHAIN: [Step 1 → Step 2 → ... → RCE]
IMPACT: [RCE / Theft / Escalation / Bypass]
POC: [Working exploit / Script / Proof — ≤50 lines]
EVIDENCE: [Line numbers or code snippets proving the chain]
CONFIDENCE: [PROVEN / HIGH / THEORETICAL]
MITIGATION: [Root cause + Fix]
VERIFICATION: reproduce → tx hash / screenshot → minimal PoC."""

OUTPUT_FORMATS: dict[str, str] = {
    # -- hunter: ships findings and chains ------------------------------------
    "hunter": f"""\
### Output format — HUNTER state

You ship findings. Every finding you ship uses the canonical format above,
verbatim, with no field omitted and no field invented:

```
{_FINDING_FORMAT}
```

Rules for this state:
- A finding without a CHAIN is an observation, not a finding. Ship it as a
  lead (note_add) and keep working, or ship the chain.
- CONFIDENCE is PROVEN only when the POC ran and the evidence shows it.
  HIGH means the source proves it and you could not execute it. THEORETICAL
  does not ship — it goes to note_add.
- One finding per create_finding_request call. Do not bundle two chains into
  one claim to save turns.""",
    # -- verifier: adjudicates, never authors ---------------------------------
    "verifier": """\
### Output format — VERIFIER state

You do not author findings. You adjudicate one that already exists and return
a verdict. Your output is a verdict block, never a finding block:

```
CLAIM: [finding id + one-line restatement of what is claimed]
VERDICT: [PROVEN / DISPROVEN / UNPROVEN]
BASIS: [what you ran, read, or replayed to decide]
GAP: [the exact step that is missing, if the verdict is not PROVEN]
CHALLENGE: [the strongest argument that this is NOT exploitable]
RESIDUAL: [what remains true even if the claim fails]
```

Rules for this state:
- UNPROVEN is a real verdict and often the correct one. Do not upgrade a
  claim to PROVEN because it is well written.
- You may not cite evidence you did not yourself observe in this run.
- If the claim is DISPROVEN, say what disproved it — a bare "no" is not a
  verdict.""",
    # -- architect / recon: maps and ranks ------------------------------------
    "architect": """\
### Output format — ARCHITECT state

You do not ship findings. You produce the map and the ranked questions that
the hunters will spend their budget on:

```
SURFACE: [what exists — hosts, paths, functions, storage, endpoints]
TRUST_BOUNDARIES: [every place privilege or authority changes hands]
ASSUMPTIONS: [what must be true for each boundary to hold]
UNVERIFIED: [which assumption has no check — the entry candidates]
RANKED_QUESTIONS: [1. ... 2. ... 3. ... — most likely to yield a chain first]
ELIMINATED: [what you ruled out, and why — so nobody re-walks it]
```

Rules for this state:
- Every RANKED_QUESTION must name the tool or read that would answer it.
- ELIMINATED is not optional: an eliminated route that is not written down
  gets re-walked by the next worker and burns the budget twice.
- A question you cannot rank, you do not understand yet — say so in
  UNVERIFIED rather than guessing an order.""",
    # -- orchestrator: plans, routes, reports ---------------------------------
    "orchestrator": """\
### Output format — ORCHESTRATOR state

You do not hunt. You decide what gets hunted, by which state, with what
budget, and you report the state of the operation:

```
MISSION: [the real objective, one line]
STATE: [which worker runs next — hunter / verifier / architect]
WHY: [the one-line reason this worker and not another]
BUDGET: [turns or minutes allocated, and the abort condition]
HANDOFF: [exactly what the next worker is told — it sees nothing else]
CHECKPOINT: [what result would prove this step worked]
```

Rules for this state:
- A handoff that does not name its checkpoint cannot be evaluated later.
- If two routes look equal, pick the one that is cheaper to abandon.
- Report blockers as blockers. Do not route around a blocked gate by
  re-describing the task so it slips through.""",
}

STATES = tuple(sorted(OUTPUT_FORMATS))

_DEFAULT_STATE = "hunter"

# Aliases: the shipped souls and the REPL's own vocabulary map onto the four
# states above. A soul name resolves to the state whose output shape fits the
# work that soul actually does.
_STATE_ALIASES: dict[str, str] = {
    "redteam": "hunter",
    "red_team": "hunter",
    "fuzzer": "hunter",
    "chainer": "hunter",
    "hunt": "hunter",
    "hunting": "hunter",
    "verify": "verifier",
    "verification": "verifier",
    "recon": "architect",
    "architect": "architect",
    "plan": "architect",
    "planning": "architect",
    "orchestrate": "orchestrator",
    "orchestration": "orchestrator",
    "operator": "orchestrator",
    "sovereign": "orchestrator",
}


def resolve_state(name: str | None) -> str:
    """Map any state/soul name onto one of the four canonical states.

    Unknown names fall back to ``hunter`` — the state that ships findings —
    because an unrecognised label is far more likely to mean "go hunt" than
    "go plan", and a hunt that ships nothing is recoverable while a plan
    that never hunts is not.
    """
    if not name:
        return _DEFAULT_STATE
    key = str(name).strip().lower().replace("-", "_").replace(" ", "_")
    if key in OUTPUT_FORMATS:
        return key
    return _STATE_ALIASES.get(key, _DEFAULT_STATE)


def output_format_block(state: str | None) -> str:
    """Render the output-format section for ``state``.

    ``None`` renders the HUNTER format, not an empty string: the hunter is
    the state that ships findings, and a prompt with no output-format section
    at all leaves the model to invent one. An explicitly empty string is the
    only way to suppress the section.
    """
    if isinstance(state, str) and not state.strip():
        return ""
    return OUTPUT_FORMATS[resolve_state(state)]
