# HunterOs Skills Index

Doctrine cards mounted into agent contexts (CLI, TUI, the LLM audit agent).
A skill is not documentation you hope the agent reads — it is a compact,
frontmattered contract the harness loads into the loop before the agent
acts. Sharp, short, binding.

## Tier tags

- **basic** — safe for every run: passive reasoning, notes, coverage, ledger
  hygiene. Works at `agent.tier: basic` (passive-only) and above.
- **advanced** — active-testing doctrine: assumes all HTTP methods and
  active probes are authorized (tier `advanced` in the agent config). The
  harness still enforces tier gating structurally — out-of-tier actions are
  refused in the tool handlers (`tier.passive_only`, `tier.capability_locked`)
  regardless of what a skill says.

## Skills

| Skill | Tier | Teaches |
| ----- | ---- | ------- |
| [`recon-basics`](recon-basics/SKILL.md) | basic | Map before you touch — recon as chain-building, not page collection. |
| [`verification-ladder`](verification-ladder/SKILL.md) | basic | Candidate → verified requires independent replay; overturn fast. |
| [`scope-discipline`](scope-discipline/SKILL.md) | basic | Fail-closed scope: consent is enforced by code, not by prompts. |
| [`eliminate-trace-walkthrough`](eliminate-trace-walkthrough/SKILL.md) | advanced | The method loop — eliminate, trace, walk through, repeat. |
| [`bypass-principles`](bypass-principles/SKILL.md) | advanced | Bypasses hijack trusted mechanisms — never attack the defense head-on. |
| [`cdc-thinking`](cdc-thinking/SKILL.md) | advanced | Diverge before you converge — the zero-day reasoning loop. |
| [`black-swan-engine`](black-swan-engine/SKILL.md) | advanced | Derive invariants first — violations are laws, not bug patterns. |

## Rules for new skills

1. Frontmatter: `name`, `description` (≤ 60 chars), `version`, and
   `metadata: {min_tier: basic|advanced}` mirroring the agent tier system.
2. Body: 20–45 lines. If it does not change behavior, it does not ship.
3. Every skill must be consistent with the kernel: evidence or nothing,
   the ledger is the only source of truth, the ladder is enforced in code.
4. A skill may never instruct the agent around a gate. Gates are code;
   the only fix for a `BLOCKED` outcome is the evidence it asks for.
