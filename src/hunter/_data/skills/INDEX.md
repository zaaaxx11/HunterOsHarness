# HunterOs Skills Index

Doctrine cards mounted into agent contexts (CLI, TUI, future LLM engines).
A skill is not documentation you hope the agent reads — it is a compact,
frontmattered contract the harness loads into the loop before the agent
acts. Sharp, short, binding.

| Skill | Teaches |
| ----- | ------- |
| [`recon-basics`](recon-basics/SKILL.md) | Map before you touch — recon as chain-building, not page collection. |
| [`verification-ladder`](verification-ladder/SKILL.md) | Candidate → verified requires independent replay; overturn fast. |
| [`scope-discipline`](scope-discipline/SKILL.md) | Fail-closed scope: consent is enforced by code, not by prompts. |

Rules for new skills:

1. Frontmatter: `name`, `description` (≤ 60 chars), `version`.
2. Body: 20–40 lines. If it does not change behavior, it does not ship.
3. Every skill must be consistent with the kernel: evidence or nothing,
   the ledger is the only source of truth, the ladder is enforced in code.
