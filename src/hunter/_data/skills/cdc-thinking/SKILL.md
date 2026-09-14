---
name: cdc-thinking
description: Diverge before you converge — the zero-day reasoning loop.
version: 0.2.0
metadata:
  min_tier: advanced
tags:
- divergence
- convergence
- zero-day
- reasoning
- hypothesis
---

# CDC thinking — the meta-pattern behind zero-day discovery

A reasoning structure, not a checklist: how to hunt unknown unknowns in a
large target. Applies when scanners came back quiet but the surface is
large, when the target has custom logic no probe models — and exactly when
you are about to converge on the first promising lead.

## The tenets

1. **First principles or die.** Ignore CVE lists and changelogs. The
   developers' assumptions *are* the attack surface: ask what must be true
   for the mechanism to work, then which of those assumptions nobody
   verified. That is the entry point.
2. **Divergent before convergent.** Open with 4+ genuinely different
   approaches, grouped by research *idea* — three angles on one bug class
   are one family. The first promising lead is usually a trap.
3. **Stall means block, not push.** Nothing new across two rounds → mark
   the route dead (`ruled_out` coverage row with cited evidence). A route
   reopens only for a materially new mechanism. This kills sunk-cost loops.
4. **Keep incompatible routes alive.** Winning chains combine ideas that
   initially contradict — state control, trigger, privilege source from
   different mental models. Cross-pollinate only after independent depth.
5. **Adversarial by default.** Challenge every concrete finding: *prove
   this is not exploitable.* If the challenge wins, drop it without ego —
   the debunk replay settles this with evidence, not debate.
6. **Chain, don't collect.** A list of bugs is inert; a chain is the
   deliverable. Map `[Trigger] → [Effect] → [Trust boundary crossed]` and
   build at the handoffs.

## Procedure and anti-patterns

- Enumerate mechanism families first (input parsing, auth, session, business
  logic, config, caching); give each a coverage row **before** probing.
- Spend `think` on assumption lists, not narratives; `note_add` on surviving
  hypotheses only. Converge when two independent routes point at the same
  mechanism — then walk it to a bound exchange.
- Do not read the target with a favorite hypothesis loaded; do not call
  four probes on one idea "divergence"; do not drop a finding for feeling
  weak instead of challenging it with a replay.

**Closing rule:** divergence is measured in ledger coverage rows, not in
ideas toured — evidence or nothing.
