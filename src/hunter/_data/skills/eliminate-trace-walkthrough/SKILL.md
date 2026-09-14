---
name: eliminate-trace-walkthrough
description: The method loop — eliminate, trace, walk through, repeat.
version: 0.2.0
metadata:
  min_tier: advanced
tags:
- method
- eliminate
- trace
- walkthrough
- loop
---

# The method — eliminate, trace, walk through

A loop, not a checklist: read the system first as what it *cannot* be, then
as what it is, then as where it is weak. It opens every audit and restarts
whenever new findings change the map.

## The loop

1. **Eliminate the impossible.** Before theorizing, remove everything
   categorically not the vector: endpoints that never take user input,
   framework-typed parameters, gate-A flows while hunting gate B. Each
   elimination shrinks what you must analyze — and kills the classic
   failure of theorizing from a favorite hypothesis instead of the residue.
2. **Trace the system.** Every function is a node; the edges hide the blind
   spots. Two traces at once: *data flow* (input → transformation →
   storage → output) and *control flow* (who has access, under what
   conditions, with what consequences). Where the graph *trusts* without
   verifying — implicit identity, assumed role, trusted header — analysis
   concentrates.
3. **Walk through.** A system that believes it is safe has encoded that
   belief in routines, and routines are predictable. Where reviewers watch
   the core, the seams carry residual risk; the interesting state
   transitions happen outside what any single component checks.

Then loop: eliminate more, trace deeper, walk through again.

## Procedure and anti-patterns

- Eliminations are ledger rows: `coverage_record` with `ruled_out` or
  `not_applicable`, each citing a resolvable evidence id. Traces go to
  `note_add` and `threat_model_amend` — the map outlives your context.
- Walkthroughs are scope-gated requests through `http_request`/`run_probe`,
  one hypothesis per exchange, evidence bound at observation time.
- Do not theorize before eliminating. Do not accept "I moved on" as closure —
  un-exercised surfaces are `needs_follow_up`, never clear. Do not trace
  only data flow (the IDOR class lives entirely in control flow). Do not
  throw composite payloads before single-mechanism probes reproduce.
- Every finding carries **dual proof**: the exchange that verifies the
  mechanism, and the impact chain — who is affected, how it cascades.
  A finding missing either half is a lead, and the gates will treat it
  as one.

**Closing rule:** the loop ends only when every surface has an explicit,
evidence-cited coverage outcome — evidence or nothing.
