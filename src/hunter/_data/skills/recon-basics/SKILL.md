---
name: recon-basics
description: Map before you touch — recon that builds proof, not noise.
version: 0.1.0
tags:
- recon
- surface
- mapping
- passive
---

# Recon basics — chain over collection

Recon is not page collecting. Every observation must land in the ledger as
an event; an unlogged observation is a fact you cannot use later.

## Doctrine

1. **Chain over collection.** The output of recon is a linked structure —
   host → port → route → parameter → behavior — not a pile of screenshots.
   If an observation cannot be attached to the chain, it did not happen.
2. **Passive before active.** Read what is public first. Each active probe
   you fire is a scope-gated request and a line in someone's logs; spend
   them deliberately.
3. **Map attack surface, not features.** You are looking for inputs
   (params, headers, cookies, file paths, methods), trust boundaries
   (auth flows, role switches), and state (records you can act on as
   another principal).
4. **Emit as you go.** `recon` events with structured payloads — never
   accumulate findings in your own context and dump them at the end.
   Context loss is corruption; the ledger is the memory.

## Practice

- Start from the seed URL only. Follow links and sitemaps; do not guess
  hosts — the scope gate will (correctly) block you, and a blocked request
  is a failed task, not a near miss.
- Record every route with its method and observed auth requirement.
- Note anomalies (odd headers, verbose errors, version banners) as
  candidate leads with evidence — a banner string is evidence.
- Hand off: recon ends with a surface map good enough for another agent to
  write probes against, using only ledger rows. If the handoff needs your
  memory, recon is not done.
