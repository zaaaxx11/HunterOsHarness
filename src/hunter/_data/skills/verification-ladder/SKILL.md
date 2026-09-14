---
name: verification-ladder
description: Candidate to verified — replay or it did not happen.
version: 0.1.0
tags:
- core
- evidence
- replay
- verification
- findings
- claim
---

# The verification ladder — evidence or nothing

A finding is a claim. The kernel enforces what you must do to make it:
candidates need one evidence artifact (RULE-E1); verified needs an
independent replay (RULE-E2). You cannot sweet-talk the gate — it is code.

## Doctrine

1. **A signal is not a finding.** Probe hit, error message, reflected
   marker — all of it is a *candidate*. Candidates are unfinished thoughts
   with a paper trail.
2. **Verify by replay, not by confidence.** Re-run exactly the check that
   produced the candidate, through the engine's `replay` contract, and
   bind the second artifact. Different request, same result, now proven.
3. **Overturn fast.** When a replay disagrees, kill the candidate
   immediately (`ruled_out`, with a reason in the trail). Sunk cost is
   noise; RULE-E4 keeps it forever so the audit trail stays honest. A
   hunter's value is what they *disprove*, too.
4. **Never weaken evidence to fit the claim.** If the payload only worked
   with encoding X, the claim is "works with encoding X". Downgrade the
   claim, never upgrade the evidence.

## Practice

- Bind evidence at the moment of observation — redaction happens at the
  gate; raw secrets must never reach the ledger.
- Payload excerpts, status codes, and response fragments belong in the
  evidence data; adjectives belong nowhere.
- Before calling a run done, ask: which of my candidates would not survive
  a hostile reviewer? Replay those first — they are either your best
  findings or your fastest rulings-out.
- Severity follows impact demonstrated in evidence, not impact imagined in
  the description.
