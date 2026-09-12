---
name: black-swan-engine
description: Derive invariants first — violations are laws, not patterns.
version: 0.2.0
metadata:
  min_tier: advanced
---

# Black swan engine — universal discovery by invariant violation

Known bug patterns find known bugs. This engine finds the rest: derive the
invariants the system must hold to stay consistent, then classify every
violation by the **law it breaks**, not by the bug it resembles. Apply after
recon, when routes and parameters are mapped well enough to reason about
state — never before.

## The universal laws (web surfaces)

1. **Authorization is per-object, never per-route.** Every object reference
   (id, uuid, slug) must re-check its owner per request; "route is safe"
   because you accessed it once is the violation.
2. **State transitions are total.** For every state machine (order, user,
   workflow), the legal transitions form a closed set — any unlisted
   transition the server accepts is a finding, however harmless it looks.
3. **Amounts and identities are server-side truth.** Prices, quantities,
   user ids, roles, tenant bindings — client-supplied values for these
   break the invariant whatever the field is named.
4. **Every input has a declared shape.** The server enforcing less than it
   declares is a violation; so is trusting the client to enforce at all.
5. **Side effects are idempotent or guarded.** Replaying a request that
   duplicates state (double credit, double email) breaks exactly-once.
6. **Failure paths fail closed.** Error, timeout, partial results — must
   deny; a catch-block that proceeds is a violation.

## Procedure and anti-patterns

- List the target's stateful objects and invariants from recon data;
  record them with `threat_model_amend` — invariants are run-scoped truth.
- For each invariant craft the minimal request that violates *only* it: one
  violation, one exchange, one coverage row. Classify impact by the law
  broken (what becomes inconsistent, for whom), not by the payload; severity
  follows demonstrated impact.
- Do not fuzz for error messages instead of proving an invariant false; do
  not report "accepted weird input" without the inconsistent state it
  produces; do not test invariants you never wrote down.

**Closing rule:** an invariant violation is only a finding once the broken
state is replayable evidence in the ledger — evidence or nothing.
