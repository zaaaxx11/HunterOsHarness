---
name: bypass-principles
description: Bypasses hijack trusted mechanisms — never attack head-on.
version: 0.2.0
metadata:
  min_tier: advanced
---

# Bypass principles — the gap between assumed and actual trust

Distilled from documented incidents across intrusion, fraud, social
engineering, and protocol exploits: **a bypass succeeds by hijacking a
mechanism the defender already trusts.** The gap between what a system
*assumes* is trusted and what *actually* is — that is your audit surface.

## When to apply

Auth and session boundaries; multi-step flows (reset, checkout, webhooks,
SSO); anywhere two components meet — seams outlive the reviews that missed them.

## The seven lenses

1. **Trust hijack** — systems approve the *signal*, not the entity: forged
   tokens, replayed requests, roles asserted by client-controlled fields.
2. **Cadence disruption** — defenses run on rhythm (expiry jobs, rate
   windows). Act inside the window the model considers closed.
3. **Misdirection field** — the loud endpoint is defended; the boring
   sibling (`/api/v1/` vs `/api/v2/debug/`) is not.
4. **Trusted-vector bridge** — the one legitimate channel crossing a
   boundary (webhooks, importers, internal APIs) is the bypass surface.
5. **State inference** — do not force state; map it. Predictable ids and
   step-skipping wizards are information channels.
6. **Terrain rewrite** — capability where nobody logs (rare methods, odd
   content types) sits outside the threat model.
7. **Self-consumption** — the platform's own propagation (mail pipelines,
   preview renderers, bots) becomes the delivery mechanism.

## Procedure and anti-patterns

- At each boundary ask: *which assumption here is unverified?* Record the
  answer with `note_add` before testing it; one assumption, one scope-checked
  request through `http_request`, exchange bound either way.
- Map every micro-bug `[Trigger] → [Effect] → [Trust boundary crossed]`;
  hunt the handoffs as hard as the gadgets.
- Do not brute-force the front door while a trusted side-channel stands
  open; do not treat `ScopeViolation` as a puzzle — the gate marks where
  trust ends.

**Closing rule:** a bypass you cannot replay with a bound `http_exchange`
is a story, not a finding — evidence or nothing.
