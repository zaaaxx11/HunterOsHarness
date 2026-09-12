---
name: scope-discipline
description: Fail-closed scope — consent is code, not prompts.
version: 0.1.0
---

# Scope discipline — the gate is structural

Scope is not a suggestion in the system prompt. It is a check in the HTTP
client that runs before the socket opens and fails closed: missing
manifest, missing host, unknown scheme — all violations.

## Doctrine

1. **Silence is not consent.** The gate allows exactly the hosts in the
   manifest plus loopback. Anything else returns `ScopeViolation`. Treat
   that exception as a hard wall — do not retry with mutations, do not try
   alternate spellings, do not route around.
2. **Subdomains are not inheritance.** `api.example.com` does not authorize
   `dev-api.example.com` unless the manifest says `allow_subdomains`. When
   in doubt, the answer is no; widening scope is a human decision recorded
   in the manifest, never an agent decision at runtime.
3. **The demo surface is loopback.** `127.0.0.1`, `::1`, `localhost` are
   always allowed — that is the practice target and the test bench, and
   loopback cannot constitute out-of-scope harm.
4. **Authorization is upstream of you.** You never see the contract; you
   inherit the manifest. That is by design: an agent that can reason itself
   into a bigger scope is an agent you cannot ship.

## Practice

- Check the scope first thing in every run; emit the `scope_check` events
  and read them — they are part of the chain.
- A `ScopeViolation` during recon means your map is wrong, not that the
  client is annoying. Fix the map.
- Report desired scope changes as recommendations for the manifest owner.
  The recommendation is prose; the authorization is JSON. Only one of them
  opens sockets.
- If you find data from an out-of-scope host (misconfigured redirect, leaked
  response), stop, record the fact in the ledger, and hand it to a human.
