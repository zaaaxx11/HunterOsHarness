# Roadmap — v0.3 working backlog

Priorities: **P1** = lands in v0.3; **P2** = candidate, lands if the v0.3
window allows. Every item keeps the one invariant that cannot regress:
findings are machine-validated against the ledger — a feature that lets the
model bypass evidence is not a feature.

## P1

- **Challenger LLM falsification pass** — the adversarial pass the debunk
  replay reserved a `provider` hook for: a second model argues *why this
  finding is wrong* before promotion; the deterministic replay still makes
  the final call.
- **Compaction checkpoint** — summarize long agent sessions into the ledger
  so context overflow becomes a checkpoint/restore, not a dead run.
- **Threat-model persistence** — promote the run-scoped threat model from
  agent state to a ledgered artifact, so `threat_model_amend` survives
  across sessions and feeds the opening read of the next run.
- **`web_search` tool** — scoped, auditable research capability for the
  planner tier (CVE context, docs, error-message triage), with queries and
  results bound as evidence-class rows.
- **Coverage update/list hardening** — update_finding semantics and a
  coverage list view that reconciles the surface map against findings for
  report-grade "what was checked and cleared" output.
- **`update_finding` supersede** — immutable-by-rewrite is wrong for
  corrections: an explicit supersede event that references the finding it
  replaces, keeps the old row (RULE-E4), and re-enters the ladder.

## P2

- **Subagent graph** — planner/recon/exploit-verify roles as separate
  agent contexts over one shared ledger (FRAMEWORK L3: roles without a
  shared mouth).
- **MCP integration** — mount external tool servers as governed tools: same
  ToolSpec contract, same BLOCKED-code refusals, same evidence binding.
- **Browser automation** — a browser tool behind the scope gate for
  client-rendered surfaces; DOM events bound as evidence like exchanges.
- **CVSS computation** — derive vector strings from demonstrated impact
  (R1/R6 fields) as a deterministic post-pass; severity justification stays
  the model's burden.
- **`/audit` slash command (stretch)** — drive a full governed audit from
  the chat REPL: target + tier in, verified-findings summary out.
- **Curator** — post-run pass that mines coverage rows, ruled-out
  candidates, and debunk outcomes into doctrine/skill updates (the L5 retro
  loop, automated).
- **Busy modes** — per-target concurrency policy for gateway and chat:
  queue, reject, or coalesce turns instead of one global lease.
- **Stream consumer** — first-class event stream (SSE/WebSocket) so
  dashboards and the gateway render ledger events live instead of polling.
