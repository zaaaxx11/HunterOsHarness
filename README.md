# HunterOs Harness

![ci](https://github.com/zaaaxx11/HunterOsHarness/actions/workflows/ci.yml/badge.svg)

**The security-audit harness whose LLM cannot fabricate findings.**
Every finding must be backed by tamper-evident evidence in a hash-chained
ledger — the database is the only ledger, reports render only from it, and
the claim gate vetoes any claim the ledger cannot prove. A vulnerability you
cannot replay is a vulnerability you cannot bill, defend, or trust:
**evidence or nothing**.

## Why it matters

Prompt-only agents are asked not to fabricate; HunterOs makes fabrication
structurally impossible. The LLM's only write path is a machine-validated
finding request — evidence ids are re-resolved and re-hashed against the
ledger, a self-written note can never carry a finding, and "verified" is
decided by a deterministic replay, never by the model. Trust the chain, not
the chat.

## Features

- **Deterministic engine** (no LLM required) — 9 first-pass vulnerability
  probes against the built-in practice target, offline, no API keys.
- **LLM brain, BYOK** (v0.2) — plug in OpenAI, Anthropic, OpenRouter, or a
  local Ollama via LiteLLM; tier routing (planner/exploit/verify/utility),
  a budget governor with staged spend warnings, and a fallback chain.
  [docs/LLM.md](docs/LLM.md).
- **Governed agent** — 15 tools, nothing else. `create_finding_request` is
  machine-validated (R1–R6: prose, evidence resolution + hash integrity,
  http_exchange required, scope, dedupe, scales); a debunk replay —
  deterministic, no LLM argument — decides what becomes verified.
- **Hash-chained ledger** — append-only SQLite store; every event chains
  `sha256(prev_hash + canonical row)`; the chain can be recomputed at any
  time.
- **Claim gate** — findings without bound evidence are structurally
  impossible to insert (RULE-E1); verification requires an independent
  replay (RULE-E2); evidence is deep-redacted before storage (RULE-E3).
- **Scope gate in code, not prompts** — out-of-scope requests are rejected
  fail-closed in the HTTP client; a prompt injection cannot open the socket.
- **Chat + gateway** (v0.2) — `hunter chat` REPL with sessions and slash
  commands; Telegram and HMAC-signed webhook front-ends with default-deny
  allowlists and turn leases. [docs/GATEWAY.md](docs/GATEWAY.md).
- **Beautiful TUI** (`hunter tui`) — runs, findings, live event tail,
  doctor; `d` runs the demo from inside the dashboard.
- **One-command demo** (`hunter demo`) — boots the practice target, scans,
  ≥ 7/9 first-blood, evidence in the ledger.

## Quick start

```bash
./install.sh                 # Windows: powershell -ExecutionPolicy Bypass -File install.ps1
hunter doctor                # check environment
hunter demo                  # scan the built-in practice target, find planted vulns
hunter report                # render markdown + SARIF from the ledger
hunter tui                   # interactive dashboard
```

Add a brain (optional — everything above works with zero keys):

```bash
pip install hunteros-harness        # the brain (LiteLLM) ships in the core install
export OPENAI_API_KEY=sk-...      # or ANTHROPIC_API_KEY / OPENROUTER_API_KEY
export HUNTEROS_MODEL=gpt-4o
hunter chat
```

Details, scope manifests for real targets, and troubleshooting:
[QUICKSTART.md](QUICKSTART.md).

## Architecture in three lines

1. **Kernel (L0)** — the append-only, hash-chained event ledger with the
   claim gate; the single source of truth.
2. **Engines** — pluggable brains behind the `EngineDriver` protocol
   (deterministic probes and, since v0.2, the governed LLM agent; the brain
   changes, the evidence contract does not).
3. **Scope gate** — fail-closed, structural, enforced in the HTTP client
   before the socket opens.

Full layer diagram, governance flow, and invariants:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

**v0.2.0** — LLM brain (BYOK, tier router, budget governor, fallback
chain), governed agent loop with machine-validated findings and debunk
replay, chat REPL + sessions, Telegram/webhook gateway, tier-advanced
doctrine skills. The multi-agent workflow lands in v0.3
([docs/ROADMAP-v0.3.md](docs/ROADMAP-v0.3.md),
[docs/BUSINESS.md](docs/BUSINESS.md) for the commercial roadmap).

## Doctrine

1. Evidence or Nothing — a finding without evidence cannot exist in the ledger.
2. The database is the only ledger — reports render from rows, never prose.
3. Scope is enforced by code, not by prompts.
4. The ledger predates the harness and outlives it.

## License

MIT (see the `license` field in [pyproject.toml](pyproject.toml)).
