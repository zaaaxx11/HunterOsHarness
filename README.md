# HunterOs Harness

![ci](https://github.com/zaaaxx11/HunterOsHarness/actions/workflows/ci.yml/badge.svg)

**Evidence-first security-audit harness.** Every finding must be backed by
tamper-evident evidence in a hash-chained ledger — the database is the only
ledger, reports render only from it, and the claim gate vetoes any claim the
ledger cannot prove. A vulnerability you cannot replay is a vulnerability you
cannot bill, defend, or trust: **evidence or nothing**.

## Features

- **Deterministic engine** (no LLM required) — 9 first-pass vulnerability
  probes against the built-in practice target, offline, no API keys.
- **Hash-chained ledger** — append-only SQLite store; every event chains
  `sha256(prev_hash + canonical row)`; `hunter verify` recomputes the chain.
- **Claim gate** — findings without bound evidence are structurally
  impossible to insert (RULE-E1); verification requires an independent
  replay (RULE-E2); evidence is deep-redacted before storage (RULE-E3).
- **Scope gate in code, not prompts** — out-of-scope requests are rejected
  fail-closed in the HTTP client; a prompt injection cannot open the socket.
- **Pluggable `EngineDriver`** — an LLM brain (LiteLLM) mounts later, the
  same way modern agent harnesses (hermes, Strix) mount their models.
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

Details, scope manifests for real targets, and troubleshooting:
[QUICKSTART.md](QUICKSTART.md).

## Architecture in three lines

1. **Kernel (L0)** — the append-only, hash-chained event ledger with the
   claim gate; the single source of truth.
2. **Engines** — pluggable brains behind the `EngineDriver` protocol
   (deterministic probes today; an LLM engine mounts later without touching
   the kernel).
3. **Scope gate** — fail-closed, structural, enforced in the HTTP client
   before the socket opens.

Full layer diagram and invariants: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

**v0.1.0** — deterministic engine, kernel, workflow pipeline, reporting,
TUI, and release pack. The LLM brain and multi-agent workflow land in v0.2
(see [docs/BUSINESS.md](docs/BUSINESS.md) for the roadmap).

## Doctrine

1. Evidence or Nothing — a finding without evidence cannot exist in the ledger.
2. The database is the only ledger — reports render from rows, never prose.
3. Scope is enforced by code, not by prompts.
4. The ledger predates the harness and outlives it.

## License

MIT (see the `license` field in [pyproject.toml](pyproject.toml)).
