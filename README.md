# HunterOs Harness

![ci](https://github.com/zaaaxx11/HunterOsHarness/actions/workflows/ci.yml/badge.svg)

**The security-audit harness whose LLM cannot fabricate findings.**
Every finding must be backed by tamper-evident evidence in a hash-chained
ledger — the database is the only ledger, reports render only from it, and
the claim gate vetoes any claim the ledger cannot prove. A vulnerability you
cannot replay is a vulnerability you cannot bill, defend, or trust:
**evidence or nothing**.

## User skills and curator

Local methodology cards live under `~/.hunteros/skills/<name>/SKILL.md`. The merged bundled/user corpus shows `[bundled]`, `[user]`, and `[quarantined]` source markers; relevance matching selects at most five skills. The `/skills` and `hunter skills` surfaces mark each effective card with its `[source]`; `/curate` previews retro-derived cards before an explicit y/N save. Flagged drafts are saved with `[quarantined]` semantics and remain inert until manually reviewed.

## Why it matters

Prompt-only agents are asked not to fabricate; HunterOs makes fabrication
structurally impossible. The LLM's only write path is a machine-validated
finding request — evidence ids are re-resolved and re-hashed against the
ledger, a self-written note can never carry a finding, and "verified" is
decided by a deterministic replay, never by the model. Trust the chain, not
the chat.

## Features

- **The HunterOS phase pipeline, enforced** (v0.4) — every run walks
  `score → recon → classify → hunting → verify → report → retro`. Canonical
  phases are hash-chained ledger events, order is enforced in code (no
  skipping, no re-ordering), and each phase closes through a deterministic
  gate that reads only the ledger. Gate failures are recorded facts, never
  crashes.
- **Governed LLM agent** — the brain ships with the body (LiteLLM is a core
  dependency; you bring only the API key). BYOK against OpenAI, Anthropic,
  OpenRouter, DeepSeek, Groq, Together, Ollama, LM Studio, vLLM, or any
  OpenAI-compatible endpoint, with model-tier routing
  (orchestrator/hunter/verifier/utility), a budget governor with staged spend
  warnings, and a cross-provider fallback chain. [docs/LLM.md](docs/LLM.md).
- **15 tools, nothing else** — `create_finding_request` is machine-validated
  (R1–R6: prose, evidence resolution + hash integrity, http_exchange
  required, endpoint match, dedupe, scales); a debunk replay — deterministic,
  no LLM argument — decides what becomes verified. Capability tiers
  (basic/advanced) are structural: out-of-tier tools are absent and refused.
- **Hash-chained ledger** — append-only SQLite store; every event chains
  `sha256(prev_hash + canonical row)`; `hunter verify` recomputes the chain
  at any time.
- **Claim gate** — findings without bound evidence are structurally
  impossible to insert (RULE-E1); verification requires an independent
  replay (RULE-E2); evidence is deep-redacted before storage (RULE-E3).
- **Scope gate in code, not prompts** — out-of-scope requests are rejected
  fail-closed in the HTTP client; a prompt injection cannot open the socket.
- **Deterministic engine** — 12 baseline-first probes run offline with zero
  keys; every signal is baseline-diffed and evidence-bound.
- **Chat + gateway** — `hunter chat` REPL with sessions, 20 slash commands,
  unified chat, `/hunt`, `/audit`, and `/curate`; Telegram and HMAC-signed
  webhook front-ends with default-deny allowlists, anti-replay signatures,
  and turn leases.
  [docs/GATEWAY.md](docs/GATEWAY.md).
- **Errors that tell you where** — every failure is notified as
  `[BLOCKED]` / `[ERROR <layer>]` with a `where: file:line` location, an
  actionable `Hint:`, and a stable exit code; `--verbose` prints the full
  traceback to stderr. The REPL and gateway never die from unexpected
  errors.
- **Doctor that actually diagnoses** — `hunter doctor` checks the
  environment, ledger chain, engines, config, per-provider keys and
  reachability, and the chat DB; `--json` for scripts.
- **Beautiful TUI** (`hunter tui`) — runs with a live phase column, findings,
  event tail, doctor; `d` runs the demo from inside the dashboard.
- **One-command demo** (`hunter demo`) — boots the practice target, scans,
  9/9 first-blood, evidence in the ledger, retro lessons included.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
# Windows (PowerShell):
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
```

The installer registers `hunter` and `hunt` shims in `~/.hunteros/bin` and
starts the onboarding wizard on first run. From a checkout, run
`./install.sh` (Windows: `powershell -ExecutionPolicy Bypass -File install.ps1`)
instead, then:

```bash
hunter                       # welcome panel + next steps
hunter demo                  # first blood in ~10s — no API key needed
hunter report                # markdown + SARIF rendered from the ledger only
hunter retro --run <id>      # deterministic retrospective: stats, gaps, lessons
hunter tui                   # interactive dashboard
```

Bring a key for the interactive brain (the brain library is already
installed — LiteLLM ships in the core install):

```bash
export OPENAI_API_KEY=sk-...      # or ANTHROPIC_API_KEY / OPENROUTER_API_KEY
export HUNTEROS_MODEL=gpt-4o
hunter chat                       # normal chat; hunt intent offers a governed audit
```

Chat is ordinary free text until you say something like `audit http://127.0.0.1:8941/`; target-bearing hunt intent requires explicit confirmation when mode is off. `/hunt on` and `/hunt off` control process-local hunt mode. Use `/audit <target>` or `/hunt <target>` for a one-shot hunt, and `hunter hunt <target>` from the shell (including local directories). The scope gate is unchanged: non-localhost targets require an authorized scope manifest; authorization is your responsibility and enforcement is fail-closed.

Browser automation is optional and hunt-only. Install explicitly with
`pip install 'hunteros-harness[browser]'` and then separately run
`python -m playwright install chromium`. Browser actions are scope-gated and
available only inside an authorized hunt; normal chat remains browser-free. The
onboarding `agent.browser` flag is usable without the extra, but enabling it
does not authorize a hunt by itself. HunterOs never automatically installs
Chromium.

```bash
hunter hunt http://127.0.0.1:8941/        # one-shot CLI hunt
```

Add any third-party provider:

```bash
hunter config provider add lab-vllm --base-url http://10.0.0.9:8000/v1
hunter config provider test lab-vllm --model mistralai/Mistral-7B-Instruct-v0.4.0
hunter config provider list
```

Scan a real target (authorized only — the scope gate is fail-closed):

```bash
hunter scan https://target.example.com --scope scope.manifest.json
```

Details, scope manifests, and troubleshooting: [QUICKSTART.md](QUICKSTART.md).
First-run transcripts: [docs/FIRST-RUN.md](docs/FIRST-RUN.md).

## Updating

```bash
hunter update
```

`hunter update` detects how the harness was installed (installer venv,
`pipx`, or plain `pip`) and runs the matching upgrade; a git checkout gets
`git pull && pip install -e .` advice instead. The GitHub-first check falls
back silently to PyPI, using a 24-hour cache. It prints one-line notices only
on stderr (never into `--json` stdout and never in long-lived `chat`/`tui`/
`gateway` surfaces). Disable it with `HUNTEROS_NO_UPDATE_CHECK=1`; CI
environments are skipped automatically. Manual install, any time:

```bash
curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
# Windows (PowerShell):
irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex
```

## Architecture in four lines

1. **Kernel (L0)** — the append-only, hash-chained event ledger with the
   claim gate; the single source of truth.
2. **Phase pipeline (L1)** — the enforced `score..retro` machine; every
   gate reads the ledger, nothing else.
3. **Engines** — pluggable brains behind the `EngineDriver` protocol
   (deterministic probes and the governed LLM agent; the brain changes, the
   evidence contract does not).
4. **Scope gate** — fail-closed, structural, enforced in the HTTP client
   before the socket opens.

Full layer diagram, governance flow, invariants, and the L1–L5 framing:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

**v0.4.0** — the phase pipeline, governed provider roles, unified chat and
`hunter hunt`, advisory GitHub-first/PyPI-fallback updates, dynamic skills and
curator, and optional hunt-only browser tools are shipped. Release quality is
tracked by the offline test matrix and Ruff gates; see [CHANGELOG.md](CHANGELOG.md)
and [docs/ROADMAP-v0.5.md](docs/ROADMAP-v0.5.md) for maintenance work.

## v0.4.0 current contracts

- Exit codes are stable: `0` clean, `1` error, `2` findings, and `3`
  refused/usage for `hunter hunt`; other classified CLI errors remain documented
  in the architecture and LLM references.
- Browser support is optional and explicit: `pip install 'hunteros-harness[browser]'`
  then `python -m playwright install chromium`. `agent.browser` remains
  loadable without the extra; browser actions are hunt-only and scope-gated,
  normal chat is browser-free, and HunterOs never installs Chromium
  automatically.
- Skills live at `~/.hunteros/skills/<name>/SKILL.md`; the merged corpus uses
  `[bundled]`, `[user]`, and `[quarantined]` markers, matches at most five, and
  `/curate`/`hunter curate` require preview plus explicit confirmation to save.
  Quarantined cards are inert until review.
- Scan only systems you own or are explicitly authorized to test. Authorization
  is your responsibility; enforcement is the harness's. Non-localhost targets
  require an authorized scope manifest.

## Doctrine

1. Evidence or Nothing — a finding without evidence cannot exist in the ledger.
2. The database is the only ledger — reports render from rows, never prose.
3. Scope is enforced by code, not by prompts.
4. Every phase is earned — gates read the ledger, order is enforced, and a
   phase that fails its gate is recorded, never papered over.
5. Every error is notified — location, hint, exit code; silence is not a
   failure mode.
6. The ledger predates the harness and outlives it.

## License

MIT (see the `license` field in [pyproject.toml](pyproject.toml)).
