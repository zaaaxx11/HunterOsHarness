# HunterOs Harness

![ci](https://github.com/zaaaxx11/HunterOsHarness/actions/workflows/ci.yml/badge.svg)

**The security-audit harness whose LLM cannot fabricate findings.**
Every finding must be backed by tamper-evident evidence in a hash-chained
ledger — the database is the only ledger, reports render only from it, and
the claim gate vetoes any claim the ledger cannot prove. A vulnerability you
cannot replay is a vulnerability you cannot bill, defend, or trust:
**evidence or nothing**.

## User skills and curator

Local methodology cards live under `~/.hunter/skills/<name>/SKILL.md`. The merged bundled/user corpus shows `[bundled]`, `[user]`, and `[quarantined]` source markers; relevance matching selects at most five skills. `hunter skills` lists the merged corpus, while `hunter skills --view NAME` shows one card. The `/skills` and `hunter skills` surfaces mark each effective card with its source; `/curate` and `hunter curate` preview retro-derived cards before an explicit y/N save. Duplicate drafts are skipped, flagged drafts are saved with quarantined semantics, and quarantined cards remain inert until manually reviewed and are never mounted into a prompt.

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
  warnings, and a cross-provider fallback chain. The configured provider is
  loaded consistently from `$HUNTEROS_CONFIG` or `~/.hunter/config.yaml` for
  chat, `hunter hunt`, and the LLM engine; an implicit hunt falls back to
  deterministic when no config exists, while explicit `--engine llm` records a
  governed failed run instead of silently switching providers.
  [docs/LLM.md](docs/LLM.md).
- **15 core tools by default** — `create_finding_request` is machine-validated
  (R1–R6: prose, evidence resolution + hash integrity, http_exchange
  required, endpoint match, dedupe, scales); a debunk replay — deterministic,
  no LLM argument — decides what becomes verified. Optional browser support adds
  four narrow, hunt-only tools. Capability tiers (basic/advanced) are
  structural: out-of-tier actions are refused by the handlers.
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
  unified chat, `/hunt`, `/audit`, and `/curate`; Telegram, Discord, WhatsApp,
  and HMAC-signed webhook front-ends with default-deny allowlists,
  anti-replay signatures, and turn leases.
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
- **One-command safe demo** (`hunter demo`) — boots the deliberately
  vulnerable PracticeVault only on `127.0.0.1`, runs deterministic probes with
  no API key or external target, records evidence in the ledger, and tears the
  server down. The first-blood gate requires at least 7/9 planted issues.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
# Windows (PowerShell):
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
```

The installer registers `hunter` and `hunt` shims (installer venv plumbing) in
`~/.hunteros/bin` (installer venv shims) and starts the onboarding wizard on an
interactive first run.
Run `hunter` for the welcome panel, or run `hunter init` explicitly at any
time. The wizard writes `~/.hunter/config.yaml`; a pasted key is stored in
`~/.hunter/keys.env`,
never echoed and never written to YAML. Auto mode assigns one model to the
`orchestrator`, `hunter`, `verifier`, and `utility` roles; Advanced mode lets
you choose each role. A key is optional for `hunter demo`, deterministic scans,
reports, and the TUI. Run `hunter doctor` to check the environment.

From a checkout, run `./install.sh` (Windows:
`powershell -ExecutionPolicy Bypass -File install.ps1`) instead, then:

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

Chat is ordinary free text until you say something like `audit http://127.0.0.1:8941/`; target-bearing hunt intent requires explicit confirmation when mode is off. `/hunt on` and `/hunt off` control process-local hunt mode. Use `/audit <target>` or `/hunt <target>` inside chat for a one-shot governed hunt, and `hunter hunt <target>` from the shell for URLs, hosts, or local directories. `hunter scan <target>` remains the manifest-required pipeline command for non-localhost targets. For `hunter hunt`, localhost needs no prompt; a non-localhost target with `--scope scope.json` uses that manifest, while without `--scope` the CLI prints a minimal exact-host manifest and asks for authorization. Refusal exits 3 and nothing runs; `--yes` accepts the proposed exact-host scope. A local directory is served temporarily on loopback and shuts down when the command ends. Authorization is your responsibility and enforcement is fail-closed.

Browser automation is optional and hunt-only. Install explicitly with
`pip install 'hunteros-harness[browser]'` and then separately run
`python -m playwright install chromium`. Browser actions are scope-gated and
available only inside an authorized hunt; normal chat remains browser-free. The
onboarding `agent.browser` flag is usable without the extra, but enabling it
does not authorize a hunt by itself. HunterOs never automatically installs
Chromium.

`hunter hunt` accepts a live localhost URL or a local directory. For the
self-contained PracticeVault walkthrough, use `hunter demo` above; its port is
ephemeral and the server is shut down when the demo ends.

Add any third-party provider:

```bash
hunter config provider add lab-vllm --base-url http://10.0.0.9:8000/v1
hunter config provider test lab-vllm --model mistralai/Mistral-7B-Instruct-v0.4.0
hunter config provider list
```

The same group is available as `hunter provider`. Providers feed the four
model roles: `orchestrator`, `hunter`, `verifier`, and `utility`. Legacy
`planner`, `exploit`, and `verify` names are accepted on load and canonicalized
on the next config write. The interactive provider wizard can probe chat versus
responses endpoints, list models, and assign one model to every role or assign
roles individually.

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
`pipx`, or plain `pip`) and asks for confirmation before upgrading (`--yes`
for automation). A git checkout is never auto-mutated: it gets
`git pull && pip install -e .` advice instead. The GitHub-first check falls
back silently to PyPI, using a 24-hour cache. It prints one-line notices only
on stderr (never into `--json` stdout and never in long-lived `chat`/`tui`/
`gateway` surfaces). Disable it with `HUNTEROS_NO_UPDATE_CHECK=1`; CI
environments are skipped automatically. If the check is offline or
rate-limited, the manual installer command is printed and the command exits
1. Config migration notes appear on the next command. Manual install, any time:

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

## v0.5.0 additions

- **24/7 engine** — `hunt start` boots the persistent engine once (no target
  needed; it stays on for ordinary chat); `hunt status`, `hunt logs`,
  `hunt stop` manage it. Queue hunts from any surface with
  `/hunt <target> [<target> ...] --time 30m [--budget 2]` (or
  `hunt start --target URL --time 2h --min-time 30m` for a legacy one-shot):
  time is a minimum per target, `0 = unlimited` for every budget key.
- **Shell approval** — `shell_exec` classifies every command as readonly /
  mutating / catastrophic; anything that modifies the local system needs an
  explicit `/approve <id>` (single-use, expires after 300 seconds) in every
  mode, auto-allow covers read-only recon in hunter mode only. Output is
  redacted and capped at 16k, the cwd is locked inside the state directory,
  and every run is ledgered.
- **Brand palette** — `#00FFE5` base with a brighter gradient (`#4DFFF0` →
  `#80FFF6` → `#B3FFFC` → `#E6FFFE`), deep/dim companions, one `hunter.palette`
  source of truth for CLI, REPL, TUI, and daemon output.
- **Browser cloak** — on by default (`agent.browser_cloak`): plausible
  user-agent/viewport/locale/timezone pools, non-automation launch args,
  and one masking init script. The scope interceptor and redaction are
  untouched; `cloak: false` restores stock behavior exactly.
- **Soul** — `SOUL.md` is the user-editable operating character (silent,
  precise, patient, evidence-or-nothing; no levels, no scoring). It binds
  every turn; the engine-hardcoded core identity (`You are Hunter, the
  HunterOS audit agent built by zaaaxx.`) is always prepended before it
  reaches a prompt. Persona text is sanitized and capped before render.
- **Session compression** — `/compress` and automatic 24k-char compaction
  keep head and tail verbatim and summarize the middle extractively;
  evidence ids are never dropped or invented; the store stays append-only.
- **Discord + WhatsApp gateways** — the same default-deny allowlists as
  Telegram: `HUNTEROS_DISCORD_TOKEN` + `HUNTEROS_DISCORD_ALLOWED_USERS`,
  or the `HUNTEROS_WHATSAPP_TOKEN` / `HUNTEROS_WHATSAPP_PHONE_NUMBER_ID` /
  `HUNTEROS_WHATSAPP_ALLOWED_USERS` trio. WhatsApp inbound payloads are
  HMAC-verified against the Meta app secret or refused with 403.
  See [docs/GATEWAY.md](docs/GATEWAY.md).
- **Development notes** — roadmaps, plans, tests, and testing products
  stay untracked from v0.5 and are not part of the release package.
  Install the package, then edit your own `SOUL.md` copy to tune the
  operating character.

## Status

**v0.5.0** — approval-gated shell, the 24/7 hunt daemon, minimum-time
budgets with unlimited-credit semantics, the browser cloak, the operating
character, session compression, Discord and WhatsApp gateways, and the
`scripts/` toolkit are shipped. v0.4.0 shipped the phase pipeline, governed
provider roles, unified chat and `hunter hunt`, advisory GitHub-first/
PyPI-fallback updates, dynamic skills and curator, and optional hunt-only
browser tools. Release quality is tracked by the offline test matrix and
Ruff gates; see [CHANGELOG.md](CHANGELOG.md).

## v0.4.0 current contracts

- Exit codes are stable: `0` clean, `1` error, `2` findings, and `3`
  refused/usage for `hunter hunt`; other classified CLI errors remain documented
  in the architecture and LLM references.
- Provider roles are `orchestrator`, `hunter`, `verifier`, and `utility`;
  legacy `planner`, `exploit`, and `verify` names are accepted on load and
  rewritten to canonical names on the next config write.
- Browser support is optional and explicit: `pip install 'hunteros-harness[browser]'`
  then `python -m playwright install chromium`. `agent.browser` remains
  loadable without the extra; browser actions require an explicitly authorized
  governed hunt, are scope-gated, normal chat is browser-free, and HunterOs
  never installs Chromium automatically.
- Skills live at `~/.hunter/skills/<name>/SKILL.md`; the merged corpus uses
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
