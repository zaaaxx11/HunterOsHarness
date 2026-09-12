# QUICKSTART — HunterOs Harness in 60 seconds

**Evidence-first security auditing.** Every finding lives in a hash-chained
ledger with bound evidence — a claim the harness cannot prove is a claim it
refuses to store.

> **SAFETY** — Scan only systems you own or are explicitly authorized to
> test. The scope gate is fail-closed: nothing outside `localhost` and the
> hosts in your scope manifest can be touched. Authorization is your
> responsibility; enforcement is the harness's.

---

## 1. Install (~30s)

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

**macOS / Linux:**

```bash
./install.sh
```

Both installers create a dedicated venv at `~/.hunteros/venv` — they do not
touch your system Python. From a checkout they install editable; otherwise
from PyPI (git fallback).

Or manually:

```bash
python -m venv ~/.hunteros/venv
source ~/.hunteros/venv/bin/activate        # Windows: ~/.hunteros/venv\Scripts\activate
pip install -e .                            # from a checkout
```

## 2. `hunter init` — configure a brain (~60s, optional)

One wizard picks the provider, captures the key safely (the key itself is
never echoed), runs a 1-token live test, and writes `~/.hunteros/config.yaml`:

```bash
hunter init                    # interactive wizard
hunter init --provider openrouter --yes   # non-interactive, defaults from the table
```

Every step has a safe default and failures are printed as notes — a missing
key never blocks the deterministic core. Custom/third-party providers
(Ollama, LM Studio, vLLM, any OpenAI-compatible endpoint) work the same way:
`hunter config provider add <name> --base-url <url>`. Full walkthrough with
real transcripts: **[docs/FIRST-RUN.md](docs/FIRST-RUN.md)**; config reference
and provider examples: **[docs/LLM.md](docs/LLM.md)**.

Prefer env vars only? Skip init and set `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` +
`HUNTEROS_MODEL` later — everything below works with zero keys.

## 3. `hunter doctor` (~5s)

```bash
hunter doctor
```

Checks Python version, package version, dependencies (textual, rich, httpx,
typer), the state directory (`HUNTER_STATE_DIR` or `./.hunter`), the ledger
hash chain, available engines, your LLM config (with YAML line numbers when a
file is broken), per-provider key status, and the chat database. Everything
green → continue. (LLM items are opt-in notes — they never block the
deterministic core. `--json` for scripts, `--live` to probe provider
endpoints.)

## 4. `hunter demo` (~10s)

```bash
hunter demo
```

What it does — all against a **local practice target** it boots itself:

1. Starts the built-in vault server on loopback (a practice web app with
   planted vulnerabilities).
2. Runs the deterministic engine through the scan pipeline: recon → probes →
   evidence binding. No LLM, no API keys, fully offline.
3. Writes everything — events, evidence, findings — into the hash-chained
   ledger at `./.hunter/ledger.db`.
4. Verifies the ladder: findings enter as **candidates** and are promoted to
   **verified** only by an independent replay (claim gate RULE-E2). Expect
   **≥ 7/9 first-blood** (first-pass detections) on the practice target.

## 5. `hunter report` (~2s)

```bash
hunter report
```

Renders markdown + SARIF **from the ledger rows** — never from prose. Every
claim in the report links back to evidence with a sha256 you can re-verify.

## 6. `hunter tui` (interactive)

```bash
hunter tui
```

The dashboard:

| Key | Action |
| --- | ------ |
| `d` | Run the demo scan (async — UI never blocks; toast when done) |
| `r` | Refresh from the ledger |
| `1`–`4` | Jump to Dashboard / Findings / Events / Doctor |
| Enter | Inspect a run (Dashboard) or a finding's evidence (Findings) |
| `q` | Quit |

Tabs: **Dashboard** (runs + verified/candidate counts), **Findings**
(severity-colored table + full evidence detail: evidence ids, sha256
prefixes, excerpt), **Events** (live tail of the last 100 ledger events),
**Doctor** (environment report).

---

## 7. Add the brain manually (alternative to `hunter init`)

If you skipped `hunter init`, the deterministic core above runs with zero
keys. To add the LLM agent by hand:

```bash
pip install hunteros-harness        # LiteLLM brain included
export OPENAI_API_KEY=sk-...       # or ANTHROPIC_API_KEY / OPENROUTER_API_KEY
export HUNTEROS_MODEL=gpt-4o
```

That is the whole setup — full config reference, provider examples
(Anthropic, OpenRouter, local Ollama), budget governor, and the governance
model: **[docs/LLM.md](docs/LLM.md)**.

## 8. Talk to it (`hunter chat`)

```bash
hunter chat
```

```
HunterOs chat — Evidence or Nothing.
model: gpt-4o (planner) · tier: advanced · budget: $5.00 max / 60 iters
type a request, or /help for commands

you> scan the practice target and tell me what is verified
hunter> mapped 12 routes · 2 verified findings (1 high, 1 medium) ·
        chain ok — say `report` to render from the ledger
```

Sessions persist; slash commands (`/help`, `/model`, `/usage`, …) work
the same here and over the gateway. The agent's findings pass through the
same machine validation (R1–R6) and debunk replay as every other run — the
chat cannot promote a claim the ledger cannot prove.

## 9. Connect Telegram (optional)

Expose the agent to your phone with a default-deny allowlist:

```bash
pip install 'hunteros-harness[telegram]'
export HUNTEROS_TELEGRAM_TOKEN="123456:AAE..."       # from @BotFather
export HUNTEROS_TELEGRAM_ALLOWED_USERS="111111111"   # numeric ids, CSV
hunter gateway start
```

Bot setup, the HMAC-signed webhook transport, and the security model:
**[docs/GATEWAY.md](docs/GATEWAY.md)**.

---

## Scanning a real (authorized) target

Define a scope manifest — the only way the gate opens for a non-loopback
host (a documented copy ships at
[examples/scope.manifest.json](examples/scope.manifest.json)):

```json
{
  "name": "client-x-staging",
  "hosts": ["staging.client-x.com", "api.client-x.com"],
  "allow_subdomains": false
}
```

```bash
hunter scan https://staging.client-x.com --scope scope.json
```

Fail-closed means: missing manifest, missing host, unknown scheme — all
violations. Silence is not consent.

State lives in `HUNTER_STATE_DIR` (or `./.hunter` by default). The ledger is
append-only and hash-chained; `hunter doctor` recomputes and reports chain
health at any time.

## Troubleshooting

**`hunter: command not found`** — the venv is not active. Activate it
(`source ~/.hunteros/venv/bin/activate`, Windows:
`~\.hunteros\venv\Scripts\Activate.ps1`) or call it via
`~/.hunteros/venv/bin/hunter`.

**Windows PowerShell: "running scripts is disabled"** — run
`powershell -ExecutionPolicy Bypass -File install.ps1` exactly as shown, or
set `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once. The TUI also
needs Windows Terminal (or any modern console); legacy `cmd.exe` conhost may
render the interface poorly.

**Port busy during demo** — the demo picks a free loopback port
automatically; if a previous run left a zombie process, kill it
(`netstat -ano | findstr :<port>` on Windows, `lsof -i :<port>` on
macOS/Linux). Set `HUNTER_STATE_DIR` to a fresh directory to start clean.

**Venv problems** — delete `~/.hunteros/venv` and re-run the installer; it
recreates everything from scratch.

**`pip install` fails behind a proxy** — export `HTTPS_PROXY`/`HTTP_PROXY`
before running the installer.

**LLM errors** — auth and rate-limit exits, `config.model_unresolved`,
context overflow: see the troubleshooting table in
[docs/LLM.md](docs/LLM.md). `hunter doctor` shows which keys and models are
actually resolved.
