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

## 2. `hunter doctor` (~5s)

```bash
hunter doctor
```

Checks Python version, package version, dependencies (textual, rich, httpx,
typer), the state directory (`HUNTER_STATE_DIR` or `./.hunter`), the ledger
hash chain, and available engines. Everything green → continue.

## 3. `hunter demo` (~10s)

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

## 4. `hunter report` (~2s)

```bash
hunter report
```

Renders markdown + SARIF **from the ledger rows** — never from prose. Every
claim in the report links back to evidence with a sha256 you can re-verify.

## 5. `hunter tui` (interactive)

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

## Scanning a real (authorized) target

Define a scope manifest — the only way the gate opens for a non-loopback
host:

```json
{
  "name": "client-x-staging",
  "hosts": ["staging.client-x.com", "api.client-x.com"],
  "allow_subdomains": false
}
```

```bash
HUNTER_SCOPE_MANIFEST=scope.json hunter scan https://staging.client-x.com
```

Fail-closed means: missing manifest, missing host, unknown scheme — all
violations. Silence is not consent.

State lives in `HUNTER_STATE_DIR` (or `./.hunter` by default). The ledger is
append-only and hash-chained; `hunter verify` recomputes the chain at any
time.

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
