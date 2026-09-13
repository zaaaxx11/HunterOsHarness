# M1 — Installer & Onboarding (v0.4)

**Goal:** adopting HunterOS is as easy as adopting Hermes/Strix — one-liner
install → auto-launch onboarding wizard → configured and hunting in ~60 seconds.

**Design status:** final for M1. AUDITOR writes the failing tests in
§11/§12 first; BUILDER implements until green. Every acceptance criterion is
mechanically checkable and none requires live network.

---

## 0. Non-goals (M1)

- Router support for the `responses` API (M2) — we only **store** `endpoint`.
- The `[browser]` extra / Playwright wiring (M6) — we only **store**
  `agent.browser`.
- A `hunter hunt <url>` command (later milestone) — installers only *mention*
  it as "coming soon".
- Changing `run_init` (v1 wizard) behavior or its tests in any way.
- `hunter config provider add --endpoint` (M2).

---

## 1. Current-state map (what exists, what changes)

| File | Today | M1 change |
| --- | --- | --- |
| `install.sh` | venv at `~/.hunteros/venv`, PyPI→git fallback, `OWNER` placeholder | real URL, ASCII banner, `hunter`+`hunt` shims, PATH block, `--skip-setup`/`--dry-run`, auto-run `hunter init`, new final printout |
| `install.ps1` | same, Windows | same + iex-safety fix for `$scriptDir`, `-SkipSetup`/`-DryRun` switches, `HUNTEROS_PROFILE` override |
| `src/hunter/cli/init_wizard.py` | v1 6-step wizard (`run_init`), injectable `ask`/`secret`/`ping_fn` | **unchanged**; add `run_onboarding` (v2), `OnboardingAnswers`, `onboarding_updates`, `config_missing`, `offer_onboarding` |
| `src/hunter/cli/main.py` | bare `hunter` panel; `init` → v1 | root callback + `chat` get the offer; `init` routes interactive → v2 |
| `src/hunter/llm/config.py` | loader, unknown keys rejected | accept `providers.<n>.endpoint`, `agent.browser` |
| `src/hunter/llm/writing.py` | canonical commented template, atomic write | emit the two new keys (template gains lines, comments preserved) |
| `src/hunter/llm/providers.py` | known table | **unchanged** |
| `src/hunter/llm/ping.py` | 1-token ping, `litellm_module` seam | **unchanged** (reused as smoke test) |
| `src/hunter/llm/probe.py` | — | **new**: `detect_endpoint`, `list_models` |
| `src/hunter/llm/keys.py` | — | **new**: keys.env parse/write/load |
| `src/hunter/cli/doctor_core.py` | `collect_checks` | **unchanged** (reused by wizard step 6) |
| `pyproject.toml` | `[project.scripts] hunter` | add `hunt = "hunter.cli.main:main"` |
| `README.md`, `QUICKSTART.md`, `docs/FIRST-RUN.md` | `./install.sh` style | one-liner raw.githubusercontent URLs, shim/wizard-v2 docs |

Tests live in `tests/` (flat, not `tests/cli/`). Conventions observed:
string `rich.Console(file=io.StringIO())` capture, `$HUNTEROS_CONFIG` sandbox +
`HOME`/`USERPROFILE` monkeypatched to `tmp_path`, injectable seams, zero network.

---

## 2. Part A — Installer spec (install.sh + install.ps1)

Both scripts must behave identically except platform syntax. Order of steps:

```
banner → [--dry-run? → shims + PATH + final printout → exit 0]
       → python detection → venv create/reuse → pip upgrade → install
       (checkout-editable → PyPI → git fallback) → import verify
       → shims (hunter + hunt) → PATH registration
       → auto-run `hunter init` handoff (unless --skip-setup)
       → final printout + authorization disclaimer
```

### 2.1 Constants and flags

- `REPO_URL` default becomes exactly `https://github.com/zaaaxx11/HunterOsHarness.git`.
  - bash: `REPO_URL="${INSTALL_REPO_URL:-https://github.com/zaaaxx11/HunterOsHarness.git}"`,
    then the arg loop below may override with a positional URL.
  - ps1: `param([string]$RepoUrl = $(if ($env:INSTALL_REPO_URL) { $env:INSTALL_REPO_URL } else { "https://github.com/zaaaxx11/HunterOsHarness.git" }))`.
- bash arg loop (replaces `REPO_URL="${1:-...}"`):

```bash
SKIP_SETUP=0; DRY_RUN=0
REPO_URL="${INSTALL_REPO_URL:-https://github.com/zaaaxx11/HunterOsHarness.git}"
for arg in "$@"; do
  case "$arg" in
    --skip-setup) SKIP_SETUP=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            REPO_URL="$arg" ;;
  esac
done
```

  `usage()` prints the three lines: `Usage: ./install.sh [--skip-setup] [--dry-run] [git-url]`,
  `  --skip-setup  do not run the onboarding wizard after installing`,
  `  --dry-run     write shims + PATH registration only (no python/pip/network)`.
- ps1: `param([string]$RepoUrl = ..., [switch]$SkipSetup, [switch]$DryRun)`.
- `set -euo pipefail` and `$ErrorActionPreference = "Stop"` stay.

### 2.2 ASCII banner (exact bytes, pure ASCII, printed first)

Embed via quoted heredoc in bash (`cat <<'BANNER'`) and single-quoted
here-string in ps1 (`@'...'@`) so backslashes survive verbatim:

```
 _   _   _   _   _   _   _____   _____   ____     ___    _____
| | | | | | | | | \ | | |_   _| | ____| |  _ \   / _ \  / ____|
| |_| | | | | | |  \| |   | |   |  _|   | |_) | | | | | \___ \
|  _  | | |_| | | |\  |   | |   | |___  |  _ <  | |_| |  ___) |
|_| |_|  \___/  |_| \_|   |_|   |_____| |_| \_\  \___/  |____/
  HunterOs Harness - evidence or nothing
```

followed by one blank line. In dry-run mode the first banner line is prefixed
with `[dry-run] ` (or the tagline line is printed as
`[dry-run] shims + PATH registration only — no install`). The rest of the
output uses the existing `step`/`ok`/`fail` (bash) and `Write-Step`/`Write-Ok`/
`Write-Fail` (ps1) helpers, unchanged.

### 2.3 Shims

POSIX — `$HOME/.hunteros/bin/` (created with `mkdir -p`, both files `chmod 755`):

`~/.hunteros/bin/hunter` (exact content):
```bash
#!/usr/bin/env bash
# HunterOs Harness shim (generated by install.sh) - wraps the venv entry point.
exec "$HOME/.hunteros/venv/bin/hunter" "$@"
```

`~/.hunteros/bin/hunt` (exact content):
```bash
#!/usr/bin/env bash
# HunterOs Harness shim (generated by install.sh) - wraps the venv entry point.
exec "$HOME/.hunteros/venv/bin/hunt" "$@"
```

Windows — `Join-Path $env:USERPROFILE ".hunteros\bin"` (the script uses
`$env:USERPROFILE`, never the automatic `$HOME`, so CI/dry-run sandboxing by
overriding the env var is exact and predictable):

`hunter.cmd` (exact content):
```bat
@echo off
rem HunterOs Harness shim (generated by install.ps1) - wraps the venv entry point.
"%USERPROFILE%\.hunteros\venv\Scripts\hunter.exe" %*
```

`hunt.cmd` (exact content): same but `hunt.exe`.

Notes:
- Shims are written unconditionally on every run (overwrite = refresh), even
  in dry-run, and even if the venv does not exist yet (they only take effect
  when the entry points exist).
- After a real (non-dry-run) install the installer must verify the venv entry
  points exist and `fail` otherwise: bash
  `[ -x "$VENV_DIR/bin/hunter" ] || fail "the 'hunter' entry point is missing — re-run the installer"`
  and the same for `bin/hunt` (message: "the 'hunt' entry point is missing —
  re-run the installer"); ps1 `Test-Path "$venvDir\Scripts\hunter.exe"` /
  `hunt.exe` with the same messages. This pins the pyproject `hunt` alias.

### 2.4 PATH registration (tagged block + dedupe)

bash — rc file selection: if `${SHELL}` basename ends with `zsh` → `"$HOME/.zshrc"`,
else `"$HOME/.bashrc"`. If the file does not exist, create it (mode 600 via
`umask 077` around creation, or `touch` + `chmod 600`). If it already contains
the literal marker `# >>> hunteros PATH >>>` (checked with `grep -qF`, inside
an `if` so `set -e` is safe) → skip with `ok "PATH already registered in <rc>"`;
else append the exact block:

```bash
# >>> hunteros PATH >>>
# Added by the HunterOs Harness installer (idempotent - do not edit between markers).
export PATH="$HOME/.hunteros/bin:$PATH"
# <<< hunteros PATH <<<
```

then `ok "PATH registered in <rc> — open a NEW shell or: source <rc>"`.

ps1 — profile path: `$profilePath = if ($env:HUNTEROS_PROFILE) { $env:HUNTEROS_PROFILE } else { $PROFILE }`.
If missing, create it (`New-Item -ItemType File -Path $profilePath -Force | Out-Null`).
If `Select-String -LiteralPath $profilePath -SimpleMatch '# >>> hunteros PATH >>>' -Quiet`
is true → skip with the same "already registered" wording; else append:

```powershell
# >>> hunteros PATH >>>
# Added by the HunterOs Harness installer (idempotent - do not edit between markers).
$env:PATH = "$env:USERPROFILE\.hunteros\bin;$env:PATH"
# <<< hunteros PATH <<<
```

`HUNTEROS_PROFILE` exists so CI/dry-runs (and users with unusual setups) can
redirect the write; it is documented in the script header comment.

### 2.5 iex-safety fix (install.ps1)

The canonical remote one-liner is `irm <url> | iex`, where `$PSScriptRoot` and
`$MyInvocation.MyCommand.Path` are both empty. Replace:

```powershell
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$localCheckout = Test-Path (Join-Path $scriptDir "pyproject.toml")
```

with:

```powershell
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
             elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
             else { $null }
$localCheckout = [bool]$scriptDir -and (Test-Path (Join-Path $scriptDir "pyproject.toml"))
```

Behavior under `iex` (no script path): `$localCheckout` is false → PyPI → git
fallback, exactly the remote-install case. install.sh already handles this
(`SCRIPT_DIR` only consulted when `pyproject.toml` exists; under
`curl | bash` `$0` is `bash` and the `cd "$(dirname "$0")"` yields `.` — keep,
but guard: `if [ -f "$SCRIPT_DIR/pyproject.toml" ]` stays as-is; a piped run
just won't see a checkout next to it).

### 2.6 Dry-run mode

`--dry-run` / `-DryRun`: skip python detection, venv, pip, install, import
verification, and the init handoff. Perform: banner (marked), shim dir +
shim writes, PATH registration (same dedupe), final printout. Exit 0.
Purpose: hermetic orchestrator verification of shim + PATH behavior with no
python/pip/network.

### 2.7 Auto-run `hunter init` handoff

After PATH registration, before the final printout:

bash:
```bash
if [ "$SKIP_SETUP" = "1" ]; then
    step "Skipping setup (--skip-setup)"
elif [ -n "${HUNTEROS_CONFIG:-}" ] || [ -f "$HOME/.hunteros/config.yaml" ]; then
    step "Config found — skipping the wizard (run 'hunter init' to reconfigure)"
elif [ -t 0 ]; then
    step "Launching the onboarding wizard"
    "$VENV_DIR/bin/hunter" init || true   # a declined/failed wizard never fails the install
else
    step "Non-interactive session — run 'hunter init' to configure your brain"
fi
```

ps1 equivalent using `[Console]::IsInputRedirected` in place of `[ -t 0 ]`,
`& "$venvDir\Scripts\hunter.exe" init` (wrap in `try { } catch { }`? No —
native exe; check `$LASTEXITCODE` and ignore), and the same three skip
messages ("Config found — skipping the wizard (run 'hunter init' to
reconfigure)" / "Non-interactive session — run 'hunter init' to configure
your brain" / "Skipping setup (-SkipSetup)").

Idempotent re-run semantics: venv reused + packages refreshed (pip reinstall),
shims overwritten, PATH deduped, wizard skipped when a config already exists.
A re-run is an **update**, never a re-prompt.

### 2.8 Final printout (exact copy, both scripts, after everything)

```
Installed. Next steps:

  1. Open a NEW shell (PATH updated), then run:
       hunter
     The onboarding wizard configures your brain in about a minute —
     then `hunter chat` talks to it. (`hunt` works anywhere `hunter` does.)
  2. Coming in a later release:
       hunter hunt <url> — one-command hunt on an authorized target.

Scan only systems you own or are explicitly authorized to test.
```

(The em-dash above is the only non-ASCII character; use `-` instead so the
whole installer stays byte-ASCII: "about a minute -". The disclaimer line
must be printed verbatim: `Scan only systems you own or are explicitly authorized to test.`)

---

## 3. Part B — `hunter init` v2 onboarding wizard

### 3.1 Routing (src/hunter/cli/main.py)

`init` command gains exactly one branch; everything else unchanged:

```python
if provider is None and not yes:
    from hunter.cli.init_wizard import run_onboarding
    code = run_onboarding(path=path, console=console, err_console=err_console)
else:
    # existing v1 path: run_init(path=path, provider=provider, yes=yes, ...)
```

Rationale: `--provider`/`--yes` keep the v1 contract the existing tests pin;
the interactive experience becomes v2. Deterministic (no tty sniffing), so
CliRunner tests can drive both.

### 3.2 New module surface (src/hunter/cli/init_wizard.py additions)

```python
__all__ += ["OnboardingAnswers", "onboarding_updates", "run_onboarding",
            "config_missing", "offer_onboarding", "DECLINED_ENV"]

DECLINED_ENV = "HUNTEROS_ONBOARD_DECLINED"

@dataclass
class OnboardingAnswers:
    mode: str = "auto"                 # "auto" | "advanced"
    tier: str = "basic"                # always written; v2 does NOT prompt tier
    provider: str = ""
    base_url: str = ""
    endpoint: str = ""                 # "chat" | "responses" | "" (empty = store nothing)
    key_env: str = ""
    key_inline: str = ""               # goes to keys.env, NEVER into config.yaml
    browser: bool = False
    role_models: dict[str, str] = field(default_factory=dict)  # tier -> model
    notes: list[str] = field(default_factory=list)

def onboarding_updates(a: OnboardingAnswers) -> dict[str, Any]:
    """Pure. The write_config fragment for v2 (see 3.5)."""

def run_onboarding(
    *,
    path: str | Path | None = None,
    console: Console | None = None,
    err_console: Console | None = None,
    ask: Callable[[str, str], str] | None = None,       # (prompt, default) -> str
    secret: Callable[[str], str] | None = None,          # (prompt) -> str
    ping_fn: Callable[..., Any] | None = None,           # same seam as v1 (ping_provider)
    probe_fn: Callable[..., str] | None = None,          # (base_url, api_key, timeout) -> "chat"|"responses"|""
    list_models_fn: Callable[..., list[str]] | None = None,  # (base_url, api_key, timeout) -> [ids]
    checks_fn: Callable[[], list] | None = None,         # doctor_core.collect_checks seam
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> int:
    """v2 wizard. Returns 0 on every normal terminal path (failures are notes);
    lets HunterError from write_config propagate (handle.py renders it)."""
```

Default seam implementations: `ask`/`secret` reuse the existing
`_default_ask(console)` / `_default_secret()` helpers (EOFError → default /
`""`); `ping_fn` → `ping_provider`; `probe_fn` → `hunter.llm.probe.detect_endpoint`;
`list_models_fn` → `hunter.llm.probe.list_models`; `checks_fn` →
`hunter.cli.doctor_core.collect_checks`.

`config_missing` / `offer_onboarding` are specified in §5.

### 3.3 Exact wizard UX (copy is normative; `step k/7` prefixes like v1)

Header (after the clobber guard, which behaves exactly like v1: existing
config → `ask("config already exists at {target} — overwrite it", "n")`;
decline → `kept {target} — pass --path <file> to write elsewhere`, return 0;
`run_onboarding` is only offered by the auto-trigger when no config exists,
so the guard fires mainly on explicit `hunter init` re-runs):

```
hunter init — onboarding wizard
config target: <target>
About 60 seconds. Writes <target> (+ keys.env only if you paste a key).
Your key is sent nowhere except the provider you pick.
```

**Step 1/7 — role mode**

```
How should models be assigned?
  1. Auto — one model for every role (fastest setup)
  2. Advanced — pick a model per role (planner / exploit / verify / utility)
mode [1]:
```
`"2"` or `"advanced"` → advanced; anything else → auto.

**Step 2/7 — provider** — identical rendering to v1 step 3 (numbered
`known_provider_names()` list, notes from the table, `custom` last, digits or
name accepted, unrecognized reply → note + first entry). `custom` additionally
prompts:
```
base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)
```
blank → note `custom provider skipped — no base URL given`, `provider = ""`
(wizard continues; config still gets `agent` block). Keyless known providers
(ollama, lmstudio, vllm) print `step 3/7 key: none needed — this provider is keyless`.

**Step 3/7 — key** (skipped for keyless / no-provider paths)

If `${KEY_ENV}` (the table's `key_env`, or `CUSTOM_API_KEY` for custom) is
already set in `environ`:
```
key: using $<KEY_ENV> from the environment — nothing is stored on disk
```
and `key_env` is recorded, no keys.env write. Otherwise:

```
key source for <name>:
  1. Paste the key now — stored in <keys_path>, never echoed, never in the config
  2. Set the env var <KEY_ENV> yourself (recommended for shared machines)
key [1]:
```
- Reply 1 (default): `secret(f"paste the {key_env} key (input hidden)")`.
  Non-empty → `key_inline = pasted`, `key_env = default name`
  (for custom: `ask("env var name for the key", "CUSTOM_API_KEY")` first).
  Empty → note `no key pasted — set $<KEY_ENV> before first use` + the v1
  `_print_export_lines` output.
- Reply 2: `ask("API key env var name", <table key_env or CUSTOM_API_KEY>)`
  (blank → keyless note) + `_print_export_lines(console, key_env)`.
- `key_env` empty → the provider block is keyless (base_url-only) exactly like v1.

**Step 4/7 — endpoint probe + models**

Endpoint probe runs only when `provider == "custom"` (user-supplied base_url):
```
probing <base_url> for the API shape...
  endpoint: chat  (POST {base}/chat/completions)     ← or: responses / undetermined
```
- probe_fn returns `"chat"|"responses"` → stored (`answers.endpoint`).
- `""` or raise → note `endpoint probe failed — storing no endpoint (the router will use the OpenAI chat API)`, nothing stored.
- The probe is called with the captured key value (inline paste, or env value,
  or `""` for keyless).

Models:
- Known provider: `planner model [table.default_model]` — in **auto** mode that
  single answer fills all four tiers; in **advanced** mode four prompts:
  `planner model [<default_model>]`, `exploit model [<planner answer>]`,
  `verify model [<cheap_model or planner>]`, `utility model [<cheap_model or planner>]`.
- Custom: call `list_models_fn(base_url, key, 10)`.
  - Non-empty list (sorted, filtered to non-empty ids):
    ```
    available models (GET {base}/models):
      1. <id>
      ...
      m. type a model id manually
    model [1]:
    ```
    digit in range → that id; `m`, blank, or out-of-range → `ask("model id", <first id>)`.
  - Empty list → note `model list failed — enter it manually` + the same
    `ask("model id", "")`-style manual prompt (default = table default for
    known, empty for custom).
- No provider → `step 4/7 model: (skipped — no provider configured)`.

**Step 5/7 — web automation**

```
Enable web automation (browser-driven hunting)? [y/N]
```
`y`/`yes` → `answers.browser = True` + note
`note: browser automation (the [browser] extra) ships in a later release — 'agent.browser: true' is stored now; nothing else changes yet`.
Anything else → False (no note). This is the **entire** interim behavior: the
flag is inert in M1 (the [browser] extra lands in M6).

**Step 6/7 — tools check**

```
step 6/7 tools:
  OK  python 3.13.7 on Windows
  OK  state-dir ... — 0 run(s)
  ...
```
Call `checks_fn()` (default `doctor_core.collect_checks()` — creates
`./.hunter/ledger.db` exactly like `hunter doctor`; documented side effect).
Render each row as `  <OK|FAIL|NOTE>  <label> <detail>` with the doctor's
status marks. Wrap the call in `try/except Exception` → on exception append
note `tools check failed: <type>: <exc>` and print it. Every row whose status
is `"fail"` is ALSO appended to notes (`tools check: <label> — <detail>`).
Never aborts.

**Write phase (before step 7):**

1. If `answers.key_inline` → `hunter.llm.keys.write_keys_env({key_env: key_inline}, env=env, home=home)`;
   HunterError from it → re-raise (classified, handle.py renders). Print
   `wrote <keys_path>` (path only, never contents).
2. `write_config(onboarding_updates(answers), target, env=env, home=home)`
   (unchanged writer — atomic, comment template preserved) → print `wrote <target>`.

**Step 7/7 — smoke test**

```
step 7/7 smoke test: dialing <provider>/<model> with a 1-token ping...
```
Skip conditions (each with a note, mirroring v1): no model →
`smoke test skipped — no model configured`; key declared (`key_env` set) but
neither env value nor inline key available → `smoke test skipped — <KEY_ENV> is not set`.
Otherwise call `ping_fn(provider, model, base_url, key_value, 15)` with the
identical try/except classification as v1 (HunterError → note
`smoke test unavailable: ...`; other Exception → note `smoke test failed: ...`;
ok → `  smoke test: OK (<n> ms)`; not ok → note `smoke test failed: <flat message>`).
The key value passed is `env.get(key_env, "") or key_inline` — the same
expression as v1.

**Done panel** (rich `Panel`, title `done`, subtitle `Evidence or Nothing`):

```
config:  <target>
keys:    <keys_path> (<KEY_ENV>) | $<KEY_ENV> | keyless
brain:   <provider> / <model>[ (endpoint: <endpoint>)] | none
tier:    basic
browser: off | on
next:
  hunter chat        — talk to your brain
  hunter demo        — first blood, no keys needed
  hunter doctor      — verify the environment
```
If `notes`, print them after the panel as v1 does (`notes:` + `  - ...`).
The LAST line of the command output, always, is:
```
Scan only systems you own or are explicitly authorized to test.
```
This line prints on every terminal path: success, clobber decline, all-notes
failure runs, EOF-driven default runs (adversarial item 6).

EOF behavior: every `ask` falls back to its default (mode auto, provider 1,
key paste empty, models default, browser no) — a fully non-interactive run
writes an `openai`-keyless-ish valid config and exits 0 with notes. It must
never crash and never write a key it did not receive.

### 3.4 `onboarding_updates` shape (pure, test-visible)

```python
def onboarding_updates(a: OnboardingAnswers) -> dict[str, Any]:
    updates: dict[str, Any] = {"agent": {"tier": a.tier, "browser": a.browser}}
    if a.provider:
        block: dict[str, Any] = {}
        if a.key_env:    block["key_env"] = a.key_env
        if a.base_url:   block["base_url"] = a.base_url
        if a.endpoint:   block["endpoint"] = a.endpoint
        updates["providers"] = {a.provider: block}
    if a.role_models:
        updates["model_tiers"] = {
            tier: {"provider": a.provider or "auto", "model": model}
            for tier, model in a.role_models.items()
        }
    return updates
```

Auto mode: `role_models = {t: model for t in TIERS}` (planner/exploit/verify/
utility all get the SAME model — "one model for ALL roles"). Advanced mode:
per-role answers. `write_config` deep-merges, so re-running the wizard
upgrades all four tiers and preserves unrelated keys (budget, fallbacks).

The pasted key is **never** in this fragment: `api_key` stays reserved for
explicit `hunter config provider add --api-key-stdin` flows.

### 3.5 Schema dependency

`onboarding_updates` emits `endpoint` and `browser`; the loader must accept
both — see §6 before implementing either half.

---

## 4. Part C — keys.env (new module `src/hunter/llm/keys.py`)

```python
__all__ = ["KEYS_ENV_FILENAME", "KEYS_ENV_ENVVAR", "keys_env_path",
           "parse_keys_env", "load_keys_env", "write_keys_env"]

KEYS_ENV_FILENAME = "keys.env"
KEYS_ENV_ENVVAR = "HUNTEROS_KEYS_FILE"
```

- `keys_env_path(*, env=None, home=None) -> Path` — `$HUNTEROS_KEYS_FILE` if
  set, else `home (default Path.home()) / .hunteros / keys.env`.
- `parse_keys_env(text: str) -> dict[str, str]` — line rules: strip; skip
  empty and `#`-prefixed; optional leading `export `; split on first `=`;
  key must match `[A-Za-z_][A-Za-z0-9_]*`; value stripped of ONE layer of
  matching single or double quotes; unescape `\"`, `\\`, `\$`, `` \` ``
  inside double quotes (inverse of the writer); malformed lines and bad keys
  are silently skipped; duplicate keys → last wins. Never raises.
- `write_keys_env(entries: Mapping[str, str], *, env=None, home=None) -> Path`
  — empty mapping → no-op, return the path without creating the file.
  Refuses when `$HUNTEROS_KEYS_FILE` points outside `home` (same
  containment rule as `resolve_config_target`, no `force` override):
  `HunterError(code="keys.refused", layer="config", message=..., hint=...)`.
  File format (header + `KEY="escaped-value"` lines):

  ```
  # HunterOs API keys — written by `hunter init`.
  # Loaded into the environment by the `hunter` CLI at startup (real env
  # vars win). POSIX perms 0600; on Windows the file inherits your user-profile
  # ACL. NEVER commit, copy, or paste this file anywhere.
  OPENROUTER_API_KEY="sk-..."
  ```
  Escaping: inside double quotes replace `\` → `\\`, `"` → `\"`, `$` → `\$`,
  `` ` `` → `` \` ``. Write atomically with the exact pattern of
  `write_config` (NamedTemporaryFile in the target directory, flush, fsync,
  close, `os.replace` with the bounded PermissionError retry). Then
  best-effort `os.chmod(path, 0o600)` wrapped in `try/except OSError` — on
  Windows chmod is a no-op; the file sits under the per-user profile whose
  ACL already restricts access to the user. **Chosen pragmatic Windows
  approach: os.chmod best-effort + documented ACL limitation; no os.open
  share-mode gymnastics.**
- `load_keys_env(*, env=None, home=None, target=None) -> dict[str, str]` —
  read `keys_env_path`; missing file or any `OSError` → `{}` (best-effort,
  never raises, never logs values). Inject each `k, v` with
  `(target or os.environ).setdefault(k, v)` — **real env vars always win**.
  Returns the dict of values actually injected.
- Startup wiring: the root callback in `main.py` calls `load_keys_env()`
  (lazy import, wrapped in nothing — it cannot raise) BEFORE the panel/offer,
  so every subcommand (`chat`, `config provider test`, scans) sees keys.env
  values. `resolve_key` semantics are unchanged: `key_env` env lookup
  (now including keys.env-injected values) → inline `api_key` → auth error.

---

## 5. Part D — auto-trigger (bare `hunter`, `hunter chat`)

In `init_wizard.py`:

```python
def config_missing(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> bool:
    """True when load_config would find no config file anywhere:
    find_config_path(...) is None OR the resolved path does not exist."""

def offer_onboarding(
    *,
    console: Console | None = None,
    err_console: Console | None = None,
    env: Mapping[str, str] | None = None,   # read-only decisions
    home: Path | None = None,
    ask: Callable[[str, str], str] | None = None,
    run: Callable[..., int] | None = None,  # default: run_onboarding
) -> bool:
    """Offer the wizard when no config exists. Returns True iff it ran."""
```

Behavior (normative order):
1. `env = os.environ` when not given. If `env.get(DECLINED_ENV)` is truthy →
   return False immediately (no prompt, no output).
2. If not `config_missing(env=env, home=home)` → return False silently.
3. Prompt via `ask` (default impl: `console.input` with EOFError → `"n"`):
   `no brain configured yet — run the setup wizard now? [Y/n]` (default `"y"`).
4. Answer yes → call `run(...)` (default `run_onboarding(console=console,
   err_console=err_console, home=home)`); return True.
5. Answer no (or EOF/any exception from the default ask) → print
   `skipped — run 'hunter init' anytime; you won't be asked again this session`,
   then **always** set `os.environ[DECLINED_ENV] = "1"` (process-local; the
   one-shot `hunter` process and the long-lived chat REPL each ask at most
   once), and return False.

Wiring:
- Root callback (`main.py::_root_callback`): after the welcome panel and
  still inside `if ctx.invoked_subcommand is None:` →
  `from hunter.cli.init_wizard import offer_onboarding; offer_onboarding(console=console)`.
  `--help` never reaches the callback (click prints help first), so the full
  help dump stays wizard-free.
- `chat` command: after setting `HUNTER_STATE_DIR`, before `run_repl` →
  `offer_onboarding(console=console)`. Decline does NOT abort: the REPL opens
  with its existing `model: (unset)` banner.

Suppression semantics (adversarial item 4): the flag is process env only,
never persisted, never read from disk; a NEW `hunter` invocation after a
decline is a new session and asks again — the "forever loop" being guarded
against is re-prompting within one process (chat REPL) and re-prompting after
EOF in scripted contexts.

---

## 6. Part E — schema changes (loader + writer + back-compat)

### 6.1 `providers.<name>.endpoint`

- `config.py`: `_PROVIDER_KEYS = ("key_env", "api_key", "base_url", "endpoint")`;
  `ProviderConfig.endpoint: str = ""`; in the providers loop:
  `endpoint=_as_str(block.get("endpoint"), f"providers.{name}.endpoint")`,
  then validate: `if endpoint not in ("", "chat", "responses")` →
  `config.value` error naming `providers.<name>.endpoint` and the two valid
  values in the hint.
- `writing.py::render_config`: after the `base_url` line,
  `if block.get("endpoint"): lines.append(f"    endpoint: {_scalar(block['endpoint'])}")`.
- Consumer contract: **nothing reads it in M1** (router still dials the
  OpenAI chat completions path via LiteLLM). The field exists so M2 can
  branch without another migration. Old configs (no `endpoint`) load as `""`
  and render without the line — byte-identical to today for old data.

### 6.2 `agent.browser`

- `config.py`: `_AGENT_KEYS = ("tier", "api_max_retries", "browser")`;
  `AgentConfig.browser: bool = False`; new helper
  `_as_bool(value, key)` — accepts Python bool (YAML `true`/`false`) or the
  strings `"true"`/`"false"` case-insensitively; anything else → `config.type`
  error naming `agent.browser`. Loader:
  `browser=_as_bool(agent_raw.get("browser", False), "agent.browser")`.
- `writing.py::render_config`: in the agent section append (after the
  `api_max_retries` line, keeping existing lines byte-identical):
  `lines.append(f"  browser: {_scalar(bool(agent.get('browser', False)))}")`
  — always emitted (`false` when unset) so the template is stable.
- `hunter config show` needs no change (it prints agent.tier etc.; extra
  fields are additive).

### 6.3 Migration / back-compat

- No file migration: both keys default (`""` / `False`) and old configs load
  unchanged. New keys are rejected for no one (they were `config.unknown_key`
  before M1 — that is the only behavior change, and it is additive).
- v1-written inline `api_key` configs keep loading; v2 never removes or reads
  them; `resolve_key` order (env → inline) is untouched.

---

## 7. Part F — probe module (new `src/hunter/llm/probe.py`)

```python
__all__ = ["detect_endpoint", "list_models"]

def detect_endpoint(base_url: str, api_key: str = "", timeout: float = 10.0,
                    *, client_factory: Callable[[], Any] | None = None) -> str:
    """POST {base}/chat/completions then {base}/responses with 1-token bodies.
    Returns "chat" | "responses" | "". NEVER raises, never includes the key
    in any returned data (it returns only the enum)."""

def list_models(base_url: str, api_key: str = "", timeout: float = 10.0,
                *, client_factory: Callable[[], Any] | None = None) -> list[str]:
    """GET {base}/models -> sorted, de-duplicated, non-empty data[].id list.
    [] on ANY failure. NEVER raises."""
```

Decision table for `detect_endpoint` (uses `httpx`, a core dep):
- POST `{base}/chat/completions`, headers `Content-Type: application/json`
  plus `Authorization: Bearer <key>` only when key non-empty, body
  `{"model": "probe", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}`.
  Status 200–499 except 404/405 → `"chat"` (auth/model errors still prove the
  route exists). 404/405 or transport/timeout error → try the next probe.
- POST `{base}/responses`, body
  `{"model": "probe", "input": "ping", "max_output_tokens": 1}` →
  same status logic → `"responses"`, else `""`.
- `client_factory` seam: tests inject
  `lambda: httpx.Client(transport=httpx.MockTransport(handler), timeout=...)`
  — fully offline. Default factory: `lambda: httpx.Client(timeout=timeout)`.

`list_models`: GET `{base}/models` with the same auth header; 200 → parse
`data[*].id` (ignore non-dict entries / non-string ids), sorted unique; any
non-200, parse failure, or exception → `[]`.

---

## 8. Part G — pyproject + docs

- `pyproject.toml`:
  ```toml
  [project.scripts]
  hunter = "hunter.cli.main:main"
  hunt = "hunter.cli.main:main"
  ```
- `README.md` — replace the first line of the Quick start block
  (`./install.sh ...`) with:
  ````markdown
  ```bash
  curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
  # Windows (PowerShell):
  powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
  ```
  ````
  plus one sentence: the installer registers `hunter` and `hunt` shims in
  `~/.hunteros/bin` and starts the onboarding wizard on first run.
- `QUICKSTART.md` — section 1 "Install (~30s)" gets the same two one-liners
  above the checkout instructions, and the troubleshooting entry
  `hunter: command not found` gains: "or use the shim path
  `~/.hunteros/bin/hunter` (Windows: `%USERPROFILE%\.hunteros\bin\hunter.cmd`),
  or re-run the installer which registers `~/.hunteros/bin` on your PATH".
- `docs/FIRST-RUN.md` — after implementation, re-capture: §1 installer
  transcript (banner, shim + PATH lines, final printout), §4 replaced by the
  v2 wizard transcript (keep a note that `--provider x --yes` still runs the
  classic flow), and the "Where things live" table gains
  `Keys | ~/.hunteros/keys.env (0600; env vars win)`. The doc's "actual
  rendered output" claim requires real captured output — BUILDER captures,
  AUDITOR does not test prose.

---

## 9. Existing contracts that must NOT break (builder's red lines)

1. `tests/test_cli_init.py` — all v1 `run_init` tests: signatures, step
   copy, exit codes, key-never-echoed, inline `api_key` writes, exit 2 for
   `--provider custom` without base URL and unknown providers.
2. `tests/test_cli_init.py::test_bare_hunter_shows_welcome_panel_and_writes_no_config`
   — welcome panel strings, exit 0, no config written. (The offer may print
   AFTER the panel; with `HUNTEROS_CONFIG` sandboxed the offer fires and EOF
   declines it — still exit 0, still no config.)
3. `tests/test_llm_config.py` — loader semantics; only additive changes
   (two new accepted keys + their validation).
4. `tests/test_cli_providers.py::…render_config({})` roundtrip — the
   template may gain lines but must stay loadable.
5. `tests/test_chat_repl.py` — `run_repl` signature and behavior unchanged
   (the offer lives in the `chat` command, not the REPL).
6. `hunter llm ping` seam (`litellm_module`) untouched.
7. No test may touch the network (CI is ubuntu/windows × 3.11/3.13);
   `$HUNTEROS_CONFIG`/`HOME`/`USERPROFILE` sandboxing conventions are
   mandatory in all new tests (copy `_cli_env` from `tests/test_cli_init.py`).

---

## 10. Data flow (one glance)

```
run_onboarding
  ├─ ask/secret ────────────────► OnboardingAnswers
  ├─ probe_fn(base_url, key) ───► answers.endpoint  ("chat"|"responses"|"")
  ├─ list_models_fn(base_url) ─► answers.role_models
  ├─ write_keys_env({key_env: key_inline})          (only when pasted)
  ├─ write_config(onboarding_updates(answers))      (atomic, template)
  ├─ ping_fn(provider, model, base_url, key, 15)    (smoke test, notes on fail)
  └─ done panel + disclaimer
bare `hunter` / `hunter chat`
  └─ offer_onboarding ── y ─► run_onboarding ─┐
                       └ n ─► DECLINED_ENV=1 ─┴─ continue
```

---

## 11. ACCEPTANCE CRITERIA

### (a) pytest-testable Python behavior — each maps to exactly one test

- **A1** Auto-mode onboarding writes a loadable config: with scripted
  answers (mode auto, provider `groq`, env-var key source, table-default
  model), the written file loads via `load_config`; all four `model_tiers`
  entries have `provider="groq"` and the table's `default_model`;
  `agent.tier == "basic"`; `agent.browser is False`.
- **A2** Pasted key lands in keys.env, never in config.yaml: with
  `secret` returning a sentinel, the written YAML contains no `api_key`,
  keys.env exists in the sandbox home containing `<KEY_ENV>="<sentinel>"`,
  and the provider block carries `key_env`.
- **A3** Advanced mode assigns models per role: scripted per-role answers
  produce `model_tiers.planner/exploit/verify/utility` models exactly as
  answered (planner answer reused as the exploit default when the reply is
  blank; verify/utility default to the cheap model when blank).
- **A4** Custom provider endpoint probe result is stored: `probe_fn` →
  `"chat"` (and a second test run → `"responses"`) yields
  `providers.custom.endpoint == "chat"` (resp. `"responses"`) in the loaded
  config.
- **A5** Endpoint probe failure is a note, stores nothing: `probe_fn`
  returning `""` (and a second run raising `RuntimeError`) → exit 0, output
  contains `endpoint probe failed`, loaded config has empty `endpoint`.
- **A6** Model auto-list is offered and used for custom providers:
  `list_models_fn` returns a list → the numbered menu prints, the scripted
  digit pick becomes every tier's model (auto mode).
- **A7** Model auto-list failure falls back to manual input:
  `list_models_fn` returns `[]` → output contains
  `model list failed`, and the manually scripted id lands in
  `model_tiers.planner.model`.
- **A8** Browser option writes `agent.browser: true` plus the interim note:
  answering `y` → loaded config `agent.browser is True` and output contains
  `ships in a later release`; answering default (blank) → `agent.browser is False`
  and the note absent.
- **A9** Smoke-ping failure is a note with exit 0: `ping_fn` raising →
  exit 0, output contains `smoke test failed` and `wrote`.
- **A10** The pasted key is never echoed: with the sentinel key pasted, the
  sentinel appears in NEITHER stdout nor stderr captures (mirrors the v1
  test, plus keys.env content is never printed — assert the sentinel is
  absent from output while present in the file).
- **A11** The scope disclaimer prints on every terminal path: for (i) a
  successful auto run, (ii) a smoke-failure run, (iii) a clobber-decline run,
  and (iv) an EOF-driven default run — output ends with
  `Scan only systems you own or are explicitly authorized to test.`
- **A12** Clobber guard in v2 matches v1: pre-existing config + decline →
  `kept` printed, exit 0, file bytes untouched.
- **A13** `init` CLI routing: with no `--provider`/`--yes`, the command
  calls `run_onboarding` (monkeypatched sentinel); with `--provider groq
  --yes` it still calls `run_init` (v1).
- **A14** Bare `hunter` offer, accept: no config in sandbox + input `y` +
  `run_onboarding` monkeypatched → output contains
  `no brain configured yet`, the sentinel was invoked once, exit 0.
- **A15** Bare `hunter` offer, decline: input `n` → output contains
  `won't be asked again`, exit 0, no config written, welcome panel still
  rendered, and `HUNTEROS_ONBOARD_DECLINED` set in `os.environ` afterwards.
- **A16** Offer suppressed by the declined flag: preset
  `HUNTEROS_ONBOARD_DECLINED=1` → no offer line, no prompt, exit 0.
- **A17** Offer suppressed when a config exists: sandbox config file
  present → no offer line.
- **A18** `hunter chat` offer: no config + input `n` then EOF → output
  contains both the offer line and the chat banner (`HUNTEROS — Evidence or
  Nothing`), exit 0; the offer text appears exactly once.
- **A19** keys.env roundtrip: `write_keys_env` then `parse_keys_env` on the
  file bytes returns the original mapping (quoting/escaping survives:
  values with spaces, double quotes, `$`, backslash).
- **A20** keys.env POSIX perms: after `write_keys_env` the file mode is
  `0o600` (skipif Windows).
- **A21** Env precedence: `load_keys_env` with `target` containing a
  pre-set var does not overwrite it; missing vars are injected and returned.
- **A22** keys.env path resolution: `HUNTEROS_KEYS_FILE` overrides;
  default is `<home>/.hunteros/keys.env`.
- **A23** keys.env write refuses out-of-home targets:
  `HUNTEROS_KEYS_FILE` outside `home` → `HunterError` (layer `config`).
- **A24** Parser tolerance: `export ` prefixes, comments, blank lines,
  malformed lines (no `=`, bad key chars) are handled — malformed skipped,
  valid ones captured, no exception.
- **A25** `load_keys_env` on a missing file returns `{}` and creates
  nothing.
- **A26** CLI loads keys.env: sandbox home with keys.env defining a var,
  config referencing it as `key_env` → after invoking `hunter version`
  through `CliRunner`, the var is present in `os.environ` and `resolve_key`
  resolves it end-to-end.
- **A27** `providers.<n>.endpoint` accepted + roundtrips: YAML with
  `endpoint: chat` loads as `"chat"`; `render_config` emits the
  `endpoint:` line; re-loading the rendered text yields the same value.
- **A28** Invalid endpoint rejected: `endpoint: grpc` → `HunterError`
  code `config.value` naming `providers.<name>.endpoint`.
- **A29** `agent.browser` loader rules: `true` → True; `"false"` → False;
  absent → False; `1` → `config.type` error naming `agent.browser`.
- **A30** Renderer emits the browser line: `render_config({})` contains
  `browser: false`; with browser true it contains `browser: true`; both
  render outputs load successfully.
- **A31** Back-compat: a full v0.3-style config (no endpoint/browser)
  loads with `endpoint == ""` and `browser is False`.
- **A32** `onboarding_updates` shape: the exact dict for (i) auto answers
  (all four tiers + agent block + provider block with endpoint) and (ii)
  no-provider answers (`agent` only) — pure, no file I/O.
- **A33** `detect_endpoint` decision table with `httpx.MockTransport`
  (offline): chat-200 → `"chat"`; chat-404 + responses-200 → `"responses"`;
  both 404 → `""`; transport error → `""`; and the Authorization header is
  sent only when a key is passed.
- **A34** `list_models` with MockTransport: 200 with ids → sorted unique
  non-empty ids; 404 → `[]`; malformed JSON → `[]`.
- **A35** pyproject declares `hunt`: `tomllib` parses `pyproject.toml`;
  `[project.scripts]["hunt"] == "hunter.cli.main:main"` and `hunter` keeps
  its existing value.
- **A36** Installer static contract (reads `install.sh`/`install.ps1` from
  the repo root, no execution): both contain the default repo URL
  `https://github.com/zaaaxx11/HunterOsHarness.git` and honor
  `INSTALL_REPO_URL`; the banner block is present and every banner byte is
  ASCII (`ord < 128`); shim targets `bin/hunter`, `bin/hunt`, `hunter.cmd`,
  `hunt.cmd` all appear; `# >>> hunteros PATH >>>` + dedupe mechanisms
  (`grep -qF` / `Select-String -SimpleMatch`) appear; `--skip-setup`,
  `--dry-run`, `-SkipSetup`, `-DryRun` appear; bash checks `[ -t 0 ]` and ps1
  checks `[Console]::IsInputRedirected`; both contain
  `Scan only systems you own or are explicitly authorized to test.`.
- **A37** Docs one-liners: `README.md` and `QUICKSTART.md` each contain
  both exact one-liner commands (the curl line and the
  `irm ... install.ps1 | iex` line against
  `raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/`);
  `docs/FIRST-RUN.md` mentions `~/.hunteros/bin`.

### (b) Script-level checks — verified by the orchestrator (not pytest)

- **S1** `bash -n install.sh` exits 0.
- **S2** PowerShell parse (Git Bash on Windows):
  `powershell -NoProfile -Command "$e=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path install.ps1),[ref]$null,[ref]$e); if ($e -and $e.Count){ $e | ForEach-Object { $_.Message }; exit 1 } else { 'install.ps1 parses clean' }"`
  → prints `install.ps1 parses clean`, exit 0.
- **S3** bash dry-run: `HOME=$(mktemp -d) bash install.sh --dry-run` →
  exit 0; `$HOME/.hunteros/bin/hunter` and `hunt` exist, are executable,
  and contain the exact `exec "$HOME/.hunteros/venv/bin/hunter"` /
  `.../hunt` lines; the selected rc file contains the tagged PATH block;
  stdout contains the banner tagline and the final two next steps.
- **S4** bash dry-run idempotency: run S3 twice → the marker
  `# >>> hunteros PATH >>>` appears exactly once in the rc file.
- **S5** bash dry-run `--skip-setup --dry-run` (flag order both ways) →
  exit 0.
- **S6** PowerShell dry-run: with `$env:USERPROFILE` and
  `$env:HUNTEROS_PROFILE` pointed into a temp dir,
  `powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -DryRun`
  → exit 0; `<tmp>\.hunteros\bin\hunter.cmd` and `hunt.cmd` exist with the
  exact `%USERPROFILE%\...hunter.exe` / `hunt.exe` lines; the
  `HUNTEROS_PROFILE` file contains the tagged PATH block.
- **S7** PowerShell dry-run idempotency: run S6 twice → marker appears
  exactly once.
- **S8** PowerShell dry-run `-SkipSetup -DryRun` → exit 0.

---

## 12. ADVERSARIAL matrix (risk → design answer → where tested)

| # | Risk | Design answer | Test |
| --- | --- | --- | --- |
| 1 | Config corrupt mid-write / crash leaves partial config | `write_config` unchanged (temp + `os.replace`, bounded retry); keys.env uses the same atomic pattern and is written BEFORE config; a crash can leave keys-without-config (harmless, next wizard run heals); nothing else is incremental | existing writer tests + A2/A9 |
| 2 | Key leaked into logs/output | The sentinel-echo test (A10) covers stdout+stderr; `detect_endpoint`/`list_models` never return or print the key (A33/A34 return enums/lists only); keys.env contents are never printed by the wizard (only the path); the ping/`litellm` classifier redaction is already tested upstream | A10, A33, A34 |
| 3 | Wizard crash mid-flow | All prompts precede all writes; `write_config`/`write_keys_env` failures are classified `HunterError`s rendered by `handle.py` (no traceback); smoke ping and tools check run AFTER the write and can only add notes | A9, §3.3 |
| 4 | Auto-trigger loop (decline re-prompts forever) | `HUNTEROS_ONBOARD_DECLINED` process env set on decline AND on EOF; chat REPL asks at most once per process; the flag is never persisted, so a fresh session may offer again by design | A15, A16, A18 |
| 5 | PATH registration idempotency | Tagged markers + `grep -qF` / `Select-String -SimpleMatch` dedupe; shims are overwrite-safe (idempotent by rewrite) | S4, S7, A36 |
| 6 | Scope disclaimer not shown on some path | Disclaimer is the unconditional last line of (i) both installers' final printout and (ii) every `run_onboarding` terminal path | A11, A36 |
| 7 | keys.env parsed as shell / poisoned by malformed lines | Never sourced/executed — parser-only; malformed lines skipped; quotes escaped round-trip | A19, A24 |
| 8 | keys.env world-readable | POSIX `0600` (asserted); Windows: chmod no-op + profile-ACL limitation documented in the file header; env-var route remains the recommended path for shared machines | A20, §4 |
| 9 | Env var clobbered by keys.env | `setdefault` injection — real env always wins | A21 |
| 10 | Stray `$HUNTEROS_KEYS_FILE` aiming writes outside home | Same containment refusal as `resolve_config_target` | A23 |
| 11 | Endpoint probe against a hostile/slow URL | Bounded 10s timeout, no retries, returns only `"chat"|"responses"|""`, body never echoed | A33 |
| 12 | Auto-list returns garbage (empty ids, dupes, non-strings) | Filter + sort + dedupe; empty result → manual fallback note | A7, A34 |
| 13 | New schema keys break old files / old loaders | Both keys are additive with defaults; old configs load byte-identically; renderer only ADDS lines | A27–A31 |
| 14 | Offer breaks `--help` / subcommands | Offer runs only in the bare-`hunter` branch of the root callback and inside `chat`; click handles `--help` before the callback | A13–A18, §9.2 |

---

## 13. TEST PLAN (auditor implements verbatim)

| File | Test name | Asserts |
| --- | --- | --- |
| `tests/test_cli_init_v2.py` | `test_onboarding_auto_mode_writes_all_four_tiers` | A1 |
| `tests/test_cli_init_v2.py` | `test_onboarding_pasted_key_goes_to_keys_env_not_config` | A2 |
| `tests/test_cli_init_v2.py` | `test_onboarding_advanced_mode_per_role_models` | A3 |
| `tests/test_cli_init_v2.py` | `test_onboarding_custom_endpoint_probe_stores_chat_and_responses` | A4 (both values; may be one test with two `run_onboarding` calls) |
| `tests/test_cli_init_v2.py` | `test_onboarding_endpoint_probe_failure_is_note_and_stores_nothing` | A5 |
| `tests/test_cli_init_v2.py` | `test_onboarding_model_autolist_menu_used_for_custom` | A6 |
| `tests/test_cli_init_v2.py` | `test_onboarding_model_autolist_failure_falls_back_to_manual` | A7 |
| `tests/test_cli_init_v2.py` | `test_onboarding_browser_true_writes_flag_and_note` | A8 |
| `tests/test_cli_init_v2.py` | `test_onboarding_smoke_ping_failure_is_note_exit_0` | A9 |
| `tests/test_cli_init_v2.py` | `test_onboarding_key_is_never_echoed` | A10 |
| `tests/test_cli_init_v2.py` | `test_onboarding_disclaimer_on_every_terminal_path` | A11 |
| `tests/test_cli_init_v2.py` | `test_onboarding_decline_overwrite_keeps_config` | A12 |
| `tests/test_cli_init_v2.py` | `test_init_command_routes_v2_interactive_v1_flagged` | A13 |
| `tests/test_cli_init_v2.py` | `test_bare_hunter_offer_accept_runs_wizard` | A14 |
| `tests/test_cli_init_v2.py` | `test_bare_hunter_offer_decline_sets_flag_once` | A15 |
| `tests/test_cli_init_v2.py` | `test_offer_suppressed_by_declined_env` | A16 |
| `tests/test_cli_init_v2.py` | `test_offer_suppressed_when_config_exists` | A17 |
| `tests/test_cli_init_v2.py` | `test_chat_offer_decline_then_repl_banner` | A18 |
| `tests/test_llm_keys.py` | `test_write_and_parse_keys_env_roundtrip` | A19 |
| `tests/test_llm_keys.py` | `test_write_keys_env_posix_mode_0600` | A20 (`@pytest.mark.skipif(os.name == "nt", ...)`) |
| `tests/test_llm_keys.py` | `test_load_keys_env_env_wins_setdefault` | A21 |
| `tests/test_llm_keys.py` | `test_keys_env_path_env_override_and_default` | A22 |
| `tests/test_llm_keys.py` | `test_write_keys_env_refuses_outside_home` | A23 |
| `tests/test_llm_keys.py` | `test_parse_keys_env_tolerates_malformed_lines` | A24 |
| `tests/test_llm_keys.py` | `test_load_keys_env_missing_file_is_noop` | A25 |
| `tests/test_llm_keys.py` | `test_cli_startup_loads_keys_env_and_resolve_key_sees_it` | A26 |
| `tests/test_llm_config_m1.py` | `test_provider_endpoint_roundtrip_through_render` | A27 |
| `tests/test_llm_config_m1.py` | `test_provider_endpoint_invalid_rejected` | A28 |
| `tests/test_llm_config_m1.py` | `test_agent_browser_loader_rules` | A29 |
| `tests/test_llm_config_m1.py` | `test_render_config_browser_line_and_roundtrip` | A30 |
| `tests/test_llm_config_m1.py` | `test_v03_config_without_new_keys_loads` | A31 |
| `tests/test_cli_init_v2.py` | `test_onboarding_updates_shape_auto_and_no_provider` | A32 |
| `tests/test_llm_probe.py` | `test_detect_endpoint_decision_table_mock_transport` | A33 |
| `tests/test_llm_probe.py` | `test_list_models_mock_transport_and_garbage` | A34 |
| `tests/test_installer_static.py` | `test_pyproject_declares_hunt_script` | A35 |
| `tests/test_installer_static.py` | `test_installer_static_contract` | A36 |
| `tests/test_installer_static.py` | `test_docs_one_liner_urls` | A37 |

Conventions for the auditor: copy `_string_console` and `_cli_env` from
`tests/test_cli_init.py`; script wizard answers with needle-matching `ask`
functions (most-specific needle first) exactly like
`test_key_is_never_echoed_but_written_inline`; never let a seam hit the
network (`probe_fn`/`list_models_fn`/`ping_fn` injected, or
`httpx.MockTransport` for the two probe-module tests). Additional hygiene
rules (env leakage between tests): every test in the new files extends its
setup with `monkeypatch.delenv("HUNTEROS_ONBOARD_DECLINED", raising=False)`
and `monkeypatch.delenv("HUNTEROS_KEYS_FILE", raising=False)`; CLI-level
routing tests additionally `monkeypatch.delenv` the provider key vars they
could touch (e.g. `GROQ_API_KEY`, `OPENAI_API_KEY`) so v1's live-test branch
skips; the A26 test deletes its keys.env-defined var from `os.environ` via
monkeypatch cleanup after the assertion.

---

## 14. Verify commands (Windows dev reality + CI)

```bash
# Python (repo venv):
.venv/Scripts/python -m pytest tests/test_llm_keys.py tests/test_llm_probe.py \
  tests/test_llm_config_m1.py tests/test_cli_init_v2.py tests/test_installer_static.py -q
.venv/Scripts/python -m pytest -q          # full suite: 601 existing + ~37 new must pass
.venv/Scripts/python -m ruff check src tests

# Installers:
bash -n install.sh                         # S1
powershell -NoProfile -Command "$e=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path install.ps1),[ref]$null,[ref]$e); if ($e -and $e.Count){ $e | ForEach-Object { $_.Message }; exit 1 } else { 'install.ps1 parses clean' }"   # S2

# Dry runs (S3–S8): see §11(b) — each is a single shell command with temp dirs.
```

CI (ubuntu/windows × 3.11/3.13) runs ruff + pytest only; S1–S8 are
orchestrator checks and must also pass locally on the Windows dev box.

---

## 15. Builder order (suggested)

1. Schema (§6) + its tests (A27–A31) — everything else depends on it.
2. `probe.py` (§7) + tests (A33–A34).
3. `keys.py` (§4) + tests (A19–A26).
4. Wizard v2 (§3) + tests (A1–A13).
5. Auto-trigger (§5) + tests (A14–A18).
6. pyproject `hunt` (A35) + installers (§2) + static tests (A36–A37) +
   orchestrator checks (S1–S8).
7. Docs (§8) — capture real transcripts last.
