# M4 — `hunter update` & background version check (v0.4)

**Goal:** the polite update loop used by Hermes/Strix — the CLI checks for a
newer release at most once a day in the background, prints a one-line notice
AFTER the command output (never mid-REPL, never into `--json` stdout), and
`hunter update` detects how the harness was installed and runs the matching
upgrade (or prints the exact manual command).

**Design status:** final for M4. AUDITOR writes the failing tests in
§10/§12 first; BUILDER implements until green. Every acceptance criterion is
mechanically checkable and none requires live network (MockTransport +
injected seams only).

---

## 0. Non-goals (M4)

- No self-restart/exec of the running process; the new version is picked up
  by the next `hunter` invocation.
- No pre-release/beta tags: `parse_version` accepts dot-separated integers
  only (`v0.4.0` → `(0, 4, 0)`; `0.4.0-beta1` is malformed → treated as a
  failed fetch).
- No `--check`-only flag, no rollback, no version pinning.
- No config-file surface (no new key in `config.py` — M2-owned, forbidden).
  The GitHub→PyPI fallback is automatic; justification in §3.4.
- No installer changes: `hunter update` RE-RUNS the existing
  `install.sh`/`install.ps1` with the flags M1 already shipped
  (`--skip-setup` / `-SkipSetup`).
- No background auto-install: the background path only ever prints a notice.
- No telemetry, no phoning home beyond the two documented GETs.

---

## 1. Current-state map (what exists, what changes)

| File | Today | M4 change |
| --- | --- | --- |
| `src/hunter/cli/update_core.py` | — | **new**: version check + 24h cache + background thread + install-method table + install plans + migration-notes stub |
| `src/hunter/cli/main.py` | root callback loads keys.env; commands: version, init, doctor, demo, scan, report, runs, findings, retro, skills, tui, chat, gateway, config(+provider), verify | **additive only**: root callback gains TWO lines (spawn check + `ctx.call_on_close(emit_notice)`); new `@app.command update [--yes]` (name collision-free — `provider` is a separate top-level group from M2) |
| `tests/conftest.py` | sys.path bootstrap only | **additive only**: one autouse fixture setting `HUNTEROS_NO_UPDATE_CHECK=1` (belt) — the check core also self-gates on `PYTEST_CURRENT_TEST` (braces) |
| `src/hunter/llm/probe.py` | `client_factory` seam, never-raise doctrine | **unchanged** (pattern reused) |
| `src/hunter/llm/keys.py` | `_atomic_write` (temp+fsync+`os.replace`+bounded retry) | **unchanged** (pattern reused) |
| `src/hunter/llm/config.py`, `writing.py`, `router*.py` | M2-owned | **untouched** (`config_example_yaml()`/`resolve_config_target()` are only CALLED) |
| `install.sh`, `install.ps1` | `--skip-setup`/`-SkipSetup`, idempotent re-run = update | **untouched** |
| `README.md`, `QUICKSTART.md`, `docs/FIRST-RUN.md` | no update story | "Updating" sections + FIRST-RUN note |

Tests live in `tests/` (flat). Conventions observed: `CliRunner`, string
`rich.Console(file=io.StringIO())` capture, `$HUNTEROS_CONFIG` +
`HOME`/`USERPROFILE` monkeypatched to `tmp_path`, injectable seams, zero
network, `test_cli_doctor.py` autouse `_hermetic` env fixture style.

---

## 2. Environment findings (verified by reading code/docs — no network hit)

1. **probe.py seam (read):** `client_factory: Callable[[], Any] | None` with
   default `lambda: httpx.Client(timeout=...)`; every failure collapses to a
   sentinel (`""`/`[]`), no retries. `update_core` mirrors this exactly:
   `client_factory` seam + "any error → silent no-op".
2. **keys.py atomic write (read):** NamedTemporaryFile in the target
   directory, flush, `os.fsync`, `os.replace` with a 5-attempt bounded
   `PermissionError` retry (`0.01s * (n+1)` — Windows AV/reader locks). The
   cache write reuses this pattern as a **best-effort JSON variant** that
   swallows every exception (the cache is disposable; a failed write must
   never surface).
3. **Version source (read):** `cli/main.py::_version()` =
   `importlib.metadata.version("hunteros-harness")` → fallback
   `hunter.__version__` (`"0.3.1"`; pyproject in sync). `update_core`
   carries its own `_current_version()` with the identical 3-line fallback —
   `_version()` itself stays untouched (avoids a main↔update_core import
   cycle at module scope). Tests inject `current_version=` explicitly.
4. **GitHub rate-limit reality (documented, per
   [GitHub REST rate-limit docs](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)):**
   unauthenticated `api.github.com` calls are capped at **60 requests/hour
   per IP**; when exhausted the API answers **HTTP 403** with a JSON
   `{"message": "API rate limit exceeded..."}` body and
   `X-RateLimit-Remaining: 0`. Shared CI/office IPs exhaust this quickly, so
   403 is a *designed-for* outcome, not an edge: any non-200 (esp. 403),
   transport error, or malformed payload silently falls back to the PyPI
   JSON API (`pypi.org/pypi/hunteros-harness/json` — keyless, no published
   rate limit, `{"info": {"version": "..."}}`).
5. **click/typer control flow (read `handle.py`):** `run_app` drives
   `app_command.main(standalone_mode=False)`; click wraps invoke in
   `with self.make_context(...) as ctx`, so the ROOT context's `close()` —
   and therefore any `ctx.call_on_close` callback — runs **after the
   subcommand's output** (child contexts close first) and even on the
   `typer.Exit` unwinding path. `CliRunner` invokes the same main() and
   observes the close hook, which a `main()`-level hook would NOT (CliRunner
   bypasses `hunter.cli.main:main`). Consequences, accepted:
   - argument-parse errors raise *before* the callback → no thread, no notice;
   - backstop-rendered escapes (ClickException/HunterError at `handle.py`)
     render *after* the close hook → the notice may precede the error line
     on stderr for failed commands (harmless, both are stderr advisory).
6. **rich Console stream capture (read):** `Console(stderr=True)` with no
   explicit file resolves `sys.stderr` at print time, so `err_console`
   output is visible to `CliRunner(mix_stderr=False)` — the stream-separation
   test is real, not mocked.
7. **Platform (read/known):** httpx is already a core dependency
   (`httpx>=0.27`) — no new deps. Dev box: Git Bash + `powershell` both
   available (needed only by the *real* installer update path, never by
   tests). `Path.home()` honors `USERPROFILE` on Windows and `HOME` on
   POSIX — the repo's `_cli_env`-style sandbox (both vars → `tmp_path`)
   makes `<home>/.hunteros/update-check.json` land in the sandbox on every
   OS.

---

## 3. Part A — the version check (`update_core.check_for_newer_version`)

### 3.1 Types and constants

```python
__all__ = [
    "CheckResult", "InstallPlan", "QUIET_COMMANDS", "OPT_OUT_ENV",
    "check_for_newer_version", "start_background_check", "pop_pending_notice",
    "emit_notice", "reset", "detect_install_method", "classify_install",
    "build_install_plan", "execute_plan", "run_update",
    "migration_notes", "example_schema", "parse_version",
]

GITHUB_RELEASES_URL = "https://api.github.com/repos/zaaaxx11/HunterOsHarness/releases/latest"
PYPI_JSON_URL       = "https://pypi.org/pypi/hunteros-harness/json"
RAW_INSTALL_SH      = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh"
RAW_INSTALL_PS1     = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1"

CHECK_TIMEOUT   = 1.5      # seconds, per HTTP request
CACHE_TTL       = 86400.0  # 24h
CACHE_FILENAME  = "update-check.json"
OPT_OUT_ENV     = "HUNTEROS_NO_UPDATE_CHECK"
_CI_ENV_VARS    = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI")
QUIET_COMMANDS  = frozenset({"chat", "tui", "gateway"})   # long-lived surfaces

@dataclass(frozen=True)
class CheckResult:
    latest: str = ""            # normalized ("0.4.0"); "" when the check failed
    current: str = ""
    source: str = ""            # "github" | "pypi" | "cache"
    update_available: bool = False
    error: str = ""             # short reason when latest == ""
```

### 3.2 Pure helpers

- `parse_version(tag: str) -> tuple[int, ...] | None` — strip whitespace and
  ONE leading `v`/`V`; split on `.`; every component must be all-digits and
  the first non-empty → tuple of ints; else `None`.
- `_newer(a, b) -> bool` — zero-pad both tuples to equal length; strict `>`.
- `_truthy(value)` — `value.strip().lower()` not in `("", "0", "false", "no")`.

### 3.3 Check flow (normative order)

```python
def check_for_newer_version(force=False, *, environ=None, home=None,
                            now_fn=None, client_factory=None,
                            current_version=None) -> CheckResult:
```

1. `current = current_version or _current_version()`.
2. **Cache** (unless `force`): read `<home>/.hunteros/update-check.json`
   (`home = Path.home()` default). Valid only when: JSON dict with numeric
   `checked_at`, string `latest`, `0 <= now - checked_at < CACHE_TTL`.
   Fresh hit → `CheckResult(latest=cached.latest, current, source="cache",
   update_available=_newer(parse(cached.latest), parse(current)))` — the
   comparison is ALWAYS recomputed against the *running* version, never
   trusted from the file. Corrupt/missing/stale cache → continue. Never
   raises.
3. **Network — GitHub first:** GET `GITHUB_RELEASES_URL`, header
   `Accept: application/vnd.github+json`, `timeout=CHECK_TIMEOUT`, via
   `client_factory` (default `lambda: httpx.Client(timeout=CHECK_TIMEOUT)`).
   200 → JSON dict → `tag_name` string → `parse_version` → success
   (`source="github"`). Any non-200 (esp. **403 rate limit**), transport
   error, or malformed payload → **silent fallback** to PyPI.
4. **PyPI fallback:** GET `PYPI_JSON_URL`, same timeout/seam; 200 → dict →
   `info` dict → `version` string → success (`source="pypi"`). Any failure
   here → `CheckResult(current=current, error="unreachable")` — **no cache
   write** (the next invocation retries).
5. **Cache write** (best-effort, never raises): on a successful fetch only,
   atomically write `{"checked_at": now, "latest": <normalized>,
   "current": current, "source": source}` using the keys.py `_atomic_write`
   pattern wrapped in `try/except Exception`.
6. Return `CheckResult(latest, current, source,
   update_available=_newer(...))`.

Rules:

- **Any error is a silent no-op.** The function never raises, never logs,
  never prints. Offline / 403 / malformed → `error` set, `latest == ""`.
- **Downgrade ignored:** `latest <= current` → `update_available=False`
  (a locally newer dev build is "up to date"). The cache is still written.
- **`force=True` semantics:** bypasses the freshness window (re-fetches even
  with a fresh cache; used only by `hunter update`) and still refreshes the
  cache. The CI/opt-out env gates do NOT live here — they gate the
  *background spawn* only (§4.1), so an explicit `hunter update` works
  everywhere.

### 3.4 Why the PyPI fallback is automatic, not config-gated

1. Both endpoints are keyless public reads; worst case is one small GET per
   user per day — there is nothing to consent to.
2. The hedged failure (GitHub 403 on shared IPs) is common enough that an
   opt-in fallback would make the feature silently degrade exactly for the
   users most likely to hit it.
3. A config key would require touching M2-owned `config.py` — forbidden this
   milestone. Revisit only if PyPI becomes unreliable.

---

## 4. Part B — background notify (Strix/Hermes pattern)

### 4.1 Spawn gate (`start_background_check`)

```python
def start_background_check(*, environ=None, check_fn=None,
                           suppress_notice=False, wait=False) -> bool:
```

- Reset module state first (fresh per invocation): clear pending result,
  completion event, suppression flag.
- **Gate — `environ` (default `os.environ`):** return `False` (no thread,
  no output) when any of:
  - any `_CI_ENV_VARS` var present with a `_truthy` value;
  - `HUNTEROS_NO_UPDATE_CHECK` present with a `_truthy` value
    (`=0`/`false`/empty → checks allowed, documented);
  - `PYTEST_CURRENT_TEST` is present at all (the check can never fire under
    pytest, even if a future test forgets the conftest belt).
- Spawn **one** `threading.Thread` (daemon, name `"hunter-update-check"`)
  running `_run_check`: call `check_fn or check_for_newer_version()`, store
  the result under a module lock, set the completion `Event`. Any exception
  from the check is swallowed (stored as a failed `CheckResult`). The thread
  is fire-and-forget: nothing ever joins it in production (`wait=True`
  exists for tests only, join timeout 5s).
- Returns `True` iff a thread was spawned.

### 4.2 Emission (`pop_pending_notice` / `emit_notice`)

```python
def pop_pending_notice() -> str | None:
```
Returns the notice line at most once per process; `None` when the check has
not completed, found no update, or was spawned with `suppress_notice=True`.
Exact line (the em-dash-free, arrow-bearing normative copy):

```
A new version of hunter is available: 0.3.1 → 0.4.0. Run: hunter update
```

```python
def emit_notice() -> None:
```
Context-close hook: `line = pop_pending_notice()`; when non-empty print
`f"[yellow]{line}[/yellow]"` via `main.err_console` (lazy import — no module
cycle at call time). Wrapped in `try/except Exception` — it must never break
process exit.

### 4.3 Wiring (the ONLY main.py change to existing code)

Root callback, immediately after the existing `load_keys_env()` block:

```python
    # M4: polite background version check — one daemon thread per process,
    # never for `hunter update` (it checks forcefully itself) and never for
    # the long-lived surfaces; the notice prints AFTER command output via a
    # context-close hook (click closes the root context last, even when a
    # subcommand raises Exit).
    from hunter.cli import update_core

    sub = ctx.invoked_subcommand
    if sub != "update":  # the update command performs its own forced check
        update_core.start_background_check(
            suppress_notice=sub in update_core.QUIET_COMMANDS
        )
    ctx.call_on_close(update_core.emit_notice)  # pop is empty when nothing spawned
```

### 4.4 Suppression rule (decision + justification)

- **stderr for every non-interactive command, including `--json`.**
  Repository precedent: `_scope_for_target` already prints advisory lines to
  `err_console` with the comment "stderr on purpose: with --json this line
  must never touch stdout". Consumers of `scan/report/findings/doctor/verify
  --json` (jq, CI collectors) read stdout only, so a stderr notice cannot
  corrupt machine output; suppressing per-command would need a flag threaded
  through every command body for zero benefit.
- **Fully suppressed for `QUIET_COMMANDS = {chat, tui, gateway}`** (thread
  still spawned → cache stays fresh; the notice simply never prints this
  process). Deciding between "suppress" and "print pre-banner": a pre-banner
  line in `chat`/`tui` pollutes the first-run REPL banner contract pinned by
  existing tests, and for `gateway` the process may run for weeks — a
  post-exit notice after Ctrl+C is noise. The next short command surfaces
  the notice instead.
- The notice is **opportunistic**: `emit_notice` only prints when the check
  already finished (`Event.is_set()`), never waits — a fast command
  (`hunter version`) may legitimately exit before the 1.5s network budget
  elapses and print nothing. Never blocks exit: the thread is a daemon, the
  hook never joins.
- `hunter update` never spawns the background check (no double messaging;
  the close-hook pop is empty).

---

## 5. Part C — `hunter update`

### 5.1 Command

```python
@app.command()
def update(yes: bool = typer.Option(False, "--yes", help="...")) -> None:
    """Update the harness (or print the exact manual command)."""
    from hunter.cli.update_core import run_update
    code = run_update(console=console, err_console=err_console, yes=yes)
    if code:
        raise typer.Exit(code)
```

`run_update(*, console, err_console, yes, **seams)` — every seam defaults to
a module-level function so tests monkeypatch (`update_core.detect_install_method`,
`update_core.check_for_newer_version`, `update_core.default_runner`,
`update_core.default_fetch_script`, `update_core._stdin_isatty`) or pass
explicit callables. Flow:

1. `method = detect_install_method()` → `"dev" | "installer" | "pipx" | "pip"`.
2. **dev** → print `dev/checkout install detected — update with: git pull && pip install -e .`, **exit 0**. Nothing executed.
3. `result = check_for_newer_version(force=True, ...)` — a live check; the
   user asked. `result.latest == ""` → print `could not check for the latest
   version (offline or rate-limited) — install manually:` + the manual
   one-liner, **exit 1**.
4. `not result.update_available` → print `hunter <current> is up to date
   (latest release: <latest>)`, **exit 0** (covers downgrade/equality).
5. **Confirm:** `--yes` → proceed. Else if not `_stdin_isatty()` → print
   `update declined — manual install any time:` + one-liner, **exit 0**
   (never blocks on a dead stdin; mirrors `init`'s declined-clobber exit 0).
   Else `ask("update hunter <current> → <latest> now?", "n")` (default impl:
   `console.input`, `EOFError → "n"`); anything but `y`/`yes` → same
   declined line, **exit 0**.
6. `plan = build_install_plan(method, is_windows=..., home=...)` →
   `execute_plan(plan, script_fetcher=..., runner_fn=...) -> int`.
7. `code != 0` → print `update failed (exit <code>) — install manually:` +
   one-liner, **exit 1**.
8. Success → print `updated: hunter <current> → <latest>`, then
   `note: config migrations run on next command`, then up to 5
   `note: <migration note>` lines (§6), **exit 0**.

Manual one-liners (normative copy, platform-keyed):

- POSIX: `curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash`
- Windows: `irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex`

### 5.2 Install-method detection table (ordered — order is load-bearing)

| # | method | detection | action |
| --- | --- | --- | --- |
| 1 | `installer` | `sys.prefix` resolves **inside** `<home>/.hunteros/venv` (covers `bin/` and `Scripts\` — prefix containment, not exe names) | download the raw install script to a temp file and run it with `--skip-setup` (§5.3) |
| 2 | `dev` | `direct_url.json` present in the `hunteros-harness` dist metadata (editable, `file://`, or VCS install) | advice only: `git pull && pip install -e .` — exit 0 |
| 3 | `pipx` | `"pipx"` in `sys.prefix.parts` | `pipx upgrade hunteros-harness` |
| 4 | `pip` | fallback | `<sys.executable> -m pip install --upgrade hunteros-harness` |

Why `installer` first: the M1 installer's git-fallback path (`pip install
git+https://...` INTO `~/.hunteros/venv`) also produces `direct_url.json`;
checking the venv containment first keeps that install correctly routed to
the installer path. `classify_install(*, sys_prefix, home, direct_url,
is_windows) -> str` is pure (all inputs explicit); `detect_install_method()`
gathers real inputs (`importlib.metadata.distribution("hunteros-harness")`
read of `direct_url.json`, `sys.prefix`, `Path.home()`) and NEVER raises —
any metadata hiccup degrades to `"pip"`.

### 5.3 Plans and execution (seams: tests never execute real installers)

```python
@dataclass(frozen=True)
class InstallPlan:
    method: str             # "installer" | "pipx" | "pip"
    argv: tuple[str, ...]   # "{script}" placeholder for the installer method
    fetch_url: str = ""     # non-empty only for "installer"
```

`build_install_plan(method, *, is_windows=None, home=None) -> InstallPlan`:

| method | POSIX argv | Windows argv | fetch_url |
| --- | --- | --- | --- |
| `installer` | `bash {script} --skip-setup` | `powershell -NoProfile -ExecutionPolicy Bypass -File {script} -SkipSetup` | `RAW_INSTALL_SH` / `RAW_INSTALL_PS1` |
| `pipx` | `pipx upgrade hunteros-harness` | same | — |
| `pip` | `<sys.executable> -m pip install --upgrade hunteros-harness` | same | — |

`execute_plan(plan, *, script_fetcher=None, runner_fn=None, is_windows=None) -> int`
— **never raises; internal failures map to exit `127`**:

- `installer`: `text = (script_fetcher or default_fetch_script)(plan.fetch_url)`
  (default: httpx GET, 15s timeout, `raise_for_status`); write the text to a
  `NamedTemporaryFile(delete=False, suffix=".sh"/".ps1")`; substitute the
  placeholder; `runner_fn(argv)`; `finally` unlink the temp file
  (best-effort). Fetch or write failure → 127.
- `pipx`/`pip`: `runner_fn(list(plan.argv))` directly.
- `default_runner(argv)`: `subprocess.run(argv, check=False).returncode`
  (output streams to the inherited console), `except OSError → 127`
  (e.g. `bash` missing on a bare Windows box → the manual `irm` one-liner).

---

## 6. Part D — migration hook (conservative, read-only)

Piggybacks the M2 `legacy_notes` doctrine ("notes computed once, printed at
most once per command, never inside resolve/complete") without touching
M2-owned files: the notes are computed by `update_core` and printed once, by
`hunter update` only, after a successful install.

```python
def example_schema() -> dict:
    """yaml.safe_load(config_example_yaml()); {} on ANY failure. Never raises."""

def migration_notes(raw: dict | None, schema: dict | None = None) -> list[str]:
    """Read-only schema diff stub. Pure; NEVER raises; capped at 5 notes."""
```

Diff rules (walk one level deep):

- top-level key in `raw` absent from `schema` →
  `config key '<key>' is not in the current schema — run 'hunter config example'`
- `schema[key]` is a dict and `key` missing from `raw` →
  `optional config section '<key>' is available — see 'hunter config example'`
- both are dicts → subkeys of the user's block absent from the schema block →
  `config key '<key>.<sub>' is not in the current schema — run 'hunter config example'`
- anything not a dict (either side), or `schema == {}` → `[]`.
- Hard cap: 5 notes total.

The stub works on the RAW YAML (via `resolve_config_target()` +
`yaml.safe_load`, both read-only, best-effort — unreadable config → no
notes) precisely BECAUSE the loader would reject unknown keys: this warns
the user *before* the next command's `load_config` fails against a newer
schema. v0.5+ replaces the stub with real migrations; the print-once surface
is already in place.

---

## 7. Part E — docs

- **README.md** — new `## Updating` section (after Quick start):
  ``hunter update`` one-liner; one paragraph: how it detects the install
  method, the daily background check printing a one-line stderr notice
  (once per command), disable with `HUNTEROS_NO_UPDATE_CHECK=1`
  (skipped on CI automatically); the two manual one-liners (§5.1 copy).
- **QUICKSTART.md** — short `### Updating` subsection near the end:
  `hunter update` + the disable note.
- **docs/FIRST-RUN.md** — "Where things live" table gains
  `Update check | ~/.hunteros/update-check.json (24h cache; HUNTEROS_NO_UPDATE_CHECK=1 disables)`
  plus one narrative sentence.

---

## 8. Existing contracts that must NOT break (builder's red lines)

1. Baseline **673 passed / 2 skipped** stays green; `ruff check src tests` clean.
2. **No M2-owned file changes:** `src/hunter/llm/config.py`,
   `src/hunter/llm/router*.py`, `src/hunter/llm/writing.py` are only CALLED
   (`config_example_yaml`, `resolve_config_target`), never edited.
3. `main.py` changes are exactly: the two additive root-callback lines (§4.3)
   and the new `update` command. Every existing command body, `_version()`,
   and the welcome panel are byte-identical. `hunter`/`hunt` behavior
   unchanged (same app).
4. `keys.env` and config write paths untouched; `update-check.json` never
   contains secrets (versions + timestamp + source only).
5. Installer scripts untouched — `hunter update` re-runs them with the
   existing `--skip-setup` / `-SkipSetup` flags.
6. **No test touches the network:** MockTransport for HTTP, injected
   `check_fn`/`runner_fn`/`script_fetcher` for everything else. Two
   independent pytest gates: `tests/conftest.py` autouse fixture sets
   `HUNTEROS_NO_UPDATE_CHECK=1`, and `start_background_check` itself refuses
   to spawn while `PYTEST_CURRENT_TEST` is set.
7. New files only: `src/hunter/cli/update_core.py`,
   `tests/test_update_core.py`, `tests/test_cli_update.py`.
8. The notice must never appear on stdout of ANY command (§4.4) and never
   inside `chat`/`tui`/`gateway` processes.

---

## 9. Data flow (one glance)

```
root callback (every invocation, after load_keys_env)
  ├─ start_background_check(suppress_notice = sub in {chat, tui, gateway})
  │    ├─ gates: CI vars / HUNTEROS_NO_UPDATE_CHECK / PYTEST_CURRENT_TEST → no thread
  │    └─ ONE daemon thread → check_for_newer_version()
  │         ├─ fresh cache (<24h)? ──► CheckResult(source="cache")      (no network)
  │         ├─ GET api.github.com/.../releases/latest (≤1.5s) → tag_name
  │         ├─ 403/offline/malformed ─► GET pypi.org/.../json → info.version
  │         ├─ both fail ────────────► silent CheckResult(error=...)     (no cache write)
  │         └─ success ──────────────► atomic cache write (24h TTL)
  └─ ctx.call_on_close(emit_notice) ── AFTER command output ──► stderr, once, never waits
hunter update [--yes]
  ├─ detect_install_method ──► dev | installer | pipx | pip
  ├─ dev ──► "git pull && pip install -e ." advice ──► exit 0
  ├─ check_for_newer_version(force=True)
  │     ├─ latest=="" ──► could-not-check + manual one-liner ──► exit 1
  │     └─ not newer ───► "up to date" ────────────────────────► exit 0
  ├─ confirm: --yes | tty y/N (non-tty/decline ──► advice, exit 0)
  ├─ build_install_plan ──► execute_plan(script_fetcher, runner_fn)
  │     ├─ installer: GET raw install.{sh,ps1} ─► temp ─► bash --skip-setup | powershell -File -SkipSetup
  │     ├─ pipx: pipx upgrade hunteros-harness
  │     └─ pip:  <python> -m pip install --upgrade hunteros-harness
  └─ success ──► "updated: X → Y" + "config migrations run on next command" (+ ≤5 schema notes)
```

---

## 10. ACCEPTANCE CRITERIA

### (a) pytest-testable Python behavior — each maps to exactly one test

**Update core**

- **U1** GitHub happy path: `check_for_newer_version(current_version="0.3.1",
  client_factory=MockTransport(...))` where the handler asserts the request
  URL is exactly `GITHUB_RELEASES_URL` and returns
  `{"tag_name": "v0.4.0"}` → `latest == "0.4.0"` (v stripped), `source ==
  "github"`, `update_available is True`, `error == ""`, and the cache file
  exists afterwards.
- **U2** 403 fallback: GitHub handler returns 403 (rate-limit JSON body),
  PyPI handler returns `{"info": {"version": "0.4.0"}}` → `source ==
  "pypi"`, `update_available is True`, no exception.
- **U3** total failure is a silent no-op: GitHub 403 + PyPI 500 (and a
  transport-error variant) → `latest == ""`, `update_available is False`,
  `error != ""`, no exception, and NO cache file was written.
- **U4** malformed payloads fall through: GitHub 200 with
  `tag_name: "banana"` → PyPI consulted; PyPI 200 with
  `{"info": {"version": "not-semver"}}` → `latest == ""`, `error != ""`.
- **U5** 24h cache: first check (GitHub mock) writes
  `<home>/.hunteros/update-check.json` with keys `checked_at` (number),
  `latest`, `current`, `source`; a second check whose handler FAILS the
  request if called returns the cached `latest` with `source == "cache"`
  (proves no network) and `update_available` recomputed.
- **U6** stale cache: same setup with `now_fn` shifted +25h → the network
  handler IS called and the cache is rewritten with the new `checked_at`;
  `force=True` with a FRESH cache also re-fetches (network called).
- **U7** corrupt cache: garbage bytes in the cache file → ignored (no
  exception), network path proceeds, cache rewritten parseable.
- **U8** downgrade ignored: latest `0.3.0` vs current `0.3.1` →
  `update_available is False` while the cache is still written.
- **U9** skip-gate table: `_auto_check_allowed` (or equivalent observable)
  is False when any of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`,
  `BUILDKITE`, `CIRCLECI` is set truthy, False for
  `HUNTEROS_NO_UPDATE_CHECK=1`, True for `HUNTEROS_NO_UPDATE_CHECK=0`, and
  False when `PYTEST_CURRENT_TEST` is present.
- **U10** force ignores politeness gates: `check_for_newer_version(force=True,
  environ={"CI": "true", ...})` with a fresh cache still performs the network
  fetch (mock handler records the request).
- **U11** `parse_version`/`_newer` pure table: `v0.4.0`→`(0,4,0)`;
  `0.4.0-beta1`→None; `banana`→None; `(0,4)` vs `(0,4,0)` equal after
  padding; `(0,10,0) > (0,9,0)`; strict (equal is not newer).

**Background notify**

- **N1** spawn/store/pop-once: `start_background_check(environ={}, wait=True,
  check_fn=lambda: CheckResult(latest="0.4.0", current="0.3.1",
  source="github", update_available=True))` returns True; the pop returns
  exactly `A new version of hunter is available: 0.3.1 → 0.4.0. Run: hunter
  update`; the second pop returns `None`.
- **N2** pop suppression cases: pop before completion → `None` (blocking
  check_fn + no wait); a completed no-update result → `None`;
  `suppress_notice=True` with an update available → `None`.
- **N3** thread never crashes the process: `check_fn` raising
  `RuntimeError` → `start_background_check` still returns True, pop returns
  `None`, no exception escapes; `update_core.reset()` clears state so a
  later pop stays `None`.
- **N4** root-callback wiring: with `update_core.start_background_check`
  monkeypatched to a recorder, `CliRunner(["version"])` records exactly one
  call with `suppress_notice=False`; `CliRunner(["update"])` records none.
- **N5** quiet surfaces: `CliRunner(["chat"])` (run_repl monkeypatched to a
  sentinel) records the spawn with `suppress_notice=True`.
- **N6** stdout stays machine-clean: `hunter doctor --json` with the real
  spawn forced via a monkeypatched wrapper injecting `environ={}` + an
  update-available `check_fn` → `CliRunner(mix_stderr=False)`: stdout parses
  as JSON with no notice text in it, and the notice line appears on stderr.

**Install method + plans**

- **M1** `classify_install` table (pure): prefix inside `<home>/.hunteros/venv`
  → `"installer"` EVEN WITH `direct_url` present; prefix elsewhere +
  `direct_url` dict → `"dev"`; prefix containing a `pipx` part → `"pipx"`;
  plain prefix + no direct_url → `"pip"`; POSIX and Windows prefixes both
  covered (Scripts path).
- **M2** `detect_install_method()` returns one of the four strings and never
  raises (real metadata in the test venv).
- **M3** `build_install_plan` table: installer+POSIX → argv
  `("bash", "{script}", "--skip-setup")` + `fetch_url == RAW_INSTALL_SH`;
  installer+Windows →
  `("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
  "{script}", "-SkipSetup")` + `RAW_INSTALL_PS1`; pipx →
  `("pipx", "upgrade", "hunteros-harness")`; pip →
  `(sys.executable, "-m", "pip", "install", "--upgrade",
  "hunteros-harness")`; unknown method degrades to pip.

**`hunter update` command flows**

- **C1** dev: `detect_install_method` monkeypatched to `"dev"` → output
  contains `git pull && pip install -e .`, exit 0, and the runner seam was
  never called.
- **C2** check failure: method pip, `check_for_newer_version` monkeypatched
  to a failed result → output contains `could not check` and the platform
  manual one-liner, exit 1, runner never called.
- **C3** up to date: check returns `update_available=False` with a latest →
  output contains `up to date`, exit 0, runner never called.
- **C4** non-tty without `--yes` (`_stdin_isatty` → False): output contains
  the declined line + manual one-liner, exit 0, runner never called.
- **C5** `--yes` end-to-end (pipx): runner seam records exactly
  `["pipx", "upgrade", "hunteros-harness"]` and returns 0 → output contains
  `updated: hunter 0.3.1 → 0.4.0` and `config migrations run on next
  command`, exit 0.
- **C6** interactive confirm: `_stdin_isatty → True` + `ask` seam `y` → the
  runner runs (exit 0); `ask` seam `n` (and EOF-default) → declined line +
  advice, exit 0, runner never called.
- **C7** installer POSIX end-to-end: `script_fetcher` returns script text →
  the runner records argv `[bash, <real temp path>, --skip-setup]`, the temp
  file existed with the fetched bytes at call time, returns 0 → success
  output, exit 0, and the temp file is gone afterwards.
- **C8** installer failure: runner returns 1 (and an OSError-raising runner
  variant → 127) → output contains `update failed` and the manual one-liner,
  exit 1.
- **C9** migration notes on success: sandbox config containing a key absent
  from the example schema → success output includes the `note:` line for it;
  with no config file → no schema notes (reminder line still present).

**Migration stub**

- **G1** `migration_notes` known shapes: unknown top-level key, unknown
  subkey, and a missing optional section each produce their §6 note; a raw
  dict matching the schema exactly produces `[]`.
- **G2** robustness: `example_schema()` parses `config_example_yaml()` into
  a non-empty dict; `migration_notes` on non-dict/garbage inputs returns
  `[]` and never raises; a pathological input producing many violations is
  capped at 5 notes.

**Docs**

- **D1** `README.md` and `QUICKSTART.md` each contain a heading containing
  `Updating`, the string `hunter update`, and `HUNTEROS_NO_UPDATE_CHECK`;
  `docs/FIRST-RUN.md` mentions `update-check.json`.

### (b) Orchestrator-level checks (not pytest)

- **S1** `python -m pytest -q` full suite: 673 existing + ~32 new pass,
  2 skipped (baseline preserved).
- **S2** `python -m ruff check src tests` clean.

---

## 11. ADVERSARIAL matrix (risk → design answer → where tested)

| # | Risk | Design answer | Test |
| --- | --- | --- | --- |
| 1 | Background thread hits the network from tests | Triple gate: conftest `HUNTEROS_NO_UPDATE_CHECK=1`; `PYTEST_CURRENT_TEST` refusal inside the spawn gate; tests inject `check_fn`/`client_factory` (MockTransport) | U9, N1–N6, §8.6 |
| 2 | Notice corrupts `--json` stdout | stderr-only rule (repo precedent in `_scope_for_target`); never printed via `console` (stdout) | N6 |
| 3 | Mid-REPL corruption (chat/tui/gateway) | `QUIET_COMMANDS` suppression at spawn; thread still refreshes the cache so the next short command surfaces the notice | N5 |
| 4 | Notice blocks exit or fires mid-command | Fire-and-forget daemon thread; `emit_notice` only pops when the completion Event is set (never joins/waits); registered as a context-close hook that runs after command output | N1–N3, §4.2 |
| 5 | GitHub 403 rate limit (60 req/h per IP, shared IPs) | Designed-for path: any non-200/transport/malformed → silent PyPI JSON fallback; total failure → silent no-op, no cache write | U2, U3, §2.4 |
| 6 | Malformed tag/version/cache JSON | `parse_version` → None → fallback/error; cache reader requires typed keys + fresh timestamp; corrupt cache ignored and rewritten | U4, U7 |
| 7 | Downgrade (local build newer than release) | Strict `_newer` comparison recomputed against the RUNNING version; `update_available=False`, message "up to date"; cache still written | U8, U11 |
| 8 | Cache torn by crash | Atomic temp+fsync+`os.replace`+bounded retry (keys.py pattern); best-effort, failure silent | U5, U7 |
| 9 | Tests execute a real installer/pip | `runner_fn`/`script_fetcher` seams mandatory in tests; plans assert argv lists only; `execute_plan` never invoked with defaults under pytest | C5–C8, M3 |
| 10 | Update fails and strands the user | Every failure/decline path prints the platform manual one-liner (curl/irm) | C2, C4, C8 |
| 11 | Non-tty stdin blocks on the prompt | isatty gate aborts with advice before any read (`--yes` is the automation path) | C4 |
| 12 | Migration stub damages configs | Read-only diff (no writes, no loader involvement), never raises, capped at 5 notes, printed once by `hunter update` only | G1, G2, C9 |
| 13 | `update` name collision (e.g. `provider` group from M2) | Distinct top-level typer command name; no `config update`/`provider update` subcommand added | N4, C1 |
| 14 | Double notice (close hook + update output) | `hunter update` never spawns the check; pop is once-per-process and clears | N1, N4 |
| 15 | Thread/pop race | Single lock around store/clear; completion Event; daemon thread swallows check exceptions | N1, N3 |
| 16 | `bash` missing on Windows (installer path) | `default_runner` maps OSError → 127 → failure line + `irm` one-liner, exit 1 | C8 |
| 17 | `--help` / arg errors | Group `--help` and arg-parse errors never reach the callback (no thread, no hook); subcommand `--help` may spawn the check but exits too fast for the notice — harmless | §4.3, §2.5 |
| 18 | Stale notice leaks between tests | `start_background_check` resets module state; auditor fixture calls `update_core.reset()` per test | N3 |

---

## 12. TEST PLAN (auditor implements verbatim)

| File | Test name | Asserts |
| --- | --- | --- |
| `tests/test_update_core.py` | `test_github_release_happy_path_writes_cache` | U1 |
| `tests/test_update_core.py` | `test_github_403_falls_back_to_pypi` | U2 |
| `tests/test_update_core.py` | `test_total_failure_is_silent_noop_without_cache` | U3 |
| `tests/test_update_core.py` | `test_malformed_payloads_fall_through_to_error` | U4 |
| `tests/test_update_core.py` | `test_fresh_cache_serves_without_network` | U5 |
| `tests/test_update_core.py` | `test_stale_cache_and_force_refetch` | U6 |
| `tests/test_update_core.py` | `test_corrupt_cache_ignored_and_rewritten` | U7 |
| `tests/test_update_core.py` | `test_downgrade_not_reported_but_cached` | U8 |
| `tests/test_update_core.py` | `test_skip_gates_ci_optout_and_pytest` | U9 |
| `tests/test_update_core.py` | `test_force_bypasses_freshness_and_gates` | U10 |
| `tests/test_update_core.py` | `test_parse_version_and_newer_table` | U11 |
| `tests/test_update_core.py` | `test_spawn_store_pop_once_notice_format` | N1 |
| `tests/test_update_core.py` | `test_pop_suppressed_before_completion_no_update_or_quiet` | N2 |
| `tests/test_update_core.py` | `test_check_exception_swallowed_and_reset_clears` | N3 |
| `tests/test_update_core.py` | `test_root_callback_spawns_version_not_update` | N4 |
| `tests/test_update_core.py` | `test_chat_spawn_is_suppressed` | N5 |
| `tests/test_update_core.py` | `test_doctor_json_stdout_clean_notice_on_stderr` | N6 |
| `tests/test_update_core.py` | `test_classify_install_table` | M1 |
| `tests/test_update_core.py` | `test_detect_install_method_returns_known_member` | M2 |
| `tests/test_update_core.py` | `test_build_install_plan_table` | M3 |
| `tests/test_cli_update.py` | `test_update_dev_method_advice_only` | C1 |
| `tests/test_cli_update.py` | `test_update_check_failure_prints_manual_one_liner` | C2 |
| `tests/test_cli_update.py` | `test_update_up_to_date_exits_zero` | C3 |
| `tests/test_cli_update.py` | `test_update_non_tty_without_yes_aborts_with_advice` | C4 |
| `tests/test_cli_update.py` | `test_update_yes_pipx_runs_plan_and_prints_reminder` | C5 |
| `tests/test_cli_update.py` | `test_update_confirm_y_runs_n_declines` | C6 |
| `tests/test_cli_update.py` | `test_update_installer_posix_downloads_temp_and_cleans_up` | C7 |
| `tests/test_cli_update.py` | `test_update_installer_failure_prints_manual_one_liner` | C8 |
| `tests/test_cli_update.py` | `test_update_success_prints_migration_notes` | C9 |
| `tests/test_update_core.py` | `test_migration_notes_shapes` | G1 |
| `tests/test_update_core.py` | `test_example_schema_and_migration_notes_never_raise_capped` | G2 |
| `tests/test_cli_update.py` | `test_docs_updating_sections` | D1 |

Conventions for the auditor:

- Copy `_cli_env` from `tests/test_cli_init.py` (HOME+USERPROFILE+HUNTEROS_CONFIG
  → `tmp_path`); copy `test_cli_doctor.py`'s autouse `_hermetic` env fixture
  for the doctor test (`HUNTER_STATE_DIR`, `HUNTEROS_CHAT_DB`).
- `tests/conftest.py` already provides `HUNTEROS_NO_UPDATE_CHECK=1` via its
  autouse fixture; the per-file autouse fixtures in the two new test files
  call `update_core.reset()` before each test. Tests that need the spawn
  gate OFF pass `environ={}` (or the conftest var is delenv'd) explicitly.
- HTTP is always `httpx.MockTransport` via the `client_factory` seam
  (`_mock_client` helper style from `tests/test_llm_probe.py`); handlers
  that must prove "no network" raise if called.
- Fake clock: `now_fn=lambda: <fixed float>`; sandbox home: `home=tmp_path`.
- CLI flow tests drive `CliRunner` against `cli_main.app` with
  `monkeypatch.setattr(update_core, "detect_install_method" /
  "check_for_newer_version" / "default_runner" / "default_fetch_script" /
  "_stdin_isatty", fake)` — the command resolves seams via module attributes
  at call time, so monkeypatching is sufficient and nothing real executes.
- The N6 stream-separation test constructs its own
  `CliRunner(mix_stderr=False)`; the notice must be asserted in
  `result.stderr`, the JSON in `result.stdout`.
- `update` command tests assert on the string consoles' captured output for
  `run_update`-level tests and on `result.output`/`result.stderr` for
  CliRunner-level ones; never on exit-code-only.

---

## 13. Verify commands (Windows dev reality + CI)

```bash
.venv/Scripts/python -m pytest tests/test_update_core.py tests/test_cli_update.py -q
.venv/Scripts/python -m pytest -q        # S1: 673 existing + ~32 new pass, 2 skipped
.venv/Scripts/python -m ruff check src tests   # S2
```

CI (ubuntu/windows × 3.11/3.13) runs ruff + pytest only; there are no script
checks this milestone (no installer changes). No command in this milestone
may perform network I/O — grep the new tests for
`MockTransport|check_fn=|runner_fn=|script_fetcher=` before review.

---

## 14. Builder order (suggested)

1. `update_core` check core: pure helpers + fetch/fallback + cache + gates
   (§3) + tests U1–U11.
2. Notify machinery: `start_background_check`/`pop_pending_notice`/
   `emit_notice`/`reset` (§4.1–4.2) + tests N1–N3.
3. `main.py` wiring: the two additive root-callback lines + the `update`
   command (§4.3, §5.1) + tests N4–N6 (conftest fixture lands here).
4. Install machinery: `classify_install`/`detect_install_method`/
   `build_install_plan`/`execute_plan`/`run_update` (§5.2–5.3) + tests
   M1–M3, C1–C9.
5. Migration stub: `example_schema`/`migration_notes` (§6) + tests G1–G2.
6. Docs (§7) + test D1 — final full-suite + ruff pass (S1/S2).
