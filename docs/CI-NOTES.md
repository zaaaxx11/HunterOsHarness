# CI Notes — why the pipeline was red, and how to never relearn it

CI: `.github/workflows/ci.yml` — matrix `ubuntu-latest|windows-latest × 3.11|3.13`,
steps: `pip install -e ".[dev]"` → `ruff check src tests` → `python -m pytest`.
This file records the root-cause chain of the v0.3.1 red-CI incident so future
squads don't rediscover it one 15-minute CI round at a time.

## Root-cause chain (three independent causes, fixed in three commits)

### 1. Missing `click` dependency — run ce16853 era (v0.3.0)

`ModuleNotFoundError: No module named 'click'` at import of
`src/hunter/cli/handle.py`. `typer >= 0.26` no longer depends on click, and
`handle.py` uses click directly (`Command.main`, `Abort`/`ClickException`,
`PacifyFlushWrapper`). Lesson: **anything imported directly must be declared in
`pyproject.toml`** — never rely on a transitive dep surviving a dep upgrade.
Fixed by declaring `click>=8.1` (commit f47c081).

### 2. Init wizard + core deps — local CI-parity repro (commit b8f9c21)

With litellm uninstalled, the init wizard dropped the provider+model in
no-litellm mode (`test_init_provider_openrouter_yes_writes_loadable_config`).
Fixed two ways: the wizard configures an explicitly requested `--provider`
regardless, and **litellm was promoted to a core dependency** (the interface
every agent path rides on; API keys stay BYOK).

### 3. Run b8f9c21 — two more test-only causes, found in CI logs (not guessed)

| Jobs red | Step | Cause |
|---|---|---|
| ubuntu-latest 3.11 + 3.13 (12 tests) | pytest | `$HUNTEROS_CONFIG` containment guard |
| windows-latest 3.11 (1 test) | pytest | wall-clock tie in session ordering |
| windows-latest 3.13 | — | green (installed deps + ruff + all tests) |

**(a) The `$HUNTEROS_CONFIG` home-containment guard vs pytest's tmp_path.**
`hunter.llm.writing.resolve_config_target` refuses an env-var config target
outside the home directory (a stray env var must not aim writes at arbitrary
filesystem locations) unless `force` or an explicit `path` is used. On Linux,
pytest's `tmp_path` lives under `/tmp` — outside `$HOME` — so every CLI test
that pointed `$HUNTEROS_CONFIG` at `tmp_path` and then *wrote* config died with
`HunterError: $HUNTEROS_CONFIG points outside the home directory`. On Windows
`tmp_path` sits under `%USERPROFILE%` (i.e. inside home), which is why the tests
passed locally and on windows-3.13 — the bug was invisible until CI ran Linux.
**Fix (c44fd7e): tests, not the guard.** `HOME` (POSIX) + `USERPROFILE`
(Windows) are monkeypatched to the pytest sandbox in the three setup helpers
(`test_cli_providers._hermetic`, `test_cli_init._cli_env`, two inline setups in
`test_qa_v03.py`), so the env target is in-home on every OS. The guard stays
live and is still covered by
`test_write_config_refuses_env_path_outside_home` (refusal + `--force`) and
`test_explicit_config_path_outside_home_is_allowed` (explicit path bypass).

**(b) Wall-clock granularity flake in chat session ordering.**
`ChatStore.list_sessions()` orders by `last_active_at DESC, session_id DESC`.
Before py3.13, `time.time()` on Windows ticks every ~15.6 ms
(`GetSystemTimeAsFileTime`); py3.13 switched to
`GetSystemTimePreciseAsFileTime`. On windows-3.11 the three rapid writes in
`test_set_title_and_list_order` landed on one tick, tied on `last_active_at`,
and the `session_id DESC` tie-break flipped the order — a ~50% flake.
**Fix (40d2765): test-side deterministic clock** (strictly increasing fake
`time.time` via monkeypatch), not sleeps and not weakened assertions; the
"most recently active first" contract is unchanged. Lesson for product code:
never assert strict ordering across operations that only rely on wall-clock
separation — coarse clocks tie.

## Environment parity rules of thumb

- **Ruff**: `dev` extras pin `ruff>=0.6` only; CI resolves the latest. Both the
  repo venv and a fresh CI-parity venv resolved **ruff 0.16.7** and CI's
  `ruff check src tests` passed on all four jobs — rule drift has not bitten
  *yet* because the selected rule set (`E,F,W,I,UP,B,SIM`) has been stable.
  If a future ruff release adds/re-enables rules inside a selected category,
  CI can go red on lint while local stays green: pin a ceiling (e.g.
  `ruff>=0.6,<0.17`) or fix the violations — never relax the rule set to hide
  real findings.
- **Local CI-parity venv**: `.venv-ci` (`python -m venv .venv-ci; pip install -e
  ".[dev]"`) reproduces CI's fresh dependency resolution; keep it around when
  debugging CI-only failures.
- **Linux-only failures reproduce on Windows** by pointing `HOME`/`USERPROFILE`
  of the test process at a directory outside the pytest tmp tree — the tests'
  own monkeypatched isolation then proves the fix.
- Baseline: **601 tests (600 passed + 1 environmental skip: textual run_test
  pilot unavailable), ruff clean**, on both venvs at py3.13.
