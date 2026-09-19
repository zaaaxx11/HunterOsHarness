# M11 — RED baseline report (Tester)

Contract: `docs/plans/m11-ux.md`. This report records the state the
Builder inherits: **all M11 behavior tests are RED for the named reasons;
everything else is GREEN at the recorded baseline.** The Builder's job is to
make the red tests green WITHOUT touching them (drift-updated files are
updated by the Tester per §14; their current red state is the pending
behavior change).

## 1. Green baseline (before any M11 test existed)

- Command: `.venv/Scripts/python -m pytest -q` (venv, editable install).
- **1005 pre-existing tests collected: 1003 passed, 2 skipped, 0 failed**
  (clean run; exactly derived: 1136 post-addition − 131 new M11 cases).
- Pre-existing flake (reported, NOT fixed, per instructions):
  `tests/test_tui.py::test_selecting_run_switches_to_findings` failed once in
  the first full baseline run (`tab-dashboard` != `tab-findings` — Textual
  pilot timing under full-suite load) and passed in isolation (twice) and in a
  second full baseline run.

## 2. Additive test infrastructure (spec §13)

`tests/conftest.py` keeps its sys.path bootstrap untouched and gains:

- `isolated_home` (autouse) — private `HOME`/`USERPROFILE` at
  `tmp_path/hunter-home`, scrubbed HUNTEROS_* env, `HUNTEROS_NO_UPDATE_CHECK=1`.
  Test-level monkeypatch overrides still win. No test touches the real home.
- `fake_console` — string-console factory (records prints as plain text,
  scripts `input()`, `is_terminal=False`; test_chat_repl.FakeConsole convention).
- `scripted_ask` — needle-matching `(ask, secret)` pair factory; unmatched
  prompts raise AssertionError; `""` reply = take the default; Exception
  entries are raised (Ctrl+C/EOF scripting).
- `fake_litellm` — zero-network litellm module double for
  `ProviderRouter(config, litellm_module=...)`; records `completion(**kwargs)` calls.
- `no_update_check` — kept for clarity (covered by the autouse fixture).

Full suite verified green immediately after the fixture landed (additive-only).

## 3. New M11 test files — red matrix

Counts are from the recorded red run (per-file `-q --tb=no`).

| File (milestone) | Cases | Red | Green (day-1 guards) | Why red today | Greened by |
|---|---|---|---|---|---|
| `tests/test_m11_home.py` (M1) | 13 | 13 | 0 | `ModuleNotFoundError: hunter.home` (deferred imports); Ledger/ChatStore defaults still `cwd`/`.hunteros`; `where`/doctor rows missing | M1 |
| `tests/test_m11_config_cli.py` (M1) | 15 | 15 | 0 | `config path/get/set/unset/edit/check/key` commands do not exist (CliRunner exit 2); `validate_raw`/`KEY_NAME_RE` missing | M1 |
| `tests/test_m11_init.py` (M2) | 18 | 18 | 0 | `run_init_wizard` missing (ImportError); pinned M2 copy (mode picker, backup, cancel, honest browser note) absent | M2 |
| `tests/test_m11_chat_oneshot.py` (M3) | 16 | 15 | 1 — `test_hunt_mode_still_intercepts_free_text` (explicit-mode regression guard, true today) | one-shot prompt arg / `--resume/--continue/--list` missing (exit 2); no `_build_engine` seam; no panel/short-line flow; no intent hint | M3 |
| `tests/test_m11_provider.py` (M4) | 14 | 13 | 1 — `test_provider_add_wizard_regressions_green` (today's provider_add contract that the M4 re-point must preserve) | `key_env_for_endpoint`/`is_local_endpoint`/`run_model_picker` missing; `hunter model` command missing; probe copy is today's note copy | M4 |
| `tests/test_m11_gateway.py` (M5) | 12 | 12 | 0 | `drain_daemon`/`_should_claim`/`_consume_restart_marker` missing; gateway stop/restart/status/logs + top-level restart/logs missing; no drain-first restart | M5 |
| `tests/test_m11_tui.py` (M6) | 8 | 7 | 1 — `test_tui_regressions_green` (static sanity that test_tui.py survives §14 item 12) | only 4 tabs (no Engine/Config); Doctor tab still duplicates doctor_core; stale copy + `metadata.version(dep)` loop still in source; no status bar | M6 |
| `tests/test_m11_hunt_start.py` (M7) | 14 | 14 | 0 | no `interactive_ask` seam (TypeError); no positional `hunter start <url>` (exit 2); scope gate still refuses (exit 3, no `approved_scopes`); chat `/hunt` has no `ask_fn` flow | M7 (schema keys M1) |
| `tests/test_m11_hospitality.py` (M8) | 13 | 12 | 1 — `test_paused_does_not_kill_in_flight` (vacuously true until pause exists; kills a wrong implementation that aborts in-flight runs) | `hunter.hospitality` missing (exit_hint/panel/short line); `--version`, `pause`/`resume`, welcome footer, installer PATH order all missing | strings M1, wiring M8 |
| `tests/test_docs_m11.py` (M0) | 8 | 7 | 1 — `test_no_y_n_prompt_in_hunt_start_path` (static guard, true from day one) | UX-NOTES.md missing (M0); `~/.hunter` docs / disclaimer-in-wizard / 0.6.0 / installer PATH / hospitality module / LLM docs pending | M0/M1/M2/M4/M8 |
| **Total** | **131** | **126** | **5** | | |

## 4. Drift register (§14) — pre-existing tests updated by the Tester

| # | File | Edit | Red today | Greened by |
|---|---|---|---|---|
| 1 | `tests/test_llm_config.py` | find-path order block pins `~/.hunter/config.yaml` | 1/18 | M1 |
| 2 | `tests/test_llm_keys.py` | keys path pins → `~/.hunter/keys.env` | 3/8 | M1 |
| 3 | `tests/test_kernel_ledger.py` | `test_default_state_dir_and_env_override`: default = `~/.hunter/ledger.db` (HOME-isolated), cwd never written; env override unchanged | 1/18 | M1 |
| 4 | `tests/test_chat_hunt.py` | interception tests (C1/C2/C3/C8/C10-arm/C13-confirm/C16) rewritten to the explicit-mode contract: free text → reply + 💡 hint, confirm never consulted, no headless decline; `/hunt on` intercepts (incl. headless decline inside hunt_mode); `/audit` one-shots unchanged; classifier tests untouched | 6/17 | M3 |
| 5 | `tests/test_cli_daemon.py` | `test_daemon_start_target_is_optional_but_scope_gate_remains`: non-localhost start without `--scope` exits 0 + records `agent.approved_scopes` (source="hunt-start"); ADDED `scope_confirm: true` → exit 3 case | 1/6 | M7 |
| 6 | `tests/test_skills_surfaces.py` (2), `tests/test_agent_curator.py` (6 pins), `tests/test_agent_skills_corpus.py` (3), `tests/test_docs_m5.py` (README pin), `tests/test_release_m7.py` (skills docs pin) | skills path pins → `~/.hunter/skills` | 2/5, 2/12, 7/10, 1/1, 1/22 | M1 |
| 7 | `tests/test_cli_doctor.py` | `home` added to the expected doctor labels (new row) | 1/11 | M1 |
| 8 | `tests/test_cli_init_v2.py` | rewritten against `run_init_wizard`: EOF-defaults, disclaimer-last (now incl. the cancel path), smoke-never-aborts, keys-before-config content, keys.env-only, honest browser note, clobber prompt GONE (backup + keep-defaults), re-ask-not-silent; offer tests + `onboarding_updates` shape kept verbatim | 14/19 | M2 |
| 9 | `tests/test_cli_init.py` | `--provider/--yes` contract folded into `run_init_wizard` (same exit codes); v1 inline-key renderer tests replaced by keys.env-only; clobber refusal → backup + deep-merge (exit 0) | 6/9 | M2 |
| 10 | `tests/test_chat_repl.py` | `_no_provider_text` assert → panel once + short line afterwards | 1/9 | M3 |
| 10 | `tests/test_chat_commands.py` | NO EDIT — no `/hunt` usage-line tests exist in this file (verify-only) | — | — |
| 11 | `tests/test_cli_providers.py` | NO EDIT — no `~/.hunteros` message pins exist (verify-only) | — | — |
| 12 | `tests/test_tui.py` | NO EDIT (verify-only; tab set grows in M6, existing helpers preserved) | — | M6 |
| 13 | `tests/test_installer_static.py`, `tests/test_release_m7.py` (PATH markers) | NO EDIT — markers byte-identical per spec | — | M8 |

## 5. Full-suite red run (recorded)

- Command: `.venv/Scripts/python -m pytest --tb=no -q -rf`
- **Collection: 1136 tests (1005 pre-existing + 131 new), 0 collection errors.**
- **173 failed = 126 new M11 cases + 47 drift-updated cases; 2 skipped;
  961 passed** (958 pre-existing non-drift + 5 day-1 guards in the new files).
- Every red failure is an assertion failure or the named missing-feature
  error (ImportError/TypeError on the new seam); there are NO errors on
  import at collection time (all new modules are imported inside test bodies).

## 6. Spec-vs-code notes and reconciliation points for the Builder

1. `config set` single-part-key refusal: the spec does not state an exit
   code. Pinned in `test_m11_config_cli.py` as exit 2 (usage layer) plus the
   `leaf key` hint fragment — reconcile if the spec's Builder pass decides
   otherwise (behavior change must update the drift register, not the test).
2. `run_model_picker` (spec §8) exposes `list_models_fn` but no `probe_fn`
   seam. The two model-picker list tests seed loopback base URLs with fully
   faked `list_models_fn` output; if the implementation dials a probe
   internally, the Builder must keep the probe advisory/offline for seeded
   URLs or add the seam.
3. `hunter where` human output may be soft-wrapped by rich at 80 columns in
   CliRunner; the byte-exact surface is `--json` (state_source pinned
   flag|env|home) and the human assertions use stable line fragments.
4. Migration "unreadable legacy file" (§5 plan 8) is modeled deterministically
   cross-platform as a legacy `skills` entry that is a FILE where a directory
   is expected (plus a binary-garbage config that must copy as bytes and
   record notes). Monkeypatching shutil would have coupled the test to
   implementation internals the spec does not pin.
5. `--version` output value is asserted as `hunter {_version()}` (no literal
   0.6.0) to stay robust against dist-info staleness; the literal 0.6.0 pin
   lives in `test_docs_m11.py::test_changelog_and_version_bumped` per spec §4.
6. The spec's §13 `no_update_check(monkeypatch)` fixture is implemented as the
   trivial setenv the spec describes (the autouse fixture already covers it).
7. `test_paused_does_not_kill_in_flight` drives `hunt_worker` directly with a
   fake `run_hunt` that raises `pause.flag` mid-run and must still land
   `done-*.json` — green today (no pause exists), and the killing test for any
   implementation that aborts claimed work on the pause flag.
8. The pre-existing TUI flake (§1) predates M11; do not "fix" it in M11.
