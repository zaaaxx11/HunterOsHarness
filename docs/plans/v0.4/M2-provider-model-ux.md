# M2 — Provider & Model UX (v0.4)

**Goal:** adding models/providers must be effortless (`hunter provider add`
interactive wizard: endpoint auto-detect + model auto-add + role assignment),
and the config role vocabulary becomes the user's language:
`orchestrator / hunter / verifier / utility` (renamed from
`planner / exploit / verify / utility`) with automatic migration.

**Design status:** final for M2. AUDITOR writes the failing tests in §10/§12
first; BUILDER implements until green. Every acceptance criterion is
mechanically checkable and none requires live network. Structure and
conventions match `docs/plans/v0.4/M1-installer-onboarding.md`.

---

## 0. Non-goals (M2)

- `hunter provider add` flag behavior changes beyond vocabulary (all existing
  flags keep their exact semantics; only `name` becomes OPTIONAL to open the
  wizard).
- The `verify`/`utility` WORDS outside the tier vocabulary: pipeline phases
  (`phases.py` PHASE_ORDER `"verify"`), `hunter verify` (ledger tamper check),
  `kernel/events.py::verify`, agent capability `PROBE_TIERS`
  (`basic|advanced`), and the two skill SKILL.md mentions of "exploits" are
  COINCIDENTAL and must not be touched (see §2.6 classification).
- Per-role system prompts or new role behavior — only the vocabulary/keys.
- `fallback_providers` gaining an `endpoint` field — a fallback entry's
  endpoint is inherited from the named provider's block (§4.3).
- Async gateway/TUI provider-UX changes — the TUI and gateway carry no tier
  literals today (verified by grep) and get none.
- Stream-token-level changes to the responses path — LiteLLM's bridge owns
  the wire; we only choose the wire model (§4).
- Removing the `hunter init` v1 flow or changing its step ORDER (vocabulary
  only, see §2.5).

---

## 1. Current-state map (what exists, what changes)

| File | Today | M2 change |
| --- | --- | --- |
| `src/hunter/llm/base.py` | `Tier = Literal["planner","exploit","verify","utility"]`, `TIERS` | new `TIERS`, `LEGACY_TIER_ALIASES`, `LEGACY_TIERS`, `normalize_tier` |
| `src/hunter/llm/config.py` | tier keys validated against `TIERS`; `resolve_model` hardcodes `"planner"` | loader accepts+migrates legacy names, `HunterConfig.legacy_notes`, env/agent.tier normalization, example YAML new vocabulary |
| `src/hunter/llm/writing.py` | renderer iterates `TIERS`, emits raw tier keys, `_TIER_COMMENTS` keyed by old names | legacy-key migration before render; new-name-only output; new comments |
| `src/hunter/llm/router.py` | `_wire_model(provider, model, base_url)`; `_Candidate` | `_wire_model(..., *, endpoint="")` inserts `responses/` segment; `_Candidate.endpoint`; `_build_chain` reads `providers.<n>.endpoint` |
| `src/hunter/llm/ping.py` | `ping_provider(..., *, litellm_module=None)` | new keyword-only `endpoint=""` passed through to `_wire_model` |
| `src/hunter/llm/providers.py` | docstring says "planner model"/"verify tier" | docstring vocabulary only |
| `src/hunter/llm/probe.py` | `detect_endpoint`/`list_models` (M1) | **unchanged — REUSED, not duplicated** |
| `src/hunter/cli/main.py` | `config provider` sub-app; `add` requires name; `list`/`test`/`show` read `"planner"` | optional `name` → wizard; `app.add_typer(provider_app, name="provider")` shortcut; `test` passes endpoint; `show`/`list`/`add` new vocabulary |
| `src/hunter/cli/provider_add.py` | — | **new**: `run_provider_add_wizard`, `ProviderAddAnswers`, `provider_add_updates` |
| `src/hunter/cli/init_wizard.py` | v1+v2 wizards write/prompt old names | vocabulary update (prompts + `config_updates`/`onboarding_updates` keys); step order untouched |
| `src/hunter/cli/doctor_core.py` | `resolve_model("planner")`, `"planner: <model>"` detail | `resolve_model("orchestrator")`, new labels, legacy-note surfacing |
| `src/hunter/agent/loop.py` | `provider.complete("planner", ...)` | `"orchestrator"` |
| `src/hunter/chat/repl.py` | docstring + `complete("planner", ...)` | `"orchestrator"` |
| `src/hunter/chat/commands.py` | `/model [tier]` validates against `TIERS` | legacy alias accepted (normalized before mutation/persist), hint copy updated |
| `examples/config.example.yaml` | old tier names | new names |
| `README.md`, `docs/LLM.md`, `docs/ARCHITECTURE.md`, `QUICKSTART.md` | old vocabulary in provider/tier prose | new vocabulary |
| `docs/FIRST-RUN.md` | captured v2 transcript with old copy | BUILDER re-captures (prose, untested) |

Tests live flat in `tests/`. Conventions unchanged from M1: string
`rich.Console(file=io.StringIO())` capture, `$HUNTEROS_CONFIG` sandbox +
`HOME`/`USERPROFILE` → `tmp_path`, injected seams, `litellm_module`
fakes, `httpx.MockTransport` for probes — zero network.

---

## 2. Part A — Tier rename + migration (highest-risk change)

### 2.1 Canonical vocabulary (`src/hunter/llm/base.py`)

```python
Tier = Literal["orchestrator", "hunter", "verifier", "utility"]
TIERS: tuple[str, ...] = ("orchestrator", "hunter", "verifier", "utility")

# Old names load fine but never render again (v0.4 rename). Order matters
# only for hint text; keep the rename history order.
LEGACY_TIERS: tuple[str, ...] = ("planner", "exploit", "verify")
LEGACY_TIER_ALIASES: dict[str, str] = {
    "planner": "orchestrator",
    "exploit": "hunter",
    "verify": "verifier",
}

def normalize_tier(name: str) -> str:
    """Canonical tier for ``name``; unknown names pass through unchanged so
    the validator's unknown-tier error still fires with the input echoed."""
    return LEGACY_TIER_ALIASES.get(name, name)
```

- `AGENT_TIERS` stays `("basic", "advanced", *TIERS)` — canonical names only;
  every entry point normalizes BEFORE membership checks.
- `hunter/llm/__init__.py` re-exports `LEGACY_TIER_ALIASES`, `LEGACY_TIERS`,
  and `normalize_tier` alongside `TIERS` (additive).

### 2.2 Occurrence-by-occurrence mapping table (src/ — the authoritative rename spec)

Every old-vocabulary occurrence in `src/hunter` with its fate. "tier" = real
vocabulary; "coincidental" = different concept, DO NOT TOUCH.

| # | Location | Today | Kind | M2 fate |
| --- | --- | --- | --- | --- |
| 1 | `llm/base.py:18-19` | `Tier` Literal + `TIERS` tuple | tier | new names + alias table (§2.1) |
| 2 | `llm/config.py:9` (module docstring) | "→ planner.model" | tier | "→ orchestrator.model" |
| 3 | `llm/config.py:55` (`TierConfig` docstring) | "planner/exploit/verify/utility" | tier | "orchestrator/hunter/verifier/utility" |
| 4 | `llm/config.py:31` | "deterministic/utility behavior" | coincidental (adjective) | unchanged |
| 5 | `llm/config.py:311` + `writing.py:356` | hint "model_tiers:\n  planner:\n    model: ..." | tier | "orchestrator:" |
| 6 | `llm/config.py:322-333` | unknown-tier errors, hint `', '.join(TIERS)` | tier | auto-updates via `TIERS`; message text unchanged |
| 7 | `llm/config.py:443-449` (`agent.tier`) | validates raw value | tier | `normalize_tier` first; hint gains "(legacy names planner/exploit/verify are accepted)" |
| 8 | `llm/config.py:461-469` (`HUNTEROS_TIER`) | validates raw value | tier | `normalize_tier` first; same hint treatment |
| 9 | `llm/config.py:518-537` (`resolve_model`) | `tier != "planner"`, `get("planner")`, docstrings | tier | `tier = normalize_tier(tier)` at entry; compare/lookup `"orchestrator"`; docstrings updated |
| 10 | `llm/config.py:546-548` (`default_model`) | `resolve_model("planner", ...)` | tier | `resolve_model("orchestrator", ...)` |
| 11 | `llm/config.py:597-640` (`config_example_yaml`) | planner/exploit/verify blocks + agent.tier comment | tier | orchestrator/hunter/verifier blocks + "basic \| advanced \| orchestrator \| hunter \| verifier \| utility" |
| 12 | `llm/writing.py:47-52` (`_TIER_COMMENTS`) | old keys + "inherits planner" | tier | new keys; "inherits orchestrator unless set" |
| 13 | `llm/writing.py:252` | agent.tier comment | tier | new vocabulary comment |
| 14 | `llm/providers.py:4-5` (docstring) | "planner model"/"verify tier" | tier | "orchestrator model"/"verifier tier" |
| 15 | `agent/loop.py:4` (docstring) + `:139` | `complete("planner", ...)` | tier | docstring + `complete("orchestrator", ...)` |
| 16 | `chat/repl.py:15` (docstring) | "chat brain is the planner tier" | tier | "orchestrator tier" |
| 17 | `chat/repl.py:221` | `provider.complete("planner", ...)` | tier | `"orchestrator"` |
| 18 | `chat/repl.py:443` (`_agent_tier` docstring) | "(basic\|planner\|...)" | tier | "(basic\|orchestrator\|...)" |
| 19 | `chat/commands.py:602-614` (`/model`) | validates raw tier; hint "e.g. /model planner gpt-4o-mini" | tier | `normalize_tier` before validation/mutation; hint "e.g. /model orchestrator gpt-4o-mini" (§2.4) |
| 20 | `cli/main.py:717` (`config show`) | hardcoded tuple `("planner","exploit","verify","utility")` | tier | iterate `TIERS` (import) |
| 21 | `cli/main.py:759` | `--default-model` help "model_tiers.planner.model" | tier | "model_tiers.orchestrator.model" |
| 22 | `cli/main.py:820` | `updates["model_tiers"] = {"planner": ...}` | tier | `{"orchestrator": ...}` |
| 23 | `cli/main.py:842-857` (`provider list`) | `cfg.model_tiers.get("planner")` | tier | `.get("orchestrator")` |
| 24 | `cli/main.py:896,927-932` (`provider test`) | planner-tier default model | tier | orchestrator tier; plus passes `endpoint=` (§5.3) |
| 25 | `cli/doctor_core.py:160-171` | `resolve_model("planner")`, "model_tiers.planner.model" note, "planner: <m>" | tier | orchestrator equivalents |
| 26 | `cli/doctor_core.py:223-249` | planner model + `model_tiers.get("planner")` | tier | orchestrator equivalents |
| 27 | `cli/init_wizard.py:67-73` (v1 `config_updates`) | `{"planner": ...}`, `{"verify": ...}` | tier | `{"orchestrator": ...}`, `{"verifier": ...}` |
| 28 | `cli/init_wizard.py:295-298` (v1 prompts/print) | "planner model"/"verify model (cheap sibling)" | tier | "orchestrator model"/"verifier model (cheap sibling)"; print `orchestrator=... verifier=...` |
| 29 | `cli/init_wizard.py:469` (v2 step-1 copy) | "(planner / exploit / verify / utility)" | tier | "(orchestrator / hunter / verifier / utility)" |
| 30 | `cli/init_wizard.py:594-637` (v2 models) | `planner_model` var + same-name prompts + `role_models` old keys | tier | `orchestrator_model` var; prompts "orchestrator model"/"hunter model"/"verifier model"/"utility model"; `role_models` new keys |
| 31 | `cli/init_wizard.py:677` (v2 smoke) | `role_models.get("planner")` | tier | `.get("orchestrator")` |
| 32 | `phases.py:68,250,274,278,319` | pipeline phase `"verify"` | coincidental | unchanged |
| 33 | `workflow/pipeline.py` "verify" mentions | phase names | coincidental | unchanged |
| 32b | `chat/repl.py:74` | "verify/report/retro stay PENDING" (PHASE names) | coincidental | unchanged |
| 34 | `engine/llm.py:16` | "the pipeline's verify ladder" | coincidental | unchanged |
| 35 | `kernel/events.py:118` | `def verify(self)` hash-chain check | coincidental | unchanged |
| 36 | `cli/main.py:950-982` | `hunter verify` command | coincidental | unchanged |
| 37 | `agent/tools_base.py` `TIER_ORDER`, `agent/tools.py` `PROBE_TIERS` | capability tiers `basic\|advanced` | coincidental | unchanged |
| 38 | `_data/skills/*/SKILL.md` | "exploits"/"exploitable" prose | coincidental | unchanged |
| 39 | `_data/prompts/audit_system_prompt.md` | (no tier names — grep clean) | — | unchanged |
| 40 | `tui/`, `gateway/` | (no tier literals — grep clean) | — | unchanged |

**Zero-stale-writes guarantee:** after the build, the string literals
`"planner"` / `"exploit"` (any quoting) may appear in `src/hunter/**/*.py`
ONLY in `llm/base.py` (the alias table). Every other occurrence — including
error hints and docstrings that echo the old names — must be built from
`LEGACY_TIERS`/`LEGACY_TIER_ALIASES` instead of literals. This is mechanically
checked (criterion D3). Rationale: `verify`/`utility` cannot be grepped
safely (coincidental uses) and are fully covered by behavior tests instead.

### 2.3 Loader migration (`src/hunter/llm/config.py`)

`HunterConfig` gains one trailing field:

```python
legacy_notes: tuple[str, ...] = ()
```

Note text (normative, one per renamed item, deduped per load, in encounter
order — model_tiers keys first, then agent.tier, then HUNTEROS_TIER):

```
model_tiers.planner renamed to model_tiers.orchestrator (old names are accepted; update your config)
```
(agent.tier / HUNTEROS_TIER notes use the same sentence shape:
`agent.tier 'exploit' renamed to 'hunter' (...)` /
`$HUNTEROS_TIER 'planner' renamed to 'orchestrator' (...)`.)

Loader rules (in the `model_tiers` loop):

1. `name = normalize_tier(str(name))` BEFORE the membership check. Unknown
   names still raise `config.unknown_key` with the ORIGINAL name echoed and
   the hint `valid tier names: <TIERS new names> (legacy names planner,
   exploit, verify are accepted)` — hint built from `TIERS` + `LEGACY_TIERS`,
   never literals.
2. If the legacy key and its canonical twin are BOTH present in the same file
   (`planner` + `orchestrator`): raise `config.value`,
   message `model_tiers has both 'planner' (legacy) and 'orchestrator' — remove the legacy key`,
   hint names both keys. Fail-closed: silently merging two blocks would
   surprise the operator about which values won.
3. `cfg.model_tiers` always ends up keyed by canonical names only;
   `__post_init__` unchanged (all four tiers exist).
4. `agent.tier` and `HUNTEROS_TIER`: `normalize_tier` before validation; a
   mapped value appends its note. Garbage (`"boss"`) still raises
   `config.value` with the canonical vocabulary in the message.
5. "Warning once, not per-call": the notes live on the loaded
   `HunterConfig`; nothing in `resolve_model`/`_build_chain`/`complete` ever
   emits warnings, so a long-lived chat session never re-warns. Surfaces
   print the notes at most once per command:
   - `doctor` (`_llm_checks`): the `llm-config` row detail becomes
     `"<source> — <note 1>; <note 2>"` when notes exist (source string
     unchanged otherwise).
   - `config show`: after the agent rows, `table.add_row("legacy names", "; ".join(cfg.legacy_notes))`
     only when notes exist.

### 2.4 `/model` command (`src/hunter/chat/commands.py::_exec_model`)

- `tier = normalize_tier(positionals[0].lower())` before the `tier not in
  TIERS` check → `/model planner m-x` mutates `cfg.model_tiers["orchestrator"]`
  and (with `--global`) persists `model_tiers.orchestrator` through
  `write_config` — the file NEVER regains an old-name key.
- Reply text uses the CANONICAL name: `orchestrator -> m-x (session-scoped)`.
- Bare `/model` show: iterates `TIERS` (new names render automatically).
- Usage hint (both the `chat.model_usage` error and the registry
  `args_hint`-adjacent copy): `e.g. /model orchestrator gpt-4o-mini — bare
  /model shows the current map`.
- Unknown tier (`/model turbo m-x`) still `config.tier_unknown` with the new
  vocabulary hint.

### 2.5 Wizards (v1 `run_init`, v2 `run_onboarding`) — vocabulary only

- v1 `config_updates`: `model_tiers` keys become `orchestrator` /
  `verifier`; prompt copy becomes "orchestrator model" /
  "verifier model (cheap sibling)"; step print
  `step 5/6 model: orchestrator=<m> verifier=<m| (inherits)>`.
- v2 `onboarding_updates`/`role_models`: keys become the four canonical
  tiers; prompts "orchestrator model" / "hunter model" / "verifier model" /
  "utility model" (advanced mode; defaults keep the same inheritance rules:
  hunter ← orchestrator answer, verifier/utility ← cheap model or
  orchestrator answer); step-1 menu copy
  "(orchestrator / hunter / verifier / utility)"; smoke test reads
  `role_models.get("orchestrator")`.
- Step ORDER, exit codes, clobber guard, notes machinery, disclaimer: all
  byte-identical to M1.

### 2.6 CONTRACT-CHANGE INVENTORY — every existing test that pins old names

The auditor rewrites these DELIBERATELY (mechanical `planner→orchestrator`,
`exploit→hunter`, `verify→verifier` unless noted). Anything NOT listed here
must stay green untouched.

| Test file::test | Lines (approx) | Rewrite |
| --- | --- | --- |
| `tests/test_llm_config.py::FULL_YAML` (fixture) | 19-53 | tier keys → `orchestrator:`/`hunter:`; `agent.tier: verify` → `verifier`. Assertions follow. |
| `tests/test_llm_config.py::test_full_yaml_parse` | 86-109 | `["planner"]`→`["orchestrator"]`, `["exploit"]`→`["hunter"]`, `["utility"]` unchanged |
| `tests/test_llm_config.py::test_env_overrides_win_over_yaml` | 197-213 | `HUNTEROS_TIER: "exploit"` → `"hunter"`; assert `cfg.agent.tier == "hunter"` (legacy-env alias covered by new R5, not here) |
| `tests/test_llm_config.py::test_env_overrides_work_without_file` | 216-219 | NO CHANGE (`utility` is valid in both vocabularies) |
| `tests/test_llm_config.py::test_model_resolution_chain` | 241-264 | `["exploit"]`→`["hunter"]`; `resolve_model("verify",...)`→`("verifier",...)`; `["planner"]`→`["orchestrator"]`; final unresolved probe `resolve_model("planner", ...)`→`("orchestrator", ...)` |
| `tests/test_llm_config.py::test_example_yaml_parses` | 296-304 | `model_tiers["planner"]`→`["orchestrator"]` |
| `tests/test_llm_config.py::test_agent_tier_vocabulary`, `test_defaults_without_file` | — | NO CHANGE (iterate `TIERS`) |
| `tests/test_llm_router.py::make_config` | 102-119 | `"planner"` key → `"orchestrator"` |
| `tests/test_llm_router.py` — all `complete("planner", ...)` / `complete("planner", ..., stream_cb=...)` / budget calls | 24 sites (129, 155, 165, 176, 180, 188, 201, 214, 231, 245, 265, 279, 294, 314, 336, 348, 369, 411, 453, 472, 486, 497) | mechanical → `"orchestrator"` |
| `tests/test_llm_router.py::test_wire_model_prefix_table` | 604-617 | NO CHANGE (new keyword-only param defaults to `""`) |
| `tests/test_chat_commands.py::test_model_show_when_unset` | 236-239 | `"planner" in reply.text` → `"orchestrator"` |
| `tests/test_chat_commands.py::test_model_in_session_mutation` | 242-248 | args `"orchestrator gpt-x"`; `model_tiers["orchestrator"]` |
| `tests/test_chat_commands.py::test_model_global_persists_yaml` | 257-265 | YAML fixture `orchestrator:`; args `"orchestrator new-model --global"`; persisted assert `["orchestrator"]["model"]` |
| `tests/test_chat_commands.py::test_model_global_without_file_hints_env` | 268-272 | args → `"orchestrator"` |
| `tests/test_chat_commands.py::test_model_unknown_tier_blocked` | 251-254 | NO CHANGE (`turbo` still unknown) |
| `tests/test_cli_providers.py::test_add_default_model_pins_planner` | 135-143 | rename to `test_add_default_model_pins_orchestrator`; assert `model_tiers["orchestrator"]` |
| `tests/test_cli_providers.py::test_remove_referenced_provider_refuses_and_force_works` | 155-177 | raw dict `"planner"` → `"orchestrator"`; assert `"model_tiers.orchestrator.provider"` in output |
| `tests/test_cli_providers.py::_config` + `test_keyless_block_routes_api_key_none` + `test_fallback_with_keyless_custom_link_is_dialed` | 230-272 | `"planner"` → `"orchestrator"` (3 sites) |
| `tests/test_cli_init.py::test_init_provider_openrouter_yes_writes_loadable_config` | 71-85 | `["planner"]` → `["orchestrator"]` (2 asserts) |
| `tests/test_cli_init.py::test_build_config_yaml_output_passes_loader` | 104-127 | `["planner"]`→`["orchestrator"]`, `["verify"]`→`["verifier"]` |
| `tests/test_cli_init.py` other v1 tests | — | NO CHANGE (no tier pins; scripted asks take model defaults) |
| `tests/test_cli_init_v2.py::test_onboarding_auto_mode_writes_all_four_tiers` (A1) | 122-148 | `for tier in TIERS:` instead of the old-name tuple |
| `tests/test_cli_init_v2.py::test_onboarding_advanced_mode_per_role_models` (A3) | 177-208 | ask needles → `("orchestrator model", "m-orch")`, `("hunter model", "")`, `("verifier model", "")`, `("utility model", "")`; asserts on `["orchestrator"]/["hunter"]/["verifier"]/["utility"]` |
| `tests/test_cli_init_v2.py::test_onboarding_model_autolist_menu_used_for_custom` (A6) | 283-314 | tier tuple → `TIERS` |
| `tests/test_cli_init_v2.py::test_onboarding_model_autolist_failure_falls_back_to_manual` (A7) | 317-344 | `model_tiers["planner"]` → `["orchestrator"]` |
| `tests/test_cli_init_v2.py::test_onboarding_updates_shape_auto_and_no_provider` (A32) | 514-539 | NO CHANGE (builds from `TIERS`) |
| `tests/test_cli_init_v2.py::test_onboarding_custom_endpoint_probe_stores_chat_and_responses` (A4) + A5/A8/A9/A10/A11/A12 | — | NO CHANGE (no tier pins) |
| `tests/test_adversarial_v02.py::test_config_tier_vocabulary_maps_to_capability_tier` | 420-440 | param values `("planner","advanced")`→`("orchestrator","advanced")`, `("exploit","advanced")`→`("hunter","advanced")`, `("verify","advanced")`→`("verifier","advanced")`; `("utility",...)`, basic/advanced unchanged |
| `tests/test_agent_loop.py::test_system_prompt_and_goal_shape_first_provider_call` | 175 | `== "planner"` → `== "orchestrator"` (this rewrite IS acceptance R15) |
| `tests/test_llm_config_m1.py::test_v03_config_without_new_keys_loads` (A31) | 142-150 | KEEP `V03_YAML` verbatim (it is now the legacy smoke file); `cfg.agent.tier == "verify"` → `== "verifier"`; add `cfg.model_tiers["orchestrator"].model == "claude-sonnet-4-5"` (rename test to `test_v03_config_legacy_tiers_load_mapped`) |
| `tests/test_llm_config_m1.py` endpoint/browser tests (A27-A30) | — | NO CHANGE |
| `tests/test_qa_v03.py::test_write_config_rewrite_is_a_fixpoint_and_round_trips` | 498-520 | updates `"planner"` → `"orchestrator"`; asserts follow (legacy-input migration is covered by new R8, not here) |
| `tests/test_qa_v03.py::test_write_config_type_conflict...` (scalar tier) | 574-575 | input `{"model_tiers": {"planner": "auto"}}` → `{"orchestrator": "auto"}`; message assert `"model_tiers.orchestrator"` |
| `tests/test_qa_v03.py::test_render_config_refuses_pre_corrupted_blocks` | 587 | NO CHANGE (legacy input still raises HunterError after migration) — verified unaffected |
| `tests/test_qa_v03.py::test_yaml_errors_carry_line_numbers` | 900 | NO CHANGE (parse error precedes tier mapping) |
| `tests/test_cli_doctor.py::test_broken_indent_yaml_reports_line_number` | 35-42 | NO CHANGE (parse error, tier name incidental) |

Baseline: 636 green today. After rewrites + new tests (§12), every test green.

---

## 3. Part B — Writer migration (`src/hunter/llm/writing.py`)

`write_config` renders ONLY new names. Add one pure helper, applied in BOTH
`write_config` (after `_deep_merge`) and `render_config` (first statement, so
direct callers are covered too):

```python
def _migrate_legacy_tiers(data: dict[str, Any]) -> dict[str, Any]:
    """model_tiers legacy keys → canonical (move when the twin is absent,
    config.write_failed when both exist); agent.tier legacy value → canonical.
    Mutates + returns ``data``. Import LEGACY_TIER_ALIASES from llm.base."""
```

Rules:
1. For each `old` in `LEGACY_TIER_ALIASES` present under `model_tiers`:
   `new = LEGACY_TIER_ALIASES[old]`; if `new` NOT present → `data["model_tiers"][new] = data["model_tiers"].pop(old)`;
   else → `_config_write_error` message
   `model_tiers has both 'planner' (legacy) and 'orchestrator' — remove the legacy key`.
2. `agent.tier` value mapped through `normalize_tier` when present.
3. `providers`/`fallback_providers` keys are PROVIDER names — never migrated.

Effect: an M1-era file rewritten by ANY M2 write path (provider add,
`/model --global`, wizard re-run) comes back fully canonical — the migration
story is "first write heals the file", and a read-only session still works
because the loader maps on read.

Renderer text changes:
- `_TIER_COMMENTS`: `orchestrator` → 'task decomposition — the "top default"
  model'; `hunter` → "payload/craft tier — inherits orchestrator unless set";
  `verifier` → "evidence checking — a cheap, careful model"; `utility`
  unchanged.
- agent.tier comment: `# basic | advanced | orchestrator | hunter | verifier | utility`.
- `config.py::config_example_yaml` mirrors the same vocabulary (its
  `model_tiers` block, comments, and the agent.tier comment); everything else
  byte-identical to today.

---

## 4. Part C — Router: honor `providers.<n>.endpoint: responses`

### 4.1 LiteLLM research findings (verified in `.venv`, litellm 1.100.1)

- `litellm.responses(...)` EXISTS (signature `input`, `model`, `tools`,
  `stream`, `base_url` via kwargs, ...) — but its response is a
  `ResponsesAPIResponse` (`.output` item list, ResponseAPIUsage) — a SECOND
  normalization/stream path would be needed in the router.
- MUCH better: litellm ships a chat↔responses BRIDGE.
  `litellm.completion(model="<provider>/responses/<model>", messages=...,
  tools=..., stream=...)` routes through
  `litellm.completion_extras.responses_api_bridge.completion`
  (`litellm/completion_extras/litellm_responses_transformation/handler.py`):
  it transforms the chat messages/tools into Responses input, calls the
  responses API, and transforms the result back into a STANDARD chat
  `ModelResponse` (usage converted by
  `ResponseAPILoggingUtils._transform_response_api_usage_to_chat_usage`) and
  streamed events back into chat-shaped `ModelResponseStream` chunks.
- Empirical probes (no network, bridge spied):
  - `responses/gpt-4o` (no provider prefix) → `get_llm_provider` raises
    BadRequestError "LLM Provider NOT provided" — NEVER reaches the bridge.
  - `openai/responses/gpt-4o`, `anthropic/responses/<m>`,
    `openrouter/responses/<m>` → all ENTER the bridge
    (`responses_api_bridge_check` returns `mode="responses"`, model stripped
    to the bare id). Azure form `azure/responses/<deployment>` is explicitly
    handled upstream.
- CONSEQUENT design: **the router never calls `litellm.responses`.** It
  honors `endpoint: responses` by inserting a `responses/` segment AFTER the
  provider prefix in the wire model. One call site, one normalization path,
  one streaming path, one classification path — the bridge owns the wire.

### 4.2 Wire-model rule (`src/hunter/llm/router.py`)

```python
def _wire_model(provider: str, model: str, base_url: str, *, endpoint: str = "") -> str:
    # existing prefix logic first (unchanged) → wire
    if endpoint == "responses" and wire:
        head, sep, rest = wire.partition("/")
        if not sep or not head:
            raise HunterError(
                code="config.value", layer="config",
                message=f"endpoint 'responses' needs a provider with a LiteLLM prefix "
                        f"or a base_url (got provider '{provider}')",
                hint="set providers.<name>.endpoint to 'chat', use a known provider "
                     "name, or add providers.<name>.base_url",
            )
        return f"{head}/responses/{rest}"
    return wire
```

Examples: `openai/gpt-4o` → `openai/responses/gpt-4o`;
`openrouter/anthropic/claude-3` → `openrouter/responses/anthropic/claude-3`;
`azure/responses/<deployment>` (matches litellm's documented Azure form);
unknown-name + base_url `openai/m` → `openai/responses/m`; bare model (auto,
no base_url) → HunterError BEFORE any dial (terminal — `_attempt` re-raises
`HunterError` untouched, so no retries/failover burn on a config mistake).

- `_Candidate` gains `endpoint: str = ""`.
- `_build_chain`: for the primary AND every fallback entry,
  `endpoint = self.config.providers.get(provider_name).endpoint or ""`
  (provider blocks are the single source of the stored shape; fallback
  entries intentionally have no `endpoint` key of their own).
- `_invoke` kwargs unchanged except `model=candidate.wire_model` already
  carries the `responses/` segment. `base_url`, `api_key`, `timeout`,
  `reasoning_effort`, `stream`, `tools` flow through the bridge verbatim.
- Failover/retries/budget: untouched — the bridge sits INSIDE
  `litellm.completion`, so `_attempt`/`complete`/`RunBudget.add_cost` see a
  normal chat response exactly as today. Classification unchanged: a 404
  from a missing `/responses` route arrives as `NotFoundError` →
  `model_not_found` → should_fallback=True (a responses-only outage falls
  back to a chat provider — sensible by construction).

### 4.3 Streaming decision (minimal viable — no new code)

Streaming for responses goes through the SAME `stream=True` +
`_normalize_stream` path: the bridge converts responses SSE events into
chat-shaped `ModelResponseStream` chunks (verified: the transformation module
implements `get_model_response_iterator` over `BaseModelResponseIterator` and
emits `GenericStreamingChunk`s with text deltas + tool-call fragments +
chat-usage conversion). A user who configured `endpoint: responses` gets
streaming tokens in chat exactly like `endpoint: chat`. Non-stream fallback
is NOT needed; if a specific provider's responses streaming is broken
upstream, the error is classified/retried/fallback'd like any provider
failure.

### 4.4 Tool-call regression posture

Our code never parses responses-native shapes, so there is no new parsing to
get wrong: `TurnResult.tool_calls` come from the bridged chat-shaped
`message.tool_calls` exactly as before. Tests assert pass-through (P2/P3)
with the fake litellm seam; litellm's own bridge correctness is upstream's
contract, and any bridge failure is classified/retried/fallback'd by the
existing machinery (no new silent path).

---

## 5. Part D — ping per endpoint type + provider-add wizard

### 5.1 `src/hunter/llm/ping.py`

```python
def ping_provider(
    provider_name: str, model: str, base_url: str = "", api_key: str = "",
    timeout: float = 15, *, endpoint: str = "", litellm_module: Any | None = None,
) -> PingResult:
```

Only change: `wire_model = _wire_model(provider_name, model, base_url,
endpoint=endpoint)`. Additive keyword-only param — every existing caller
(v1/v2 wizard `ping_fn(name, model, base_url, key, 15)`) is unaffected.
Redaction guarantees unchanged (classified messages only).

### 5.2 `hunter config provider add` → optional interactive wizard (new module `src/hunter/cli/provider_add.py`)

Trigger rule (deterministic, no tty sniffing — CliRunner-testable):
- `name` argument becomes OPTIONAL (`typer.Argument("", ...)`).
- `name == ""` → interactive wizard. Every existing flagged invocation
  (`provider add corp --base-url ...`, `provider add groq`,
  `provider add mysterycorp` → exit 2) takes today's code path unchanged —
  the existing tests that pass a name stay green.
- Top-level shortcut: `app.add_typer(provider_app, name="provider")` right
  after the `config` registration (SAME Typer instance, second parent —
  verified working on typer 0.27.2: `hunter provider add|list|test|remove`
  === `hunter config provider ...`; help text identical under both paths;
  no duplicate registration side effects).

New public surface:

```python
__all__ = ["ProviderAddAnswers", "provider_add_updates", "run_provider_add_wizard"]

@dataclass
class ProviderAddAnswers:
    provider: str = ""
    base_url: str = ""
    endpoint: str = ""                 # "" (chat default) | "chat" | "responses"
    key_env: str = ""
    key_inline: str = ""               # keys.env ONLY, never config.yaml, never echoed
    role_models: dict[str, str] = field(default_factory=dict)  # canonical tier -> model
    notes: list[str] = field(default_factory=list)

def provider_add_updates(a: ProviderAddAnswers) -> dict[str, Any]:
    """Pure. providers block (+ endpoint only when set) + model_tiers for the
    four canonical tiers, provider pinned to a.provider or 'auto'."""

def run_provider_add_wizard(
    *, path: str | Path | None = None,
    console: Console | None = None, err_console: Console | None = None,
    ask: Callable[[str, str], str] | None = None,
    secret: Callable[[str], str] | None = None,
    ping_fn: Callable[..., Any] | None = None,
    probe_fn: Callable[..., str] | None = None,      # hunter.llm.probe.detect_endpoint
    list_models_fn: Callable[..., list[str]] | None = None,  # hunter.llm.probe.list_models
    environ: Mapping[str, str] | None = None, home: Path | None = None,
) -> int:
    """Returns 0 on every normal terminal path (failures are notes); lets
    HunterError from the writes propagate (handle.py renders it)."""
```

Shared prompt helpers (`_default_ask`, `_default_secret`,
`_print_export_lines`) are imported from `hunter.cli.init_wizard` (same
package) — no duplication.

### 5.3 Exact wizard UX (copy is normative; `step k/6` prefixes like onboarding)

Header:

```
hunter config provider add — wizard
config target: <target>
Your key is sent nowhere except the provider you pick.
```

**Step 1/6 — provider** — byte-identical rendering to onboarding step 2
(numbered `known_provider_names()` list with notes, `custom` last, digits or
name accepted, unrecognized reply → note + first entry). `custom` additionally
prompts `base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)`;
blank → note `custom provider skipped — no base URL given` and the wizard
prints the notes block and returns 0 (nothing written).
Print `step 1/6 provider: <name> (<base_url>)`.

**Step 2/6 — key** — identical logic/copy to onboarding step 3 (env-set →
`step 2/6 key: using $<KEY_ENV> from the environment — nothing is stored on
disk`; else the two-option key-source menu; paste → `secret(...)` →
keys.env; env-var route → `_print_export_lines`). Keyless known providers:
`step 2/6 key: none needed — this provider is keyless`. No provider (declined
custom): `step 2/6 key: (skipped — no provider configured)`.

**Step 3/6 — endpoint**

```
endpoint for <name>:
  1. chat — OpenAI chat completions (default, works everywhere)
  2. responses — OpenAI Responses API
  3. auto-detect — probe the base URL now
endpoint [1]:
```
- Option 3 is printed ONLY when `base_url` is set. With no base_url the menu
  shows just options 1-2.
- Reply `2`/`responses` → `answers.endpoint = "responses"`;
  print `step 3/6 endpoint: responses`.
- Reply `3`/`auto`/`auto-detect` (only with base_url) → call
  `probe_fn(base_url, key_value, 10)` (key_value = env value or pasted key,
  same expression as onboarding). `"chat"|"responses"` → store +
  `  endpoint: <result>  (POST {base}/chat/completions|responses)`;
  `""` or raise → note
  `endpoint probe failed — storing no endpoint (the router will use the OpenAI chat API)`
  + `  endpoint: undetermined`.
- Anything else (default) → store NOTHING ("" = chat default);
  print `step 3/6 endpoint: chat (default)`.

**Step 4/6 — model**
- With base_url: call `list_models_fn(base_url, key_value, 10)`; non-empty →
  the numbered menu exactly like onboarding (`available models (GET
  {base}/models):`, `m. type a model id manually`, `model [1]:`, digit pick
  or manual `model id` fallback); empty/raise → note
  `model list failed — enter it manually` + `ask("model id", "")`.
- Without base_url: `ask("orchestrator model", known.default_model or "")`
  (known provider takes the table default; custom never reaches here without
  a base URL).
- Blank reply with no default → note `no model given — provider stored without a model`
  and the run ends after this step (roles skipped, smoke skipped).
- Print `step 4/6 model: orchestrator=<model>`.

**Step 5/6 — role assignment**

```
How should this model be assigned?
  1. Auto — one model for every role (orchestrator / hunter / verifier / utility)
  2. Advanced — pick per role
mode [1]:
```
- Auto (DEFAULT): all four canonical tiers get the SAME model.
- Advanced: `orchestrator model [<model>]`, `hunter model [<orchestrator
  answer>]`, `verifier model [<cheap>]`, `utility model [<cheap>]` where
  `cheap = known.cheap_model or the orchestrator answer`.
- Print `step 5/6 roles: auto (one model for all roles)` or
  `step 5/6 roles: advanced`.

**Step 6/6 — smoke test** — onboarding's rules verbatim (skip notes when no
model / declared key missing; `step 6/6 smoke test: dialing
<provider>/<model> with a 1-token ping...`; `ping_fn(provider, model,
base_url, key_value, 15, endpoint=answers.endpoint)`; HunterError →
`smoke test unavailable: ...`; other Exception → `smoke test failed: ...`;
ok → `  smoke test: OK (<n> ms)`).

**Write phase (before step 6):** pasted key →
`write_keys_env({key_env: key_inline})` FIRST and print `wrote <keys_path>`
(path only); then `write_config(provider_add_updates(answers), target)` and
print `[green]added provider '<name>'[/green] → <target>`. After step 6 print
`next: [bold]hunter config provider test <name>[/bold] · provider list`, then
the `notes:` block when notes exist (same rendering as onboarding).

### 5.4 `provider test` honors the stored endpoint

`provider_test` passes `endpoint=(prov.endpoint if prov is not None else "")`
to `ping_provider`. `provider list` keeps its exact columns (key source shows
`env:<NAME>`/`inline`/`keyless` — never a value) and switches its
default-model lookup to the orchestrator tier.

---

## 6. Part E — example config + docs

- `examples/config.example.yaml`: tier keys → `orchestrator:` /
  `hunter:` / `verifier:` / `utility:` (comments updated to match §3 text),
  agent.tier comment → new vocabulary, and a commented
  `#   endpoint: responses  # OpenAI Responses API (chat is the default)`
  line inside the provider block comment area. Everything else unchanged.
- `README.md` (line ~33): `(planner/exploit/verify/utility)` →
  `(orchestrator/hunter/verifier/utility)`.
- `docs/LLM.md`: §"One model per tier" paragraph, the `agent.tier` table row,
  every config snippet, the `config.model_unresolved` hint row, and the
  doctor description → new vocabulary; add one sentence: legacy names
  `planner/exploit/verify` still load but are auto-renamed on the next
  config write.
- `docs/ARCHITECTURE.md` (L32, 67, 85-89): vocabulary + "orchestrator.model"
  references; L251 (`planner/recon/exploit-verify agents`) is historical
  version-history prose — left as-is.
- `QUICKSTART.md` (L151): `(planner)` → `(orchestrator)`.
- `docs/FIRST-RUN.md`: BUILDER re-captures the v2 transcript (old copy
  appears there) — prose, untested.
- Historical docs (`docs/ROADMAP-v0.3.md`, `docs/BUSINESS.md`, the M1 plan):
  left untouched on purpose.

---

## 7. Existing contracts that must NOT break (builder's red lines)

1. `tests/test_llm_probe.py` — `detect_endpoint`/`list_models` untouched; the
   wizard REUSES them via seams (no duplication).
2. `tests/test_llm_router.py::test_wire_model_prefix_table` — `_wire_model`
   stays callable with the 3-arg positional form (new param keyword-only,
   default `""`).
3. v1 `run_init` tests except the two tier-key assertions listed in §2.6 —
   step order, exit codes, clobber, key-echo rules unchanged.
4. `hunter config provider add <name> ...` flagged behavior — all existing
   tests in `tests/test_cli_providers.py` except the three rewrites in §2.6
   stay green as-is (including `test_add_unknown_name_without_base_url_exits_2`,
   which PROVES the wizard trigger is name-omission, not flag-absence).
5. `hunter llm ping` seam (`litellm_module`) untouched; `litellm_module`
   injection remains the ONLY litellm entry in tests.
6. Error taxonomy + redaction: `_redact`, `_REASON_TO_ERROR`, exit codes,
   `PingResult` contract unchanged; keys never appear in wizard/CLI output
   or config files (inline `api_key` still exists ONLY via the legacy
   `--api-key-stdin` flag path).
7. No new dependencies; no test touches the network; `$HUNTEROS_CONFIG` +
   `HOME`/`USERPROFILE` sandboxing mandatory in all new tests (copy
   `_cli_env` from `tests/test_cli_init_v2.py`).

---

## 8. Data flow (one glance)

```
hunter provider add            (no name)
  └─ run_provider_add_wizard
       ├─ ask/secret ─────────────► ProviderAddAnswers
       ├─ probe_fn(base_url, key) ► answers.endpoint   (auto-detect option only)
       ├─ list_models_fn(base_url)► answers.role_models (or manual fallback)
       ├─ write_keys_env({key_env: key_inline})         (only when pasted; BEFORE config)
       ├─ write_config(provider_add_updates(answers))   (merge; renders NEW names only)
       └─ ping_fn(..., endpoint=answers.endpoint)       (smoke test, notes on fail)
router.complete(tier, ...)
  └─ resolve_model(tier) ─ normalize_tier (defensive)
  └─ _build_chain: endpoint = providers[<p>].endpoint ─► _Candidate.endpoint
  └─ _wire_model(provider, model, base_url, endpoint) ─► "openai/responses/m1"
  └─ litellm.completion(...)  ── chat⇄responses BRIDGE (litellm) ──► ModelResponse
  └─ _normalize / _normalize_stream / budget / failover  (unchanged)
load_config(legacy file)
  └─ model_tiers keys mapped (+legacy_notes) ─► cfg.model_tiers canonical
  └─ first write via write_config heals the file (writer migration)
```

---

## 9. litellm environment findings (recorded 2026-09-13)

- Installed: **litellm 1.100.1** (`.venv/Lib/site-packages/litellm`).
- `litellm.responses` exists (`hasattr(litellm, "responses")` → True).
- pyproject floor is `litellm>=1.40` (`dependencies` + `[llm]` extra) —
  **unchanged**: fresh installs resolve ≥1.100.x, which contains the
  chat⇄responses bridge (`litellm/completion_extras/litellm_responses_transformation/`)
  used by this design. No bump required, no new dependency.
- Degradation on 1.40–1.62 (bridge absent): `openai/responses/<m>` would be
  dialed as an ordinary chat model named `responses/<m>` → the provider
  answers 404 → classified `model_not_found` with the existing
  fallback-chain hint. Honest, classified, no crash; documented in LLM.md.
- Empirical bridge-entry check (spy on
  `litellm.completion_extras.responses_api_bridge.completion`, no network):
  `openai/responses/gpt-4o`, `anthropic/responses/claude-3-5-sonnet`,
  `openrouter/responses/m/a` → bridge entered;
  `responses/gpt-4o` (prefixless) → BadRequestError before the bridge.

---

## 10. ACCEPTANCE CRITERIA

### (a) pytest-testable Python behavior — each maps to exactly one test

**Rename + migration**

- **R1** Vocabulary: `TIERS == ("orchestrator", "hunter", "verifier",
  "utility")`; `LEGACY_TIERS == ("planner", "exploit", "verify")`;
  `LEGACY_TIER_ALIASES == {"planner": "orchestrator", "exploit": "hunter",
  "verify": "verifier"}`; `normalize_tier` maps all three legacy names,
  passes all four canonical names and unknown names through; `AGENT_TIERS`
  contains basic/advanced + the four canonical names.
- **R2** Legacy model_tiers config loads mapped: a file with
  `planner/exploit/verify` blocks loads with the values under
  `orchestrator/hunter/verifier`, `set(cfg.model_tiers) == set(TIERS)`, and
  `cfg.legacy_notes` mentions all three renames.
- **R3** New-name config loads with `cfg.legacy_notes == ()`.
- **R4** Both-names conflict: `model_tiers` containing `planner` AND
  `orchestrator` → `HunterError` code `config.value` with both key names in
  the message.
- **R5** Legacy `agent.tier: exploit` loads as `agent.tier == "hunter"` with
  a note; `HUNTEROS_TIER=planner` → `cfg.agent.tier == "orchestrator"` with
  a note.
- **R6** `HUNTEROS_TIER=boss` (garbage) still raises `config.value` naming
  `HUNTEROS_TIER`; unknown `model_tiers.boss` still `config.unknown_key`
  with the hint listing the NEW tier names (and the legacy-accepted
  sentence).
- **R7** Writer renders only new names:
  `write_config({"model_tiers": {"planner": {...}}}, path)` produces a file
  containing `orchestrator:` and NOT `planner:`; it loads with the values
  under `orchestrator`.
- **R8** Writer both-names conflict: pre-existing canonical file + updates
  with the legacy twin → `HunterError` (`config.write_failed`), file bytes
  untouched on disk.
- **R9** Writer migrates `agent.tier`: `write_config({"agent": {"tier":
  "verify"}}, path)` → file contains `tier: verifier`; loads as `"verifier"`.
- **R10** `render_config({})` emits the four canonical tier blocks (with the
  new `_TIER_COMMENTS` text), the updated agent.tier comment line, and loads
  via `load_config`; `config_example_yaml()` likewise loads and contains no
  `planner`/`exploit` literals.
- **R11** `/model` legacy alias: `/model planner m-x` (a) mutates
  `cfg.model_tiers["orchestrator"].model`, (b) reply text names
  `orchestrator`, (c) with `--global` persists `model_tiers.orchestrator`
  and the file contains no `planner:` key.
- **R12** `/model turbo m-x` still `[ERROR config]`.
- **R13** `config show` renders `model_tiers.orchestrator` …
  `model_tiers.utility` rows (no `planner`), and with a legacy config also a
  `legacy names` row.
- **R14** Doctor maps legacy: with a legacy config the `llm-model` check is
  `ok` with detail `orchestrator: <model>`, and the `llm-config` row detail
  contains the rename note.
- **R15** Agent loop dials the orchestrator tier: fake provider records
  `calls[0]["tier"] == "orchestrator"`.
- **R16** Stale-write static scan: for every `*.py` under `src/hunter`, the
  literals `"planner"` and `"exploit"` (both quote styles) appear ONLY in
  `src/hunter/llm/base.py`.

**Router responses path**

- **P1** `_wire_model` responses table (no network): openai →
  `openai/responses/gpt-4o`; already-prefixed model never double-prefixed
  (`openai/openai/gpt-4o` input → `openai/responses/openai/gpt-4o`);
  openrouter nested model keeps its path; azure form
  `azure/responses/<deployment>`; unknown+base_url →
  `openai/responses/m`; auto+base_url → `openai/responses/m`; bare model
  (auto/unknown without base_url) → `HunterError` code `config.value`;
  `endpoint=""` reproduces the existing prefix table exactly.
- **P2** Router honors the provider endpoint: `ProviderConfig(endpoint="responses")`
  → fake litellm receives `model == "openai/responses/m1"` and otherwise
  identical kwargs; a chat provider (endpoint "") receives `openai/m1`
  (regression guard).
- **P3** Failover honors per-candidate endpoint: primary (chat) 401 →
  fallback whose provider block has `endpoint="responses"` is dialed with
  the `responses/` wire model and the fallback's resolved key.
- **P4** Prefixless responses is terminal config: tier provider `auto`, no
  base_url, provider block `endpoint="responses"` → `complete()` raises
  `config.value` and the fake litellm recorded ZERO calls.
- **P5** Streaming passes through: responses candidate with `stream_cb` →
  fake receives `stream=True` + the prefixed model; the streamed chunks
  normalize into a `TurnResult` (existing `_normalize_stream`, prefix-only
  assertion).
- **P6** `ping_provider(endpoint="responses")` → fake litellm receives
  `model == "openai/responses/m1"`; default call unchanged (`openai/m1`).
- **P7** CLI `provider test` passes the stored endpoint: config with
  `providers.corp.endpoint: responses` + `--default-model` → fake litellm
  receives the prefixed wire model; exit 0.

**Provider-add wizard + shortcut**

- **W1** `hunter config provider add` (no name) runs the wizard: scripted
  answers (`groq`, env key) write a providers block AND all four canonical
  tiers with the table default model; `agent`/budget untouched elsewhere
  (merge preserved when a config already exists).
- **W2** Custom provider + pasted key: base URL prompt → `secret` sentinel
  lands in keys.env (never config.yaml, never echoed), `key_env` recorded in
  the providers block; endpoint probe seam returns `"responses"` →
  `providers.custom.endpoint == "responses"`.
- **W3** Endpoint auto-detect: probe seam receives `(base_url, key_value,
  10)` and its result is stored; probe returning `""` and probe raising each
  produce the `endpoint probe failed` note with no endpoint stored, exit 0.
- **W4** Endpoint menu semantics: default (option 1) stores NO endpoint key;
  option 2 stores `responses` WITHOUT probe_fn being called; option 3
  without a base_url is not offered (menu renders two options).
- **W5** Model auto-add for base_url providers: `list_models_fn` list renders
  the numbered menu; the scripted pick lands in all four tiers (auto mode).
- **W6** Model list failure (`[]` and raising) → `model list failed` note +
  the manually entered id lands in all four tiers.
- **W7** Advanced role assignment: per-role scripted answers land in
  `orchestrator/hunter/verifier/utility` exactly; blank hunter → orchestrator
  answer; blank verifier/utility → cheap model (or orchestrator answer when
  no table).
- **W8** Smoke-ping failure is a note with exit 0 and the write still
  happened; the sentinel key never appears in stdout/stderr.
- **W9** Known provider without base_url: the endpoint menu has no
  auto-detect option, `list_models_fn` is NEVER called, the model prompt
  takes the table default, and the written providers block has no
  `base_url`/`endpoint` keys.
- **W10** Flagged path unchanged: `provider add mysterycorp` (no flags) →
  exit 2 with `--base-url` hint (wizard NOT triggered); `provider add demo
  --base-url http://x/v1 --default-model m1` pins
  `model_tiers.orchestrator.model == "m1"` and stores no endpoint.
- **W11** `provider_add_updates` pure shape: (i) full answers (provider,
  base_url, endpoint, key_env, four role models) and (ii) no-model answers
  (providers block only) — exact dict equality.
- **W12** Top-level shortcut: `hunter provider list` (root app) exits 0 and
  renders the same providers table as `hunter config provider list`;
  `hunter provider add` (no further args) triggers the wizard exactly like
  W1's trigger (the monkeypatched wizard sentinel invoked exactly once).
- **W13** keys.env ordering: with a pasted key AND a `write_config` that
  would fail (corrupted existing config), keys.env already exists (written
  first) and the classified error propagates (no traceback).

**Docs / static**

- **D1** `examples/config.example.yaml` contains `orchestrator:`,
  `hunter:`, `verifier:`, `utility:` and NO `planner`/`exploit` anywhere;
  the file loads via `load_config`.
- **D2** `README.md` contains `(orchestrator/hunter/verifier/utility)`;
  `docs/LLM.md` contains `orchestrator` and documents the legacy-accepted
  sentence; `docs/ARCHITECTURE.md` and `QUICKSTART.md` contain
  `orchestrator`.
- **D3** is R16 (listed there to keep one-criterion-one-test).

### (b) Script-level checks

None expected — M2 adds no installer/shell surface.

---

## 11. ADVERSARIAL matrix (risk → design answer → where tested)

| # | Risk | Design answer | Test |
| --- | --- | --- | --- |
| 1 | Old-name config loaded → warning spam per call | Notes ride on the loaded `HunterConfig`; resolution/complete paths NEVER warn; surfaces print at most once per command | R2, R13, R14 |
| 2 | Key leaked in `provider test`/`list`/wizard output | list prints only the key SOURCE; wizard sentinel echo test; ping classification redaction untouched | W8, W2, §7.6 |
| 3 | `providers.<n>.endpoint` corrupt (e.g. `grpc`) | Loader rejects at load (`config.value`, M1 rule unchanged); writer never invents endpoint values | P2 uses valid values; existing A28 test stays green |
| 4 | Responses-mode tool-call regression | No new parsing: bridge returns chat-shaped tool_calls; classification/failover unchanged; pass-through asserted | P2, P3, P5 |
| 5 | Wizard crash leaves loadable config | All prompts precede all writes; writes go through atomic `write_config`; keys.env written first (crash can only leave keys-without-config, next run heals) | W13, W1 |
| 6 | `HUNTEROS_TIER` garbage | Normalization maps only the three known aliases; anything else fails `config.value` with the canonical vocabulary | R6 |
| 7 | `/model` with old name writes an old-name key | Alias normalized BEFORE mutation and persistence; writer migrates legacy keys anyway (belt-and-braces) | R11, R7 |
| 8 | Legacy + canonical twin keys in one file | Fail-closed `config.value` (loader) / `config.write_failed` (writer) naming both — no silent merge precedence | R4, R8 |
| 9 | `responses` endpoint on a provider without any prefix | Terminal `config.value` before dialing — no wasted retries/failover | P4 |
| 10 | Prefixless `responses/...` sent to litellm | Impossible by construction: `_wire_model` raises before `litellm.completion` sees it | P1, P4 |
| 11 | Old litellm (1.40–1.62) without the bridge | Wire model dials as a chat model → provider 404 → classified `model_not_found` + fallback hint; documented | §9 (doc-level) |
| 12 | Typer double registration breaks help/commands | Same instance verified working on typer 0.27.2; `--help` still lists doctor/scan (existing test) | W12, existing `test_hunter_help_still_prints_full_dump` |
| 13 | Stale old-name writes hidden somewhere in src/ | Static scan: old-name literals only in `llm/base.py` (alias table) | R16 |
| 14 | Wizard triggers accidentally in CI (flag-less scripted runs) | Trigger is name-OMISSION only; every flagged/unknown-name invocation keeps today's behavior | W10, existing provider-add tests |
| 15 | Rename breaks `/model` show for legacy configs | Loader maps before the REPL ever sees tiers; show iterates canonical `TIERS` | R13, R11 |

---

## 12. TEST PLAN (auditor implements verbatim)

New files:

| File | Test name | Asserts |
| --- | --- | --- |
| `tests/test_llm_rename.py` | `test_tier_vocabulary_and_normalize` | R1 |
| `tests/test_llm_rename.py` | `test_legacy_model_tiers_load_mapped_with_notes` | R2 |
| `tests/test_llm_rename.py` | `test_new_name_config_loads_without_notes` | R3 |
| `tests/test_llm_rename.py` | `test_both_legacy_and_canonical_tier_rejected` | R4 |
| `tests/test_llm_rename.py` | `test_agent_tier_and_env_legacy_aliases_map` | R5 |
| `tests/test_llm_rename.py` | `test_garbage_tier_inputs_still_rejected` | R6 |
| `tests/test_llm_rename.py` | `test_write_config_renders_only_new_names` | R7 |
| `tests/test_llm_rename.py` | `test_write_config_both_names_conflict_untouched_disk` | R8 |
| `tests/test_llm_rename.py` | `test_write_config_migrates_agent_tier_value` | R9 |
| `tests/test_llm_rename.py` | `test_render_and_example_yaml_new_vocabulary` | R10 |
| `tests/test_llm_rename.py` | `test_model_command_legacy_alias_persists_orchestrator` | R11 |
| `tests/test_llm_rename.py` | `test_model_command_unknown_tier_still_blocked` | R12 |
| `tests/test_llm_rename.py` | `test_config_show_new_rows_and_legacy_note` | R13 |
| `tests/test_llm_rename.py` | `test_doctor_maps_legacy_config_and_notes` | R14 |
| `tests/test_llm_rename.py` | `test_no_stale_old_name_literals_outside_base` | R16 |
| `tests/test_llm_router_responses.py` | `test_wire_model_responses_insertion_table` | P1 |
| `tests/test_llm_router_responses.py` | `test_router_honors_provider_endpoint_responses` | P2 |
| `tests/test_llm_router_responses.py` | `test_fallback_candidate_inherits_provider_endpoint` | P3 |
| `tests/test_llm_router_responses.py` | `test_prefixless_responses_is_terminal_config_error` | P4 |
| `tests/test_llm_router_responses.py` | `test_streaming_responses_passes_prefixed_model` | P5 |
| `tests/test_llm_router_responses.py` | `test_ping_provider_endpoint_kwarg` | P6 |
| `tests/test_llm_router_responses.py` | `test_provider_test_passes_stored_endpoint` | P7 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_auto_mode_writes_tiers` | W1 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_custom_key_and_endpoint` | W2 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_autodetect_and_failure_note` | W3 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_endpoint_menu_semantics` | W4 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_model_autolist_menu` | W5 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_model_list_failure_fallback` | W6 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_advanced_role_assignment` | W7 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_smoke_failure_and_key_silence` | W8 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_known_provider_without_base_url` | W9 |
| `tests/test_cli_provider_add_wizard.py` | `test_flagged_add_path_unchanged` | W10 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_updates_pure_shape` | W11 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_top_level_shortcut_group` | W12 |
| `tests/test_cli_provider_add_wizard.py` | `test_provider_add_wizard_keys_env_written_first` | W13 |
| `tests/test_llm_rename.py` | `test_example_yaml_and_docs_vocabulary` | D1+D2 (single static test) |
| `tests/test_agent_loop.py` | `test_system_prompt_and_goal_shape_first_provider_call` (rewritten) | R15 |

Rewrites (existing files — see §2.6 for the exact per-test diffs): every row
of the §2.6 inventory, including `tests/test_agent_loop.py`
(test_system_prompt_and_goal_shape_first_provider_call → R15) and
`tests/test_llm_config_m1.py::test_v03_config_legacy_tiers_load_mapped`.

Conventions for the auditor: copy `_string_console`/`_cli_env`/hygiene rules
from `tests/test_cli_init_v2.py`; needle-matching scripted `ask`
(most-specific first); inject `probe_fn`/`list_models_fn`/`ping_fn` (never
let a seam reach the network); router tests use `FakeLiteLLM`-style fakes;
the static tests (R16, D1/D2) read repo files with `pathlib` — no execution,
no network; delete `HUNTEROS_TIER` in every new test's env hygiene fixture.

---

## 13. Verify commands (Windows dev reality)

```bash
.venv/Scripts/python -m pytest tests/test_llm_rename.py \
  tests/test_llm_router_responses.py tests/test_cli_provider_add_wizard.py -q
.venv/Scripts/python -m pytest -q        # full suite: 636 baseline, all green
.venv/Scripts/python -m ruff check src tests
# litellm sanity (already recorded in §9):
.venv/Scripts/python -c "import litellm; print(hasattr(litellm, 'responses'))"
```

---

## 14. Builder order (suggested)

1. `llm/base.py` vocabulary + `normalize_tier` (R1) — everything imports it.
2. Loader migration + `legacy_notes` (R2-R6) + the `test_llm_config.py`
   rewrites that unblock the suite.
3. Writer migration + renderer/example text (R7-R10) + `test_qa_v03.py`
   rewrites.
4. Callers sweep: loop, repl, commands `/model`, main.py
   show/add/list/test, doctor_core, both wizards (R11-R15 + §2.6 rewrites).
5. Router `_wire_model` + `_Candidate.endpoint` + ping `endpoint` (P1-P7).
6. `provider_add.py` wizard + CLI optional-name + typer shortcut (W1-W13).
7. Static scans (R16, D1/D2) last, then docs prose + FIRST-RUN re-capture.
