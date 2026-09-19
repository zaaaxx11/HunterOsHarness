# Reference UX pattern dossier — M11 adoption map

Verified pattern dossier behind `docs/plans/m11-ux.md` (M11 —
Polished UX, v0.6.0). One section per adopted pattern: what the reference does,
what HunterOS takes, and where it lands. The Adoption map table at the end is
the per-item index the milestones cite — no milestone re-derives a decision
recorded here.

## home-dir

Reference keeps ONE home (a single reference home) for everything user-facing: config,
sessions, state. Secrets live in a `.env` file beside it (never in the YAML),
and the YAML references them as `${VAR}` names — never values.

HunterOS adoption (M1): one unified home `~/.hunter` for `config.yaml`,
`keys.env`, `chat.db`, the default ledger state dir, `daemon/`, `approvals/`,
`reports/`, `sessions/`, and `skills/`. `keys.env` is the secrets-only file
(keys NEVER in config.yaml — the existing doctrine, now at the new path). The
old `~/.hunteros` becomes plumbing only (venv, `bin/` shims,
`update-check.json`) and is NEVER deleted; a copy-once migration moves
user-facing state on first load, originals kept.

## config

Reference exposes a full management surface — `show/edit/get/set/unset/path/
env-path/check/migrate` — with a wizard that backs up before overwriting,
shows existing values as keep-defaults, and never silently clobbers.

HunterOS adoption (M1): `hunter config path/get/set/unset/edit/check` plus
`config key set/list` for masked key management, and `hunter where` to print
the resolved layout. Unknown keys are REFUSED on `config set` (exit 8) because
the loader is strictly fail-closed — saving an unknown key would brick every
later command. Adopted halves: the advisory probe and the never-silent rule.

## chat-CLI

Reference ships interactive chat plus a one-shot mode (`-z`), resumable SQLite
sessions (`--resume`/`--continue`), and a single slash-command registry shared
by every surface.

HunterOS adoption (M3): `hunter chat "text"` one-shot, `--resume <id|last>` /
`--continue` / `--list`, unknown session ids fail with the recent-session list
(never silently discarded), and ONE no-provider setup panel instead of
per-line error spam. Free text containing hunt keywords gets a normal reply
plus a `💡` hint — it never auto-starts an audit and never declines
headlessly; only `/audit`, `/hunt <target>`, and explicit `hunt_mode`
intercept.

## provider

Reference custom-endpoint flow: numbered provider menu, masked key capture, an
ADVISORY `/models` probe (never fatal), per-host key variable names derived
from the endpoint, and a `Detected model:` auto-pick when exactly one model is
visible.

HunterOS adoption (M4): `key_env_for_endpoint` per-host key vars, advisory
probe copy with the `/v1` hint, `hunter model` picker writing all four tiers,
and honest local-server hints (`ollama serve`). Probes stay advisory — a
failed probe still saves the provider.

## gateway

Reference daemon surface: `run/start/stop/restart/status/install/list/setup`,
a drain-first restart (in-flight work finishes, then the process exits), a
restart marker that suppresses stale deliveries, and idempotent restart
(restart when stopped simply starts).

HunterOS adoption (M5): `gateway stop/restart/status/logs` verbs delegating to
the daemon CLI, top-level `hunter restart` / `hunter logs`, drain-first
restart with a timeout escalation to force-stop, `daemon/restart.json` marker
consumed on boot, and auto-start when nothing was running.

## gateway-config

Reference renders gateway status with the live config path and ends every status
screen with the exact next commands.

HunterOS adoption (M5/M6): `daemon_status` carries `config_path`; the status
render gains `💡 logs/stop/restart` trailers and the TUI consumes the same
line builder (single source).

## TUI

Reference TUI: identity theme (its gold-on-navy), a status bar, and panes per
concern; skins are pure data.

HunterOS adoption (M6): identity theme is HunterOS teal-on-navy (the palette
is soul — not Reference gold), a status bar (version · model · tier · engine),
new Engine and Config panes, and the Doctor tab re-rendered from
`doctor_core.collect_checks` (the duplicated logic and its stale copy are
deleted). Skins-as-data are deferred.

## hospitality

Reference hospitality rules: y/N prompts only for dangerous operations, every
error ends with the exact next command as a `💡` trailer, emoji as state
language, a pause/resume sentinel that never kills in-flight work, and never
silently overwriting user data.

HunterOS adoption (M2/M3/M7/M8): `hunter/hospitality.py` authors every pinned
string (surfaces render); `hunt start` asks exactly TWO questions and never a
y/N (scope auto-authorized and recorded under `agent.approved_scopes`,
opt-back-in via `agent.scope_confirm`); the wizard buffers writes so Ctrl+C
before the write changes nothing; `hunter pause`/`hunter resume` write a
sentinel the daemon claims-gate honors (in-flight runs always complete);
`exit_hint` backstop appends `💡 Try: ...` to hintless classified errors only.

## tools

Reference keeps a single tool registry with per-surface entry points and never
duplicates logic between surfaces.

HunterOS adoption (M2/M6): `cli/wizard_steps.py` extracts the shared wizard
steps so init and provider-add cannot drift; the TUI Doctor tab consumes
`doctor_core` directly (single source of truth).

---

## Adoption map

| Governed pattern | HunterOS implementation | Milestone |
| --- | --- | --- |
| One reference home | `~/.hunter` unified home (`hunter/home.py`) | M1 |
| `.env` secrets-only file | `keys.env` moves to `~/.hunter/keys.env` | M1 |
| Copy-once migration, originals kept | `ensure_home()` migration + doctor rows | M1 |
| `config path/get/set/unset/edit/check` | `hunter config` verbs (`cli/config_cmd.py`) | M1 |
| `where` layout command | `hunter where --json` | M1 |
| Never silently overwrite (backup first) | `config edit` `.bak` + wizard timestamped backup | M1/M2 |
| Refuse-to-save dangerous state | `config set` refuses unknown keys (exit 8) | M1 |
| Wizard mode picker | Quick / Advanced / Blank Slate picker | M2 |
| Existing values as keep-defaults | bracketed defaults in the unified wizard | M2 |
| Graceful Ctrl+C everywhere | buffered writes + cancelled copy + exit 130 | M2 |
| Single slash registry, one-shot chat | `hunter chat "text"` + shared ChatEngine | M3 |
| `--resume`/`--continue`/`--list` | chat session flags (SQLite ChatStore) | M3 |
| Unknown id never silent | `unknown_session_message` + exit 2 | M3 |
| One no-provider setup panel | `hospitality.no_provider_message` panel-once flow | M3 |
| Free text never swallowed | conversational reply + `💡` hunt hint (Q3) | M3 |
| Numbered provider menu, custom last | shared `wizard_steps.pick_provider` | M2/M4 |
| Advisory `/models` probe | `probe_verified_line` / `probe_unverified_line` copy | M4 |
| Per-host key variable | `key_env_for_endpoint` + keys.env save confirmation | M4 |
| `Detected model:` auto-pick | `pick_model` single-model keep-default | M4 |
| `hunter model` picker | `cli/model_cmd.py::run_model_picker` (all four tiers) | M4 |
| Local-server auto-probe hint | `ollama serve` hint on empty model list | M4 |
| Gateway verb set | `gateway stop/restart/status/logs` | M5 |
| Top-level `restart`/`logs` | `hunter restart` / `hunter logs --follow` | M5 |
| Drain-first restart | `drain_daemon` + `drain.flag` claim gate | M5 |
| Restart marker suppresses stale deliveries | `daemon/restart.json` consumed on boot | M5 |
| Idempotent restart (stopped → start) | `engine was not running — starting it` | M5 |
| Status shows config path + next commands | `status_lines()` shared CLI/TUI renderer | M5 |
| Identity theme | HunterOS teal-on-navy TUI CSS (Q10) | M6 |
| Status bar | version · model · tier · engine bar (30s refresh) | M6 |
| Panes per concern | Engine + Config panes in the TUI | M6 |
| Single doctor source | TUI Doctor tab renders `doctor_core.collect_checks` | M6 |
| Two-question start, no y/N | `hunt start` Target URL + Time (Q11 positional) | M7 |
| Audit trail for auto-authorized scope | `agent.approved_scopes` (cap 50) | M7 |
| Opt-back-in confirmation | `agent.scope_confirm: true` restores refusal | M7 |
| y/N only for dangerous ops | plain `hunter hunt` keeps its confirm gate | M7 |
| Exact-next-command `💡` trailers | `hospitality.exit_hint` backstop in `handle.py` | M8 |
| Emoji as state language | 📋 ✅ ⚠️ 💡 ⏸️ on new surfaces only (Q7) | M8 |
| Pause/resume sentinel never kills work | `hunter pause`/`hunter resume` + `pause.flag` | M8 |
| Instant, side-effect-free version | `hunter --version` short-circuits | M8 |
| venv on PATH before shims | `install.ps1` PATH order fix | M8 |
