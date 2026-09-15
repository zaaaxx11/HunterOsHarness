# Changelog

All notable changes to HunterOs Harness are documented here.

Compare releases: `v0.3.1...v0.4.0`.

## [Unreleased]

## [0.5.0] - 2026-09-14

### Approval gate and shell

- Added `shell_exec` (denylist-first, minimal env, state-dir-contained cwd,
  16k redacted output cap, unparseable commands refused) and
  `runtime_inventory`; every execution — allowed or blocked — lands a ledger
  event.
- Added the approval gate: catastrophic commands never run in any mode,
  `approval`-danger tools fail closed without a gate, pending requests
  expire (300s TTL) and decisions are single-use, and `/approve <id>` /
  `/deny <id>` over chat nudge the agent to retry or move on.

### Daemon — 24/7 hunts

- Added `hunt start/stop/status/restart/logs` (plus top-level `hunter
  start/stop/status` aliases): detached spawn with a PID-reuse guard,
  heartbeats with staleness, an atomic single-winner task queue, and a
  stop-file estop that outranks cost inside the run budget.

### Time budget and unlimited credit

- Added `min_wall_seconds`: the time given to a hunt is a floor, never a
  stop reason — the engine is nudged to keep hunting (bounded) until it
  passes. Added the `hunter.duration` grammar (`90s`, `90m`, `2h`,
  `1h30m`). `0 = unlimited` for every budget key (`max_cost_usd`,
  `max_iterations`, `wall_seconds`, `min_wall_seconds`); negatives stay
  refused.

### Browser cloak

- Added the browser cloak (on by default): plausible user-agent, viewport,
  locale, and timezone pools chosen per context, non-automation launch
  arguments, and one masking init script. The scope route interceptor,
  out-of-scope aborts, and every redaction pass are untouched; `cloak:
  false` restores stock behavior exactly.

### Soul — the operating character

- Added `SOUL.md`: the user-editable operating character (silent, precise,
  patient, evidence-or-nothing, scope discipline, no drama, hard-won
  brevity — no levels, no scoring). It ships bundled byte-equal, binds
  every prompt turn, and is always preceded by the engine-hardcoded core
  identity (`hunter/agent/soul.py` `CORE_IDENTITY`). Persona text is
  sanitize-not-refuse: injection markers are neutralized and length is
  capped at 4000 chars.

### Context compression

- Added extractive session compaction: head and tail kept verbatim, the
  middle summarized with real-message prefixes only, evidence and run ids
  preserved in full, the store untouched (append-only) — `/compress` in
  chat, automatic above 24k chars in the conversational path.

### Discord and WhatsApp gateways

- Added the Discord adapter (`hunteros-harness[discord]`; 2000-char UTF-16
  chunking) and the WhatsApp Cloud adapter (4096-char chunks; loopback
  webhook with Meta hub verification and `X-Hub-Signature-256` HMAC checks
  — missing or invalid signatures get 403 and the handler is never called).
  Both are default-deny: a token without an allowlist refuses to start.

### Scripts, docs, and release hygiene

- Added `scripts/`: `huntctl.py`, `stop_hunt.py`, `audit_toolkit.py`,
  `compress_session.py`, `quick_recon.py`, `report_pack.py` — stdlib +
  httpx + hunter imports only, scope-gated, Windows-safe, exit codes
  0/1/3.
- Release posture: roadmaps, plans, tests, and ALL testing products are
  untracked from v0.5 and stay out of the release package. README,
  QUICKSTART, ARCHITECTURE, GATEWAY, and LLM docs updated for every
  surface above.

## [0.4.0] - 2026-09-14

### M1 — Installer and onboarding

- Added macOS/Linux and Windows one-line installers with dedicated venvs,
  `hunter`/`hunt` shims, tagged idempotent PATH registration, dry-run mode,
  `--skip-setup`/`-SkipSetup`, and safe onboarding handoff.
- Added onboarding v2 with provider/model setup, custom endpoint probing,
  model listing, role assignment, browser flag persistence, doctor checks, and
  failure-as-note behavior.
- Added `keys.env` atomic storage/loading with environment variables taking
  precedence; pasted keys are not placed in `config.yaml` or echoed.

### M2 — Provider and model UX

- Added canonical orchestrator/hunter/verifier/utility roles while
  loading legacy `planner`/`exploit`/`verify` names and healing them on write.
- Added interactive `provider add` and the top-level `hunter provider`
  shortcut, custom endpoint/model discovery, endpoint-aware routing, and
  Responses API bridging through LiteLLM.
- Added provider listing/testing/removal guardrails and role-aware doctor,
  wizard, and chat model surfaces.

### M3 — Unified chat and hunting

- Added pure hunt-intent classification: ordinary free text remains chat until
  a target-bearing hunt request receives explicit permission.
- Added process-local `/hunt on|off`, one-shot `/audit <target>` and
  `/hunt <target>`, headless fail-closed behavior, and preserved scope
  confirmation.
- Added `hunter hunt <target>` for authorized URLs and local-directory loopback
  mounts, proposed-manifest confirmation, report writing, and exit codes 0
  (clean), 1 (error), 2 (findings), and 3 (refused/usage).

### M4 — Update and maintenance path

- Added GitHub-first daily version checks with silent PyPI fallback, a 24-hour
  atomic cache, CI/opt-out gates, and stderr-only post-command notices.
- Added `hunter update` with dev-checkout advice, installer/pipx/pip detection,
  confirmation, manual one-liner fallback, and read-only config migration notes.

### M5 — Dynamic skills and curator

- Added validated bundled-plus-user skill loading, user shadow notes, source
  markers, size limits, deterministic relevance matching capped at five skills,
  and the core safety fallback.
- Added `/skills`/`hunter skills` source-aware views and `/curate`/`hunter curate`
  preview-before-save workflows for retro-derived cards.
- Added duplicate detection, injection scanning, atomic skill writes, and
  quarantine for flagged drafts; unreviewed drafts are never mounted.

### M6 — Browser automation (optional)

- Added optional [browser] support (`playwright>=1.40`) with four narrow
  hunt-only tools: navigate, snapshot, click, and type.
- Added optional `[browser]` support (`playwright>=1.40`) with four narrow
  hunt-only tools: navigate, snapshot, click, and type.
- Added one lazy run-owned headless session, preflight and redirect/subrequest
  scope checks, CSS-only bounded selectors, redacted/capped snapshots, typed
  value omission, browser-event evidence, and idempotent cleanup.
- Browser capability requires both `agent.browser: true` and governed hunt
  permission; ordinary chat, gateway, webhook, and TUI turns remain browser-free.

### Security

- Preserved fail-closed HTTP and browser scope enforcement, including redirect
  and subrequest checks; no browser path bypasses `ScopeSet`.
- Preserved claim-gate requirements: browser events and skill text cannot become
  findings without the required scope-gated `http_exchange` evidence.
- Preserved key redaction, `keys.env` permissions/containment, JSON stdout
  purity, update-check silence on failure, and installer syntax/idempotency
  contracts.
- No runtime or test path downloads Chromium, runs `playwright install`,
  executes arbitrary JavaScript, or accepts a skill as executable code.

## [0.3.1] - historical release

- See the v0.3.1 release history.

[Unreleased]: https://github.com/zaaaxx11/HunterOsHarness/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/zaaaxx11/HunterOsHarness/releases/tag/v0.4.0
[0.3.1]: https://github.com/zaaaxx11/HunterOsHarness/releases/tag/v0.3.1
