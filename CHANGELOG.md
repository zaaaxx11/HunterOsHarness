# Changelog

All notable changes to HunterOs Harness are documented here.

Compare releases: `v0.3.1...v0.4.0`.

## [Unreleased]

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
