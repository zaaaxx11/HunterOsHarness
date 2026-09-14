# M7 — Release & Maintenance (v0.4.0)

**Goal:** release HunterOs Harness `v0.4.0` as a reproducible, supportable
artifact and leave the repository maintainable after M1–M6. This is a
release/maintenance design, not an implementation task. The BUILDER changes
source, tests, CI, and user docs only after the release gates below are
reviewed; this plan itself must not change those files.

**Design status:** final release plan. AUDITOR implements the release tests and
checks first; BUILDER executes the ordered changes; RELEASE OWNER performs the
manual publication and rollback rehearsal. Every acceptance criterion in §9
maps one-to-one to exactly one planned test or check. No check may use an
external provider, target, browser, or Chromium download.

**Current repository state observed 2026-09-14:** HEAD is the committed M5
commit (`4c9fced`, dynamic skill corpus/relevance matcher/curator). M1–M5
feature commits are present. M6 is concurrently being implemented: the
working tree already contains the M6 `[browser]` extra and untracked
`tests/test_browser_tools.py` / `tests/test_docs_m6.py`, while the browser
implementation is not yet present in this checkout. M7 therefore treats M6 as
a hard release prerequisite, not as a feature to silently omit.

---

## 0. Non-goals

- No new product capability beyond finishing and releasing M6.
- No weakening of the scope gate, claim gate, ledger/hash chain, phase machine,
  budget, provider-key redaction, browser permission gate, or skill quarantine.
- No live LLM/provider calls, target scans, internet calls, Playwright import,
  Chromium launch, or installer execution in pytest or CI.
- No rewriting historical milestone plans, `docs/CI-NOTES.md`, or
  `docs/ROADMAP-v0.3.md` merely to remove historical version strings. M7 adds a
  forward-looking roadmap and clearly labels historical material.
- No pre-release channel. `v0.4.0` is a stable SemVer release; prerelease
  tags are outside the update-check contract.
- No changing the M4 update protocol from GitHub-first with PyPI fallback.
- No source/test edits are made while this design is being authored.

---

## 1. Release scope and current-state map

### 1.1 Files that must change in the implementation PR

| File | Current line/state | M7 action |
| --- | --- | --- |
| `src/hunter/__init__.py:3` | `__version__ = "0.3.1"` | Change exactly to `__version__ = "0.4.0"`. |
| `pyproject.toml:7` | `version = "0.3.1"` | Change exactly to `version = "0.4.0"`. Keep `requires-python >=3.10`, dependencies, scripts, and M6 optional extra unchanged except where a release check proves a packaging defect. |
| `CHANGELOG.md` | absent | Create a Keep-a-Changelog-style file with `[Unreleased]` and the exact v0.4.0 inventory in §4. |
| `docs/ROADMAP-v0.5.md` | absent | Create the forward roadmap in §5. Keep `docs/ROADMAP-v0.3.md` as historical backlog. |
| `README.md:54` | says `17 slash commands` | Say `20 slash commands` (M3 `/hunt` + M5 `/curate`), and refresh the v0.4 feature/status copy. |
| `README.md:159-167` | status says v0.3.1 and 636 tests | Replace with the v0.4.0 status and release-gate result; do not hard-code a test count until the final matrix run. |
| `QUICKSTART.md` | current M1–M5 walkthrough | Keep both exact one-liners; align update, canonical provider roles, chat/hunt, skills, browser-extra, and current version language with README. |
| `docs/FIRST-RUN.md:38,70,90,235,338` | mixed 0.4.0/0.3.0 and old selected-skill count | Re-capture or rewrite the transcript so all current-release examples say v0.4.0 and the M5 selected-skill/source format is accurate. |
| `install.sh:122-123` | says `hunter hunt` is coming later | Replace the stale “coming in a later release” wording with the shipped `hunter hunt` next step; retain ASCII, idempotency, flags, and disclaimer. |
| `install.ps1:121-122` | same stale wording | Make the same copy change using PowerShell syntax; retain parser-safe behavior. |
| `.github/workflows/ci.yml:1-19` | matrix exists, commands use bare `ruff`/`pytest` | Make the matrix/reproducibility requirements explicit in §6: Python 3.11/3.13 on Ubuntu/Windows, module-invoked Ruff/Pytest, update-check opt-out, no browser extra/install. |
| `tests/test_release_m7.py` | absent | Add release static/contract checks described in §11. This is a planned test file, not created by this design task. |

The exact version bump is deliberately only these two runtime/package source
locations. `src/hunter/cli/main.py::_version()` and
`src/hunter/cli/update_core.py::_current_version()` already read package
metadata and fall back to `hunter.__version__`; neither gets a hard-coded
release number. M4 tests that use `current_version="0.3.1"` are historical
upgrade scenarios and must not be mass-edited into tautological v0.4.0 tests.

### 1.2 Existing release inputs reviewed

- `pyproject.toml`: package version, scripts, optional `telegram`, `browser`,
  `dev` extras, Ruff/Pytest configuration.
- `README.md`, `QUICKSTART.md`, `docs/FIRST-RUN.md`: user promises and captured
  workflows.
- `docs/CI-NOTES.md`: the four-job CI shape and lessons from the v0.3.1 red-CI
  incident; preserve its historical root-cause record.
- `docs/ROADMAP-v0.3.md`: prior backlog; carry unfinished items forward only
  into the new v0.5+ roadmap with explicit status.
- `.github/workflows/ci.yml`: existing Ubuntu/Windows × Python 3.11/3.13
  matrix, Ruff, and Pytest.
- `install.sh`, `install.ps1`: M1 idempotent installer, dry-run, shims, PATH,
  onboarding, and syntax contracts.
- `src/hunter/cli/update_core.py`: M4 GitHub-first latest-release lookup,
  PyPI fallback, strict version parser, 24-hour cache, stderr-only notice,
  CI/opt-out gates, and install-method-aware update path.
- Flat `tests/` conventions: `CliRunner`, string `rich.Console`, temp-home
  sandboxing via `HOME`/`USERPROFILE`/`HUNTEROS_CONFIG`, injected HTTP/fake
  seams, and no network.

---

## 2. Release invariants

1. **Evidence or Nothing remains structural.** No release note may imply that a
   browser snapshot, skill, model response, or prose is itself a finding.
2. **Scope is code-enforced.** M7 must re-run HTTP, chat, CLI, and browser scope
   refusal checks before publication.
3. **Secrets stay out of artifacts.** Keys remain in environment/`keys.env` or
   test-only sentinels; no changelog, transcript, cache, report, or release
   command may contain a real credential.
4. **JSON is a protocol.** Update notices and all advisory text stay on stderr;
   `--json` stdout must parse as one JSON value.
5. **Optional browser remains optional.** Core installs do not install
   Playwright; CI does not install the `[browser]` extra or Chromium. Browser
   tests use the fake Playwright graph only.
6. **Old configs remain loadable.** M2 legacy tier names load and first write
   heals them to `orchestrator`/`hunter`/`verifier`/`utility`; M1 `agent.browser`
   remains default-false and loadable without Playwright.
7. **Update checks are advisory.** A malformed/offline/rate-limited check never
   breaks a command; explicit `hunter update` remains the only update action.
8. **Release artifacts are reproducible.** The sdist/wheel version, runtime
   version, tag, PyPI version, changelog heading, and GitHub release all agree.

---

## 3. SemVer, tag, and update-check convention

### 3.1 Canonical version rule

- Use SemVer `MAJOR.MINOR.PATCH`, represented as `0.4.0` in Python metadata,
  `pyproject.toml`, `hunter version`, and PyPI.
- A **major** release may break a documented contract; a **minor** release adds
  backwards-compatible user capability; a **patch** release fixes defects or
  security issues without changing the documented contract.
- `v0.4.0` is the only release tag for this cut. Do not create or publish
  `0.4.0-beta`, `0.4.0-rc1`, or a tag with a moving name.

### 3.2 Git/GitHub/PyPI convention

1. Merge the release commit containing the two exact version bumps, changelog,
   roadmap, docs, CI, and accepted M6 implementation/tests.
2. Create an annotated tag named exactly `v0.4.0` at that commit:
   `git tag -a v0.4.0 -m "HunterOs Harness v0.4.0"`.
3. Push the commit and tag; create a GitHub release for `v0.4.0` and mark it
   as the latest stable release. Do not retag a different commit.
4. Build and publish PyPI distribution version `0.4.0`. PyPI has no leading
   `v`; the GitHub tag does.
5. Add compare links in `CHANGELOG.md` using `v0.3.1...v0.4.0` and a future
   `[Unreleased]` link. Links are advisory and must not be required at runtime.

### 3.3 Update-check compatibility

`update_core.py:77-80,126-147,292-347` remains the protocol authority:

- `check_for_newer_version()` asks
  `https://api.github.com/repos/zaaaxx11/HunterOsHarness/releases/latest`
  first and reads `tag_name`.
- Any GitHub non-200 (especially 403 rate limit), transport error, or malformed
  tag silently falls back to `https://pypi.org/pypi/hunteros-harness/json` and
  reads `info.version`.
- `parse_version()` accepts one leading `v`/`V` and dot-separated integers;
  it rejects prerelease suffixes. `v0.4.0` therefore normalizes to `0.4.0`.
- A fresh `~/.hunteros/update-check.json` cache is used for 24 hours; the
  comparison is recomputed against the running package version.
- The background check is skipped under CI, `PYTEST_CURRENT_TEST`, or a truthy
  `HUNTEROS_NO_UPDATE_CHECK`; an explicit `hunter update` still force-checks.
- Notices remain one line on stderr, after short-command output, never in
  `--json` stdout and never inside `chat`, `tui`, or `gateway`.

---

## 4. Exact `v0.4.0` inventory and CHANGELOG content

The BUILDER must create `CHANGELOG.md` with this structure. The release date is
filled at tag cut; the feature/security wording is normative so the release
cannot overclaim work that did not ship.

```markdown
# Changelog

All notable changes to HunterOs Harness are documented here.

## [Unreleased]

## [0.4.0] - <release date>

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

- Added canonical `orchestrator`/`hunter`/`verifier`/`utility` roles while
  loading legacy `planner`/`exploit`/`verify` names and healing them on write.
- Added interactive `provider add` and the top-level `hunter provider` shortcut,
  custom endpoint/model discovery, endpoint-aware routing, and Responses API
  bridging through LiteLLM.
- Added provider listing/testing/removal guardrails and role-aware doctor,
  wizard, and chat model surfaces.

### M3 — Unified chat and hunting

- Added pure hunt-intent classification: ordinary free text remains chat until
  a target-bearing hunt request receives explicit permission.
- Added process-local `/hunt on|off`, one-shot `/audit <target>` and `/hunt
  <target>`, headless fail-closed behavior, and preserved scope confirmation.
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

## [0.3.1] - 2026-09-<historical date>

- See the v0.3.1 release history.
```

The final file may use a real historical date for the existing release and
compare links, but must preserve the M1–M6 headings and Security section. The
M6 section is publishable only after all B1–B16 checks from
`M6-browser-automation.md` pass; otherwise the release is blocked rather than
silently documenting an unfinished browser feature.

### Exact v0.4.0 feature inventory

The release contains exactly these user-visible feature groups:

1. **M1 adoption:** cross-platform one-liners; dedicated venv; `hunter` and
   `hunt` shims; idempotent PATH; dry-run/update-safe installer behavior;
   onboarding v2; custom endpoint/model probing; `keys.env`; additive endpoint
   and `agent.browser` config fields.
2. **M2 provider/model UX:** four canonical roles and legacy migration;
   provider wizard and top-level shortcut; model discovery and role assignment;
   endpoint-aware chat/Responses routing; safe provider list/test/remove and
   doctor surfaces.
3. **M3 chat/hunt:** pure intent router; explicit permission; process-local
   hunt mode; one-shot chat commands; `hunter hunt` URL/local-directory flow;
   proposed scope confirmation; exit-code contract; report output; M3 skill
   selector seam.
4. **M4 maintenance:** GitHub-first/PyPI-fallback update check; 24-hour cache;
   background stderr notice; CI/opt-out/quiet-surface behavior; explicit
   `hunter update`; install-method detection; migration-note stub.
5. **M5 skills/curator:** validated bundled+user corpus; shadow/source/quarantine
   semantics; deterministic top-five matcher and core fallback; bounded prompt
   rendering; retro candidate extraction/dedupe; preview + y/N curator; safe
   atomic writes; `/curate`, `hunter curate`, and retro hint.
6. **M6 browser (release gate):** optional Playwright extra; four narrow browser
   tools; lazy run session; scope and redirect/subrequest enforcement; CSS-only
   selectors; redaction/caps; typed-secret omission; browser evidence; hunt-only
   permission; fake-only tests and no automatic browser installation.

No release note should list the M1–M6 design documents themselves as product
features. Those documents are design history; the inventory above is the
public behavior.

---

## 5. ROADMAP v0.5+

Create `docs/ROADMAP-v0.5.md`. It is a maintained forward roadmap, not a promise
of dates. Every item must preserve the evidence, scope, claim, and redaction
invariants. Suggested content:

### v0.5 — Operability and integration

- **Dashboard:** evolve the TUI from a useful local view into a maintained
  operator dashboard: stable run/finding/event/doctor contracts, live event
  consumption instead of polling where practical, bounded rendering, and
  deterministic headless fallbacks.
- **Gateway hardening:** production-ready Telegram/webhook operations: explicit
  deployment/health guidance, busy-mode policy per target (queue/reject/
  coalesce), stream/event consumption, key rotation/replay observability, and
  default-deny tests across transports.
- **Provider catalog:** versioned provider metadata and capability catalog
  (chat/Responses, model defaults, key source, endpoint shape, local/self-hosted
  hints), generated config examples, deprecation notes, and a tested extension
  path for new OpenAI-compatible providers. Catalog data must never contain API
  keys.
- **Maintenance baseline:** dependency upper-bound review, Python support policy,
  reproducible build metadata, security-advisory process, and a small release
  smoke suite that remains offline.

### v0.6 — Knowledge and skill growth

- **Skills growth:** curated, reviewable skill expansion; richer tags and
  coverage reporting; skill provenance/versioning; migration/removal tooling;
  regression tests that keep user shadows and quarantine visible.
- **Knowledge loop:** challenger/falsification pass, threat-model persistence,
  compaction checkpoints, and coverage/update-finding hardening, all ledgered
  and replayable.
- **External integrations:** governed MCP/web-search adapters only after the
  same ToolSpec, scope, evidence, and redaction contracts are proven.

### v0.7 — Distribution and PyPI maturity

- **PyPI:** trusted publishing, reproducible sdist/wheel builds, release
  provenance/SBOM, documented yanked-release procedure, install smoke tests on
  supported Python/OS combinations, and version parity checks against GitHub
  tags and `hunter version`.
- **Upgrade lifecycle:** tested deprecation windows, config migrations with
  explicit backups/rollback, and update notices that remain advisory and
  machine-output safe.

### Continuous maintenance

- Keep Ubuntu/Windows × Python 3.11/3.13 green until a support-policy change
  is explicitly documented.
- Review dependencies and security advisories monthly; update direct imports in
  `pyproject.toml` rather than relying on transitive packages.
- Keep all target/provider/browser tests hermetic. Any live smoke test must be a
  separate explicitly opt-in workflow and never part of normal CI.
- For each release, update `CHANGELOG.md`, verify the two version sources, run
  the adversarial release checklist, and rehearse rollback from the previous
  immutable tag.

---

## 6. Documentation consistency contract

The BUILDER updates only current user-facing prose; historical plans and
incident notes remain historical. The following exact content must agree across
`README.md`, `QUICKSTART.md`, `docs/FIRST-RUN.md`, `docs/LLM.md`,
`docs/ARCHITECTURE.md`, `examples/config.example.yaml`, `install.sh`, and
`install.ps1`.

1. **Install one-liners:** both README and QUICKSTART contain exactly:
   ```text
   curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
   irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex
   ```
   The PowerShell full command may include `powershell -NoProfile ... -Command`
   in the Windows walkthrough, but the `irm ... | iex` URL must be exact.
2. **Update:** all current docs say `hunter update`, mention the GitHub-first /
   PyPI-fallback check, 24-hour cache, `HUNTEROS_NO_UPDATE_CHECK=1`, and that
   notices are stderr-only/quiet in long-lived surfaces. Do not call update a
   self-restart or promise prerelease support.
3. **Provider roles:** current docs and config examples use
   `orchestrator/hunter/verifier/utility`; explain that legacy
   `planner/exploit/verify` names load and are canonicalized on the next write.
   Do not rename unrelated pipeline phase `verify` or `hunter verify` ledger
   terminology.
4. **Chat/hunt:** state that ordinary free text remains chat, target-bearing
   hunt intent requires confirmation when mode is off, `/hunt on|off` is
   process-local, `/audit`/`/hunt` can be one-shot, `hunter hunt` supports
   authorized URLs and local directories, and non-localhost targets require an
   authorized manifest (CLI proposed-manifest confirmation is the only explicit
   exception path).
5. **Browser optional extra:** explain `agent.browser` remains loadable without
   Playwright; browser actions are hunt-only and scope-gated; installation is
   explicit:
   ```text
   pip install 'hunteros-harness[browser]'
   python -m playwright install chromium
   ```
   No doc may imply onboarding, normal chat, gateway, or deterministic hunts
   require the extra; no doc may imply HunterOs installs Chromium automatically.
6. **Skills:** explain `~/.hunteros/skills/<name>/SKILL.md`, merged bundled/user
   corpus, `[bundled]`/`[user]`/`[quarantined]` visibility, max-five matching,
   `/curate`/`hunter curate` preview + explicit save, and that flagged cards are
   inert until manually reviewed.
7. **Installer next step:** `hunter hunt` is shipped in v0.4.0 and must not be
   described as “coming in a later release.” Keep the authorization disclaimer
   verbatim in both installers and onboarding transcript.
8. **Counts and examples:** current docs say 20 slash commands and show selected
   skill/source output, not the old M3 whole-corpus `skills mounted: 7` claim.

Historical `docs/CI-NOTES.md`, `docs/ROADMAP-v0.3.md`, and milestone plans may
retain old version/role wording when clearly describing the state at that time.

---

## 7. CI additions and requirements

Modify `.github/workflows/ci.yml` without changing the supported matrix:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python-version: ["3.11", "3.13"]
    runs-on: ${{ matrix.os }}
    env:
      HUNTEROS_NO_UPDATE_CHECK: "1"
      CI: "true"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: python -m pip install -e ".[dev]"
      - run: python -m ruff check src tests
      - run: python -m pytest
```

The exact YAML may retain existing formatting, but these requirements are
load-bearing:

- Four jobs: Ubuntu and Windows, each on Python 3.11 and 3.13; `fail-fast:
  false` so one platform failure does not hide another.
- Install only `.[dev]` for normal CI. Do not install `.[browser]`,
  `pytest-playwright`, Playwright, or Chromium.
- Invoke `python -m ruff` and `python -m pytest` so the selected interpreter is
  unambiguous on Windows and in fresh runners.
- Set `HUNTEROS_NO_UPDATE_CHECK=1` and `CI=true`; tests additionally retain the
  `PYTEST_CURRENT_TEST` hard gate and injected HTTP seams.
- M6 browser tests run with fake Playwright objects only. They must not import a
  real Playwright package, launch a browser, open a socket, invoke subprocesses,
  or download Chromium. The optional browser smoke commands are documented as
  manual and never added to this workflow.
- The matrix must run the full flat `tests/` suite, including
  `tests/test_browser_tools.py` and `tests/test_docs_m6.py` once the M6 builder
  lands them.

Ruff remains the configured rule set (`E,F,W,I,UP,B,SIM`) and the package remains
Python `>=3.10`; CI is the release matrix, not a claim that 3.10/3.12 are
currently hosted in GitHub Actions.

---

## 8. Release verification and rollback

### 8.1 Local preflight (Windows Git Bash, `.venv`)

Run from the repository root with a clean release worktree except for intended
M7 changes:

```bash
# Version parity and metadata
.venv/Scripts/python -c "import hunter, tomllib; from pathlib import Path; p=tomllib.loads(Path('pyproject.toml').read_text()); assert hunter.__version__ == '0.4.0'; assert p['project']['version'] == '0.4.0'; print(hunter.__version__)"
.venv/Scripts/python -m hunter version
.venv/Scripts/python -m pip check

# Release tests and all tests
.venv/Scripts/python -m pytest tests/test_release_m7.py -q
.venv/Scripts/python -m pytest tests/test_browser_tools.py tests/test_docs_m6.py -q
.venv/Scripts/python -m pytest tests/test_adversarial.py tests/test_adversarial_v02.py -q
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m ruff check src tests

# Offline/install-script checks
bash -n install.sh
powershell -NoProfile -Command "$e=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path install.ps1),[ref]$null,[ref]$e); if ($e -and $e.Count){ $e | ForEach-Object { $_.Message }; exit 1 } else { 'install.ps1 parses clean' }"

# M1 dry-run checks; use fresh temp homes and run twice for idempotency
h1=$(mktemp -d)
HOME="$h1" bash install.sh --dry-run
HOME="$h1" bash install.sh --skip-setup --dry-run
# On Windows, repeat the equivalent PowerShell -DryRun and -SkipSetup -DryRun
# with USERPROFILE and HUNTEROS_PROFILE pointed into a fresh temporary folder.

# Package build (use the repository's approved build tool/environment)
.venv/Scripts/python -m build
.venv/Scripts/python -m twine check dist/*
```

The browser extra is not installed by these commands. A separately authorized
manual smoke, after release review, may run:

```bash
.venv/Scripts/python -m pip install -e ".[browser]"
.venv/Scripts/python -m playwright install chromium
```

This is never a CI or release-test step and is not executed by HunterOs during a
hunt.

### 8.2 Release-owner checklist

1. `git status --short` shows only intended M7/M6 release files; no `.env`, key,
   cache, database, report, `.venv`, or generated artifact is tracked.
2. Secret scan passes (see §10); inspect all findings, including examples and
   captured transcripts, before staging.
3. Version parity, changelog, roadmap, docs consistency, full test, Ruff,
   installer syntax/dry-run, and package build checks pass.
4. Review the four CI jobs on the release commit; do not publish from a local
   green run while one matrix job is pending or red.
5. Build artifacts in a clean environment; inspect filenames and embedded
   metadata for exactly `0.4.0` and the expected optional extras.
6. Upload/publish PyPI `0.4.0` only after the GitHub tag/release points at the
   same commit and CI is green.
7. Verify from a clean, isolated environment (no checkout and no browser extra):
   `pip install hunteros-harness==0.4.0`, `hunter version`, `hunter demo`,
   `hunter doctor --json`, and `hunter update` with its HTTP seam or a controlled
   release check. Never use a real provider key.
8. Verify the GitHub release is marked latest and that a `v0.4.0` tag is visible;
   verify PyPI reports `0.4.0` without a leading `v`.
9. Record artifact hashes, commit SHA, tag SHA, CI run URL, PyPI release URL,
   and the result of the rollback rehearsal in the final release report.

### 8.3 Rollback

- **Before public publication:** stop the release, fix the branch, and move the
  draft GitHub release/tag only if no consumer has received it. Re-run all gates.
- **After `v0.4.0` is public:** never force-move or reuse the tag. Prefer a
  corrective `0.4.1` patch from the immutable `v0.4.0` commit. If the wheel is
  defective, yank the PyPI file with the reason recorded; do not pretend it was
  never published.
- **Emergency user downgrade:** preserve config/state and install the prior
  immutable version explicitly:
  ```bash
  python -m pip install --force-reinstall hunteros-harness==0.3.1
  # or, when PyPI is unavailable:
  python -m pip install --force-reinstall "git+https://github.com/zaaaxx11/HunterOsHarness.git@v0.3.1"
  ```
  Run `hunter version`, `hunter doctor --json`, and `hunter verify` against the
  existing state before resuming hunts. M2's legacy loader must keep v0.4.0
  configs readable after a downgrade; do not delete `config.yaml`, `keys.env`,
  skills, or the ledger as a rollback step.
- **Update-check cleanup:** after a corrective release, verify the GitHub latest
  release is the intended version and that the 24-hour cache cannot announce a
  stale downgrade as newer. If a release is yanked before a replacement exists,
  publish a clear GitHub release note and use the manual pinned install path;
  never create a fake `v0.4.0` replacement.

---

## 9. Acceptance criteria (one-to-one test/check mapping)

Each numbered criterion is a release gate. The parenthesized ID is exactly one
planned test or check in §11; subassertions belong to that one test/check.

### Version, artifacts, and release metadata

- **A1 — Version parity.** `src/hunter/__init__.py:3`, `pyproject.toml:7`,
  installed metadata, and `hunter version` all report exactly `0.4.0`; no
  runtime source hard-codes a conflicting current version. *(Test:
  `test_release_version_sources_are_0_4_0`.)*
- **A2 — Stable tag convention.** The release metadata/changelog uses `0.4.0`
  while update fixtures use `v0.4.0`; `parse_version("v0.4.0")` normalizes and
  `parse_version("0.4.0-rc1")` rejects. *(Test:
  `test_release_semver_and_update_tag_contract`.)*
- **A3 — Changelog completeness.** `CHANGELOG.md` has `[Unreleased]`, a
  `0.4.0` heading, M1/M2/M3/M4/M5/M6 user-visible sections, and a Security
  section containing the scope/claim/redaction/browser-test safety notes.
  *(Test: `test_changelog_has_exact_v040_inventory_and_security_notes`.)*
- **A4 — Roadmap completeness.** `docs/ROADMAP-v0.5.md` identifies dashboard,
  gateway, provider catalog, skills growth, PyPI maturity, and continuous
  maintenance without promising dates or weakening invariants. *(Test:
  `test_v05_roadmap_covers_maintenance_tracks`.)*
- **A5 — Build metadata.** A clean build produces sdist and wheel artifacts
  whose metadata is version `0.4.0`, includes the browser optional extra, and
  does not promote Playwright into core dependencies. *(Check:
  `M7-CHECK-ARTIFACT-METADATA`.)*

### Documentation and user contracts

- **A6 — Install/update copy.** README and QUICKSTART contain both exact
  one-liners, `hunter update`, GitHub→PyPI fallback, cache/opt-out wording, and
  stderr/quiet-surface behavior; installers contain the shipped `hunter hunt`
  next step. *(Test: `test_current_docs_have_install_and_update_contract`.)*
- **A7 — Provider role copy.** Current README, QUICKSTART, LLM, architecture,
  first-run, and example-config docs consistently use the four canonical roles
  and explain legacy-name migration without renaming unrelated `verify` phases.
  *(Test: `test_current_docs_have_canonical_provider_roles`.)*
- **A8 — Chat/hunt copy.** Current docs describe ordinary chat, explicit hunt
  confirmation, process-local `/hunt on|off`, `/audit`/`/hunt` one-shots,
  `hunter hunt`, local directories, exit codes, and the unchanged scope-manifest
  rule. *(Test: `test_current_docs_have_chat_hunt_and_scope_contract`.)*
- **A9 — Browser copy.** Current docs state optional `[browser]`, both explicit
  install commands, hunt-only/scope-gated operation, `agent.browser` support
  without the extra, no ordinary-chat capability, and no automatic Chromium
  installation. *(Test: `test_current_docs_have_optional_browser_contract`.)*
- **A10 — Skills copy.** Current docs state the user skills path, source markers,
  bounded matching, `/curate` preview/confirmation, and quarantine/inert
  semantics. *(Test: `test_current_docs_have_skills_and_curator_contract`.)*
- **A11 — Current-version transcript.** User-facing current examples in README,
  QUICKSTART, FIRST-RUN, and installer output do not claim that v0.3.x is the
  current release, do not claim 17 commands or `skills mounted: 7` as the M5
  contract, and retain historical files only where they are labeled historical.
  *(Test: `test_current_docs_have_no_stale_release_claims`.)*

### CI, hermeticity, and security regression gates

- **A12 — Matrix contract.** CI has exactly the required Ubuntu/Windows ×
  Python 3.11/3.13 matrix, fail-fast false, module-invoked Ruff and Pytest,
  and update-check opt-out. *(Test: `test_ci_matrix_and_commands_are_explicit`.)*
- **A13 — No network/Chromium CI path.** CI installs only `.[dev]`, contains no
  browser-extra/Playwright/Chromium install step, and M6 test contracts require
  fake-only Playwright with no subprocess/browser/socket. *(Test:
  `test_ci_has_no_browser_install_or_network_test_path`.)*
- **A14 — GitHub-first update behavior.** A MockTransport release test proves
  GitHub is requested first, a 403/malformed result falls back to PyPI,
  `v0.4.0` is normalized, and total failure is silent/no-cache; no test uses a
  real URL. *(Test: `test_update_release_path_is_github_first_and_hermetic`.)*
- **A15 — JSON stdout purity.** `doctor --json` and `hunt --json` output parse as
  one JSON value; update notices/advisories occur only on stderr, and quiet
  surfaces do not receive a mid-session notice. *(Test:
  `test_release_json_stdout_is_pure`.)*
- **A16 — Scope gate regression.** Existing adversarial and focused tests prove
  unauthorized HTTP, chat, CLI, and browser navigation/redirect/link requests
  are refused before I/O and cannot create a run or finding. *(Check:
  `M7-CHECK-SCOPE-REGRESSION`.)*
- **A17 — Config migration regression.** A v0.3/M1 config with legacy role names,
  no endpoint, and no browser field loads; a write renders canonical role names,
  preserves unrelated config, and defaults `agent.browser` false. *(Test:
  `test_release_config_migration_and_browser_default`.)*
- **A18 — Secret-scan release gate.** Tracked release files and artifacts contain
  no real provider/API credentials; only known test sentinels/placeholder values
  remain, and generated caches/keys/databases are untracked. *(Check:
  `M7-CHECK-SECRET-SCAN`.)*
- **A19 — Installer syntax and idempotency.** Bash syntax, PowerShell parser,
  both dry-run paths, both shims, tagged PATH dedupe, skip flags, ASCII output,
  and final authorization disclaimer pass without network or Python install.
  *(Check: `M7-CHECK-INSTALLER-SYNTAX-DRYRUN`.)*
- **A20 — Full quality gate.** On all four matrix jobs, `python -m ruff check
  src tests` and `python -m pytest` pass; the M6 fake-browser tests pass and no
  Chromium executable is required. *(Check: `M7-CHECK-CI-FOUR-JOBS`.)*

### Publication and rollback

- **A21 — Publication parity.** The annotated `v0.4.0` tag, GitHub release,
  PyPI `0.4.0`, changelog heading, wheel/sdist metadata, and commit SHA all
  refer to the same release commit; `hunter version` in a clean install prints
  `0.4.0`. *(Check: `M7-CHECK-PUBLISH-PARITY`.)*
- **A22 — Rollback rehearsal.** A prior immutable `v0.3.1` install and a
  corrective-version procedure are documented and exercised without deleting
  user config, keys, skills, or ledger; post-rollback doctor/verify pass.
  *(Check: `M7-CHECK-ROLLBACK-REHEARSAL`.)*

---

## 10. Adversarial release matrix

| # | Threat/adversarial input | Release answer | One mapped gate |
| --- | --- | --- | --- |
| 1 | Version bumped in `__init__` but not package metadata, or vice versa | A1 compares source, TOML, installed metadata, CLI output, and built artifacts | A1/A5 |
| 2 | Mutable/misnamed tag causes update checker to miss or misidentify release | Annotated immutable `v0.4.0`; PyPI `0.4.0`; strict parser and parity check | A2/A21 |
| 3 | GitHub 403/rate limit or malformed JSON strands users | GitHub-first then silent PyPI fallback; failed check writes no cache and never raises | A14 |
| 4 | Background notice corrupts machine-readable output | Context-close stderr emission only; `--json` stdout parse test | A15 |
| 5 | Update check phones home during CI/tests | CI env + opt-out + `PYTEST_CURRENT_TEST` hard gate; injected MockTransport in tests | A12/A14 |
| 6 | Provider role rename breaks old configs or unrelated phase `verify` | Loader migration/write healing test; docs explicitly classify vocabulary vs phase | A7/A17 |
| 7 | Browser optional dependency becomes a core/CI requirement | TOML/static CI checks; fake-only browser tests; no install command in workflow | A5/A13/A20 |
| 8 | Browser redirect, subresource, link, or form escapes authorized scope | Existing `ScopeSet` route/preflight checks and adversarial suite; no browser-local bypass | A16 |
| 9 | Browser selector injects XPath/JS/eval | CSS-only bounded selector contract and static absence of evaluate/script APIs | A13/A16 |
| 10 | Typed API password or DOM token appears in output/artifact | Type records length only; browser snapshot redacts before cap; secret scan inspects release artifacts | A16/A18 |
| 11 | Browser event or skill text bypasses claim gate | Browser evidence remains `browser_event`; findings still require `http_exchange`; skills are data | A16 |
| 12 | User skill path traversal/shadow/quarantine bypass | Shared validation/containment, visible source/shadow markers, quarantine excludes matching | A10/A16 |
| 13 | Release docs promise a feature not in the accepted build | Exact M1–M6 inventory and M6 B1–B16 release block | A3/A21 |
| 14 | Old “coming later” installer line misleads users | Static current-doc scan and both dry-run output checks | A6/A11/A19 |
| 15 | Installer shell/PowerShell parse failure or repeated PATH entries | `bash -n`, PowerShell AST parser, dry-run twice, marker count exactly one | A19 |
| 16 | Test fixtures contain real secrets or generated state is packaged | Secret scan plus clean-worktree/artifact inspection; test sentinels are documented | A18 |
| 17 | CI only passes on Linux or one Python version | Four independent non-fail-fast matrix jobs with explicit interpreter invocation | A12/A20 |
| 18 | Bad public release needs a mutable tag rollback | Never retag; yank defective artifact if needed; publish 0.4.1 and provide pinned 0.3.1 path | A21/A22 |
| 19 | Config migration destroys unrelated budget/fallback/browser fields | Atomic writer, legacy conflict refusal, and migration regression against a full old config | A17 |
| 20 | M6 builder lands tests but not implementation before release | Working-tree status plus B1–B16 focused suite is a hard pre-publication gate | A13/A20/A21 |

---

## 11. Test plan

Tests remain flat under `tests/`; no live target/provider/browser is allowed.
The new release test file is static/contract-focused and reuses existing seams.
Each row is one test/check and maps to exactly one criterion ID.

| File/check | Test/check name | Criterion | Method |
| --- | --- | --- | --- |
| `tests/test_release_m7.py` | `test_release_version_sources_are_0_4_0` | A1 | Read TOML with `tomllib`, import `hunter`, invoke CLI/version seam; scan runtime source for conflicting current literals. |
| `tests/test_release_m7.py` | `test_release_semver_and_update_tag_contract` | A2 | Assert `parse_version` normalization/rejection and current tag/changelog spelling. |
| `tests/test_release_m7.py` | `test_changelog_has_exact_v040_inventory_and_security_notes` | A3 | Read `CHANGELOG.md`; assert headings and required security phrases. |
| `tests/test_release_m7.py` | `test_v05_roadmap_covers_maintenance_tracks` | A4 | Read `docs/ROADMAP-v0.5.md`; assert dashboard, gateway, provider catalog, skills, PyPI, continuous maintenance, and invariant language. |
| `M7-CHECK-ARTIFACT-METADATA` | `python -m build` + `twine check` + metadata inspection | A5 | Build in a clean env; inspect wheel/sdist metadata and optional dependencies. |
| `tests/test_release_m7.py` | `test_current_docs_have_install_and_update_contract` | A6 | Static exact strings across README/QUICKSTART/install scripts. |
| `tests/test_release_m7.py` | `test_current_docs_have_canonical_provider_roles` | A7 | Static current-doc/config scan with historical-file allowlist. |
| `tests/test_release_m7.py` | `test_current_docs_have_chat_hunt_and_scope_contract` | A8 | Static docs scan for permission, mode, one-shot, local-dir, exit, and scope phrases. |
| `tests/test_release_m7.py` | `test_current_docs_have_optional_browser_contract` | A9 | Static docs scan for extra/install commands, hunt-only/scope-gated, agent flag, and no auto-install. |
| `tests/test_release_m7.py` | `test_current_docs_have_skills_and_curator_contract` | A10 | Static docs scan for user path/source/quarantine/preview/confirmation/max-five language. |
| `tests/test_release_m7.py` | `test_current_docs_have_no_stale_release_claims` | A11 | Scan current docs/install outputs for stale v0.3 current claims and old count/skill wording; allow historical docs and fixture comments. |
| `tests/test_release_m7.py` | `test_ci_matrix_and_commands_are_explicit` | A12 | Parse/read workflow; assert OS/Python matrix, fail-fast, env, module commands. |
| `tests/test_release_m7.py` | `test_ci_has_no_browser_install_or_network_test_path` | A13 | Assert workflow has no browser extra/Playwright/Chromium install and M6 docs/tests state fake-only/no subprocess/network. |
| `tests/test_release_m7.py` | `test_update_release_path_is_github_first_and_hermetic` | A14 | `httpx.MockTransport` records exact GitHub-first request, 403/malformed fallback, v normalization, and no-cache total failure. |
| `tests/test_release_m7.py` | `test_release_json_stdout_is_pure` | A15 | `CliRunner` with injected notice/check seams parses doctor/hunt JSON stdout and finds advisory only on stderr. |
| `M7-CHECK-SCOPE-REGRESSION` | Focused existing adversarial/scope command | A16 | Run HTTP, chat, CLI, browser scope/redirect/link refusal tests; inspect no run/evidence on refusal. |
| `tests/test_release_m7.py` | `test_release_config_migration_and_browser_default` | A17 | Load/write a full legacy config, assert canonical roles, preserved fields, endpoint default, browser false, and no key leakage. |
| `M7-CHECK-SECRET-SCAN` | `gitleaks`/approved scanner plus tracked-file and artifact inspection | A18 | Redacted scan; review allowlisted test sentinels; ensure no keys/cache/db/generated state staged. |
| `M7-CHECK-INSTALLER-SYNTAX-DRYRUN` | Bash/PowerShell parse + both dry-run/idempotency runs | A19 | Run exact §8.1 commands, assert shims/PATH marker/disclaimer/ASCII and zero network/install. |
| `M7-CHECK-CI-FOUR-JOBS` | GitHub Actions release commit | A20 | Require all four jobs green; full pytest/Ruff; no browser executable. |
| `M7-CHECK-PUBLISH-PARITY` | Tag/GitHub/PyPI/clean-install inspection | A21 | Compare commit/tag/artifact/version and run clean `hunter version`. |
| `M7-CHECK-ROLLBACK-REHEARSAL` | Isolated prior-version downgrade rehearsal | A22 | Install/pin v0.3.1 or prior tag, preserve state, run doctor/verify, document corrective 0.4.1 path. |

Existing safety tests remain part of the gate rather than being replaced:

- `tests/test_adversarial.py`, `tests/test_adversarial_v02.py` for scope,
  redaction, claim/tier, and prompt-injection regressions.
- `tests/test_update_core.py`, `tests/test_cli_update.py` for M4 network seams,
  stderr notice, install plans, and migration-note behavior.
- `tests/test_installer_static.py` plus M1 orchestrator checks for installers.
- `tests/test_llm_rename.py`, `tests/test_llm_config_m1.py` for role migration,
  endpoint, browser default, and old-config compatibility.
- `tests/test_browser_tools.py`, `tests/test_docs_m6.py` after the M6 builder
  lands the implementation; all fake Playwright, no real package/executable.
- `tests/test_docs_m3.py`, `tests/test_docs_m5.py`, and surface tests for chat,
  hunt, skills, and curator behavior.

---

## 12. Builder order

1. **Freeze the release input.** Wait for M6 to land its implementation and
   focused tests; inspect `git status`; classify every M1–M6 file as committed,
   intended release change, or accidental artifact. Do not start release edits
   while M6 acceptance is red.
2. **Finish M6 gate first.** Run B1–B16 and nearby agent/adversarial tests with
   fake Playwright. Confirm no core import/download/subprocess path. Fix M6
   implementation or tests before touching release claims.
3. **Add release test skeletons.** Add `tests/test_release_m7.py` per §11 and
   make its version/docs/CI/changelog checks fail for the current state. Keep
   all network/browser seams injected.
4. **Update maintenance artifacts.** Create `CHANGELOG.md` and
   `docs/ROADMAP-v0.5.md`; review the exact inventory and security wording.
5. **Make user docs consistent.** Update README, QUICKSTART, FIRST-RUN, LLM,
   architecture/examples as needed; fix installer “coming later” text; refresh
   current transcripts. Preserve historical docs and M4 fixture versions.
6. **Harden CI.** Apply the explicit four-job matrix requirements, module
   invocation, opt-out environment, and no-browser-install rule. Run the
   workflow on the release branch before version bump if practical.
7. **Bump exactly two version sources.** Change only
   `src/hunter/__init__.py:3` and `pyproject.toml:7` to `0.4.0`; run A1 and
   package metadata checks immediately. Do not change M4 historical
   `current_version="0.3.1"` fixtures.
8. **Run adversarial and full gates.** Run A14–A20 locally, installer syntax/
   dry-runs, focused M6/M1/M2/M3/M4/M5 suites, full pytest, and Ruff. Resolve
   platform differences with deterministic seams, not sleeps or weakened
   assertions.
9. **Build and inspect.** Build sdist/wheel in a clean environment; run `twine
   check`; inspect metadata, files, optional extras, and secret scan. No key,
   database, cache, report, `.venv`, or Chromium is an artifact input.
10. **Commit/tag/publish in order.** Commit the green release; wait for all four
    CI jobs; create annotated `v0.4.0`; create latest GitHub release; publish
    PyPI `0.4.0`; run clean-install smoke checks; record hashes and URLs.
11. **Close with final report.** Use §13 template, including all gate results,
    exact commit/tag/artifact hashes, known limitations, and rollback readiness.

---

## 13. Mandatory final report

The RELEASE OWNER must return a final report (in the release handoff/PR, not a
new generated report file in this design task) containing:

- **Release:** `0.4.0`; release commit SHA; annotated tag SHA; GitHub release
  URL; PyPI URL; sdist/wheel SHA256 values.
- **Inventory:** explicit confirmation that M1, M2, M3, M4, M5, and M6 match
  §4, with M6 B1–B16 result.
- **Criteria:** A1–A22 each marked pass, with the exact test/check name and
  CI job or command; no “not run” criterion may be called a release.
- **Quality:** full pytest count/result on each matrix job, Ruff result,
  package-build/twine result, installer syntax/dry-run result, JSON purity,
  scope regression, config migration, and secret scan.
- **Security:** confirmation of no real secrets in tracked files/artifacts,
  no network/Chromium in CI/tests, no arbitrary browser JavaScript, scope/claim
  gates unchanged, and browser optionality verified.
- **Docs:** README/QUICKSTART/FIRST-RUN/provider-role/chat-hunt/browser/skills/
  update checks passed; historical docs intentionally preserved.
- **Rollback:** prior immutable version verified, state-preserving downgrade
  command rehearsed, and corrective `0.4.1` procedure named.
- **Known limitations:** explicitly call out that browser installation and any
  live-provider/browser smoke remain operator-opt-in, not normal CI.

A release is **blocked** if any A1–A22 gate fails, M6 remains incomplete, CI is
not green on all four jobs, a secret scan is unresolved, an installer parser
fails, JSON stdout is contaminated, or any scope/config migration regression is
observed.
