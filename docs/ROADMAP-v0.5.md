# Roadmap — v0.5+

This maintained forward roadmap is not a promise of dates. Every item
preserves the evidence, scope, claim, and redaction invariants; proposed
capabilities remain governed, bounded, and reviewable.

## v0.5 — Operability and integration

- **Dashboard:** evolve the TUI into a maintained operator dashboard with
  stable run, finding, event, and doctor contracts, bounded rendering, live
a  event consumption where practical, and deterministic headless fallbacks.
- **Gateway hardening:** production-ready Telegram and webhook operations with
  deployment and health guidance, per-target queue/reject/coalesce busy modes,
  event consumption, key rotation and replay observability, and default-deny
  tests across transports.
- **Provider catalog:** versioned provider metadata and capability catalog for
  chat/Responses, model defaults, key source, endpoint shape, local hints,
  generated config examples, deprecation notes, and a tested extension path.
  Catalog data must never contain API keys.
- **Maintenance baseline:** dependency-bound review, Python support policy,
  reproducible build metadata, security-advisory process, and an offline
  release smoke suite.

## v0.6 — Knowledge and skills growth

- **Skills growth:** curated, reviewable skill expansion; richer tags and
  coverage reporting; skill provenance/versioning; migration and removal
  tooling; regression tests that preserve user shadows and quarantine.
- **Knowledge loop:** challenger/falsification passes, threat-model
  persistence, compaction checkpoints, and coverage/update-finding hardening,
  all ledgered and replayable.
- **External integrations:** governed MCP and web-search adapters only after
  the same ToolSpec, scope, evidence, and redaction contracts are proven.

## v0.7 — Distribution and PyPI maturity

- **PyPI maturity:** trusted publishing, reproducible sdist/wheel builds,
  release provenance/SBOM, documented yanked-release procedure, install smoke
  tests on supported Python/OS combinations, and version parity against GitHub
  tags and `hunter version`.
- **Upgrade lifecycle:** tested deprecation windows, config migrations with
  explicit backups and rollback, and advisory update notices that remain
  machine-output safe.

## Continuous maintenance

- Keep the Ubuntu/Windows and Python 3.11/3.13 matrix green until a support
  policy change is explicitly documented.
- Review dependencies and security advisories regularly; keep direct imports
  declared in `pyproject.toml` rather than relying on transitive packages.
- Keep all target, provider, and browser tests hermetic. Live smoke tests are
  separate, explicitly opt-in, and never part of normal CI.
- For each release, update `CHANGELOG.md`, verify the two version sources, run
  the adversarial release checklist, and rehearse rollback from an immutable
  tag without weakening evidence, scope, claim, or redaction invariants.
- Config migration and update policy must be read-only by default, preserve
  unrelated state, make backups before destructive changes, and provide a
  pinned rollback path; `hunter update` remains explicit and advisory checks
  never mutate user state.
