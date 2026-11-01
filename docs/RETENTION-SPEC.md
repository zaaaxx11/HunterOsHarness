# Retention & Session Lifecycle — Build Spec (TDD)

Status: APPROVED by operator. Implement exactly as specified. TDD: FAILING TEST FIRST.

## Core Principle

The ledger is **append-only by SQLite trigger**. `DELETE FROM events|evidence|findings`
raises `ABORT`. This is the anti-forgery foundation and MUST NOT be weakened.


**Nothing is ever deleted from the ledger. Runs are ARCHIVED to a sealed SQLite
artifact, and the live rows are then removed only via a controlled path that
temporarily drops triggers inside a single transaction — never ad hoc.**

Correction: removing rows breaks the hash chain verifiability of *the live db*.
Therefore archival is **copy-out + chain-preserving purge**:
  1. Copy every row of a closed run into `archive/<run_id>.db` (own schema, own chain).
  2. Verify the archive by re-running the hash chain check on the copy.
  3. Only then purge from the live db (drop triggers → delete → recreate triggers,
     all inside one `BEGIN IMMEDIATE` transaction).

If step 2 fails, the purge is ROLLED BACK and the run stays live. Never lose the
only copy of an unverifiable chain.

## Part A — Run Lifecycle (`hunt close`)

### Schema migration v3
Add to `runs`:
```sql
ALTER TABLE runs ADD COLUMN outcome TEXT;      -- NULL while open
ALTER TABLE runs ADD COLUMN closed_at REAL;    -- NULL while open
ALTER TABLE runs ADD COLUMN summary_json TEXT; -- sealed summary
```
Bump `PRAGMA user_version` to 3.

Note: `runs_protected_columns` trigger freezes run_id/target/engine/scope_name/
started_ts. It does NOT freeze outcome/closed_at/summary_json, so those are
writable. Verify this before relying on it.

### `close_run(ledger, run_id, *, outcome=None) -> RunClosure`
- Raises `RunNotFound` if run_id has no row in `runs`.
- Raises `RunAlreadyClosed` if `closed_at IS NOT NULL`.
- Computes summary:
  - `findings_total`, `findings_proven`, `findings_by_severity`
  - `evidence_total`, `events_total`
  - `started_ts`, `ended_ts_real` (now)
  - `promotions`: list of finding keys eligible for skill/tool promotion
- Auto-derives `outcome` when not supplied:
  - any finding with status `proven-live` AND severity in (critical, high) -> `proven`
  - any finding at all -> `partial`
  - none -> `blocked`
- Writes `outcome`, `closed_at`, `summary_json` in ONE transaction.
- Appends a ledger event `kind='run_closed'` with the summary in payload.
- Returns the `RunClosure` dataclass.

### `is_run_closed(...)` / write-guard
After close, tools must not append to that run. Implement:
- `ledger.assert_run_writable(run_id)` raising `RunClosed` when closed.
- Call it in the evidence-store path and the finding-create path.
- **Important**: do NOT break replaying/reading closed runs. Read paths unaffected.

### CLI
```
hunter hunt close <run_id> [--outcome proven|blocked|partial|abandoned] [--json]
```
Exit 0 on success, non-zero with a clear message if already closed / not found.
`--json` emits ONLY JSON on stdout.

## Part B — Garbage Collection (`hunter gc`)

### Chat retention (delete allowed)
`chat.db` has NO append-only triggers. Safe to delete.
```sql
-- sessions older than N days AND not bound to an open run
DELETE FROM chat_messages WHERE session_id IN (...);
DELETE FROM chat_sessions WHERE session_id IN (...);
VACUUM;
```
Rule: a session is KEPT when
  - `last_active_at` newer than `--chat-days` (default 7), OR
  - it is bound (via metadata/title pattern `run:<run_id>` OR a `run_id` column if
    present) to a run whose `closed_at IS NULL`.

`--dry-run` prints the plan and changes nothing. Default is dry-run; `--apply` required.

### Run archival (archive, then purge)
```
hunter gc --apply --run-days 90
```
For each run where `closed_at` is older than `--run-days`:
1. Call `archive_run(ledger, run_id, archive_dir)`.
2. `archive_run` copies runs/events/evidence/findings rows for that run into
   `<archive_dir>/<run_id>.db`, then verifies the copied hash chain.
3. Only on success, purge from live db inside one transaction:
   `DROP TRIGGER` (events_no_update/delete/replace, evidence_*, findings_*) →
   `DELETE FROM ... WHERE run_id=?` → recreate triggers from `_SCHEMA` fragment.
4. Record the purge in an `archive_purged` event row in the LIVE db
   (kind='run_archived', payload = {run_id, archive_path, sha256, counts}).
   This row has run_id of the *live* run... careful: that run is being deleted.
   INstead: append this audit event to a dedicated `gc_log` table in live db.

Open runs (`closed_at IS NULL`) are NEVER archived or purged, regardless of age.

### Safety
- Refuse to purge if the archive file already exists with different content hash.
- Refuse to purge if any finding for that run is `proven-live` and has no
  corresponding row in the archive (verify counts BEFORE delete).
- `VACUUM` only when something was actually deleted.

## Part C — Promotion (proven+critical → skill/tool)

### Eligibility
```
PROVEN-LIVE + severity IN (critical, high)  -> eligible
PROVEN-LIVE + medium/low/info               -> NOT eligible (stays in ledger)
any UNPROVEN status                         -> NEVER eligible
```
Rationale: a skill built from an unproven finding poisons future hunts.

### API
```python
def eligible_promotions(ledger) -> list[PromotionCandidate]
def promote_to_skill(ledger, finding_key, *, skills_dir) -> Path
def promote_to_tool(ledger, finding_key, *, tools_dir) -> Path
```
- `promote_to_skill` writes a SKILL.md with YAML frontmatter:
  `name`, `description` (< 200 chars), plus body describing the reproducible
  technique extracted from the finding's evidence, PoC path and target class.
- Idempotent: re-promoting updates the file, never duplicates.
- Rejects ineligible findings with `NotEligible`.
- The generated skill MUST NOT contain raw secrets, raw request bodies with
  tokens, or the literal target hostname (use the target CLASS instead).

### CLI
```
hunter promote list [--json]
hunter promote skill <finding_key> [--json]
hunter promote tool <finding_key> [--json]
```

## Part D — Cron

Script `scripts/hunter_gc_cron.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
hunter gc --apply --chat-days 7 --run-days 90
```
Documented as: add via `crontab -e` daily at 04:00.
Must be silent on success (no output) so it works as a watchdog.
Must print to stderr and exit non-zero on failure.

## Invariants the tests MUST prove

1. `DELETE FROM events` still raises ABORT before any gc code runs (trigger intact).
2. `hunt close` on an unknown run -> error, non-zero exit, no rows mutated.
3. `hunt close` twice -> second one errors, first summary unchanged.
4. After close, `assert_run_writable` raises; reading still works.
5. `gc --dry-run` mutates NOTHING (row counts identical, mtime unchanged).
6. `gc --apply` NEVER touches an open run, even if 400 days old.
7. `gc --apply` archive file verifies its hash chain before any purge.
8. If archive verification fails, live rows survive untouched.
9. Chat session bound to an open run survives 30-day-old gc.
10. Chat session unbound and 8 days old is deleted.
11. `promote` refuses an unproven finding.
12. `promote` refuses a proven-medium finding.
13. `promote` accepts proven-critical and the generated SKILL.md contains no
    target hostname, no tokens.
14. `--json` on every new command emits pure JSON on stdout (nothing else).

## Conventions to follow (read these files first)

- `src/hunter/kernel/ledger.py` — ledger, schema, triggers, migrations
- `src/hunter/kernel/claimgate.py` — gate patterns, NOTE: now fail-closed
- `src/hunter/workflow/eval_cli.py` — CLI style
- `src/hunter/cli/main.py` — command registration, console/stdout discipline
- `tests/test_local_audit.py` — test style
- Interface `--json` rule: JSON ONLY on stdout; human text on stderr.

## Anti-patterns to avoid

- Bare `except Exception: pass` around anything that guards a mutation.
- Using `console.print` (stdout) where `err_console` is required.
- Deleting rows to "save space" without archiving first.
- Any promotion path that trusts `finding.status` without re-checking severity.
- Growing `--run-days` silently; default is 90 and must be explicit.
