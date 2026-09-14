# M5 — Dynamic Skills & the Curator (v0.4)

**Goal:** skills become *dynamic*: per-hunt relevance matching mounts at most
5 skills into the audit prompt (today the whole `INDEX.md` is injected
verbatim into every run), and a Curator turns post-hunt retro lessons into
draft `SKILL.md` cards that are **always** previewed and confirmed by the user
before anything is saved — never auto-saved, never injected unreviewed.

**Design status:** final for M5. AUDITOR writes the failing tests in §10/§12
first; BUILDER implements until green. Every acceptance criterion is
mechanically checkable and none requires live network. Structure and
conventions match `docs/plans/v0.4/M1-installer-onboarding.md` /
`M3-chat-hunt-unified.md` / `M4-update-command.md`.

**Concurrency note (M3):** an M3 builder is concurrently landing chat `/hunt`
and the skills seam. This plan does NOT depend on its uncommitted code: the
seam is taken verbatim from `M3-chat-hunt-unified.md` Part D —
`install_skill_selector` / `resolve_skills_index` / `mounted_skills` /
`SkillSelector = Callable[[str], str]` in `agent/prompts`, consumed by a
one-line switch in `agent/loop.py`. Likewise M5's banner-line change is
specified against M3 §3.8 (`_audit_open` pre-hunt lines) and §4.3 step 4
(`hunter hunt` pre-hunt lines), both of which are M3 deliverables.

---

## 0. Non-goals (M5)

- Editing or restructuring the 7 bundled skill **bodies** — only frontmatter
  `tags:` are added (§6.4) and `INDEX.md` gains one rule. Bodies are frozen.
- A skills **marketplace**, remote skill sources, or any network fetch of
  skills. The corpus is bundled (read-only) + `~/.hunteros/skills` (user).
- Skill **executability** of any kind (scripts, hooks, tools). Skill files
  are data; nothing new runs them.
- Tier-aware matching (filtering `min_tier` by the run's tier) — deliberately
  rejected, see §9 decision K6.
- Changing the scope gate, claim gate, ledger, phase machine, budget, or any
  tool handler. Skills remain doctrine, never capability.
- Rewriting `load_skills_index()` or the whole-INDEX default — it stays as
  the inert no-selector fallback (M3 K2 pins it).
- Retro computation changes (`compute_retro`/`record_retro` are consumed
  read-only by the curator).
- Per-session/per-user matching preferences or feedback loops ("this skill
  was useful") — future work.

---

## 1. Current-state map (what exists, what changes)

| File | Today | M5 change |
| --- | --- | --- |
| `src/hunter/_data/skills/` | 7 `SKILL.md` cards (frontmatter: `name`, `description`, `version`, `metadata.min_tier` on advanced cards) + `INDEX.md` injected verbatim by `load_skills_index()` | frontmatter gains optional `tags:` (normative table §6.4, incl. `core` on two cards); `INDEX.md` "Rules for new skills" gains rule 5 (user dir, tags, quarantine). Bodies byte-frozen |
| `src/hunter/agent/skills.py` | — | **new**: corpus loader/validator/merger (bundled + user), `match_skills` (pure), `render_block`, `selected_skill_names`, `target_hint`, `install_default_skill_selector`, `write_skill` |
| `src/hunter/agent/prompts/__init__.py` | Part-D seam: `SkillSelector`, `install_skill_selector`, `resolve_skills_index()` (calls `_SKILL_SELECTOR("")`), `mounted_skills()` | **additive only**: `resolve_skills_index(question: str = "")` gains an optional param; new `current_skill_selector()` getter. Default path byte-identical (K2 green) |
| `src/hunter/agent/loop.py` | `skills_index = ctx.config.get("skills_index")` else `resolve_skills_index()` | `__init__` calls `install_default_skill_selector()` (idempotent); the resolver line passes `question=goal`. `ctx.config["skills_index"]` override still wins |
| `src/hunter/agent/curator.py` | — | **new**: `extract_candidates` (pure), dedupe, `draft_skill` (template or 1 LLM call), injection scan, `review_and_save` (preview + injectable ask), `curate` orchestration |
| `src/hunter/llm/keys.py` | private `_atomic_write` | **additive**: public `atomic_write_text(target, text)` extracted (same pattern); `write_keys_env` refactored onto it, behavior identical |
| `src/hunter/chat/commands.py` | `/skills` lists bundled names+descriptions; `/retro` executor; 19-command registry (M3) | `/skills` uses the merged corpus + `[source]` markers; `/retro --record` gains an inert `curator:` hint line; registry gains `/curate` (20 entries) |
| `src/hunter/cli/main.py` | `hunter skills` table (bundled only), `hunter retro --record` | `skills` gains a `source` column + user rows + shadow note on `--view`; `retro --record` gains the same hint line; new `hunter curate` command |
| `src/hunter/chat/repl.py` | (M3 §3.8) arming line `skills mounted: <n> (<names>)` from `mounted_skills()` | line content becomes the **selected** skills with sources: `skills mounted: <k> (<name [source], ...>)`, k ≤ 5; `_audit_open` gains keyword-only `goal_text: str = ""` |
| `src/hunter/hunt.py` | (M3 §4.3 step 4) `skills mounted: <n> (<names>)` | same selected-skills content (selected from the goal text) |
| `README.md`, `docs/FIRST-RUN.md` | skills not documented as user-extensible | short section: user skills dir, `[source]` markers, `/curate` + quarantine semantics (BUILDER captures, untested prose) |

Tests live flat in `tests/`. Conventions observed: string
`rich.Console(file=io.StringIO())` capture, `FakeConsole` scripted inputs,
`CommandContext` fixtures (`tests/test_chat_commands.py`), `CliRunner` +
`_cli_env` (`HOME`/`USERPROFILE` → `tmp_path`, `$HUNTEROS_CONFIG`,
`HUNTER_STATE_DIR` deleted), `FakeProvider`-style `ChatProvider` fakes
(`tests/test_agent_skills_seam.py`), `ledger_factory`-style Ledger seams.
Zero external network.

Baseline: **761 collected** on the M3-in-flight tree (M1+M2+M4 committed).
M5 keeps all of them green except the ONE documented rewrite in §7 (C12).

---

## 2. Key decisions (recorded 2026-09-14)

- **K1 — Name collision ⇒ user shadows bundled (with a note).** A user
  skill whose validated `name` equals a bundled name replaces it everywhere
  (corpus, matching, `--view`), and `load_corpus` emits the note
  `user skill '<n>' shadows the bundled skill '<n>'`. Justification: the
  bundled corpus lives in site-packages (pip-owned, possibly read-only,
  clobbered by updates) — shadowing is the only way a user can locally patch
  doctrine without touching the install; the note plus `[source]` markers in
  `/skills`, `hunter skills`, and the mount block keep it auditable. The
  reverse rule (bundled wins) would make user skills silently dead weight.
- **K2 — Empty-match fallback = the `core`-tagged subset, capped at 5.**
  Zero skills scoring ≥ 2 mounts the skills tagged `core` (bundled:
  `scope-discipline`, `verification-ladder`), name-sorted; if nothing is
  `core`-tagged, mount nothing (`"(no skills mounted)"`). Justification: an
  irrelevant-but-present goal must never strip the two doctrines the
  harness's own safety posture rests on (fail-closed scope; evidence
  ladder) — both are tier-basic and short. Selecting by tag (not hardcoded
  names) keeps the mechanism general; a corpus stripped of `core` gets an
  honest empty block rather than noise padding.
- **K3 — Tags: YES (optional frontmatter field).** Descriptions alone are
  too thin to route on (e.g. `verification-ladder`'s description shares no
  vocabulary with the standard run goal). `tags:` (single slugs) carry the
  trigger vocabulary with weight 3 in scoring, are validated on load, and
  degrade to absent for skills that omit them. The 7 bundled cards get a
  normative tag table (§6.4).
- **K4 — Curator dedupe rule: name collision (hard) or Jaccard ≥ 0.6
  (soft).** Token sets over name + description + tags (same tokenizer as
  matching); `similarity = |A∩B| / |A∪B|`; a candidate is a duplicate iff
  its normalized name equals an existing skill's name OR max similarity
  ≥ 0.6 → skipped with a note naming the existing skill. Justification:
  doctrine cards have small trigger vocabularies; 0.6 catches paraphrases
  ("recon mapping" vs "recon basics") while unrelated techniques score well
  below; the threshold is a named constant, pinned at the boundary by test
  CU3.
- **K5 — Curator surface is explicit; the retro hint is inert.** `/curate
  [run_id]` + `hunter curate [run_id]` drive the preview/confirm flow.
  `/retro --record` (and `hunter retro --record`) append one text-only hint
  line when candidates exist (`curator: <n> candidate technique(s) — run
  /curate to review`); it never prompts. Justification: auto-prompting after
  every recorded retro is a nag loop; an inert hint + explicit command gives
  the user the trigger without stealing the confirm.
- **K6 — Matching does NOT filter by tier.** An `advanced` doctrine card
  mounted into a `basic` run cannot escalate anything: out-of-tier actions
  are refused in the tool handlers (`tier.passive_only`,
  `tier.capability_locked`) regardless of what a skill says (INDEX.md tier
  section). Filtering would also need tier through the one-string seam for
  chat turns that don't name it. `min_tier` stays validated + displayed.
- **K7 — The seam stays one-string (`Callable[[str], str]`).** M3 K2 pins
  `install_skill_selector(lambda question: ...)` and
  `resolve_skills_index() == load_skills_index()` in the default state. So
  M5 passes the run goal as the question (`resolve_skills_index(question=
  goal)`), and the matcher derives the target with a pure `target_hint()`
  from that text (`build_goal` always names the URL; chat arming text names
  the target). No ambient state, no contract break.
- **K8 — Curator drafting uses the LLM when a brain is configured, with a
  deterministic template fallback.** One `utility`-tier call per candidate;
  the response is never trusted structurally (slugified name, clamped
  description, truncated body, injection scan, full validation). No brain /
  provider error → template draft. Hermetic tests inject fakes or use the
  template path.
- **K9 — Flagged drafts are saved INERT (quarantined), never silently
  dropped and never injected.** A draft matching the injection denylist is
  previewed with warnings; on explicit yes it is written with
  `quarantined: true` frontmatter; the loader excludes quarantined skills
  from matching entirely; `/skills` shows them as `[quarantined] (not
  mounted until reviewed)`. Unflagging is a deliberate manual edit of the
  file (documented).
- **K10 — No env-var override for the skills root.** `user_skills_dir()` is
  `<home>/.hunteros/skills` with an injectable `home=` parameter (test
  seam), mirroring keys.env's default but without `$HUNTEROS_KEYS_FILE`-style
  redirection — an env var aiming skill reads/writes at arbitrary locations
  is attack surface with no legitimate use.

---

## 3. Part A — corpus & validation (`src/hunter/agent/skills.py`, new)

```python
__all__ = ["MAX_MOUNTED", "MAX_BLOCK_CHARS", "MAX_SKILL_BYTES", "MAX_BODY_LINES",
           "MAX_DESCRIPTION_CHARS", "DUPLICATE_JACCARD",
           "Skill", "Corpus", "user_skills_dir", "parse_skill_md", "load_corpus",
           "target_hint", "tokenize", "match_skills", "render_block",
           "selected_skill_names", "install_default_skill_selector", "write_skill"]

DUPLICATE_JACCARD = 0.6       # curator dedupe threshold (K4) — defined here so
                              # loader and curator share one constant

MAX_MOUNTED = 5               # hard cap on skills mounted per run
MAX_BLOCK_CHARS = 16_000      # rendered skills-block budget
MAX_SKILL_BYTES = 32_768      # a SKILL.md above this is skipped (hostile/huge)
MAX_BODY_LINES = 400          # body above this is skipped
MAX_DESCRIPTION_CHARS = 200   # description above this is malformed → skip

@dataclass(frozen=True)
class Skill:
    name: str                 # ^[a-z0-9][a-z0-9-]{0,63}$ AND == directory name
    description: str
    version: str
    min_tier: str             # "basic" | "advanced" (default "basic")
    tags: tuple[str, ...]     # optional; entries ^[a-z0-9][a-z0-9-]{0,31}$, max 16
    source: str               # "bundled" | "user"
    body: str                 # frontmatter stripped, rstripped
    quarantined: bool         # frontmatter `quarantined: true`
    path: str                 # "" for bundled resources

@dataclass(frozen=True)
class Corpus:
    skills: tuple[Skill, ...]   # valid, shadow-merged, sorted by name
    notes: tuple[str, ...]      # skip/shadow notes, deterministic order
```

### 3.1 Frontmatter schema & validation (`parse_skill_md`)

Split the leading `---` fenced block; parse with `yaml.safe_load` (PyYAML is
already a core dependency). Validation, in order — any failure returns a
skip reason (never raises):

1. The **directory id** (bundled entry name / user dir name) must match
   `^[a-z0-9][a-z0-9-]{0,63}$` — kills path traversal (`..`), separators,
   uppercase, spaces, dotfiles.
2. Frontmatter must parse to a `dict`.
3. `name` required, must match the id regex AND equal the directory id
   (a frontmatter `name: ../escape` in dir `sneaky` is a skip, not a write
   target).
4. `description` required, non-empty, ≤ `MAX_DESCRIPTION_CHARS`.
5. `version` required, non-empty, ≤ 32 chars.
6. `metadata.min_tier` optional; default `"basic"`; any value outside
   `{basic, advanced}` is a skip.
7. `tags` optional list of strings; each entry matching
   `^[a-z0-9][a-z0-9-]{0,31}$` is kept (invalid entries dropped, not fatal);
   more than 16 → first 16 kept.
8. `quarantined` optional bool (YAML bool or the strings "true"/"false");
   anything else → skip.
9. File-level caps checked BEFORE parsing: file > `MAX_SKILL_BYTES` or body
   > `MAX_BODY_LINES` lines → skip note `skipped <id>: too large`.

### 3.2 Loader (`load_corpus(*, home=None) -> Corpus`)

- Bundled: `importlib.resources` traversal of `hunter/_data/skills/`,
  skipping `INDEX.md` and `_`-prefixed entries (same exclusions as
  `mounted_skills()`); any resources error → bundled contributes nothing
  (no raise).
- User: `user_skills_dir(home)` — `Path.home()/.hunteros/skills` by
  default; missing dir → no user skills, directory never created by the
  loader (read-only). Entries are the directory ids; each must contain
  `SKILL.md`.
- Merge: user shadows bundled on equal validated `name` (K1) with the shadow
  note; everything sorted by name; notes deterministic (sorted, then
  deduplicated).
- Quarantined skills ARE returned (with `quarantined=True`) — `/skills`
  lists them — but every consumer that mounts (matcher,
  `selected_skill_names`) excludes them (§4.2).
- Every exception during a skill's read/parse is a skip note; the loader
  NEVER raises (a broken corpus must never break a hunt).

### 3.3 Writer (`write_skill(draft, *, home=None) -> Path`)

Used only by the curator (§5). Refuses, with `HunterError` (layer
`"config"`):

- `code="skills.refused"` — the resolved target
  `<home>/.hunteros/skills/<name>/SKILL.md` is not within
  `<home>/.hunteros/skills` (same `_is_within` containment rule as
  `keys.write_keys_env`), or `name` fails the id regex (traversal).
- `code="skills.exists"` — a skill directory with that name already exists
  (the curator never clobbers user-authored or bundled-shadowed files).

Success: `mkdir -p` parents, assemble the canonical SKILL.md text
(frontmatter with `name/description/version/metadata.min_tier/tags/
[quarantined]` + body), write ATOMICALLY via the new public
`hunter.llm.keys.atomic_write_text` (temp file in the target directory,
flush, fsync, `os.replace` with the bounded PermissionError retry — the
exact M1 pattern; chmod best-effort like keys, irrelevant for data files but
harmless). Returns the path.

### 3.4 `keys.atomic_write_text` (additive, `src/hunter/llm/keys.py`)

```python
def atomic_write_text(target: Path, text: str) -> None:
    """The write_keys_env commit path, made public for the curator:
    temp file in target.parent, flush+fsync, os.replace with the bounded
    PermissionError retry; raises HunterError('keys.write_failed' → renamed
    'write_failed', layer config) on final failure."""
```

`write_keys_env` refactors onto it (behavior-identical; the existing keys
tests A19–A25 are the regression net).

---

## 4. Part B — matching & seam wiring

### 4.1 Pure matching primitives

```python
def target_hint(text: str) -> str:
    """Pure. The first https?:// URL token in ``text`` (trailing punctuation
    stripped), else the first bare-host token (label.label+ TLD shape), else
    "". String ops only — no DNS, no stat, no I/O of any kind."""

def tokenize(text: str) -> tuple[str, ...]:
    """Pure, deterministic. Lowercase, split on non-alphanumeric, keep tokens
    with len >= 3 that contain at least one letter, minus the normative
    stopword set (§12 conventions), deduplicated, first-occurrence order."""
```

**Scoring** (`match_skills(target, instruction, skills, *, max_mounted=MAX_MOUNTED) -> list[Skill]`):

- Query tokens = `tokenize(target) + tokenize(instruction)` (dedup).
- Skill trigger tokens: name tokens (split on `-`), description tokens, tag
  tokens.
- `score(skill) = 3·|tag hits| + 2·|name hits| + 1·|description hits|`
  counted over DISTINCT query tokens (a token repeated 10× scores once).
- Selected = skills with `score >= 2` and `not quarantined`, sorted by
  `(-score, name)`, capped at `MAX_MOUNTED`.
- Empty selection → fallback (K2): `core`-tagged, non-quarantined,
  name-sorted, capped at `MAX_MOUNTED`.
- Threshold rationale: one shared description word is noise; a tag or name
  hit (or two description hits) is deliberate vocabulary. Deterministic:
  no clock, no randomness, no I/O; equal inputs ⇒ equal outputs.

### 4.2 Rendering (`render_block(selected, *, corpus_size, notes=()) -> str`)

- Empty selection → `""` (the system prompt renders
  `skills_index or "(no skills mounted)"` — unchanged behavior).
- Otherwise: header
  `# Skills mounted for this run (matched <k> of <corpus_size>; max 5)`,
  then any **shadow** notes from the corpus (one line each, prefixed
  `note:`), then each selected skill's full `SKILL.md` verbatim
  (frontmatter included — it carries tier + source-adjacent metadata),
  separated by `\n\n---\n\n`.
- **Block budget:** while the rendered block exceeds `MAX_BLOCK_CHARS` and
  more than one skill remains, drop the LAST selected skill (lowest score;
  name-descending tiebreak via the selection order) and re-render —
  deterministic, never empty while k > 1. This is the second layer behind
  the per-file size caps against context flooding.
- `selected_skill_names(target, instruction, *, home=None) ->
  list[tuple[str, str]]` — `(name, source)` pairs for the banner line
  (§6.1); pure given the corpus.

### 4.3 Seam wiring (all additive inside the M3 Part-D contract)

```python
# agent/prompts/__init__.py — the ONLY changes:
def resolve_skills_index(question: str = "") -> str:
    """_SKILL_SELECTOR(question) if set else load_skills_index().
    agent/loop.py calls THIS (now with the run goal)."""
def current_skill_selector() -> SkillSelector | None: ...
```

```python
# agent/skills.py
def install_default_skill_selector() -> None:
    """Install the M5 matcher as the module selector ONLY when
    current_skill_selector() is None (idempotent; an explicit
    install_skill_selector — including M3's K2 sentinel — always wins).
    The installed callable: question -> render_block(match_skills(
    target_hint(question), question, load_corpus()))."""
```

- `AgentLoop.__init__` calls `install_default_skill_selector()` (lazy
  import — no cycle). K2's flow stays green: the sentinel is installed
  BEFORE construction → the install is a no-op; `install_skill_selector(None)`
  at the end restores the inert default.
- `agent/loop.py`: `resolve_skills_index()` →
  `resolve_skills_index(question=goal)` (one line; K7).
- `ctx.config["skills_index"]` remains the highest-priority override
  (checked before the resolver) — unchanged M3 behavior.

### 4.4 Banner line (M5 delta on M3 §3.8 / §4.3 step 4)

Both surfaces print the **selected** skills with sources:

```
skills mounted: <k>[ (<name1> [<source1>], <name2> [<source2>], ...)]
```

- `k ≤ 5`; `k=0` renders `skills mounted: 0` (no parenthetical).
- Chat `_audit_open` gains keyword-only `goal_text: str = ""` — intent
  arming passes the driving user text, one-shot arming passes the
  `build_goal` text, bare/default arms select on the target alone.
- `hunter hunt` selects on the goal text it drives with.
- The names come from `selected_skill_names` (default matcher). A user-
  installed custom selector owns its own banner story (documented).

---

## 5. Part C — the Curator (`src/hunter/agent/curator.py`, new)

```python
__all__ = ["Candidate", "SkillDraft", "INJECTION_MARKERS", "extract_candidates",
           "similarity", "dedupe_candidate", "scan_draft", "draft_skill",
           "review_and_save", "curate"]

@dataclass(frozen=True)
class Candidate:
    title: str          # human title, slug-source
    summary: str        # 1–3 sentences grounded in ledger rows
    lessons: tuple[str, ...]
    origin: str         # "verified-finding" | "debunk" | "gap"

@dataclass
class SkillDraft:
    name: str; description: str
    version: str = "0.1.0"; min_tier: str = "basic"
    tags: tuple[str, ...] = ("curated",)      # + origin tag
    body: str = ""
    flagged: bool = False; flag_reasons: tuple[str, ...] = ()
    duplicates: tuple[str, ...] = ()          # existing skill names it duplicates
```

### 5.1 Extraction (`extract_candidates(retro, findings, *, max_candidates=3)`) — PURE

Reads only the `RetroReport` (stats/gaps/lessons) and `Finding` rows it is
given — no ledger access, no I/O. Candidates, in this normative order:

1. **verified-finding** (max 2): distinct finding classes — the `key`
   prefix before the first `|` (e.g. `reflected-xss` from
   `reflected-xss|GET|/search|q`) over VERIFIED findings, ordered by
   (class count desc, class asc). Summary composes the class's titles +
   remediation lines; lessons carry the retro's verified-lesson line.
2. **debunk** (max 1): when ≥ 1 finding is RULED_OUT — "replay before you
   claim" candidate summarizing the ruled-out titles.
3. **gap** (max 1): when a retro gap line starts with `gate failed: recon` —
   a recon-coverage candidate.

Total capped at `max_candidates`; a run with no verified findings, no
ruled-out findings, and no recon gate failure yields `[]`.

### 5.2 Dedupe (pure; K4)

`similarity(a: frozenset[str], b: frozenset[str]) -> float` — Jaccard, 0.0
when both empty. `dedupe_candidate(candidate, corpus)` builds the candidate
token set from `tokenize(title + " " + summary)` and compares against each
corpus skill's `tokenize(name-joined + description + tags)`; duplicates =
all skill names where names are equal (normalized) or similarity ≥
`DUPLICATE_JACCARD = 0.6`. A candidate with any duplicates is skipped by
`curate` with a note naming the existing skill — never drafted, never saved.

### 5.3 Drafting (`draft_skill(candidate, *, provider=None) -> SkillDraft`)

- **Template path** (no provider, or provider error — never raises): name =
  slug of the title (id regex; empty slug → `technique-<origin>`),
  description = first ≤ 60 chars of the summary (cut at a word boundary),
  body = `# <title>\n\n## Doctrine\n` + numbered lesson lines + closing
  rule `Evidence or nothing — a skill you cannot ground in a replayed run
  is a story, not a technique.`
- **LLM path**: ONE `provider.complete("utility", messages)` call with a
  FIXED curator prompt embedded in the module (drafts one skill card from
  the candidate; demands frontmatter name/description + 20–45-line body;
  forbids instructions to the agent that bypass gates). The response is
  parsed LENIENTLY and then CANONICALIZED: name slugified, description
  clamped ≤ 60 chars, body truncated at a line boundary to ≤ 45 lines,
  result re-validated with `parse_skill_md` — anything unusable falls back
  to the template path with a note. Provider output is DATA for the draft;
  it never reaches a prompt directly.
- Every draft is run through `scan_draft` (§5.4) and gets
  `tags = ("curated", <origin>)`.

### 5.4 Injection scan (`scan_draft(text) -> tuple[bool, tuple[str, ...]]`) — PURE

Normative denylist, case-insensitive substrings:

```
ignore previous instructions   ignore all previous instructions
disregard previous instructions disregard all instructions
forget your instructions       new instructions
you are now                    act as
pretend to be                  system prompt
assistant:                     developer message
<|im_start                     <|im_end
### instruction                reveal your
```

plus any C0 control character except `\t`, `\n`, `\r`. A hit ⇒
`flagged=True` with the matched markers as reasons. False positives are
recoverable (quarantine is lifted by a manual edit) — the safe side wins.

### 5.5 Review & save (`review_and_save(draft, *, home=None, ask=None, console=None) -> Path | None`)

1. **ALWAYS preview** (rich panel on the string-capturable console): name,
   description, tier, tags, dedupe verdict (`duplicates existing skill(s):
   ...` or `unique against N skills`), the target path, the full body, and
   — when flagged — `warning: draft contains instruction-like text:
   <reasons>` plus `this skill will be saved INERT (quarantined: true) and
   never mounted until you edit the file`.
2. **ask seam**: `ask: Callable[[str], bool] | None`; prompt
   `save this skill to <path>? [y/N]`. Default implementation reads the
   console; EOFError / KeyboardInterrupt / any exception → False.
   **Ambiguity never saves.**
3. YES → `write_skill` (§3.4). Flagged drafts are written with
   `quarantined: true` (K9) and the reply notes the inert status. NO →
   `skipped — not saved` (nothing written).
4. Returns the written path or None.

### 5.6 Orchestration (`curate(run_id, *, ledger, home=None, ask=None, console=None, provider=None)`)

`compute_retro` → `ledger.findings(run_id)` → `extract_candidates` →
(no candidates) `no skill candidates from this retro` → else per candidate:
dedupe → (duplicate) skip note → else `draft_skill` → `review_and_save` →
summary line `curator: <saved> saved, <skipped> skipped, <duplicates>
duplicates of existing skills`. Read-only against the ledger; the ONLY
write in the whole module is `write_skill` behind an affirmative ask.

### 5.7 Surfaces

- Chat: `CommandDef("curate", "Draft skills from a run's retro (preview +
  confirm; never auto-saves)", "Audit", args_hint="[run_id]",
  busy_policy="reject")` after `/retro` → registry 20 entries. Executor
  `_exec_curate`: resolves run_id (default = most recent ended run, same
  rule as `/retro`), opens the ledger via the existing factory seam, ask =
  `ctx.options.get("curator_ask")` or the module default (stdin-based,
  fail-closed on EOF — a headless gateway surface declines by EOF, never
  saves), provider from `ctx.config` when one is configured (else None →
  template drafts).
- CLI: `hunter curate [run_id] [--state PATH]` — thin; loads the config for
  a provider when available; the default ask reads stdin (CliRunner tests
  script `input="y\n"`); EOF/decline saves nothing.

---

## 6. Part D — surfaces & data changes

### 6.1 `/skills` (chat) — source marking

`_exec_skills` switches from the bundled line-scan to `load_corpus()`:

```
skills (bundled + user):
  recon-basics [bundled] — Map before you touch — recon that builds proof, not noise.
  my-technique [user] — Local trick for staging hosts.
  suspect-thing [quarantined] — ... (not mounted until reviewed)
```

- One line per VALID skill; shadowed bundled names appear ONCE (as their
  effective `[user]` entry). Notes (skip/shadow) render as `note:` lines
  after the list. Total corpus failure → today's `skills corpus not
  installed`. `data={"skills": lines[1:]}` unchanged shape.

### 6.2 `hunter skills` (CLI) — source column

Table gains a `source` column (`bundled | user | quarantined`) over the
merged corpus. `--view <name>` resolves the EFFECTIVE skill (user shadow
first); when a user skill shadows a bundled one, print
`note: user skill '<n>' shadows the bundled skill '<n>'` before the body.
Unknown name → today's error path (exit 1).

### 6.3 Retro hint (inert; K5)

After a successful `record` (`/retro --record` and `hunter retro --record`),
run `extract_candidates` on the same retro+findings; when non-empty append
exactly:

```
curator: <n> candidate technique(s) — run /curate (or 'hunter curate <run_id>') to review and save
```

No prompt, no ask, no write. `compute` (without `--record`) prints no hint.

### 6.4 Bundled tags (data change; bodies frozen)

`tags:` added to the 7 bundled SKILL.md frontmatters (normative — tests
SK1/MT9 pin entries of this table):

| skill | tags |
| --- | --- |
| `recon-basics` | `recon, surface, mapping, passive` |
| `verification-ladder` | `core, evidence, replay, verification, findings, claim` |
| `scope-discipline` | `core, scope, consent, manifest, gate, blocked` |
| `eliminate-trace-walkthrough` | `method, eliminate, trace, walkthrough, loop` |
| `bypass-principles` | `bypass, auth, session, trust, boundary, webhook` |
| `cdc-thinking` | `divergence, convergence, zero-day, reasoning, hypothesis` |
| `black-swan-engine` | `invariant, violation, anomaly, law, derivation` |

`INDEX.md` "Rules for new skills" gains rule 5: user skills live in
`~/.hunteros/skills/<name>/SKILL.md` (same frontmatter; optional `tags:`;
`quarantined: true` keeps a skill unmounted), user shadows bundled with a
note, and everything is data — never executed.

### 6.5 Docs (README + FIRST-RUN)

One short section: the user skills dir, the `[source]` markers, and the
curator flow (`/curate` → preview → y/N → saved to `~/.hunteros/skills/...`;
flagged drafts are quarantined). BUILDER captures real output; AUDITOR pins
only the static markers (D1).

---

## 7. CONTRACT-CHANGE INVENTORY — every existing test pinned to old behavior

| Test file::test | Change |
| --- | --- |
| `tests/test_chat_hunt.py::test_armed_reply_shows_target_check_and_skills_mounted` (M3 C12) | **REWRITTEN deliberately.** It pins `skills mounted: {len(mounted_skills())}` + all bundled names. M5 mounts the SELECTED skills: the rewrite asserts `skills mounted: 2 (scope-discipline [bundled], verification-ladder [bundled])` for the arming text `audit http://127.0.0.1:8941/` (no topical matches → K2 core fallback), k ≤ 5 always, and keeps the `target check:` assertion unchanged. |

Explicitly verified NOT affected:

- `tests/test_agent_skills_seam.py` (K1, K2): K1 touches only
  `mounted_skills()` (unchanged). K2's flow is preserved by the
  install-only-when-none rule (§4.3): sentinel installed before
  `AgentLoop(...)` → no-op; final `install_skill_selector(None)` →
  `resolve_skills_index() == load_skills_index()`. NOTE: the new test files
  MUST carry an autouse fixture calling `install_skill_selector(None)` (§12
  conventions) so selector state never leaks into K2 regardless of file
  order.
- `tests/test_chat_commands.py::test_skills_lists_bundled` — asserts only
  `"recon-basics" in reply.text` → still true with `[bundled]` markers.
- `tests/test_cli_hunt.py::test_hunt_localhost_vault_findings_exit_2` (H1)
  — asserts `"skills mounted:"` presence only → still true.
- `tests/test_chat_commands.py::test_registry_has_required_commands` —
  subset assert; the 20th entry is additive.
- Everything asserting prompt content via `ctx.config["skills_index"]`
  override or fake selectors — the override still wins; no other test pins
  INDEX content inside a system prompt (verified by grep).

---

## 8. Existing contracts that must NOT break (builder's red lines)

1. **Skill files are DATA.** Nothing executes, imports, or evaluates
   SKILL.md content — loader, matcher, renderer, curator are string/regex
   machinery only. Gates remain code: a skill can never grant capability
   (tier/scope/claim gates untouched, §9-K6).
2. **Malformed ⇒ skipped with a note, never a crash.** Every
   read/parse/validation failure of any skill file degrades to a `notes`
   entry; a corpus of garbage yields an empty selection and a normal hunt.
3. **The curator never auto-saves.** There is no call path from
   extract/dedupe/draft to disk; only `review_and_save` writes, only on an
   affirmative injectable ask; EOF/exception ⇒ decline. Drafts are
   quarantined from prompts until confirmed: they exist in memory only, and
   flagged ones stay unmounted even after a confirmed save.
4. **The M3 seam default is byte-identical.** With no selector installed,
   `resolve_skills_index() == load_skills_index()` (K2); `mounted_skills()`
   is untouched; M5 activates matching ONLY via
   `install_default_skill_selector()` (which never overrides an explicit
   selector) called from `AgentLoop.__init__`.
5. **`ctx.config["skills_index"]` override wins** over everything, exactly
   as today.
6. **No new write path into the ledger, scope, or config.** The curator
   writes only `<home>/.hunteros/skills/<name>/SKILL.md`, refuses
   out-of-root/traversal targets and overwrites, and writes atomically.
7. **Additive-only surface changes.** `/curate` (20th command), `hunter
   curate`, the `source` column, the hint line; no existing command
   signature or reply contract changes except the §7 rewrite.
8. **Hermetic tests.** No network anywhere; the optional curator LLM call
   is injected (`FakeProvider`) or absent (template path); `home=` seams +
   `_cli_env` sandboxing; every new test file restores the selector seam
   via autouse `install_skill_selector(None)`; the 761-collected baseline
   stays green except §7.

---

## 9. Data flow (one glance)

```
hunt start (CLI / chat arm / one-shot)
  AgentLoop.__init__ ─► install_default_skill_selector()   (no-op if one is set)
  loop.run(ctx, goal)
    ├─ ctx.config["skills_index"] ─► use verbatim            (override wins)
    └─ resolve_skills_index(question=goal)
         ├─ no selector ─► load_skills_index()               (M3 default, byte-identical)
         └─ default selector
              ├─ load_corpus()        bundled ∪ user (shadow + notes, validation)
              ├─ target_hint(goal)    pure URL/host extraction
              ├─ match_skills(...)    score ≥ 2 → top-5 │ else core-tagged │ else []
              ├─ render_block(...)    ≤ 16k chars, bodies verbatim
              └─ system prompt gets the block; banner line:
                 skills mounted: <k> (<name [source], ...>)
post-hunt
  /retro --record ─► retro recorded ─► inert hint line when candidates exist
  /curate [run_id]  or  hunter curate [run_id]
    compute_retro + findings
      └─ extract_candidates (pure) ─┬─ none ──► "no skill candidates"
                                    └─ ≤ 3 candidates
         dedupe vs corpus (name ∨ Jaccard ≥ 0.6) ──► skip + note
         draft_skill (template │ 1 utility-tier LLM call → canonicalize)
         scan_draft (denylist) ──► flagged?
         PREVIEW (always) ─► ask [y/N] (injectable; EOF/raise ⇒ no)
            ├─ N ─► skipped — not saved
            └─ Y ─► write_skill (atomic; refuses traversal/out-of-root/overwrite)
                    flagged ─► saved with quarantined: true — NEVER mounted
                    clean  ─► saved; mounted by FUTURE runs' matching
```

---

## 10. Design notes (recorded 2026-09-14)

- The seam's `_SKILL_SELECTOR("")` placeholder is the reason for K7: M3's
  K2 test pins the one-argument selector contract, so the goal itself is
  the carrier of target context. `build_goal` output always contains the
  URL; chat arming text contains the target by construction (it armed the
  audit). Follow-up chat turns ("go") may hint no target — matching then
  runs on instruction alone and still lands on the core fallback floor.
- The block renders full SKILL.md bodies (not INDEX table rows). INDEX.md's
  own header defines a skill as "a compact, frontmattered contract the
  harness loads into the loop"; the table-only status quo was the M3
  stopgap. 5 × ~40-line cards ≈ 200 lines — bounded further by the block
  budget.
- The curator's LLM call reuses the existing `ChatProvider.complete` (tier
  `"utility"`, no tools, no budget side effects) — no new provider
  machinery; the utility role already exists in `model_tiers`.
- `parse_skill_md` is shared by the loader, `write_skill` (validate-before-
  commit), and `hunter skills --view` — one schema, one validator.
- PyYAML is already a core dependency (config loader) — frontmatter parsing
  adds no dependency. Ruff + 3.11/3.13 CI apply as usual.
- The quarantine escape hatch is a user file edit by design: HunterOS never
  silently re-enables content that pattern-matched injection; `/skills`
  keeps the `[quarantined]` marker visible until then.
- `extract_candidates` deliberately reads only what `compute_retro` already
  computed plus `Finding` rows — no new ledger queries, no retro format
  change, so the L5 KNOWLEDGE loop stays append-only and untouched.

---

## 11. ACCEPTANCE CRITERIA

### (a) pytest-testable Python behavior — each maps to exactly one test

**Corpus & validation (`tests/test_agent_skills_corpus.py`)**

- **SK1** Real corpus loads with tags: `load_corpus()` returns exactly the
  7 bundled skills, all `source == "bundled"`, every `name` equal to its
  directory id, every `tags` non-empty per the §6.4 table (pin: `"core" in
  scope-discipline.tags`, `"core" in verification-ladder.tags`,
  `"recon" in recon-basics.tags`), `notes == ()`.
- **SK2** Malformed frontmatter skips with notes, never raises: six
  synthetic user skills — missing `name`; `name` ≠ directory; `min_tier:
  expert`; empty `description`; `description` of 201 chars; unparsable YAML
  fence — each yield exactly one skip note naming the directory; a valid
  sibling in the same root loads; `load_corpus` returns normally.
- **SK3** Id/traversal defense: user directories `Foo`, `foo_bar`,
  `..hidden`, `x y`, and a skill whose frontmatter says
  `name: ../escape` inside dir `sneaky` — all skipped with notes; the
  corpus contains none of them; no path outside the root is ever read or
  written (loader is read-only; `write_skill` refusal is SK9's).
- **SK4** Size caps: a user skill with a 401-line body → skip note; a
  400-line body loads; a 33,000-byte SKILL.md → skip note (`too large`).
  One test, three sub-cases.
- **SK5** Shadow merge (K1): user `recon-basics` + user `my-technique` →
  exactly one `recon-basics` entry with `source == "user"`, the shadow note
  present verbatim (`user skill 'recon-basics' shadows the bundled skill
  'recon-basics'`), `my-technique` is `[user]`, all other bundled cards
  remain `[bundled]`.
- **SK6** Quarantine: a user skill with `quarantined: true` is returned by
  `load_corpus` with the flag AND is excluded from `match_skills` results
  and `selected_skill_names` even when it would score highest.
- **SK7** Tolerance: no user dir + bundled present → normal corpus, and the
  user dir is NOT created; `resources.files` monkeypatched to raise → no
  raise, user skills still load (bundled contributes nothing).
- **SK8** `parse_skill_md` minimal card: defaults applied (`min_tier`
  `"basic"`, `tags == ()`, `quarantined is False`), version preserved, body
  frontmatter-stripped; invalid tag entries are dropped while the skill
  loads.
- **SK9** `write_skill` contract: success creates
  `<root>/<name>/SKILL.md` with the exact canonical frontmatter (incl.
  `tags:` and, when flagged, `quarantined: true`) and the body;
  `name: ../escape` → `HunterError` code `skills.refused`; a pre-existing
  skill of the same name → `HunterError` code `skills.exists` (bytes
  untouched); a resolved target outside the root → `skills.refused`.
- **SK10** `keys.atomic_write_text`: writes content atomically (correct
  bytes, replaces existing content, no `.tmp` residue in the directory);
  `write_keys_env` behavior unchanged (existing keys tests still green).

**Matching & seam (`tests/test_agent_skills_match.py`)**

- **MT1** `target_hint` purity + table: URL in text → the URL (trailing
  punctuation stripped); bare host → the host; no target → `""`. With
  `socket.socket`, `socket.create_connection`, `Path.exists`, `Path.stat`
  monkeypatched to raise, `target_hint` and `tokenize` still return; the
  module source imports neither `httpx` nor `urllib` nor `socket` (static
  read).
- **MT2** Scoring table (synthetic skills): tag hit = 3, name hit = 2,
  description hit = 1; distinct-token counting (a repeated query token
  scores once); score-1-only skills are excluded (threshold 2); order is
  `(-score, name)`; result is identical across two calls (determinism).
- **MT3** Cap: eight synthetic skills all scoring ≥ 2 → exactly
  `MAX_MOUNTED` selected, highest scores first, name ascending tiebreak.
- **MT4** Core fallback (K2): a goal matching nothing on the real corpus →
  the selection is exactly the `core`-tagged skills
  (`scope-discipline`, `verification-ladder`), name-sorted.
- **MT5** Empty block: no matches and no `core` tags (synthetic corpus) →
  `render_block([]) == ""` and `build_system_prompt(..., skills_index="")`
  renders `(no skills mounted)`.
- **MT6** Block budget: five valid-but-large (~3.5 KiB) synthetic skills
  selected → rendered block ≤ `MAX_BLOCK_CHARS`, skills dropped from the
  tail in selection order, never empty while > 1 candidate, re-render
  deterministic.
- **MT7** Seam: `install_default_skill_selector()` on a clean state makes
  `resolve_skills_index(question=goal)` return a block starting
  `# Skills mounted for this run` and NOT containing INDEX.md's
  `Rules for new skills`; the question reaches the selector (an
  explicitly installed recorder receives the goal string);
  `install_default_skill_selector()` after an explicit install is a no-op;
  `install_skill_selector(None)` restores `load_skills_index()`.
- **MT8** AgentLoop wiring: a fresh-state `AgentLoop` construction installs
  the default (a following `loop.run` mounts a matched block in the system
  prompt — fake provider records it); `ctx.config["skills_index"] = "OVERRIDE"`
  still mounts `OVERRIDE` verbatim; constructing an AgentLoop never
  displaces an explicitly installed selector.
- **MT9** Normative selections: for the canonical `build_goal(...)` text the
  selection is exactly `[("verification-ladder", "bundled"),
  ("recon-basics", "bundled")]` (order pinned); for the chat arming text
  `audit http://127.0.0.1:8941/` it is exactly
  `[("scope-discipline", "bundled"), ("verification-ladder", "bundled")]`
  (core fallback).

**Curator (`tests/test_agent_curator.py`)**

- **CU1** `extract_candidates` table: two verified findings of one class +
  one of another + a ruled-out finding + a `gate failed: recon` gap →
  candidates in order [verified-finding (larger class), verified-finding,
  debunk, gap]; three verified classes → only the top 2 kept; total never
  exceeds 3.
- **CU2** No signals (no verified, no ruled-out, no recon-gate gap) →
  `extract_candidates(...) == []` and `curate` replies
  `no skill candidates from this retro`, writes nothing.
- **CU3** Dedupe rule (K4): a candidate whose normalized name equals an
  existing skill → duplicate; token sets with Jaccard exactly 0.6 →
  duplicate; 0.59 → not; a novel candidate against the real corpus →
  `duplicates == ()`.
- **CU4** Template draft (provider=None): canonical frontmatter (`version`
  `0.1.0`, `min_tier` `basic`, `tags` contains `curated` and the origin
  slug), description ≤ 60 chars, body ≤ 45 lines and non-empty, and the
  assembled SKILL.md text passes `parse_skill_md` (name == slug).
- **CU5** LLM draft canonicalization: a `FakeProvider` returning a messy
  card (prose around it, `name: My Skill!!`, 90-char description, 60-line
  body) → draft name slugified, description clamped ≤ 60, body truncated
  at a line boundary, still `parse_skill_md`-valid; the provider received
  the fixed curator prompt with the candidate summary embedded and NO
  tools; a provider that raises → template fallback + note, no raise.
- **CU6** Injection scan table: every §5.4 denylist marker flags (with the
  marker as reason), a control character flags, and a clean doctrine body
  does not.
- **CU7** Flagged draft saved INERT: preview shows the warning lines;
  `ask → True` writes the file with `quarantined: true`; `load_corpus`
  reports it quarantined; `selected_skill_names`/`match_skills` exclude it;
  the reply states the inert status.
- **CU8** Ask seam fail-closed: `ask → False` writes nothing (no file, no
  directory); `ask` raising `EOFError` (and, in a second engine, a generic
  `RuntimeError`) → decline, no raise, nothing written.
- **CU9** No auto-save path: with `write_skill` monkeypatched to fail the
  test if called, `extract_candidates` + `dedupe_candidate` +
  `draft_skill` complete without touching it; `curate` with a declining
  ask leaves the user skills dir empty; static check: `curator.py` contains
  no `os.replace`/`tempfile` outside the write path and imports no network
  module.
- **CU10** Preview contract: the captured preview contains the name, the
  description, the dedupe verdict, the target path, and the full body; a
  flagged draft's preview contains `warning:` and `quarantined` lines.
- **CU11** Overwrite refusal in flow: a pre-existing user skill with the
  draft's name → preview states it exists → skipped even with
  `ask → True`; existing file bytes untouched.
- **CU12** Surfaces end-to-end: chat `/curate <run_id>` with
  `ctx.options["curator_ask"] → True` on a ledger with one verified finding
  → reply contains the candidate summary, `saved`, and the file exists
  under the sandbox home; `hunter curate <run_id> --state` via CliRunner
  with scripted input `n\n` → `skipped — not saved`, no file; a run with no
  candidates → `no skill candidates` (both surfaces).

**Surfaces (`tests/test_skills_surfaces.py`)**

- **SU1** `/skills` source marking: bundled names carry `[bundled]`; a
  sandbox user skill appears with `[user]`; the shadowed name appears once
  (effective `[user]`) plus the shadow note; a quarantined skill shows
  `[quarantined]` and `not mounted until reviewed`; `recon-basics` still
  appears (old assert stays true).
- **SU2** `hunter skills`: the table has a `source` column and lists user
  skills; `--view <user-skill>` prints its body; `--view` of a shadowing
  name prints the shadow note + the USER body; `--view nope` → exit 1.
- **SU3** Registry: exactly 20 commands, help lists `/curate`, bare
  `/curate` with no runs answers with the no-runs message (no ledger row,
  no write).
- **SU4** Hunt banner line: a `hunter hunt` vault run (deterministic
  engine) prints `skills mounted: <k> (` where k ≤ 5 and each rendered
  `<name> [<source>]` names a corpus skill; the line stays present (H1's
  assertion untouched).
- **SU5** Retro hint: `/retro --record <run_id>` on a run with verified
  findings → reply contains the `curator:` hint line with the candidate
  count and never prompts; a clean run's `--record` output contains no
  `curator:` line; `hunter retro --record` (CliRunner) behaves the same.

**Docs**

- **D1** `README.md` contains `~/.hunteros/skills` and `/curate`;
  `docs/FIRST-RUN.md` mentions the curator preview or the
  `[quarantined]` marker — one static file-read test, no execution.

### (b) Script-level checks

None — M5 adds no installer/shell surface. (M1's S1–S8 and M4's checks are
unaffected.)

---

## 12. TEST PLAN (auditor implements verbatim)

| File | Test name | Asserts |
| --- | --- | --- |
| `tests/test_agent_skills_corpus.py` | `test_bundled_corpus_loads_with_tags` | SK1 |
| `tests/test_agent_skills_corpus.py` | `test_malformed_frontmatter_skips_with_notes` | SK2 |
| `tests/test_agent_skills_corpus.py` | `test_skill_id_regex_blocks_traversal_and_garbage` | SK3 |
| `tests/test_agent_skills_corpus.py` | `test_skill_size_caps_skip_huge_files` | SK4 |
| `tests/test_agent_skills_corpus.py` | `test_user_skill_shadows_bundled_with_note` | SK5 |
| `tests/test_agent_skills_corpus.py` | `test_quarantined_skill_listed_but_never_matched` | SK6 |
| `tests/test_agent_skills_corpus.py` | `test_missing_corpus_and_resources_failure_tolerated` | SK7 |
| `tests/test_agent_skills_corpus.py` | `test_parse_skill_md_minimal_card_and_defaults` | SK8 |
| `tests/test_agent_skills_corpus.py` | `test_write_skill_success_and_refusals` | SK9 |
| `tests/test_agent_skills_corpus.py` | `test_keys_atomic_write_text_public_wrapper` | SK10 |
| `tests/test_agent_skills_match.py` | `test_target_hint_pure_and_table` | MT1 |
| `tests/test_agent_skills_match.py` | `test_scoring_weights_threshold_and_order` | MT2 |
| `tests/test_agent_skills_match.py` | `test_max_five_cap_and_tiebreak` | MT3 |
| `tests/test_agent_skills_match.py` | `test_empty_match_falls_back_to_core_tags` | MT4 |
| `tests/test_agent_skills_match.py` | `test_no_core_tags_renders_empty_block` | MT5 |
| `tests/test_agent_skills_match.py` | `test_block_budget_drops_tail_deterministically` | MT6 |
| `tests/test_agent_skills_match.py` | `test_default_selector_install_and_seam_contract` | MT7 |
| `tests/test_agent_skills_match.py` | `test_agent_loop_auto_installs_and_override_wins` | MT8 |
| `tests/test_agent_skills_match.py` | `test_normative_selections_for_goal_and_arming_text` | MT9 |
| `tests/test_agent_curator.py` | `test_extract_candidates_table_and_cap` | CU1 |
| `tests/test_agent_curator.py` | `test_no_signal_run_yields_no_candidates` | CU2 |
| `tests/test_agent_curator.py` | `test_dedupe_name_and_jaccard_boundary` | CU3 |
| `tests/test_agent_curator.py` | `test_template_draft_is_canonical_and_valid` | CU4 |
| `tests/test_agent_curator.py` | `test_llm_draft_canonicalized_and_provider_failure_falls_back` | CU5 |
| `tests/test_agent_curator.py` | `test_injection_scan_denylist_table` | CU6 |
| `tests/test_agent_curator.py` | `test_flagged_draft_saved_quarantined_and_never_mounted` | CU7 |
| `tests/test_agent_curator.py` | `test_ask_seam_fail_closed_never_saves_on_error` | CU8 |
| `tests/test_agent_curator.py` | `test_no_auto_save_path_exists` | CU9 |
| `tests/test_agent_curator.py` | `test_preview_contains_verdict_flags_and_body` | CU10 |
| `tests/test_agent_curator.py` | `test_curate_never_overwrites_existing_skill` | CU11 |
| `tests/test_agent_curator.py` | `test_curate_surfaces_end_to_end` | CU12 |
| `tests/test_skills_surfaces.py` | `test_chat_skills_marks_sources_and_quarantine` | SU1 |
| `tests/test_skills_surfaces.py` | `test_cli_skills_source_column_and_view_shadow` | SU2 |
| `tests/test_skills_surfaces.py` | `test_registry_curate_command_and_no_runs_message` | SU3 |
| `tests/test_skills_surfaces.py` | `test_hunt_banner_line_shows_selected_sources` | SU4 |
| `tests/test_skills_surfaces.py` | `test_retro_record_hint_line_both_surfaces` | SU5 |
| `tests/test_docs_m5.py` | `test_docs_describe_user_skills_and_curator` | D1 |

Plus the §7 rewrite (1 existing test). Every criterion maps to exactly one
test; every test maps to exactly one criterion.

Conventions for the auditor:

- Copy `_string_console` / `_cli_env` from `tests/test_cli_init.py` (delete
  `HUNTER_STATE_DIR` in CLI tests); `FakeProvider` from
  `tests/test_agent_skills_seam.py`; the `ctx` fixture from
  `tests/test_chat_commands.py`; `runner.invoke` + `_flat` from
  `tests/test_cli_hunt.py`.
- **Selector hygiene (mandatory):** an autouse fixture in
  `test_agent_skills_match.py`, `test_agent_skills_corpus.py`,
  `test_agent_curator.py`, and `test_skills_surfaces.py` runs
  `install_skill_selector(None)` before AND after each test — the M3 K2
  test asserts the inert default and must stay green regardless of file
  order.
- User-skill fixtures are built under `tmp_path` and passed via the
  `home=` parameter (never by mutating `Path.home()`); CLI-surface tests
  monkeypatch `HOME`/`USERPROFILE` to `tmp_path` per `_cli_env`.
- Curator ask seams are recording lambdas — never real stdin, except the
  `hunter curate` CliRunner test which scripts `input="n\n"`.
- Synthetic corpus builders write `SKILL.md` files with programmatic line
  counts (SK4/MT6) — no large fixtures committed.
- The normative stopword set for `tokenize` (pinned by MT2):
  `the a an and or of to in on for with by is are be as at from that this
  it its you your we our not no do does did can may will would should into
  per via use used using when what how where which each any all http https
  www com net org tier basic advanced run goal`.

---

## 13. ADVERSARIAL matrix (risk → design answer → where tested)

| # | Risk | Design answer | Test |
| --- | --- | --- | --- |
| 1 | Hostile SKILL.md floods the prompt (huge file) | Two layers: the loader skips files > 32 KiB or bodies > 400 lines (skip note, never mounted); the rendered block is bounded by `MAX_BLOCK_CHARS` with deterministic tail drops | SK4, MT6 |
| 2 | Broken frontmatter crashes the loader / the hunt | Every parse/validation failure is a skip note; the loader never raises; an empty corpus yields `"(no skills mounted)"` and a normal hunt | SK2, SK7, MT5 |
| 3 | Path traversal in a skill name (`../escape`, absolute paths) | Directory id must match the slug regex AND equal the frontmatter `name`; `write_skill` re-checks the regex plus the same containment rule as keys.env (`_is_within`) before any write | SK3, SK9 |
| 4 | Curator draft carries prompt-injection text scraped from target pages (saved, then mounted into FUTURE prompts) | Denylist scan flags the draft; preview shows warnings; a confirmed save is written with `quarantined: true`; the loader excludes quarantined skills from matching — the content is saved inert and can never be injected unreviewed; unflagging requires a manual file edit | CU6, CU7, SK6 |
| 5 | Name-squat: user skill reuses a bundled name to replace doctrine with hostile text | Shadowing is the designed override (K1) but is always surfaced: shadow note, `[user]` markers in `/skills` + `hunter skills` + the mount block; the squatting file passes the SAME validation as everything else, and gates stay in code regardless of what any skill says | SK5, SU1, SU2 |
| 6 | `match()` with an empty/garbage corpus | Deterministic degradation: no matches → `core` fallback → `"(no skills mounted)"`; missing dirs/failed resources are tolerated; the hunt proceeds normally | MT4, MT5, SK7 |
| 7 | The LLM drafts a hostile "skill" (provider output is attacker-influenced via retro content) | Provider output is never trusted: canonicalized (slug/clamps/truncation), re-validated with the shared parser, injection-scanned, previewed, and behind the y/N ask; a raising provider falls back to the deterministic template | CU5, CU6, CU8 |
| 8 | Skill body instructs the agent around a gate | Files are data (red line 1); tier/scope/claim gates live in tool handlers, not prompts — a skill cannot grant capability (existing adversarial coverage); INDEX rule 4 unchanged | §8.1, K6 |
| 9 | Quarantined skill silently re-enabled | No code path unflags: only a manual user edit of the file; `/skills` keeps the `[quarantined] (not mounted until reviewed)` marker until then | SK6, SU1 |
| 10 | Curator clobbers a user-authored skill | `skills.exists` refusal — the curator never overwrites; the user edits files by hand | SK9, CU11 |
| 11 | Curator writes outside home | Containment rule identical to `keys.write_keys_env` + regex id check; layer `config`, codes `skills.refused` / `skills.exists` | SK9, SK3 |
| 12 | Auto-save / nag loop after retro | The retro hint is inert text (K5); saving requires the explicit `/curate`/`hunter curate` flow AND an affirmative ask; EOF/exception declines | CU8, CU9, SU5 |
| 13 | Nondeterminism or I/O in matching | `target_hint`/`tokenize`/`match_skills`/`render_block` are pure (static import check + monkeypatched-to-raise I/O still passing); equal inputs ⇒ equal blocks | MT1, MT2 |
| 14 | Selector state leaks across tests / breaks the M3 inert default | Install-only-when-none rule (explicit selectors always win); autouse `install_skill_selector(None)` in every new test file; K2 verified green by flow analysis | MT7, MT8, §7 |
| 15 | Skills block exceeds budget with 5 huge-but-valid cards | Block budget drops lowest-scored skills tail-first; never empty while > 1 candidate; per-file caps catch the truly huge | MT6, SK4 |

---

## 14. Verify commands (Windows dev reality + CI)

```bash
# Python (repo venv):
.venv/Scripts/python -m pytest tests/test_agent_skills_corpus.py \
  tests/test_agent_skills_match.py tests/test_agent_curator.py \
  tests/test_skills_surfaces.py tests/test_docs_m5.py -q
.venv/Scripts/python -m pytest tests/test_agent_skills_seam.py \
  tests/test_chat_hunt.py tests/test_cli_hunt.py tests/test_chat_commands.py -q   # §7 rewrite + neighbors
.venv/Scripts/python -m pytest -q          # full suite: 761 baseline − C12 rewrite + 37 new, all green
.venv/Scripts/python -m ruff check src tests

# Spot the dynamic mount + curator contracts by hand (loopback only):
.venv/Scripts/python -m hunter.cli.main skills
.venv/Scripts/python -m hunter.cli.main curate --state .tmp-state
```

CI (ubuntu/windows × 3.11/3.13) runs ruff + pytest only; no new
script-level checks.

---

## 15. Builder order (suggested)

1. Bundled tags data change (§6.4) + `INDEX.md` rule 5 — SK1/MT9 depend on
   the normative tag table; bodies stay byte-frozen.
2. `keys.atomic_write_text` extraction (§3.4) + SK10 — tiny, and the
   curator's writer depends on it.
3. `agent/skills.py` corpus + validation + writer (§3) + tests (SK1–SK9).
4. Matching + rendering + seam additions + `AgentLoop.__init__` install +
   `loop.py` one-liner (§4) + tests (MT1–MT9) + the §7 C12 rewrite.
5. `agent/curator.py` (§5) + tests (CU1–CU12).
6. Surfaces: `/skills` sources, `hunter skills` column/view, `/curate` +
   `hunter curate`, retro hints, banner-line content in `_audit_open` /
   `hunt.py` (§6) + tests (SU1–SU5).
7. Docs (§6.5) — capture real output last.
