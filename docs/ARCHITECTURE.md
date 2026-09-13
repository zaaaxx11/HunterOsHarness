# Architecture — HunterOs Harness (v0.2)

The harness is a layered system with one hard rule: **everything of value is
a row in the hash-chained ledger**. Layers may be rewritten; the ledger
format is load-bearing and only changes with a migration plan.

## The five layers of the framework (L1–L5)

HunterOs thinks in five permanent layers — doctrine, pipeline, engine,
state, knowledge — mapped onto modules as follows:

| Layer | Name | In HunterOs |
| ----- | ---- | ----------- |
| **L1** | Doctrine — permanent principles, enforced by code | `Evidence or Nothing` (RULE-E1); `Chain > Collection` (hash-chained events); `Overturn fast` (debunk replay, RULE-E4); `No fabricated output` (the claim gate). Written as skills in `_data/skills/`, enforced in `kernel/`. |
| **L2** | Pipeline — phases, exit gates, artifact contracts | `workflow/pipeline.py` — ARM → RUN → COLLECT → VERIFY; a finding cannot skip a rung of the ladder; reports render only from ledger rows (`reporting/`). |
| **L3** | Engine — how execution runs | `EngineDriver` plug-point (`engine/`): deterministic probes, mock, and since v0.2 the LLM agent (`agent/` + `llm/`). Brains swap; the evidence contract does not. |
| **L4** | State — the spine | The ledger (`kernel/ledger.py`): append-only SQLite, hash-chained, tamper-guarded by triggers. The db is the only ledger; what is not a row does not exist. |
| **L5** | Knowledge — the retro loop | Coverage rows, ruled-out findings, and the audit trail compound: every run ends in an evidence-cited account of what was checked and cleared. Skills are promoted from practice into `_data/skills/`. |

## Layer diagram

```
        +----------------------------------------------------------+
   L5   |  BUSINESS   | engagement mgmt · billing · assurance certs |   (v0.5)
        +----------------------------------------------------------+
   L4   |  WORKFLOW   | scan pipeline (ARM/RUN/COLLECT/VERIFY)      |   pipeline.py
        |             | demo bench · regression runs                |   bench.py
        +----------------------------------------------------------+
   L3.5 |  INTERFACES | agent loop · chat REPL + sessions · gateway |   agent/ chat/ gateway/
        |             | (Telegram + HMAC webhook) — VIEWS + drivers |
        +----------------------------------------------------------+
   L3   |  LLM BRAIN  | tier router (orchestrator/hunter/verifier/utility)|   llm/
        |             | LiteLLM provider router · budget governor   |
        +----------------------------------------------------------+
   L2   |  TOOLS      | ScopedHttpClient (scope gate HERE)          |   tools/
        |             | scope manifests · redaction                 |
        +----------------------------------------------------------+
   L1   |  ENGINES    | EngineDriver plug-point (the "brain" socket)|
        |             | deterministic probes | mock | LLM agent     |
        +----------------------------------------------------------+
   L0   |  KERNEL     | Ledger (append-only, hash-chained SQLite)   |   kernel/
        |             | findings · events · claim gate · redaction  |
        +----------------------------------------------------------+
                UI: CLI (typer) and TUI (textual) are VIEWS over L0-L4.
```

Rules between layers:

- Dependencies point **down** only. An engine never touches the ledger; it
  returns `CandidateFinding`s with evidence, and the **pipeline** (L4)
  persists them through the kernel. The LLM agent is stricter still: its
  only write path is `create_finding_request` (see governance below).
- The UI is a view: it reads rows, it does not create truth. The only UI
  write path is delegating to the workflow (`d` in the TUI = `hunter demo`).
- Every network byte flows through the `ScopedHttpClient` (L2). There is no
  other socket path — not for the deterministic engine, not for the LLM
  agent, not for anything a prompt asks for.

## The LLM brain (v0.2)

### Provider router — classify → retry → fallback

`llm/router.py` (`ProviderRouter`, backed by LiteLLM) turns one validated
`HunterConfig` into a working brain for any provider:

1. **Resolve** — per-tier model resolution (tier.model → `$HUNTEROS_MODEL`
   → orchestrator.model) and key resolution (`key_env` env lookup > inline
   `api_key` > LiteLLM standard env vars when no provider block exists).
2. **Dial** — `agent.api_max_retries` attempts (default 3) per route with
   bounded exponential backoff (1s → 8s cap).
3. **Classify** — every provider exception is classified **once** (hermes
   pattern) into a verdict: auth, billing, rate_limit, timeout, context
   overflow, content policy, model-not-found, … Messages are redacted of
   anything credential-shaped before display.
4. **Fail over** — auth/billing/404-class verdicts jump to the next link of
   `fallback_providers`; retryable verdicts burn the remaining attempts
   first. Every terminal failure is a `HunterError` with a stable exit code
   (table below) — never a bare traceback.
5. **Govern** — every completion's cost is added to the `RunBudget`
   (staged one-time warnings at 70/85/95% of `max_cost_usd`; hard stops on
   cost, iterations, or wall clock).

### Tier routing

Four model tiers — `orchestrator` (task decomposition), `hunter`
(payload craft), `verifier` (cheap, careful evidence checking), `utility`
(summarizing) — let expensive reasoning happen only where it pays. Tier
resolution: the tier's own model, else `$HUNTEROS_MODEL`, else the
orchestrator's model. The agent-level `tier` (`basic` | one of the model tiers)
additionally gates *capability*:

- **basic** — passive-only: `http_request` accepts GET/HEAD/OPTIONS;
  only passive probes run. Everything else is refused by the handler.
- **advanced** — active methods and active probes authorized within scope.

Tier gating is **structural**: the tool schema list is identical at both
tiers, and the refusals happen inside the handlers with stable codes
(`tier.passive_only` for non-passive methods, `tier.capability_locked` for
active probes). Out-of-tier capability is absent/refused, never
negotiated — a prompt cannot talk the tool layer into a POST at basic tier.

### Governance flow — the loop that cannot fabricate

```
        +------------+
        |  LLM brain |  proposes ONE tool call per turn
        +-----+------+
              |
              v
        +------------------+    scope gate (fail-closed, in the client)
        |    tool layer    |--. every request passes the ScopedHttpClient
        +-----+------------+  |
              |                |
              v                |
   +----------------------+    |
   | evidence validation  |    |
   | R1 prose complete    |    |
   | R2 ids resolve +     |    |   BLOCKED codes name the rule;
   |    sha256 intact     |    |   the model reads and self-corrects
   | R3 >=1 http_exchange |    |
   | R4 endpoint in scope |    |
   | R5 dedupe            |    |
   | R6 severity/conf     |    |
   +----------+-----------+    |
              |                |
              v                v
        +--------------------------------------+
        |       LEDGER (L0, claim gate)        |  RULE-E1 re-checked at the
        | evidence rows + findings, hash-chain |  storage layer, atomically
        +------------------+-------------------+
                           |
                           v
        +------------------------------+
        | debunk replay (deterministic)|  re-run the check; bind replay
        | independent, no LLM argument |  evidence; the ledger decides
        +--------------+---------------+
                       |
        VERIFIED (reproduces)  /  RULED_OUT (kept forever, RULE-E4)
```

Invariants that make the loop trustworthy:

- The model **only ever cites evidence ids it was shown** — handlers return
  results without ids, the loop persists artifacts and appends the ids; R2
  re-resolves every id and recomputes its sha256, so invented, guessed, or
  tampered evidence is blocked before the ledger sees it.
- `think` is the single silent tool: chain-of-thought never reaches the
  hash chain.
- The debunk pass is deterministic. A model can never talk a finding into
  — or out of — the verified state. **The ledger decides verified.**

### Chat, sessions, gateway

`chat/` (REPL + sessions + slash commands) and `gateway/` (Telegram +
HMAC-signed webhook, turn-leased) are front-ends over the same agent loop.
Slash commands work identically in the REPL and over the gateway; a denied
Telegram sender gets one terse refusal and nothing is recorded. See
[docs/GATEWAY.md](GATEWAY.md) and [docs/LLM.md](LLM.md).

## EngineDriver — the brain plug-point

```python
class EngineDriver(Protocol):
    name: str
    def plan(self, target: TargetSpec) -> ScanPlan: ...
    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult: ...
    def replay(self, target: TargetSpec, ctx: EngineContext,
               candidate: CandidateFinding) -> bool: ...
```

- `run` receives a scope-gated HTTP client and an `emit` callback — it
  cannot open sockets, cannot write to the ledger, cannot widen its own
  scope.
- `replay` re-executes **only** the check that produced a candidate and
  returns whether the signal reproduces. The pipeline uses it for ladder
  verification. This is what makes findings reproducible by a third party.
- The deterministic engine fills the slot today. The LLM agent (v0.2)
  mounts beside it — model-driven exploration, but the same evidence
  contract, the same claim gate, the same ladder. The brain changes; the
  proof obligation does not.

## Ledger invariants

The ledger (`kernel/ledger.py`) is append-only SQLite with anti-tamper
triggers that reject direct `UPDATE`/`DELETE`:

1. **Append-only** — no update or delete path exists anywhere in the
   codebase; database triggers enforce it at the storage layer.
2. **Hash chain** — every event stores
   `hash = sha256(canonical_json({prev_hash, run_id, seq, kind, payload, ts}))`;
   genesis `prev_hash` is 64 zeros. `verify_chain` recomputes the entire
   chain and reports the first broken link.
3. **Claim gate** — RULE-E1: a finding cannot be *inserted* without ≥ 1
   bound evidence artifact (same transaction, atomic — no partial rows).
   RULE-E2: `candidate → verified` requires a second, independent replay
   artifact. RULE-E3: evidence payloads are deep-redacted *before* storage.
   RULE-E4: ruled-out findings are never deleted — the audit trail keeps its
   mistakes.
4. **Redaction** — secrets and credentials are stripped in `kernel/redaction.py`
   on the way in; the ledger never holds a replayable credential.

## The verification ladder

```
        probe signal + 1 evidence
                 |
           [ CANDIDATE ]          "we saw something once"
                 |
        independent replay (RULE-E2, 2nd evidence)
                 |
           [ VERIFIED ]           "it reproduces; anyone can check"
                 |
        debunk / challenger wins
                 |
           [ RULED_OUT ]          "kept forever, never deleted"
```

Only `verified` findings are report-grade and (later) billable. The ladder
is enforced by the kernel, not by conventions — a `verified` status change
without replay evidence raises `ClaimGateBlocked`.

## Exit codes (stable contract for scripts)

`HunterError` is the one error language for CLI, TUI, chat, and gateway —
classified layers map to stable exit codes:

| Code | Layer / meaning |
| ---- | --------------- |
| 0 | ok |
| 1 | generic error |
| 2 | usage error |
| 3 | scope denied |
| 4 | auth / billing |
| 5 | rate limit |
| 6 | claim-gate violation |
| 7 | ledger integrity |
| 8 | config error |
| 130 | interrupted |

Rendering rules: `[BLOCKED]` for scope/claim/approval refusals (name the
rule; never suggest widening scope), `[ERROR <layer>]` for everything else
(2 lines max — what happened, what to do), `[RETRYING n/m]` for visible
retries. `detail` is for verbose logs and never contains secrets.

## Roadmap

| Version | Theme | Content |
| ------- | ----- | ------- |
| v0.1 | Deterministic core | kernel, scope gate, deterministic engine, pipeline, reporting, TUI, installers |
| v0.2 | LLM brain + governance | LiteLLM tier router, 15-tool agent with R1–R6 evidence validation, debunk replay, chat REPL, gateway (Telegram/webhook), tier-advanced skills |
| v0.3 | Multi-agent workflow | planner/recon/exploit-verify agents over the same ledger; arsenal adapters (nuclei, semgrep) as additional `EngineDriver`s |
| v0.4 | Assurance atoms | coverage certificate: every probe attempt is an atom — a signed, Merkle-ready "we checked X and here is the proof" set, not just findings |
| v0.5 | Engagement layer | engagement management, billing against verified findings, customer evidence packs |

The v0.3 working backlog lives in [docs/ROADMAP-v0.3.md](ROADMAP-v0.3.md).
