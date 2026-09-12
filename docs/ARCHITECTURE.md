# Architecture — HunterOs Harness

The harness is a layered system with one hard rule: **everything of value is
a row in the hash-chained ledger**. Layers may be rewritten; the ledger
format is load-bearing and only changes with a migration plan.

## Layer diagram

```
        +----------------------------------------------------------+
   L5   |  BUSINESS   | engagement mgmt · billing · assurance certs |   (v0.5)
        +----------------------------------------------------------+
   L4   |  WORKFLOW   | scan pipeline (ARM/RUN/COLLECT/VERIFY)      |   pipeline.py
        |             | demo bench · regression runs                |   bench.py
        +----------------------------------------------------------+
   L3   |  REPORTING  | markdown · SARIF · evidence pack export     |
        +----------------------------------------------------------+
   L2   |  TOOLS      | ScopedHttpClient (scope gate HERE)          |
        |             | scope manifests · redaction                 |
        +----------------------------------------------------------+
   L1   |  ENGINES    | EngineDriver plug-point (the "brain" socket)|
        |             | deterministic probes | mock | LLM (v0.2)    |
        +----------------------------------------------------------+
   L0   |  KERNEL     | Ledger (append-only, hash-chained SQLite)   |
        |             | findings · events · claim gate · redaction  |
        +----------------------------------------------------------+
                UI: CLI (typer) and TUI (textual) are VIEWS over L0-L4.
```

Rules between layers:

- Dependencies point **down** only. An engine never touches the ledger; it
  returns `CandidateFinding`s with evidence, and the **pipeline** (L4)
  persists them through the kernel.
- The UI is a view: it reads rows, it does not create truth. The only UI
  write path is delegating to the workflow (`d` in the TUI = `hunter demo`).
- Every network byte flows through the `ScopedHttpClient` (L2). There is no
  other socket path.

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
- The deterministic engine fills the slot today. An LLM engine (v0.2,
  LiteLLM) mounts in the same socket — model-driven exploration, but the
  same evidence contract, the same claim gate, the same ladder. The brain
  changes; the proof obligation does not.

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

## Roadmap

| Version | Theme | Content |
| ------- | ----- | ------- |
| v0.1 | Deterministic core | kernel, scope gate, deterministic engine, pipeline, reporting, TUI, installers (this release) |
| v0.2 | LLM engine | LiteLLM-backed `EngineDriver` (exploration + reasoning), debunk/challenger agent that tries to overturn candidates before they bill |
| v0.3 | Multi-agent workflow | planner/recon/exploit-verify agents over the same ledger; arsenal adapters (nuclei, semgrep) as additional `EngineDriver`s |
| v0.4 | Assurance atoms | coverage certificate: every probe attempt is an atom — a signed, Merkle-ready "we checked X and here is the proof" set, not just findings |
| v0.5 | Engagement layer | engagement management, billing against verified findings, customer evidence packs |
