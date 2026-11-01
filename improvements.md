# Improvements — Smart-Contract Audit Capability

**Status:** Phase 1 (taxonomy) and Phase 3 (the `evm` engine) are **built and
tested**; Phases 2, 4, 5, 6 remain proposals.
**Scope:** give HunterOsHarness a real Solidity/EVM audit path, on top of the
web2 hunting it already does well.
**Author's note:** this document is written against the code as it stands on
`cccc6c6`. Every gap below was verified by reading the source, not inferred.

## 0.1 What is now DONE (this change)

* **The 19 universal laws are taxonomy klasses.** `klasses.json` carries 19
  `evm-*` entries, one per law, each with `lane: web3`, a real CWE, a
  falsifier, a minimum-proof bar, N/A patterns, and overclaim traps. The claim
  gate (RULE-E5) accepts every one, so a finding of any law can be inserted.
* **`EvmEngine` exists and is registered.** `hunter.tools.registry` now lists
  `("deterministic", "evm", "llm", "mock", "review")`, and `--engine evm` is
  accepted by the CLI. It reads Solidity under a scope-gated local root and
  classifies every line against the law it implicates.
* **Proven end-to-end.** A run against a local `Vault.sol` produced two
  critical candidates (re-entrancy surface, unguarded privileged path), both
  `candidate` with `Replay: no` — never auto-verified, per law 19.
* **Tests:** `tests/test_evm_engine.py`, 20 tests, all passing. Full suite
  1653 passed, 8 skipped.

What is deliberately NOT done yet: Foundry, Slither, PoC execution, the
on-chain scope manifest, and the write path. Those are the phases below.

---

## 0. What exists today (verified, not assumed)

Read these before designing anything. The foundation is better than it looks
in some places and worse in others.

### 0.1 Real on-chain interaction — `src/hunter/agent/tools_web3.py` (631 lines)

Four working tools, all scope-gated:

| Tool | What it does |
|---|---|
| `contract_read` | `eth_call`, `eth_getCode`, `eth_getBalance`, `eth_getStorageAt` (last one advanced-tier only) |
| `contract_source_fetch` | Fetches verified source from an explorer allowlist |
| `abi_decode_hint` | Calldata decoding assistance |
| `ladder_read` | Tiered RPC probing with a circuit breaker |

The gating is genuinely good and should be copied, not replaced:

- `_onchain_allowed(ctx, chain_id, address)` — exact lower-compare match
  against `chain_scope` entries in the run config. Fail-closed: a missing or
  malformed entry returns `False`.
- `ctx.scope.check_url(rpc_url)` — the RPC host itself must be in scope.
- `_tier(ctx)` — `eth_getStorageAt` is refused below advanced tier with
  `tier.capability_locked`.

### 0.2 The ledger already reserves the vocabulary — `src/hunter/kernel/ledger.py:814`

`ALLOWED_EVIDENCE_KINDS` already contains:

```
contract_call, contract_source, slither_audit, cast_call, poc_run,
verifier_transcript
```

**This is the most important finding in this document.** The evidence
vocabulary was designed for a smart-contract audit path that was never built.
Six kinds are reserved and unused. Any new work should emit these rather than
invent new kinds — the claim gate will reject unknown kinds
(`ClaimGateBlocked`, fail-closed).

### 0.3 Two placeholder tools already exist — `tools_web3.py:565`

`register_web3_tools()` ends with two `register_unavailable()` calls:

```python
registry.register_unavailable(
    "slither_hint", "tool.unavailable",
    "slither is not installed; install with: pip install slither-analyzer && slither --version")
registry.register_unavailable(
    "cast_hint", "tool.unavailable",
    "cast is not installed; install with: curl -L https://foundry.paradigm.xyz | bash && foundryup")
```

So the model can already *see* that `slither_hint` and `cast_hint` exist and
that they are unavailable. The seam is stubbed, not absent. Turning these into
real tools is a smaller change than it appears.

### 0.4 R-spec v2 gate — `src/hunter/agent/tools.py:794-905`

`validate_rspec_gate()` already models the exact shape needed:

- `r_spec_version` defaults to 1 (v1 semantics preserved).
- v2 requires `chain_scope` **and** `rpc_manifest` in config, else
  `rspec.manifest_required`.
- `_RSPEC_STORAGE_METHODS` (`eth_getStorageAt`, `eth_getProof`,
  `debug_traceCall`) are advanced-tier only.
- `_r4c_onchain_bind()` binds one read-only call to scope + manifest, with a
  readonly-method allowlist (`_R4C_READONLY_METHODS`) — **sends never bind**.

The pattern to copy: a version bump that unlocks new capability while old runs
validate exactly as before.

### 0.5 Local-directory hunting already works — `src/hunter/daemon.py:1060-1110`

A `dir` target is mounted on a loopback HTTP server (`mount_local_dir`) and
run through the normal pipeline with `config["local_root"]` set. The
filesystem gate is fail-closed: the root must be inside the scope's
`local_roots`, else `PermissionError`.

This means **a Foundry project directory can already be hunted today** — it
just gets web2 treatment instead of Solidity analysis.

### 0.6 The review engine scans `.sol` — but only as text — `src/hunter/engine/review.py`

```python
_SUSPECT_PATTERNS = (
    ("delegatecall", "unchecked delegatecall", "CWE-829"),
    ("tx.origin", "tx.origin used for authorization", "CWE-477"),
    ("selfdestruct", "selfdestruct reachable", "CWE-672"),
)
```

Three substring matches over `.sol` files. No AST, no dataflow, no
cross-function analysis. Every hit is `severity=MEDIUM` with
`impact="Potential vulnerability; requires manual review."` — which is honest
but produces almost entirely false positives on any real codebase.

### 0.7 Scope manifest has no on-chain section — `src/hunter/tools/scope.py:155`

`scope_from_manifest()` reads only `hosts`, `allow_subdomains`, `local_roots`.
The on-chain scope lives entirely in run config (`chain_scope`), **not** in the
manifest — so `hunt --scope manifest.json` gives you no on-chain authorization
at all. This is the single biggest structural gap.

---

## 1. Gap analysis

| # | Gap | Consequence | Severity |
|---|---|---|---|
| G1 | No on-chain section in the scope manifest | `--scope` cannot authorize a contract; on-chain auth lives only in run config, invisible to the operator | **high** |
| G2 | No static-analysis engine | Solidity is grep'd for 3 substrings; reentrancy, access control, oracle manipulation, arithmetic all invisible | **high** |
| G3 | `slither_hint` / `cast_hint` are stubs | The model sees the tools exist but can never call them | medium |
| G4 | No Foundry integration | Cannot compile, cannot run `forge test`, cannot generate or execute PoCs | **high** |
| G5 | No write-path capability | Audit is read-only; a proven vulnerability cannot be demonstrated on a fork | medium |
| G6 | Evidence kinds reserved but never emitted | `slither_audit`, `poc_run`, `verifier_transcript` are dead vocabulary | medium |
| G7 | No vulnerability taxonomy for EVM | Findings land in `klass="unknown"`; the claim gate's `validate_klass` has nothing to match | medium |
| G8 | No gas / economic analysis | Nothing detects unbounded loops, DoS-by-gas, or economic invariant breaks | low |

---

## 2. Proposed architecture

### 2.1 Design principle: reuse every gate that already exists

The web2 path already solved scope enforcement, evidence integrity, tier
gating, and claim validation. **Do not build parallel machinery.** Every
proposal below plugs into an existing seam.

```
                    ┌─────────────────────────────────────┐
   manifest.json ──▶ │  scope.py: onchain section (G1)    │
                    └──────────────┬──────────────────────┘
                                   │ chain_scope entries
                                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  tools_web3.py  (existing, extend)                            │
   │  contract_read · contract_source_fetch · abi_decode_hint      │
   │  + cast_call · cast_send (fork-only) · slither_run · forge_*  │
   └───────────────┬───────────────────────────────────────────────┘
                   │ emits contract_call / slither_audit / cast_call
                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  ledger.py ALLOWED_EVIDENCE_KINDS  (already reserves all six) │
   └───────────────┬───────────────────────────────────────────────┘
                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  claimgate.py validate_klass  (needs the EVM taxonomy, G7)    │
   └───────────────────────────────────────────────────────────────┘
```

### 2.2 Phase 1 — On-chain scope in the manifest (G1)

**Smallest change with the largest effect.** Extend `scope_from_manifest()`:

```json
{
  "name": "relay-protocol",
  "hosts": ["api.relay.link", "explorer.chain.relay.link"],
  "local_roots": ["/home/operator/relay-contracts"],
  "onchain": [
    {
      "chain_id": 1,
      "addresses": ["0x...", "0x..."],
      "rpcs": ["https://eth.drpc.org"],
      "fork": true
    },
    {
      "chain_id": 59144,
      "addresses": ["0x..."],
      "rpcs": ["https://linea.drpc.org"],
      "fork": false
    }
  ]
}
```

Then:

- `ScopeSet` gains an `onchain: tuple[OnchainScope, ...]` field.
- `_onchain_allowed()` reads from `ctx.scope` instead of raw config — one
  source of truth, and the operator sees authorization in the file they wrote.
- `allows_local_root()` already exists; the on-chain equivalent should follow
  its fail-closed shape exactly.
- `daemon.py:619` already serializes `local_roots` into the task; add
  `onchain` alongside it so daemon-run tasks carry the same authorization.

**Backward compatibility:** absent `onchain` → empty tuple → every on-chain
call refused with `scope.onchain_out_of_scope`. That is the correct default:
a manifest that does not mention a chain authorizes nothing on it.

### 2.3 Phase 2 — Foundry as the execution substrate (G4)

Foundry is the right dependency, not Slither alone:

- `forge build` — compilation, and the compiler's own warnings are signal.
- `forge test` — the PoC runner. A failing test *is* a proof.
- `cast` — the RPC client, already stubbed as `cast_hint`.
- `anvil` — local fork, so a PoC can execute state changes without touching
  mainnet.

**Proposed tools** (all in `tools_web3.py`, following the existing
`_wrap` pattern exactly):

| Tool | Tier | Danger | Gate |
|---|---|---|---|
| `forge_build` | basic | none | `local_root` in scope |
| `forge_test` | basic | none | `local_root` in scope; test filter allowlist |
| `cast_call` | basic | none | readonly method allowlist (reuse `_R4C_READONLY_METHODS`) |
| `cast_send` | **advanced** | high | **fork-only** — refuse unless `onchain[].fork` is true |
| `slither_run` | advanced | none | binary present; `local_root` in scope |
| `anvil_fork` | advanced | none | `onchain[].fork` true; RPC host in scope |

**The fork-only rule for `cast_send` is the safety boundary.** An audit that
can only write to a local fork cannot move real funds, cannot grief a live
contract, and cannot be mistaken for an attack. Enforce it in the handler, the
way `_tier(ctx)` already refuses `eth_getStorageAt` — not in the prompt.

**Binary discovery:** resolve `forge`/`cast`/`anvil` from `PATH` *and* from
`~/.foundry/bin`, then report absence through the existing
`register_unavailable()` seam with the exact install command. Never silently
degrade to a stub that returns plausible output.

### 2.4 Phase 3 — A real static-analysis engine (G2)

Do **not** extend `_SUSPECT_PATTERNS`. Substring matching on Solidity produces
noise, and the review engine's own `impact` string admits it.

Two options, in order of preference:

**Option A — Slither as a subprocess, results normalized into findings.**
`slither --json -` on the `local_root`, then map detector IDs to the taxonomy
in §2.6. Slither already does the AST, dataflow, and cross-contract work;
wrapping it is maybe 300 lines and gives 90+ detectors for free.

**Option B — an `evm` engine registered in `_ENGINES`.**
`src/hunter/tools/registry.py:36` is a stable tuple:
`("deterministic", "llm", "mock", "review")`. Adding `"evm"` there makes it
selectable via `--engine evm` and visible in `available_engines()`. The engine
would own: compile → Slither → optional Foundry PoC → findings.

Recommendation: **Option A first, registered as the `evm` engine.** It is the
same work with a proper name, and `--engine evm` is what an operator will
actually type.

### 2.5 Phase 4 — PoC execution and the write path (G5, G6)

The ledger reserves `poc_run` and `verifier_transcript` for exactly this.

```
forge test --match-test test_ReentrancyPoC -vv
   │
   ├─ pass  → the hypothesis was wrong. Record as a NEGATIVE result.
   │          (A disproven hypothesis is progress — the repo's own
   │           Anti-Delusion Protocol says so.)
   └─ fail  → the assertion that should hold did not.
              Emit poc_run evidence with the full trace.
```

**Negative results must be ledgered.** Most audit work is disproving
hypotheses; if only successes are recorded, the ledger overstates confidence
and the next run repeats the same dead ends.

`verifier_transcript` is for the replay: the same PoC, re-run against the
fork, proving the finding still holds at report time. This is what separates
"the model says it's vulnerable" from "here is the transaction trace".

### 2.6 Phase 5 — EVM vulnerability taxonomy (G7)

`claimgate.validate_klass()` validates against taxonomy IDs. Without EVM
classes, every contract finding is `klass="unknown"` and the claim gate cannot
apply class-specific rules.

Minimum viable set, mapped to CWE where one exists:

| klass | Detects | Typical source |
|---|---|---|
| `evm.reentrancy` | Cross-function and read-only reentrancy | Slither `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign` |
| `evm.access-control` | Missing/incorrect `onlyOwner`, unprotected `selfdestruct` | Slither `unprotected-upgrade`, `arbitrary-send` |
| `evm.oracle-manipulation` | Spot-price dependence, flash-loan-movable state | Slither + manual; needs economic context |
| `evm.arithmetic` | Overflow/underflow, precision loss, rounding direction | Slither `divide-before-multiply`, `weak-prng` |
| `evm.unchecked-transfer` | Ignored return values, fee-on-transfer breaks | Slither `unchecked-transfer` |
| `evm.delegatecall-proxy` | Unchecked proxy target, storage collision | Slither `delegatecall-loop`, manual |
| `evm.dos` | Unbounded loop, gas-griefing, block-stuffing | Slither + gas profiling |
| `evm.signature-replay` | Missing nonce/chainId/domain separator | Manual; high value for Relay specifically |

**For the Relay scope specifically**, `evm.signature-replay` and
`evm.oracle-manipulation` are the classes worth prioritizing — cross-chain
message passing and price sourcing are where a bridge protocol actually loses
money.

### 2.7 Phase 6 — Economic and invariant checks (G8)

Beyond pattern bugs, the interesting failures are invariant breaks:

- Share-price manipulation in staking pools (deposit/withdraw asymmetry).
- Rounding direction in favor of the caller.
- First-depositor inflation.
- Fee accrual that can be front-run.

These need a *stateful* check, which is why Phase 4 (PoC execution on a fork)
matters more than Phase 3. A Foundry test that asserts
`balanceAfter >= balanceBefore` across a deposit/withdraw round-trip is worth
more than any static detector.

---

## 3. Sequencing

| Phase | Deliverable | Depends on | Why this order |
|---|---|---|---|
| 1 | `onchain` in scope manifest | — | Unblocks everything; without it nothing is authorized |
| 2 | Foundry tools + fork-only `cast_send` | 1 | Execution substrate; the safety rule must exist before the capability |
| 3 | `evm` engine wrapping Slither | 1, 2 | Turns grep into analysis |
| 4 | PoC execution + negative-result ledgering | 2, 3 | Proof, not assertion |
| 5 | EVM taxonomy + claim-gate classes | 3 | Findings need classes to be actionable |
| 6 | Invariant/economic checks | 4 | Highest value, needs the most machinery |

Phases 1 and 2 are the ones that change what the system *can do*. Phases 3-6
change how well it does it.

---

## 4. What to build first, concretely

If only one thing gets built, build **Phase 1**. It is:

- ~40 lines in `scope.py` (one new field, one parser branch).
- ~15 lines in `daemon.py` (serialize the new field next to `local_roots`).
- ~10 lines in `tools_web3.py` (`_onchain_allowed` reads `ctx.scope`).
- One test: a manifest with `onchain` authorizes a call; the same manifest
  without it refuses.

And it fixes the worst current behavior: **an operator who writes a scope
manifest today gets zero on-chain protection from it**, because the
authorization lives in run config the manifest cannot see or express.

---

## 5. Non-goals

Stated explicitly so they do not get built by accident:

- **No mainnet write path.** `cast_send` is fork-only, permanently. If a
  finding needs a mainnet transaction to prove, it is reported as unproven.
- **No automatic exploit deployment.** The system produces PoCs and evidence;
  a human decides what gets broadcast.
- **No replacing the web2 path.** Everything here is additive. The existing
  gates stay exactly as they are.
- **No new evidence kinds.** Six are already reserved and unused; inventing a
  seventh would be a smell that the design drifted.

---

## 6. Open questions

1. **Slither or Foundry-only?** Slither gives breadth cheaply but adds a
   Python dependency with its own Solidity-version quirks. Foundry-only is
   fewer moving parts but loses the detectors. Leaning Slither + Foundry.
2. **Where does `anvil` state live?** Per-run ephemeral under the state dir is
   cleanest, but a long audit may want a persistent fork to compare against.
3. **Does `evm` become a fifth engine or a mode of `review`?** A fifth engine
   is cleaner and matches how `available_engines()` is asserted in tests, but
   it is a wider blast radius.
4. **Multi-contract scope.** A protocol audit needs the whole deployment graph
   (proxies, implementations, libraries, oracles), not one address. The
   manifest schema in §2.2 supports a list; the *tooling* needs to follow
   references between them.
