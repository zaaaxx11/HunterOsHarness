# Relay Bug Bounty — EVM Contract Scan Summary (HunterOsHarness)

**Target**: `relayprotocol/relay-settlement` (smart-contracts/contracts, 1075 .sol files)
**Engine**: `scan --engine evm` (EvmEngine — 19 universal laws of EVM vulnerability classifier)
**Scope**: In-scope per bounty (Relay Protocol + services). Relay Vaults excluded (out-of-scope per program).
**Run**: R-32a24c0386f6, status completed.

## Raw classifier output
- **995 candidates** across **55 files**, **14 distinct laws**
- Severity tag: 861 critical / 134 high (these are law-table severities, NOT verified exploitability)
- `klass` field is unset in JSON dump (engine sets it internally; report uses `title`/`cwe`)

## Law distribution (top)
| Count | Law |
|-------|-----|
| 385 | Message/calldata not bound to chain, contract, nonce, deadline |
| 149 | Signature used as authority without full binding |
| 98 | Price/rate sourced from movable on-chain value |
| 70 | Cross-domain message trusted without source validation |
| 49 | External call before state update (re-entrancy surface) |
| 41 | Arithmetic without overflow/rounding care |
| 39 | Privileged effect reachable without guard on every path |
| 37 | Consensus-level input read as fact |
| 36 | External token treated as plain number |
| 35 | Node/RPC surface referenced from contract |
| 30 | Economic check satisfiable with rented capital |
| 18 | Writable storage surface (packed slot/proxy) |
| 7 | Valuable op with no ordering protection |
| 1 | Unverified developer assumption |

## Checker verdict (manual verification of samples)

EvmEngine is a **classifier, not a verifier** (by design — replay returns False). Every candidate is `status: candidate`, never `verified`. Manual spot-checks:

- **Re-entrancy (RelayExecutor.sol)**: FP. Uses `HUB.transfer(...)` (internal hub call), not a raw external `.call{value}`. No exploitable external call before state update.
- **Signature binding (RelayAllocator.sol, 39 hits)**: FP. Contract uses `EIP712` + `nonce` + `chainId` + `domainSeparator` — signatures ARE fully bound. Engine flagged `ecrecover` presence without detecting the replay/domain guards.

## Bottom line
- The classifier correctly surfaces the *laws implicated* by Relay's code, but **none verified as exploitable** in the sampled files — Relay's contracts use EIP-712, nonces, and hub-mediated transfers, which defeat the naive patterns the engine matches.
- To convert any of these 995 candidates into a real submission, each needs: (1) a specific function + line, (2) a concrete exploit path (not just a pattern), (3) PoC per Relay's PoC requirements. That is manual audit work beyond the classifier.
- Realistic outcome: **no auto-confirmed Critical/High**. The engine is a triage starting point, not a finding generator.

## Note on tooling
`src/hunter/engine/evm.py` exists and works (1075 files scanned, 995 candidates). It is a law-classifier over source text, explicitly NOT Slither/dataflow/exploit-gen. For a real Relay audit, pair it with Slither + manual review of the 14 law areas.
