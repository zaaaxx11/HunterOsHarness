"""EvmEngine — Solidity source review classified against the 19 universal laws.

This engine is the HunterOsHarness half of HunterOS's ``black-swan-engine``
skill (19 universal laws of EVM vulnerability). The laws live in the taxonomy
as ``evm-*`` klass ids; this engine reads Solidity under a local root, matches
each construct against the law it implicates, and emits candidates whose
``klass`` is the law itself.

Design rules, deliberately copied from the engines already here:

* **Never auto-verify.** ``replay`` returns False, exactly like
  :class:`~hunter.engine.review.ReviewEngine`. A code reading is evidence that
  a span exists, not proof of exploitability. Law 19 (unproven impact is not
  impact) is enforced structurally, not by prompt.
* **Every candidate carries its law.** ``klass`` is one of the 19 ``evm-*``
  ids, so the claim gate's RULE-E5 validates it and the report can group by
  law. Nothing lands in ``klass="unknown"``.
* **Fail-closed filesystem gate.** The local root must be inside the scope's
  ``local_roots``; symlinks are not followed; the walk cannot escape the root.
* **Two-law violations outrank one.** The black-swan engine's own rule: a
  surface violating two laws is a priority target. When a span matches more
  than one law, the engine emits the highest-severity law as the candidate and
  records the others in ``laws_also_implicated`` on the evidence, so the
  report can still see the chain.

What this engine is NOT: it is not Slither, not a dataflow analyser, and not
an exploit generator. It is a law-classifier over source text. It finds the
surfaces worth a human or a PoC, and it says honestly which law each surface
implicates.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from ..kernel.findings import Severity
from .base import CandidateFinding, EngineContext, EngineResult, Evidence, ScanPlan, TargetSpec

# ---------------------------------------------------------------------------
# Law table
# ---------------------------------------------------------------------------
# Each row: (law_id, cwe, severity, title, needles, description, impact,
#            remediation)
#
# `needles` are matched case-insensitively as substrings of a source line.
# This is a classifier, not a parser: it answers "which law does this surface
# implicate", which is the question the black-swan engine asks first. The
# falsification step (law 19) is the engine's replay contract and the claim
# gate, not the matcher.

_SOL_SUFFIXES = frozenset({".sol"})
_MAX_FILE_BYTES = 1_000_000

# Directories that hold no deployed code. A foundry tree puts its tests in
# test/, its dependencies in lib/ (forge-std, openzeppelin), and its deploy
# scripts in script/. None of that ships to a chain, so a law hit there is
# not a finding about the protocol — it is a finding about the test suite.
#
# Scanning them anyway produced 20,736 candidates of which 15,171 (73%) came
# from these three directories, and 0 verified. The signal was buried in
# noise the walk should never have collected.
_NON_PRODUCTION_DIRS = frozenset({"test", "tests", "lib", "script", "scripts", "mock", "mocks"})

# Severity ranking used to pick the primary law when a span implicates
# several. Order matters: it is the tie-break, not a claim about the bug.
_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_LAWS: tuple[dict[str, Any], ...] = (
    {
        "id": "evm-unverified-assumption",
        "cwe": "CWE-1059",
        "severity": Severity.HIGH,
        "title": "Unverified developer assumption on a reachable path",
        "needles": (
            "// assume",
            "/* assume",
            "# assume",
            "todo: verify",
            "fixme: verify",
            "should never happen",
            "cannot happen",
            "impossible",
            "trusted",
        ),
        "description": (
            "A developer belief is stated in the source as an invariant that is "
            "never tested on this path. Law 1: the unverified assumption is the "
            "attack surface."
        ),
        "impact": (
            "If the belief is false, the contract acts on state it never "
            "validated. The reachable consequence depends on what the "
            "assumption guards."
        ),
        "remediation": (
            "Convert the assumption into an explicit require, or document why "
            "it is unreachable and add a test that fails when it stops holding."
        ),
    },
    {
        # Law 1's most expensive instance, and the one the taxonomy already
        # carries as its own klass (`reentrancy`): an external call whose
        # re-entry the surrounding code never accounts for. It is listed here
        # as a law needle because the black-swan engine classifies by law
        # first, and a `.call{value:}` before a state update is the canonical
        # shape. The taxonomy keeps `reentrancy` as the klass a PoC promotes
        # into; this law entry is the surface that points at it.
        "id": "evm-unverified-assumption",
        "cwe": "CWE-841",
        "severity": Severity.CRITICAL,
        "title": "External call before state update (re-entrancy surface)",
        "needles": (
            ".call{value:",
            ".call(",
            ".send(",
            "transfer(",
            "call{value",
            "staticcall(",
        ),
        "description": (
            "An external call sits on a path that also mutates state. Law 1 "
            "applied to the most expensive assumption in EVM: that the callee "
            "returns control exactly once and does not re-enter."
        ),
        "impact": (
            "If the callee re-enters before the state update, the same value "
            "can be withdrawn twice — the canonical fund-theft primitive."
        ),
        "remediation": (
            "Follow checks-effects-interactions: update state before the "
            "external call, or apply a reentrancy guard and verify it is "
            "effective on every path."
        ),
    },
    {
        "id": "evm-token-is-a-program",
        "cwe": "CWE-1059",
        "severity": Severity.HIGH,
        "title": "External token treated as a plain number",
        "needles": (
            "balanceof(",
            ".transfer(",
            ".transferfrom(",
            "safeTransfer".lower(),
            "decimals()",
            "feeontransfer",
            "deflationary",
        ),
        "description": (
            "The contract reads a token's reported value or calls its transfer "
            "without accounting by balance delta. Law 2: a token is a program, "
            "never a number."
        ),
        "impact": (
            "A non-standard, fee-taking, or malicious token makes the "
            "contract's accounting diverge from reality, which is the standard "
            "fund-theft primitive."
        ),
        "remediation": (
            "Measure value by balance delta around the call, or restrict the "
            "contract to a verified token allowlist."
        ),
    },
    {
        "id": "evm-arithmetic-trust",
        "cwe": "CWE-190",
        "severity": Severity.CRITICAL,
        "title": "Arithmetic on a value path without overflow or rounding care",
        "needles": (
            "unchecked {",
            "unchecked{",
            "/ 10**",
            "* 10**",
            "/ 1e",
            "* 1e",
            "wad",
            "ray",
            "muldiv",
            "rounding",
        ),
        "description": (
            "Division, scaling, or an unchecked arithmetic block sits on a "
            "value path. Law 3: arithmetic is where trust goes to die."
        ),
        "impact": (
            "Precision loss or an unchecked overflow on a value path moves "
            "funds in whichever direction the rounding favours."
        ),
        "remediation": (
            "Use a vetted fixed-point library, multiply before dividing, and "
            "prove the rounding direction favours the protocol."
        ),
    },
    {
        "id": "evm-storage-layout-writable",
        "cwe": "CWE-787",
        "severity": Severity.HIGH,
        "title": "Writable storage surface (packed slot, proxy, or raw slot)",
        "needles": (
            "assembly {",
            "assembly{",
            "sstore(",
            "delegatecall(",
            "proxy",
            "implementation",
            "eip-1967",
            "eip1967",
            "initializable",
            "slot",
        ),
        "description": (
            "Raw storage access, a proxy, or an uninitialized implementation "
            "slot. Law 4: storage layout is a writable interface."
        ),
        "impact": (
            "An attacker who can influence a slot write can overwrite "
            "privileged state, including the implementation address."
        ),
        "remediation": (
            "Verify the implementation slot on-chain, collision-check the "
            "layout against the proxy pattern, and initialize every slot."
        ),
    },
    {
        "id": "evm-access-control-path",
        "cwe": "CWE-284",
        "severity": Severity.CRITICAL,
        "title": "Privileged effect reachable without a guard on every path",
        "needles": (
            "onlyowner",
            "onlyrole",
            "require(msg.sender ==",
            "tx.origin",
            "selfdestruct(",
            "delegatecall(",
            "fallback(",
            "receive(",
            "initializer",
            "_authorizeupgrade",
        ),
        "description": (
            "A privileged effect is guarded by a modifier, but the law asks "
            "which path reaches it without passing the guard. Law 5: access "
            "control is a path, not a modifier."
        ),
        "impact": (
            "Any unguarded path to the effect is a full privilege escalation: "
            "ownership transfer, upgrade, or destruction."
        ),
        "remediation": (
            "Enumerate every path to the effect (initializers, fallbacks, "
            "delegatecalls, role-bearing proxies) and guard each one."
        ),
    },
    {
        "id": "evm-signature-is-data",
        "cwe": "CWE-294",
        "severity": Severity.CRITICAL,
        "title": "Signature used as authority without full binding",
        "needles": (
            "ecrecover(",
            "permit(",
            "signature",
            "signed",
            "v, r, s",
            "v,r,s",
            "_domainseparator",
            "domain_separator",
        ),
        "description": (
            "A signature is recovered and trusted. Law 6: signatures are data, "
            "not authority — replay, malleability, and missing bindings turn a "
            "valid signature into a skeleton key."
        ),
        "impact": (
            "A signature that is not bound to chainId, contract, nonce, and "
            "deadline can be replayed or replayed cross-chain."
        ),
        "remediation": (
            "Bind to chainId, verifyingContract, nonce, and deadline via an "
            "EIP-712 domain separator, and consume the nonce atomically."
        ),
    },
    {
        "id": "evm-oracle-movable",
        "cwe": "CWE-346",
        "severity": Severity.CRITICAL,
        "title": "Price or rate sourced from a movable on-chain value",
        "needles": (
            "getreserves(",
            "price0cumulativelast",
            "spot",
            "twap",
            "oracle",
            "latestanswer",
            "latestrounddata",
            "getprice",
        ),
        "description": (
            "A price or rate is read from a source an attacker can move within "
            "one transaction. Law 7: oracles are the cheapest object on the "
            "chain to move."
        ),
        "impact": (
            "The protocol can be priced with a price the attacker controls, "
            "which is direct value extraction."
        ),
        "remediation": (
            "Use a manipulation-resistant source (TWAP, multi-oracle median) "
            "with staleness and deviation bounds."
        ),
    },
    {
        "id": "evm-ordering-is-permission",
        "cwe": "CWE-362",
        "severity": Severity.HIGH,
        "title": "Valuable, visible operation with no ordering protection",
        "needles": (
            "deadline",
            "amountoutmin",
            "slippage",
            "minout",
            "frontrun",
            "mempool",
            "commit",
        ),
        "description": (
            "An operation whose value depends on transaction order. Law 8: "
            "ordering is permission — whoever pays to be first takes the "
            "surplus."
        ),
        "impact": (
            "Frontrunning or backrunning extracts value from every user of "
            "the operation."
        ),
        "remediation": (
            "Add a slippage bound, a commit scheme, or a batch auction with a "
            "uniform clearing price."
        ),
    },
    {
        "id": "evm-upgradability-pending-tx",
        "cwe": "CWE-749",
        "severity": Severity.HIGH,
        "title": "Upgrade path whose live target is not self-verified",
        "needles": (
            "upgradeto(",
            "upgradetoandcall(",
            "_upgradetoaddress",
            "uusups",
            "erc1967",
            "beacon",
            "proxyadmin",
        ),
        "description": (
            "A proxy or upgrade path exists. Law 9: upgradability converts "
            "trust into a pending transaction — the future contract is one you "
            "have not met."
        ),
        "impact": (
            "Whoever controls the upgrade path controls the contract's logic, "
            "including every balance it holds."
        ),
        "remediation": (
            "Verify the implementation slot on-chain yourself, timelock the "
            "upgrade, and document admin-key custody."
        ),
    },
    {
        "id": "evm-chain-boundary-trust",
        "cwe": "CWE-345",
        "severity": Severity.CRITICAL,
        "title": "Cross-domain message trusted without source validation",
        "needles": (
            "bridge",
            "relay",
            "crosschain",
            "cross-chain",
            "messagereceived",
            "_execute",
            "remotedomain",
            "sourcechain",
            "l1tol2",
            "l2tol1",
        ),
        "description": (
            "A message crosses a domain boundary. Law 10: the chain boundary "
            "is a trust boundary — the handoff point carries the source "
            "domain's assumptions into a domain that does not honour them."
        ),
        "impact": (
            "A forged or misattributed inbound message is executed with the "
            "destination's full authority."
        ),
        "remediation": (
            "Validate the source domain on every inbound message and rely on "
            "no source assumption in the destination."
        ),
    },
    {
        "id": "evm-defaults-are-secrets",
        "cwe": "CWE-798",
        "severity": Severity.CRITICAL,
        "title": "Hardcoded key or credential-shaped constant",
        "needles": (
            "privatekey",
            "private_key",
            "mnemonic",
            "seed phrase",
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "anvil",
            "hardhat",
        ),
        "description": (
            "Key-shaped material appears in source. Law 11: defaults are "
            "secrets — derive the address and check nonce and balance."
        ),
        "impact": (
            "If the key is live, whoever reads the source controls the "
            "account and everything it can reach."
        ),
        "remediation": (
            "Remove the key, rotate it, and confirm the derived address holds "
            "no value and has no nonce."
        ),
    },
    {
        "id": "evm-deterministic-derivation-leak",
        "cwe": "CWE-798",
        "severity": Severity.CRITICAL,
        "title": "Deterministic derivation seed committed",
        "needles": (
            "bip39",
            "bip32",
            "bip44",
            "hdpath",
            "m/44'/60",
            "derivation path",
            "derivepath",
        ),
        "description": (
            "A derivation seed or path is committed. Law 12: deterministic "
            "derivation means leaked once, drained forever — the same account "
            "is unlocked on every future day and every chain."
        ),
        "impact": (
            "A committed seed unlocks its derived accounts on every chain they "
            "funded, permanently."
        ),
        "remediation": (
            "Rotate the seed and confirm no derived address holds value on any "
            "chain."
        ),
    },
    {
        "id": "evm-infra-endpoint-surface",
        "cwe": "CWE-668",
        "severity": Severity.HIGH,
        "title": "Node or RPC surface referenced from contract code",
        "needles": (
            "http://",
            "https://",
            "rpc",
            "infura",
            "alchemy",
            "debug_",
            "admin_",
            "personal_",
            "cors",
        ),
        "description": (
            "An infrastructure endpoint is part of the contract's surface. "
            "Law 13: infrastructure endpoints are contract surface — RPC nodes "
            "are contracts with a JSON-RPC ABI."
        ),
        "impact": (
            "An exposed debug, admin, or personal namespace, or a wildcard "
            "CORS echo, extends the attack surface past the bytecode."
        ),
        "remediation": (
            "Disable or authenticate dangerous namespaces and restrict CORS to "
            "known origins."
        ),
    },
    {
        "id": "evm-fork-inherits-bugs",
        "cwe": "CWE-1059",
        "severity": Severity.HIGH,
        "title": "Forked code whose ancestor diff is not accounted for",
        "needles": (
            "fork of",
            "forked from",
            "based on",
            "ported from",
            "adapted from",
            "original:",
        ),
        "description": (
            "The code descends from another codebase. Law 14: the fork is a "
            "fossil record — it inherits every ancestor vulnerability plus "
            "every divergence bug introduced by the port."
        ),
        "impact": (
            "An ancestor vulnerability the fork never patched, or a bug the "
            "port itself introduced, is reachable here."
        ),
        "remediation": (
            "Diff against the ancestor and confirm every inherited fix is "
            "present before trusting any upstream audit claim."
        ),
    },
    {
        "id": "evm-liquidity-multiplier",
        "cwe": "CWE-841",
        "severity": Severity.CRITICAL,
        "title": "Economic check satisfiable with rented capital",
        "needles": (
            "flashloan",
            "flash loan",
            "flashloan(",
            "borrow",
            "quorum",
            "threshold",
            "totalSupply()",
            "totalsupply",
        ),
        "description": (
            "An economic or governance check depends on capital the attacker "
            "can rent. Law 15: liquidity is an attack multiplier — evaluate "
            "every economic check as if the attacker can rent majority power "
            "for one block."
        ),
        "impact": (
            "A check that borrowed capital can satisfy is not a check: "
            "governance capture or price control within one transaction."
        ),
        "remediation": (
            "Require capital locked across blocks, or use snapshot voting that "
            "predates the loan."
        ),
    },
    {
        "id": "evm-finality-under-stress",
        "cwe": "CWE-367",
        "severity": Severity.HIGH,
        "title": "Consensus-level input read as a fact",
        "needles": (
            "block.timestamp",
            "block.number",
            "blockhash(",
            "finality",
            "reorg",
            "sequencer",
            "l1block",
        ),
        "description": (
            "The contract reads a consensus-level input as a settled fact. "
            "Law 16: time and finality assumptions fail under stress — attack "
            "the lag, not the lock."
        ),
        "impact": (
            "A reorg, sequencer outage, or bridge lag can invalidate state the "
            "contract treated as final."
        ),
        "remediation": (
            "Wait on finality explicitly, or bound the tolerance wide enough "
            "to survive the realistic delay window."
        ),
    },
    {
        "id": "evm-replay-is-default",
        "cwe": "CWE-294",
        "severity": Severity.CRITICAL,
        "title": "Message or calldata not bound to chain, contract, nonce, deadline",
        "needles": (
            "nonce",
            "replay",
            "deadline",
            "chainid",
            "domainseparator",
            "keccak256(abi.encode",
        ),
        "description": (
            "A message is accepted without full uniqueness binding. Law 17: "
            "replay is the default, uniqueness is the exception — assume "
            "replay until proven unique."
        ),
        "impact": (
            "A message that still works when rebroadcast, on this chain or "
            "another, is a free second execution."
        ),
        "remediation": (
            "Bind to chainId, verifyingContract, nonce, and deadline, and "
            "consume the nonce atomically."
        ),
    },
    {
        "id": "evm-verifier-you-cannot-run",
        "cwe": "CWE-1059",
        "severity": Severity.MEDIUM,
        "title": "External claim relied on without local verification",
        "needles": (
            "audited by",
            "audit report",
            "according to",
            "as documented",
            "verified on etherscan",
            "trust the",
        ),
        "description": (
            "The source relies on an external claim. Law 18: a verifier you "
            "cannot run is a claim you cannot trust — verify against source "
            "and live state."
        ),
        "impact": (
            "A stale or false external claim becomes a load-bearing "
            "assumption nobody re-derived."
        ),
        "remediation": (
            "Re-derive the claim from source and confirm it against live chain "
            "state, or drop it."
        ),
    },
    {
        "id": "evm-unproven-impact",
        "cwe": "CWE-1059",
        "severity": Severity.MEDIUM,
        "title": "Impact asserted without a matching proof artefact",
        "needles": (
            "proven",
            "exploitable",
            "critical:",
            "high:",
            "jackpot",
            "pwned",
        ),
        "description": (
            "The source asserts an impact level. Law 19: unproven impact is "
            "not impact — proven-in-code needs an address and chainId, "
            "proven-live needs a tx hash or state proof."
        ),
        "impact": (
            "An unproven claim presented as proven misdirects the whole audit "
            "and is the one unforgivable violation when fabricated."
        ),
        "remediation": (
            "Attach the artefact matching the claimed level, or relabel the "
            "finding theoretical."
        ),
    },
)


class EvmEngine:
    """Classify Solidity source against the 19 universal laws of EVM vulnerability."""

    name = "evm"

    def plan(self, target: TargetSpec) -> ScanPlan:
        return ScanPlan(
            engine=self.name,
            phases=["scan-files", "classify-laws"],
            notes={
                "strategy": "law-classification",
                "laws": len({law["id"] for law in _LAWS}),
                "surfaces": len(_LAWS),
                "source": "HunterOS black-swan-engine (19 universal laws)",
            },
        )

    # -- filesystem gate (identical shape to ReviewEngine) ------------------

    def _local_root(self, ctx: EngineContext, target: TargetSpec) -> Path | None:
        root = ctx.config.get("local_root") or target.notes.get("local_root")
        if not root:
            return None
        try:
            resolved = Path(str(root)).resolve()
        except (OSError, RuntimeError, ValueError):
            return None
        # Fail-closed: the root must be inside one of the scope's local_roots
        # (absent local_roots keeps the permissive localhost behaviour).
        if not target.scope.allows_local_root(resolved):
            return None
        return resolved

    # -- classification -----------------------------------------------------

    def _laws_for_line(self, lowered: str) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for law in _LAWS:
            for needle in law["needles"]:
                if needle in lowered:
                    hits.append(law)
                    break
        return hits

    def _candidate(
        self,
        law: dict[str, Any],
        path: Path,
        idx: int,
        span: str,
        also: list[str],
    ) -> CandidateFinding:
        digest = hashlib.sha256(span.encode("utf-8")).hexdigest()
        data: dict[str, Any] = {
            "path": str(path),
            "line_start": idx,
            "line_end": idx,
            "sha256": digest,
            "law": law["id"],
        }
        if also:
            # Two-law violations outrank one. The primary law is the candidate;
            # the others ride on the evidence so the report can still see the
            # chain without inventing duplicate findings.
            data["laws_also_implicated"] = also
        return CandidateFinding(
            key=f"evm-{law['id']}|{path}|{idx}",
            title=law["title"],
            severity=law["severity"],
            cwe=law["cwe"],
            endpoint=str(path),
            method="READ",
            description=(
                f"{law['description']} Matched at {path}:{idx}: "
                f"{span.strip()[:160]}"
            ),
            impact=law["impact"],
            remediation=law["remediation"],
            klass=law["id"],
            evidence=(Evidence(kind="code_location", data=data),),
        )

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult:
        root = self._local_root(ctx, target)
        if root is None or not root.is_dir():
            ctx.emit("engine_event", {"stage": "evm.no_root", "root": str(root)})
            empty = {"files_scanned": 0, "requests": 0, "blocked": 0, "errors": 0}
            return EngineResult(candidates=[], stats=empty)

        candidates: list[CandidateFinding] = []
        files_scanned = 0
        law_hits: dict[str, int] = {}
        multi_law_spans = 0

        for dirpath, dirs, files in os.walk(root):
            # Containment guard: a link-named dirpath must not escape the root.
            try:
                Path(dirpath).resolve().relative_to(root)
            except ValueError:
                continue
            # Prune non-production directories IN PLACE so os.walk never
            # descends into them. Filtering after the fact still reads and
            # classifies every line, which is where the cost was.
            dirs[:] = [d for d in dirs if d.lower() not in _NON_PRODUCTION_DIRS]
            for fname in files:
                path = Path(dirpath) / fname
                # File symlinks are NOT followed.
                if path.is_symlink():
                    continue
                if path.suffix.lower() not in _SOL_SUFFIXES:
                    continue
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                files_scanned += 1
                for idx, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    # Imports, pragmas and comments are not code. A law needle
                    # matching the word "message" inside `import {IMessage}`
                    # or a doc comment produced a critical candidate per
                    # import line — 4,521 of the 20,736 in one run. The
                    # classifier has to see statements, not prose.
                    if not stripped or stripped.startswith(("//", "/*", "*", "import", "pragma", "using")):
                        continue
                    hits = self._laws_for_line(stripped.lower())
                    if not hits:
                        continue
                    # Highest severity wins the candidate slot; ties break on
                    # the law table order, which is stable.
                    hits.sort(
                        key=lambda lw: (
                            -_SEVERITY_RANK.get(lw["severity"], 0),
                            _LAWS.index(lw),
                        )
                    )
                    primary = hits[0]
                    also = [lw["id"] for lw in hits[1:]]
                    if also:
                        multi_law_spans += 1
                    candidates.append(
                        self._candidate(primary, path, idx, line, also)
                    )
                    law_hits[primary["id"]] = law_hits.get(primary["id"], 0) + 1

        ctx.emit(
            "engine_event",
            {
                "stage": "evm.done",
                "files_scanned": files_scanned,
                "candidates": len(candidates),
                "laws_fired": sorted(law_hits),
                "multi_law_spans": multi_law_spans,
            },
        )
        stats = {
            "files_scanned": files_scanned,
            "requests": 0,
            "blocked": 0,
            "errors": 0,
            "laws_fired": law_hits,
            "multi_law_spans": multi_law_spans,
        }
        return EngineResult(candidates=candidates, stats=stats)

    def replay(self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding) -> bool:
        # Law 19, enforced structurally: a code reading is never auto-verified.
        # The span still existing proves the span exists, nothing more.
        return False
