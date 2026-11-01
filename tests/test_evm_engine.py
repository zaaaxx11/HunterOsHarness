"""EVM engine + the 19 universal laws of EVM vulnerability.

Ports HunterOS's ``black-swan-engine`` skill into the harness: the laws live
in the taxonomy as ``evm-*`` klass ids, and :class:`EvmEngine` classifies
Solidity source against them.

The load-bearing assertions here are the ones that keep the engine honest:

* every candidate's ``klass`` is a real taxonomy id (RULE-E5 would reject it
  otherwise) — nothing lands in ``unknown``;
* ``replay`` never auto-verifies (law 19: unproven impact is not impact);
* the filesystem gate refuses a root outside the scope's ``local_roots``;
* symlinks are not followed and the walk cannot escape the root.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunter.engine.base import CandidateFinding, EngineContext, TargetSpec
from hunter.engine.evm import EvmEngine, _LAWS
from hunter.kernel.findings import Severity
from hunter.tools.scope import ScopeSet, scope_from_manifest

LAW_COUNT = 19


def _ctx(tmp_path: Path, *, local_root: Path | None = None) -> EngineContext:
    events: list[tuple[str, dict]] = []

    def emit(kind: str, payload: dict) -> None:
        events.append((kind, payload))

    ctx = EngineContext(
        http=None,  # type: ignore[arg-type] - the evm engine never makes a request
        emit=emit,
        config={"local_root": str(local_root)} if local_root else {},
    )
    ctx.events = events  # type: ignore[attr-defined] - test-only handle
    return ctx


def _target(root: Path, scope: ScopeSet) -> TargetSpec:
    return TargetSpec(url=str(root), scope=scope, notes={"local_root": str(root)})


def _scope_with_roots(tmp_path: Path, *roots: Path) -> ScopeSet:
    manifest = tmp_path / "scope.json"
    manifest.write_text(
        json.dumps({
            "name": "evm-test",
            "hosts": ["example.com"],
            "local_roots": [str(r) for r in roots],
        }),
        encoding="utf-8",
    )
    return scope_from_manifest(manifest)


def _write(root: Path, name: str, body: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------- taxonomy ----


def test_all_19_laws_are_taxonomy_klasses():
    """The law table and the taxonomy must agree, id for id.

    The table may hold MORE rows than there are laws: law 1 carries two rows
    (the generic assumption surface and the re-entrancy surface, which is law 1
    applied to the most expensive assumption in EVM). What must hold is that
    the DISTINCT ids are exactly the 19 taxonomy klasses.
    """
    from hunter.taxonomy import load_klasses

    klasses = load_klasses()
    law_ids = {law["id"] for law in _LAWS}
    assert len(law_ids) == LAW_COUNT, (
        f"expected {LAW_COUNT} distinct law ids, table has {len(law_ids)}"
    )

    missing = law_ids - set(klasses)
    assert not missing, f"laws absent from the taxonomy: {sorted(missing)}"

    for law_id in law_ids:
        entry = klasses[law_id]
        assert entry["lane"] == "web3"
        # the claim gate validates the CWE shape; a malformed one would make
        # every finding of this law un-insertable
        assert entry["cwe_primary"].startswith("CWE-")


def test_every_law_carries_anti_overclaim_substance():
    """A law without a falsifier or a proof bar is a slogan, not a law."""
    from hunter.taxonomy import load_klasses

    klasses = load_klasses()
    for law in _LAWS:
        entry = klasses[law["id"]]
        assert entry["falsifier_hint"].strip(), law["id"]
        assert entry["minimum_proof"].strip(), law["id"]
        assert entry["na_patterns"], law["id"]
        assert entry["overclaim_traps"], law["id"]


def test_claim_gate_accepts_every_law_id():
    """RULE-E5 must accept all 19, or no finding of any law can be inserted."""
    from hunter.kernel.claimgate import validate_klass

    for law in _LAWS:
        validate_klass(law["id"])  # raises ClaimGateBlocked on rejection


# ---------------------------------------------------------------- registry ---


def test_evm_engine_is_registered_and_selectable():
    from hunter.tools.registry import available_engines, get_engine

    assert "evm" in available_engines()
    engine = get_engine("evm")
    assert engine.name == "evm"
    assert isinstance(engine, EvmEngine)


def test_registry_order_is_stable():
    """available_engines() order is asserted elsewhere; pin it here too."""
    from hunter.tools.registry import available_engines

    assert available_engines() == ["deterministic", "evm", "llm", "mock", "review"]


# -------------------------------------------------------------- classification


def test_engine_classifies_a_law_violation(tmp_path):
    root = tmp_path / "contracts"
    root.mkdir()
    _write(root, "Vault.sol", """
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // CHECK-EFFECTS VIOLATION: external call before the state update
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
""")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.candidates, "no candidates from a file with several law hits"
    klasses = {c.klass for c in result.candidates}
    # every klass is a taxonomy id, never the unknown escape hatch
    assert "unknown" not in klasses
    assert klasses <= {law["id"] for law in _LAWS}


def test_every_candidate_klass_is_a_real_law(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    _write(root, "A.sol", "contract A { function f() external { unchecked { uint256 x = 1 - 2; } } }")
    _write(root, "B.sol", "contract B { address owner; function g() external { owner = tx.origin; } }")
    _write(root, "C.sol", "contract C { function h() external { selfdestruct(payable(msg.sender)); } }")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.candidates
    for candidate in result.candidates:
        assert candidate.klass.startswith("evm-"), candidate.klass
        assert candidate.klass != "unknown"
        assert candidate.evidence, "a candidate without evidence cannot be inserted"
        assert candidate.evidence[0].kind == "code_location"


def test_multi_law_span_records_the_chain(tmp_path):
    """A span violating two laws keeps the second on the evidence."""
    root = tmp_path / "src"
    root.mkdir()
    # tx.origin is both an access-control path (law 5) and a signature-adjacent
    # authority smell; the line also carries a signature keyword.
    _write(root, "Auth.sol", """
contract Auth {
    address owner;
    function approve(bytes memory signature) external {
        require(ecrecover(keccak256(abi.encode(signature)), 0, 0, 0) == tx.origin);
        owner = tx.origin;
    }
}
""")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    multi = [c for c in result.candidates
             if c.evidence and c.evidence[0].data.get("laws_also_implicated")]
    assert multi, "expected at least one span implicating more than one law"
    for candidate in multi:
        also = candidate.evidence[0].data["laws_also_implicated"]
        assert isinstance(also, list) and also
        assert candidate.klass not in also, "the primary law must not repeat in also"


def test_two_law_span_picks_the_higher_severity(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    # oracle (critical) + ordering (high) on one line
    _write(root, "Price.sol", """
contract Price {
    function quote() external view returns (uint256) {
        return getPrice() / totalSupply();
    }
}
""")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    hit = [c for c in result.candidates if "Price.sol" in c.endpoint]
    assert hit
    primary = max(hit, key=lambda c: c.severity)
    assert primary.severity == Severity.CRITICAL
    assert primary.klass == "evm-oracle-movable"


def test_clean_file_yields_nothing(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    _write(root, "Clean.sol", """
pragma solidity ^0.8.0;

/// @notice A deliberately boring contract: no law needle appears.
contract Clean {
    uint256 private counter;

    function increment() external {
        counter += 1;
    }

    function value() external view returns (uint256) {
        return counter;
    }
}
""")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.candidates == []
    assert result.stats["files_scanned"] == 1


def test_non_solidity_files_are_ignored(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    _write(root, "notes.md", "tx.origin delegatecall selfdestruct")
    _write(root, "script.py", "tx.origin = 1")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.stats["files_scanned"] == 0
    assert result.candidates == []


def test_stats_report_which_laws_fired(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    _write(root, "X.sol", "contract X { function f() external { unchecked { } } }")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.stats["laws_fired"]
    assert sum(result.stats["laws_fired"].values()) == len(result.candidates)


# ------------------------------------------------------------- safety gates ---


def test_replay_never_auto_verifies(tmp_path):
    """Law 19, enforced structurally: a code reading is not a proof."""
    root = tmp_path / "src"
    root.mkdir()
    _write(root, "A.sol", "contract A { function f() external { unchecked { } } }")

    scope = _scope_with_roots(tmp_path, root)
    target = _target(root, scope)
    ctx = _ctx(tmp_path, local_root=root)
    result = EvmEngine().run(target, ctx)
    assert result.candidates

    for candidate in result.candidates:
        assert EvmEngine().replay(target, ctx, candidate) is False


def test_root_outside_local_roots_is_refused(tmp_path):
    """Fail-closed: a root the scope never authorised yields nothing."""
    inside = tmp_path / "authorised"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    _write(outside, "A.sol", "contract A { function f() external { unchecked { } } }")

    scope = _scope_with_roots(tmp_path, inside)  # authorises `inside` only
    result = EvmEngine().run(_target(outside, scope), _ctx(tmp_path, local_root=outside))

    assert result.candidates == []
    assert result.stats["files_scanned"] == 0


def test_missing_root_is_not_an_error(tmp_path):
    scope = _scope_with_roots(tmp_path, tmp_path)
    result = EvmEngine().run(
        _target(tmp_path / "nope", scope), _ctx(tmp_path, local_root=tmp_path / "nope")
    )
    assert result.candidates == []
    assert result.stats["files_scanned"] == 0


def test_symlinked_file_is_not_followed(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    secret = tmp_path / "secret.sol"
    _write(tmp_path, "secret.sol", "contract S { function f() external { unchecked { } } }")
    link = root / "link.sol"
    try:
        link.symlink_to(secret)
    except OSError:  # pragma: no cover - filesystem without symlink support
        pytest.skip("symlinks unavailable")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.stats["files_scanned"] == 0
    assert result.candidates == []


def test_symlinked_dir_cannot_escape_the_root(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "A.sol", "contract A { function f() external { unchecked { } } }")
    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:  # pragma: no cover
        pytest.skip("symlinks unavailable")

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.stats["files_scanned"] == 0
    assert result.candidates == []


def test_oversize_file_is_skipped(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    big = root / "Big.sol"
    big.write_text("contract B { function f() external { unchecked { } } }\n" + "// pad\n" * 400_000,
                   encoding="utf-8")
    assert big.stat().st_size > 1_000_000

    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), _ctx(tmp_path, local_root=root))

    assert result.stats["files_scanned"] == 0


# ------------------------------------------------------------------- plan -----


def test_plan_declares_the_law_count_and_source(tmp_path):
    plan = EvmEngine().plan(_target(tmp_path, _scope_with_roots(tmp_path, tmp_path)))
    assert plan.engine == "evm"
    assert plan.notes["laws"] == LAW_COUNT
    assert "black-swan-engine" in plan.notes["source"]
    assert "classify-laws" in plan.phases

def test_engine_emits_a_done_event(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    _write(root, "A.sol", "contract A { function f() external { unchecked { } } }")

    events: list[tuple[str, dict]] = []
    ctx = EngineContext(
        http=None,  # type: ignore[arg-type] - the evm engine never requests
        emit=lambda kind, payload: events.append((kind, payload)),
        config={"local_root": str(root)},
    )
    scope = _scope_with_roots(tmp_path, root)
    result = EvmEngine().run(_target(root, scope), ctx)

    assert result.stats["files_scanned"] == 1
    done = [payload for kind, payload in events if kind == "engine_event"
            and payload.get("stage") == "evm.done"]
    assert done, "the engine must report what it classified"
    assert done[0]["candidates"] == len(result.candidates)
    assert done[0]["laws_fired"]
