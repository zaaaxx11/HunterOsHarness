import hashlib
import json
from pathlib import Path

from hunter.tools.scope import ScopeSet, scope_from_manifest
from hunter.kernel.ledger import Ledger
from hunter.engine.review import ReviewEngine
from hunter.engine.base import TargetSpec, EngineContext


def test_scope_local_roots_containment(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.sol").write_text("x")
    scope = ScopeSet(frozenset(), name="local", local_roots=(str(root),))
    assert scope.allows_local_root(root / "a.sol") is True
    assert scope.allows_local_root(tmp_path / "other" / "b.sol") is False
    # absent local_roots -> permissive
    s2 = ScopeSet(frozenset(), name="none")
    assert s2.allows_local_root("/any/path") is True


def test_scope_from_manifest_local_roots(tmp_path):
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps({"name": "local", "hosts": [], "local_roots": [str(tmp_path)]}))
    scope = scope_from_manifest(manifest)
    assert scope.local_roots == (str(tmp_path),)


def test_code_location_evidence_hash_validation(tmp_path):
    f = tmp_path / "a.sol"
    f.write_text("line1\nline2\nline3\n")
    span = "line2"
    digest = hashlib.sha256(span.encode("utf-8")).hexdigest()
    db = tmp_path / "ledger.db"
    ledger = Ledger(db)
    run_id = "R-test"
    ledger.create_run(run_id, "http://localhost", "review", "local")
    # valid
    eid = ledger.add_evidence(run_id, "code_location", {"path": str(f), "line_start": 2, "line_end": 2, "sha256": digest})
    assert eid.startswith("EV-")
    # invalid hash
    try:
        ledger.add_evidence(run_id, "code_location", {"path": str(f), "line_start": 2, "line_end": 2, "sha256": "deadbeef"})
        raised = False
    except Exception:
        raised = True
    assert raised
    ledger.close()


def test_review_engine_emits_code_location(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "x.sol").write_text("tx.origin\n")
    engine = ReviewEngine()
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    scope = localhost_scope()
    # attach local_root via config
    ctx = EngineContext(http=None, emit=lambda *a, **k: None, config={"local_root": str(root)}, ledger=None, run_id="")
    # EngineContext.http can be None for review (no network)
    target = TargetSpec(url="http://127.0.0.1:1/", scope=scope, notes={"local_root": str(root)})
    result = engine.run(target, ctx)
    assert result.candidates
    ev = result.candidates[0].evidence[0]
    assert ev.kind == "code_location"
    assert ev.data["path"].endswith("x.sol")


def test_code_location_rejects_bool_lines_and_open_range(tmp_path):
    import pytest as _pytest

    from hunter.kernel.claimgate import ClaimGateBlocked, validate_code_location

    f = tmp_path / "a.py"
    f.write_text("one\n" * 5)
    digest = hashlib.sha256("\n".join(["one"] * 5).encode("utf-8")).hexdigest()
    with _pytest.raises(ClaimGateBlocked):
        validate_code_location({"path": str(f), "line_start": True, "line_end": 5, "sha256": digest})
    with _pytest.raises(ClaimGateBlocked):
        validate_code_location({"path": str(f), "line_start": 1, "line_end": 10**9, "sha256": digest})
    with _pytest.raises(ClaimGateBlocked):
        validate_code_location({"path": str(f), "line_start": 1, "line_end": 6, "sha256": digest})
    validate_code_location({"path": str(f), "line_start": 1, "line_end": 5, "sha256": digest})


def test_finding_cannot_splice_cross_run_evidence(tmp_path):
    import pytest as _pytest

    from hunter.kernel.claimgate import ClaimGateBlocked
    from hunter.kernel.findings import Finding, Severity

    db = tmp_path / "ledger.db"
    ledger = Ledger(db)
    try:
        ledger.create_run("R-a", "http://localhost", "mock", "s")
        ledger.create_run("R-b", "http://localhost", "mock", "s")
        eid = ledger.add_evidence("R-a", "note", {"note": "cross-run probe"})
        f = Finding(
            id="", run_id="R-b", key="k|GET|/|-", title="t", severity=Severity.LOW,
            cwe="CWE-000", endpoint="/", evidence_ids=(eid,),
        )
        with _pytest.raises(ClaimGateBlocked):
            ledger.create_finding(f)
    finally:
        ledger.close()


def test_malformed_task_fails_done_not_wedge_worker(tmp_path):
    import asyncio

    from hunter.daemon import claim_task, enqueue_task, hunt_worker, queue_dir

    sd = tmp_path / "state"
    sd.mkdir()
    enqueue_task(sd, {"target": "http://127.0.0.1:1/", "engine": "deterministic", "max_wall_seconds": "banana"})
    stop = sd / "stop.flag"

    async def _drain():
        await hunt_worker(str(sd), stop_path=stop, heartbeat={})

    asyncio.run(_drain())  # must not raise
    done = list(queue_dir(sd).glob("done-*.json"))
    assert done, "malformed task must land as a done task"
    payload = json.loads(done[0].read_text(encoding="utf-8"))
    assert payload["status"] == "failed"