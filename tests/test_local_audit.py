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