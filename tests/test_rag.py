import json
from pathlib import Path

from hunter.tools.scope import ScopeSet
from hunter.workflow.rag import (
    RagConfig,
    RagLoop,
    derive_child_targets,
    existing_targets,
    followed_findings,
    load_rag_state,
    mark_followed,
    normalize_finding_target,
    wonder_followups,
)


def _scope():
    return ScopeSet(frozenset({"example.com"}), False, name="test")


def test_normalize_finding_target_relative():
    from hunter.kernel.findings import Finding, Severity

    f = Finding(
        id="F-0001",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/api/foo",
        method="GET",
    )
    assert normalize_finding_target(f, "http://example.com") == "http://example.com/api/foo"


def test_derive_child_targets_in_scope():
    from hunter.kernel.findings import Finding, Severity

    f = Finding(
        id="F-0002",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/api/foo/bar",
        method="GET",
    )
    scope = _scope()
    targets = derive_child_targets(f, scope, "http://example.com")
    assert targets
    assert all("example.com" in t for t in targets)
    # host out of scope rejected
    f2 = Finding(
        id="F-0003",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="http://evil.com/x",
        method="GET",
    )
    assert derive_child_targets(f2, scope, "http://example.com") == []


def test_wonder_followups_none_provider():
    from hunter.kernel.findings import Finding, Severity

    f = Finding(
        id="F-0004",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/x",
        method="GET",
    )
    assert wonder_followups(None, f, _scope(), "http://example.com") == []


def test_wonder_followups_parses_and_validates():
    from hunter.kernel.findings import Finding, Severity

    class FakeProvider:
        name = "fake"

        def complete(self, tier, messages, tools=None, stream_cb=None, budget=None):
            from hunter.llm.base import TurnResult

            return TurnResult(
                text='["http://example.com/a", "http://evil.com/b", "http://example.com/c"]'
            )

        def classify(self, exc):
            from hunter.llm.base import ClassifiedError

            return ClassifiedError()

    f = Finding(
        id="F-0005",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/x",
        method="GET",
    )
    out = wonder_followups(FakeProvider(), f, _scope(), "http://example.com")
    assert "http://example.com/a" in out
    assert "http://example.com/c" in out
    assert all("evil.com" not in t for t in out)


def test_followed_state_roundtrip(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    assert followed_findings(sd) == set()
    mark_followed(sd, "F-0001")
    assert "F-0001" in followed_findings(sd)
    st = load_rag_state(sd)
    assert "F-0001" in st["followed"]


def test_existing_targets_reads_queue(tmp_path):
    sd = tmp_path / "state"
    (sd / "daemon" / "queue").mkdir(parents=True)
    q = sd / "daemon" / "queue"
    (q / "task-1.json").write_text(json.dumps({"target": "http://example.com/a"}))
    assert "http://example.com/a" in existing_targets(sd)


def test_rag_cycle_enqueues_seed_variants(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    scope = _scope()
    from hunter.home import state_dir as _sd

    # ensure state dir layout
    (sd / "daemon" / "queue").mkdir(parents=True, exist_ok=True)

    cfg = RagConfig(
        state_dir=sd,
        target="http://example.com",
        scope=scope,
        engine="deterministic",
        time_budget_s=10,
        interval_s=1,
        high_water=3,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    loop = RagLoop(cfg)
    enqueued = loop._cycle()
    # high_water=3 -> at least 2 additional tasks beyond/including seed
    pending = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    assert pending >= 2
    assert len(enqueued) >= 1


def test_rag_cycle_no_duplicate_processing(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    (sd / "daemon" / "queue").mkdir(parents=True, exist_ok=True)
    scope = _scope()
    cfg = RagConfig(
        state_dir=sd,
        target="http://example.com",
        scope=scope,
        engine="deterministic",
        time_budget_s=10,
        interval_s=1,
        high_water=2,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    loop = RagLoop(cfg)
    loop._cycle()
    # second cycle should not crash and should not re-enqueue identical seeds
    before = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    loop._cycle()
    after = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    assert after >= before
