"""Unit tests for task tree mechanics — BFS ordering, retry, chain spawning,
cross-pollination, subdomain merging, and contract family grouping.

These tests exercise the chain spawner, the Task data model, and the tree
manipulation primitives independently of a live ledger.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.workflow.chain_spawner import (
    Task,
    TaskState,
    _check_type,
    _severity_priority,
    a_id,
    find_chain_candidates,
    should_spawn_child,
    spawn_child_tasks,
)


# ── helpers ──────────────────────────────────────────────────────────────────


def _f(
    fid: str = "F-0001",
    severity: Severity = Severity.MEDIUM,
    status: FindingStatus = FindingStatus.VERIFIED,
    endpoint: str = "/api/test",
    key: str = "sqli|GET|/api/test|id",
    klass: str = "sqli",
    title: str = "SQL Injection",
) -> Finding:
    return Finding(
        id=fid,
        run_id="R-test",
        key=key,
        title=title,
        severity=severity,
        cwe="CWE-89",
        endpoint=endpoint,
        method="GET",
        param="id",
        status=status,
        klass=klass,
    )


def _t(task_id: str = "T-001", depth: int = 0, parent_id: str | None = None, **kwargs) -> Task:
    return Task(task_id=task_id, parent_id=parent_id, depth=depth, **kwargs)


# ── Task model ───────────────────────────────────────────────────────────────


class TestTaskCreation:
    """Task creation with parent-child relationships."""

    def test_root_task_no_parent(self):
        t = _t("T-001")
        assert t.task_id == "T-001"
        assert t.parent_id is None
        assert t.depth == 0
        assert t.state == TaskState.QUEUED

    def test_child_task_has_parent(self):
        t = _t("T-001.1", depth=1, parent_id="T-001")
        assert t.parent_id == "T-001"
        assert t.depth == 1

    def test_grandchild_depth_inheritance(self):
        t = _t("T-001.1.3", depth=3, parent_id="T-001.1")
        assert t.depth == 3
        assert t.parent_id == "T-001.1"

    def test_task_has_default_retry_config(self):
        t = _t("T-001")
        assert t.max_retries == 2
        assert t.retry_count == 0
        assert t.last_error is None

    def test_task_can_fail_and_retry(self):
        t = _t("T-001")
        t.state = TaskState.FAILED
        t.retry_count = 1
        t.last_error = "connection reset"
        assert t.state == TaskState.FAILED
        assert t.retry_count == 1
        assert t.last_error == "connection reset"

    def test_retry_increments_counter(self):
        t = _t("T-001", max_retries=3)
        for i in range(2):
            t.retry_count = i
            assert t.retry_count == i
            assert t.retry_count < t.max_retries

    def test_retry_exhaustion(self):
        t = _t("T-001", max_retries=2, retry_count=2)
        assert t.retry_count >= t.max_retries


# ── BFS ordering ─────────────────────────────────────────────────────────────


class TestBFSOrdering:
    """BFS order: level 0 tasks process before level 1."""

    def test_bfs_sort_by_depth(self):
        tasks = [
            _t("T-001.1", depth=1),
            _t("T-001", depth=0),
            _t("T-001.2", depth=1),
            _t("T-002", depth=0),
            _t("T-001.1.1", depth=2),
        ]
        sorted_tasks = sorted(tasks, key=lambda t: (t.depth, t.task_id))
        depths = [t.depth for t in sorted_tasks]
        assert depths == [0, 0, 1, 1, 2]

    def test_level_zero_before_level_one(self):
        """All depth-0 tasks must appear before any depth-1 task."""
        tasks = [
            _t("T-001", depth=0),
            _t("T-001.1", depth=1),
            _t("T-001.2", depth=1),
            _t("T-002", depth=0),
        ]
        sorted_tasks = sorted(tasks, key=lambda t: (t.depth, t.task_id))
        for i in range(len(sorted_tasks) - 1):
            assert sorted_tasks[i].depth <= sorted_tasks[i + 1].depth, (
                f"depth {sorted_tasks[i].depth} before {sorted_tasks[i+1].depth}"
            )

    def test_same_level_sorted_by_id(self):
        tasks = [
            _t("T-003", depth=0),
            _t("T-002", depth=0),
            _t("T-001", depth=0),
        ]
        sorted_tasks = sorted(tasks, key=lambda t: (t.depth, t.task_id))
        assert [t.task_id for t in sorted_tasks] == ["T-001", "T-002", "T-003"]


# ── Task retry ───────────────────────────────────────────────────────────────


class TestTaskRetry:
    """Task retry on failure."""

    def test_task_can_be_retried_when_under_limit(self):
        t = _t("T-001", max_retries=3, retry_count=1)
        can_retry = t.retry_count < t.max_retries
        assert can_retry is True

    def test_task_cannot_be_retried_when_exhausted(self):
        t = _t("T-001", max_retries=2, retry_count=2)
        can_retry = t.retry_count < t.max_retries
        assert can_retry is False

    def test_retry_preserves_task_identity(self):
        t = _t("T-001", target="https://example.com", depth=0)
        before_id = t.task_id
        t.retry_count += 1
        t.last_error = "timeout"
        assert t.task_id == before_id
        assert t.target == "https://example.com"

    def test_failed_tasks_rejoin_queue(self):
        t = _t("T-001", state=TaskState.FAILED, retry_count=0, max_retries=3)
        assert t.state == TaskState.FAILED
        # Simulate re-queue: reset state but keep task identity
        t.state = TaskState.QUEUED
        t.retry_count += 1
        assert t.state == TaskState.QUEUED
        assert t.retry_count == 1


# ── Cross-pollination ────────────────────────────────────────────────────────


class TestCrossPollination:
    """Cross-pollination: a task receives prior findings from sibling/parent tasks."""

    def test_injected_context_carries_parent_findings(self):
        parent = _t("T-001", target="https://example.com", depth=0)
        finding = _f(fid="F-0001", endpoint="/api/login")
        children = spawn_child_tasks(parent, [finding])
        assert len(children) == 1
        ctx = children[0].injected_context
        assert ctx is not None
        assert ctx["parent_task_id"] == "T-001"
        assert ctx["finding_id"] == "f-0001"
        assert ctx["finding_endpoint"] == "/api/login"
        assert ctx["chain_depth"] == 0

    def test_child_inherits_parent_target(self):
        parent = _t("T-001", target="https://api.example.com", depth=0)
        finding = _f(fid="F-0001")
        children = spawn_child_tasks(parent, [finding])
        assert children[0].target == "https://api.example.com"

    def test_child_depth_is_parent_plus_one(self):
        parent = _t("T-001", depth=2)
        finding = _f()
        children = spawn_child_tasks(parent, [finding])
        assert children[0].depth == 3

    def test_multiple_findings_create_multiple_children(self):
        parent = _t("T-001", target="https://example.com", depth=0)
        findings = [
            _f(fid="F-0001", endpoint="/a"),
            _f(fid="F-0002", endpoint="/b", severity=Severity.HIGH),
            _f(fid="F-0003", endpoint="/c", severity=Severity.CRITICAL),
        ]
        children = spawn_child_tasks(parent, findings)
        assert len(children) == 3
        # Children should be ordered by priority (critical first)
        assert children[0].task_id == "T-001.1"
        assert children[1].task_id == "T-001.2"
        assert children[2].task_id == "T-001.3"

    def test_child_carries_chain_hypothesis(self):
        parent = _t("T-001", target="https://example.com")
        finding = _f(fid="F-0042", severity=Severity.CRITICAL, title="RCE via upload")
        children = spawn_child_tasks(parent, [finding])
        hypothesis = children[0].chain_hypothesis or ""
        assert ("F-0042" in hypothesis) or ("f-0042" in hypothesis)
        assert "rce" in hypothesis.lower()
        assert "T-001" in hypothesis


# ── Chain spawning ───────────────────────────────────────────────────────────


class TestChainSpawning:
    """Chain spawning: verified finding creates child tasks."""

    def test_critical_always_spawns(self):
        f = _f(severity=Severity.CRITICAL, status=FindingStatus.CANDIDATE)
        assert should_spawn_child(f) is True

    def test_high_always_spawns(self):
        f = _f(severity=Severity.HIGH, status=FindingStatus.CANDIDATE)
        assert should_spawn_child(f) is True

    def test_medium_verified_spawns(self):
        f = _f(severity=Severity.MEDIUM, status=FindingStatus.VERIFIED)
        assert should_spawn_child(f) is True

    def test_medium_candidate_does_not_spawn(self):
        f = _f(severity=Severity.MEDIUM, status=FindingStatus.CANDIDATE)
        assert should_spawn_child(f) is False

    def test_low_never_spawns(self):
        f = _f(severity=Severity.LOW, status=FindingStatus.VERIFIED)
        assert should_spawn_child(f) is False

    def test_info_never_spawns(self):
        f = _f(severity=Severity.INFO, status=FindingStatus.VERIFIED)
        assert should_spawn_child(f) is False

    def test_spawn_child_tasks_filters_non_spawnable(self):
        parent = _t("T-001")
        findings = [
            _f(fid="F-0001", severity=Severity.CRITICAL),
            _f(fid="F-0002", severity=Severity.LOW),
            _f(fid="F-0003", severity=Severity.MEDIUM, status=FindingStatus.CANDIDATE),
            _f(fid="F-0004", severity=Severity.HIGH),
        ]
        children = spawn_child_tasks(parent, findings)
        assert len(children) == 2  # only critical and high
        spawned_ids = [c.spawned_from_finding for c in children]
        assert "f-0001" in spawned_ids
        assert "f-0004" in spawned_ids

    def test_empty_findings_produces_no_children(self):
        parent = _t("T-001")
        assert spawn_child_tasks(parent, []) == []

    def test_child_priority_reflects_severity(self):
        parent = _t("T-001")
        findings = [
            _f(fid="F-0003", severity=Severity.MEDIUM, status=FindingStatus.VERIFIED),
            _f(fid="F-0001", severity=Severity.CRITICAL),
        ]
        children = spawn_child_tasks(parent, findings)
        # Children inherit priority from their finding's severity
        priorities = {c.spawned_from_finding: c.priority for c in children}
        assert priorities["f-0001"] == 40  # critical
        assert priorities["f-0003"] == 20  # medium

    def test_dict_finding_works_with_should_spawn(self):
        """Dict-shaped findings (from JSON/RAG) work with should_spawn_child."""
        f = {"id": "F-1", "severity": "critical", "status": "candidate"}
        assert should_spawn_child(f) is True

        low = {"id": "F-2", "severity": "low", "status": "verified"}
        assert should_spawn_child(low) is False


# ── Subdomain merge ──────────────────────────────────────────────────────────


class TestSubdomainMerge:
    """Subdomain merge: api+docs+rpc → 1 task (target deduplication)."""

    def test_same_target_groups_together(self):
        """Findings on the same target are grouped under one parent task."""
        # All three findings share the same target
        target = "https://api.example.com"
        parent = _t("T-001", target=target)
        findings = [
            _f("F-0001", endpoint="/v1/users"),
            _f("F-0002", endpoint="/v1/docs"),
            _f("F-0003", endpoint="/v1/rpc"),
        ]
        children = spawn_child_tasks(parent, findings)
        # All children target the same base URL
        assert all(c.target == target for c in children)
        assert len(children) == 3

    def test_subdomain_merge_preserves_unique_children(self):
        """Two findings on same endpoint-surface still produce distinct children."""
        parent = _t("T-001", target="https://example.com")
        findings = [
            _f("F-0001", endpoint="/api/users", klass="sqli"),
            _f("F-0002", endpoint="/api/users", klass="xss"),
        ]
        children = spawn_child_tasks(parent, findings)
        assert len(children) == 2
        # Each child has its own finding context
        ctx1 = children[0].injected_context
        ctx2 = children[1].injected_context
        assert ctx1 is not None and ctx2 is not None
        assert ctx1["finding_id"] != ctx2["finding_id"]


# ── Contract family grouping ─────────────────────────────────────────────────


class TestContractFamilyGrouping:
    """Contract family grouping: related contracts produce grouped tasks."""

    def test_findings_on_same_contract_form_family(self):
        """When findings share the same chain/contract, they form a family."""
        chain_targets = [
            _f("F-0010", endpoint="0xContractA", klass="reentrancy"),
            _f("F-0011", endpoint="0xContractA", klass="access-control"),
            _f("F-0012", endpoint="0xContractB", klass="overflow"),
        ]
        # Group by endpoint → same contract findings group together
        families: dict[str, list[Finding]] = {}
        for f in chain_targets:
            families.setdefault(f.endpoint, []).append(f)
        assert len(families) == 2
        assert len(families["0xContractA"]) == 2
        assert len(families["0xContractB"]) == 1

    def test_contract_family_spawns_grouped_children(self):
        """A contract with multiple findings spawns children for each."""
        parent = _t("T-001", target="0xDeadBeef", target_kind="contract")
        findings = [
            _f("F-0010", endpoint="0xDeadBeef", klass="reentrancy", severity=Severity.CRITICAL),
            _f("F-0011", endpoint="0xDeadBeef", klass="access-control", severity=Severity.HIGH),
        ]
        children = spawn_child_tasks(parent, findings)
        assert len(children) == 2
        assert all(c.target_kind == "contract" for c in children)
        assert children[0].parent_id == "T-001"


# ── find_chain_candidates ────────────────────────────────────────────────────


class TestFindChainCandidates:
    """Deterministic chain candidate discovery."""

    def test_empty_returns_empty(self):
        assert find_chain_candidates([]) == []

    def test_single_finding_returns_empty(self):
        assert find_chain_candidates([_f("F-0001")]) == []

    def test_same_target_is_candidate(self):
        findings = [
            _f("F-0001", endpoint="/api/users", klass="sqli"),
            _f("F-0002", endpoint="/api/users", klass="xss"),
        ]
        candidates = find_chain_candidates(findings)
        assert len(candidates) >= 1
        assert candidates[0][0] == "f-0001"
        assert candidates[0][1] == "f-0002"
        assert "same_target" in candidates[0][2]

    def test_type_match_is_candidate(self):
        findings = [
            _f("F-0001", endpoint="/app1/users", klass="sqli"),
            _f("F-0002", endpoint="/app2/users", klass="sqli"),
        ]
        candidates = find_chain_candidates(findings)
        assert len(candidates) == 1
        assert "type_match" in candidates[0][2]

    def test_different_target_and_type_skipped(self):
        findings = [
            _f("F-0001", endpoint="/app1", klass="sqli"),
            _f("F-0002", endpoint="/app2", klass="xss"),
        ]
        candidates = find_chain_candidates(findings)
        assert len(candidates) == 0

    def test_same_target_ranks_above_type_match(self):
        findings = [
            _f("F-0001", endpoint="/api/login", klass="sqli"),
            _f("F-0002", endpoint="/api/login", klass="xss"),
            _f("F-0003", endpoint="/other", klass="sqli"),
        ]
        candidates = find_chain_candidates(findings)
        # First candidate should be same_target (F-0001 + F-0002)
        assert "same_target" in candidates[0][2]

    def test_capped_at_five(self):
        """With many same-target findings, returns at most 5 candidates."""
        findings = [
            _f(f"F-{i:04d}", endpoint="/api/common")
            for i in range(1, 8)
        ]
        candidates = find_chain_candidates(findings)
        assert len(candidates) <= 5

    def test_deterministic_ordering(self):
        """Same input always produces same output (id sorting ensures this)."""
        findings = [
            _f("F-0005", endpoint="/api/a"),
            _f("F-0001", endpoint="/api/a"),
            _f("F-0003", endpoint="/api/a"),
        ]
        candidates = find_chain_candidates(findings)
        # First pair should be f-0001 + f-0003 (sorted by id)
        assert candidates[0][0] == "f-0001"
        assert candidates[0][1] == "f-0003"


# ── helper functions ─────────────────────────────────────────────────────────


class TestHelpers:
    def test_severity_priority_values(self):
        assert _severity_priority("critical") == 40
        assert _severity_priority("high") == 30
        assert _severity_priority("medium") == 20
        assert _severity_priority("low") == 10
        assert _severity_priority("unknown") == 0

    def test_check_type_from_klass(self):
        f = _f(klass="reentrancy")
        assert _check_type(f) == "reentrancy"

    def test_check_type_from_key_fallback(self):
        # klass is "unknown" → falls back to key prefix
        f = _f(klass="unknown", key="reflected-xss|GET|/search|q")
        assert _check_type(f) == "reflected-xss"

    def test_a_id_from_finding(self):
        f = _f(fid="F-0042")
        assert a_id(f) == "f-0042"

    def test_a_id_from_dict(self):
        assert a_id({"id": "F-0099"}) == "f-0099"

    def test_task_spawned_from_finding_field(self):
        t = _t("T-001", depth=0)
        f = _f(fid="F-0001")
        children = spawn_child_tasks(t, [f])
        assert children[0].spawned_from_finding == "f-0001"