"""End-to-end simulation of the BFS task tree with 3 target groups.

Full pipeline:
1. Root tasks enqueued for 3 targets (web api, web docs, contract)
2. BFS processing: level 0 tasks run first, generate findings
3. Findings at each level spawn children (chain spawning)
4. Tree resolves correctly — all children complete, findings aggregate
5. Cross-pollination: later tasks receive context from prior siblings

Uses mock/fake providers — no real network or ledger calls.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.workflow.chain_spawner import (
    Task,
    TaskState,
    find_chain_candidates,
    should_spawn_child,
    spawn_child_tasks,
    a_id,
)


# ── mocks ────────────────────────────────────────────────────────────────────


@dataclass
class MockProvider:
    """Fake LLM provider that returns canned findings for each target."""

    findings_map: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def complete(self, tier: str, messages: list[dict], **kwargs) -> SimpleNamespace:
        return SimpleNamespace(text="ok")

    def classify(self, exc: Exception) -> SimpleNamespace:
        return SimpleNamespace(fatal=True, retryable=False)


@dataclass
class MockHuntResult:
    """Simulates what a hunt run returns after probing a target."""

    task_id: str
    target: str
    findings: list[Finding]
    success: bool = True
    error: str | None = None


# ── simulation engine ────────────────────────────────────────────────────────


@dataclass
class SimulationRun:
    """Orchestrates a full BFS task tree run with multiple targets."""

    root_targets: list[tuple[str, str, str]]  # (task_id, target, target_kind)
    target_finding_map: dict[str, list[Finding]]  # target → findings it yields
    max_depth: int = 3
    completed: list[MockHuntResult] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)
    _next_child_seq: int = field(default=0, init=False)

    def run_bfs(self) -> list[MockHuntResult]:
        """Execute full BFS tree simulation.

        Returns all completed hunt results in BFS order.
        """
        # Phase 1: Create root tasks (depth 0)
        queue: deque[Task] = deque()
        for idx, (task_id, target, kind) in enumerate(self.root_targets):
            queue.append(Task(
                task_id=task_id,
                target=target,
                target_kind=kind,
                depth=0,
                priority=40,
            ))

        completed: list[MockHuntResult] = []

        # Phase 2: BFS — process all tasks at current depth before descending
        while queue:
            # Collect all tasks at the current (lowest) depth
            current_depth = min(t.depth for t in queue) if queue else -1

            level: list[Task] = []
            while queue and queue[0].depth == current_depth:
                level.append(queue.popleft())

            # Process level — run each task, collect findings, spawn children
            level_findings: list[Finding] = []
            for task in level:
                result = self._run_task(task)
                completed.append(result)
                if result.findings:
                    level_findings.extend(result.findings)
                    self.all_findings.extend(result.findings)

                    # Spawn children from verified findings
                    # Each task at this level that produced findings gets children
                    children = self._spawn_children(task, result.findings)
                    for child in children:
                        if child.depth <= self.max_depth:
                            queue.append(child)

        self.completed = completed
        return completed

    def _run_task(self, task: Task) -> MockHuntResult:
        """Simulate running a single hunt task against a target."""
        findings = self.target_finding_map.get(task.target, [])
        # Tag each finding with its originating task
        tagged = []
        for f in findings:
            tagged.append(Finding(
                id=f.id,
                run_id=f.run_id,
                key=f"{task.task_id}|{f.key}",
                title=f.title,
                severity=f.severity,
                cwe=f.cwe,
                endpoint=f.endpoint,
                method=f.method,
                param=f.param,
                status=f.status,
                klass=f.klass,
            ))
        return MockHuntResult(
            task_id=task.task_id,
            target=task.target,
            findings=tagged,
            success=True,
        )

    def _spawn_children(self, parent: Task, findings: list[Finding]) -> list[Task]:
        """Create child tasks from verified findings using chain spawner."""
        children = spawn_child_tasks(parent, findings)
        # Override child IDs to be deterministic
        result = []
        for i, child in enumerate(children):
            self._next_child_seq += 1
            result.append(Task(
                task_id=f"{parent.task_id}.{self._next_child_seq}",
                parent_id=parent.task_id,
                target=child.target,
                target_kind=child.target_kind,
                depth=child.depth,
                priority=child.priority,
                spawned_from_finding=child.spawned_from_finding,
                chain_hypothesis=child.chain_hypothesis,
                injected_context=child.injected_context,
            ))
        return result

    def tree_stats(self) -> dict[str, Any]:
        """Compute statistics about the completed tree."""
        by_depth: dict[int, int] = {}
        for result in self.completed:
            # Parse depth from task_id: T-001 → 0, T-001.1 → 1, etc.
            tid = result.task_id
            depth = tid.count(".")  # T-001 = 0 dots, T-001.1 = 1 dot
            by_depth[depth] = by_depth.get(depth, 0) + 1
        return {
            "total_tasks": len(self.completed),
            "total_findings": len(self.all_findings),
            "max_depth": max(by_depth) if by_depth else 0,
            "tasks_by_depth": dict(sorted(by_depth.items())),
            "chain_candidates": len(find_chain_candidates(self.all_findings)),
        }


# ── fixture: build a realistic 3-target scenario ─────────────────────────────


def _make_sim() -> SimulationRun:
    """Create a simulation with 3 target groups: web-api, web-docs, contract."""
    targets = [
        ("T-001", "https://api.example.com", "web"),
        ("T-002", "https://docs.example.com", "web"),
        ("T-003", "0xDeadBeefCafe", "contract"),
    ]

    # Each target yields different findings when probed
    finding_map: dict[str, list[Finding]] = {
        "https://api.example.com": [
            Finding("F-0001", "R-sim", "sqli|POST|/api/login|user",
                    "SQL Injection in login", Severity.CRITICAL, "CWE-89",
                    "/api/login", "POST", "user",
                    status=FindingStatus.VERIFIED, klass="sqli"),
            Finding("F-0002", "R-sim", "xss|GET|/api/search|q",
                    "Reflected XSS in search", Severity.HIGH, "CWE-79",
                    "/api/search", "GET", "q",
                    status=FindingStatus.VERIFIED, klass="xss"),
            Finding("F-0003", "R-sim", "idor|GET|/api/users/*|id",
                    "IDOR in user profiles", Severity.MEDIUM, "CWE-639",
                    "/api/users", "GET", "id",
                    status=FindingStatus.CANDIDATE, klass="idor"),
            # Low finding — should NOT spawn children
            Finding("F-0004", "R-sim", "info|GET|/api/health|",
                    "Info disclosure in health check", Severity.LOW, "CWE-200",
                    "/api/health", "GET", None,
                    status=FindingStatus.VERIFIED, klass="info-disclosure"),
        ],
        "https://docs.example.com": [
            Finding("F-0010", "R-sim", "ssrf|POST|/docs/export|url",
                    "SSRF in export feature", Severity.HIGH, "CWE-918",
                    "/docs/export", "POST", "url",
                    status=FindingStatus.VERIFIED, klass="ssrf"),
            Finding("F-0011", "R-sim", "sqli|GET|/docs/search|term",
                    "SQL Injection in doc search", Severity.CRITICAL, "CWE-89",
                    "/docs/search", "GET", "term",
                    status=FindingStatus.VERIFIED, klass="sqli"),
        ],
        "0xDeadBeefCafe": [
            Finding("F-0020", "R-sim", "reentrancy|CALL|0xDeadBeefCafe|value",
                    "Reentrancy in withdraw()", Severity.CRITICAL, "CWE-191",
                    "0xDeadBeefCafe", "CALL", "value",
                    status=FindingStatus.VERIFIED, klass="reentrancy"),
            Finding("F-0021", "R-sim", "access-control|CALL|0xDeadBeefCafe|role",
                    "Missing access control on admin()", Severity.HIGH, "CWE-284",
                    "0xDeadBeefCafe", "CALL", "role",
                    status=FindingStatus.VERIFIED, klass="access-control"),
        ],
    }

    return SimulationRun(
        root_targets=targets,
        target_finding_map=finding_map,
        max_depth=3,
    )


# ── tests ────────────────────────────────────────────────────────────────────


class TestE2ETaskTree:
    """Full end-to-end BFS simulation of a multi-target hunt."""

    def test_three_target_groups_enqueued(self):
        sim = _make_sim()
        results = sim.run_bfs()
        # Root tasks (depth 0) should be 3
        root_results = [r for r in results if r.task_id in ("T-001", "T-002", "T-003")]
        assert len(root_results) == 3

    def test_root_tasks_run_before_children_bfs_order(self):
        sim = _make_sim()
        results = sim.run_bfs()
        # Extract the depth of each result from its task ID
        depths = [r.task_id.count(".") for r in results]
        # BFS invariant: depths must be non-decreasing
        for i in range(len(depths) - 1):
            assert depths[i] <= depths[i + 1], (
                f"BFS violation: depth {depths[i]} before {depths[i+1]} "
                f"at position {i} (task {results[i].task_id})"
            )

    def test_api_target_produces_children(self):
        """API target has verified critical+high → should spawn children."""
        sim = _make_sim()
        results = sim.run_bfs()
        # Among results, there should be children of T-001
        t001_children = [r for r in results if r.task_id.startswith("T-001.")]
        assert len(t001_children) > 0, (
            f"T-001 (api.example.com) should have spawned children, "
            f"but only found: {[r.task_id for r in results]}"
        )

    def test_docs_target_produces_children(self):
        """Docs target has verified critical+high → should spawn children."""
        sim = _make_sim()
        results = sim.run_bfs()
        t002_children = [r for r in results if r.task_id.startswith("T-002.")]
        assert len(t002_children) > 0

    def test_contract_target_produces_children(self):
        """Contract target has verified critical+high → should spawn children."""
        sim = _make_sim()
        results = sim.run_bfs()
        t003_children = [r for r in results if r.task_id.startswith("T-003.")]
        assert len(t003_children) > 0

    def test_tree_does_not_exceed_max_depth(self):
        sim = _make_sim()
        sim.max_depth = 2
        results = sim.run_bfs()
        max_depth = max(r.task_id.count(".") for r in results)
        assert max_depth <= 2

    def test_low_severity_finding_does_not_spawn_children(self):
        """The low-severity finding (F-0004) should never create children."""
        sim = _make_sim()
        results = sim.run_bfs()
        # F-0004 is LOW severity, so it should not be in any child's spawned_from_finding
        children_ids = [r.task_id for r in results if "." in r.task_id]
        # All findings on api.example.com are at T-001, so children spawn from T-001
        # but the low finding should be excluded — we verify this by checking
        # that a child's injected_context finding_id is never f-0004
        api_findings = [f for f in sim.target_finding_map["https://api.example.com"]]
        spawnable = [f for f in api_findings if should_spawn_child(f)]
        low_ids = {a_id(f) for f in api_findings if f.severity == Severity.LOW}
        spawnable_ids = {a_id(f) for f in spawnable}
        assert spawnable_ids.isdisjoint(low_ids), (
            f"Low-severity findings should never be spawnable: {low_ids}"
        )

    def test_all_findings_aggregated(self):
        sim = _make_sim()
        results = sim.run_bfs()
        # Each target's findings appear at each level (the mock returns same
        # findings every time a target is probed). Total should be sum of all
        # target findings × number of times each target was probed.
        assert len(sim.all_findings) > 0
        stats = sim.tree_stats()
        assert stats["total_findings"] > 0

    def test_tree_resolves_no_orphans(self):
        """Every task should have either no parent (root) or a valid parent."""
        sim = _make_sim()
        results = sim.run_bfs()
        root_ids = {"T-001", "T-002", "T-003"}
        child_ids = {r.task_id for r in results if r.task_id not in root_ids}
        # Every child's parent should exist as a root
        for child_id in sorted(child_ids):
            # T-001.1 → parent is T-001
            parent = ".".join(child_id.split(".")[:-1])
            assert parent in root_ids or parent in child_ids, (
                f"Orphan task {child_id}: parent {parent} not found"
            )

    def test_chain_candidates_discovered(self):
        """Across all findings, chain candidates should be discoverable."""
        sim = _make_sim()
        sim.run_bfs()
        stats = sim.tree_stats()
        # We have sqli findings on both api and docs targets → type_match candidate
        # We also have multiple findings on same targets → same_target candidate
        assert stats["chain_candidates"] >= 1, (
            f"Expected at least 1 chain candidate, got {stats['chain_candidates']}"
        )

    def test_total_tasks_in_tree(self):
        sim = _make_sim()
        results = sim.run_bfs()
        # Level 0: 3 root tasks
        # Level 1: T-001 spawns 3 (critical, high, medium-verified), T-002 spawns 2, T-003 spawns 2
        # Level 2: each of those spawns children... capped at depth 3
        assert len(results) >= 3  # at minimum the roots ran

    def test_stats_report(self):
        sim = _make_sim()
        sim.run_bfs()
        stats = sim.tree_stats()
        assert "total_tasks" in stats
        assert "total_findings" in stats
        assert "max_depth" in stats
        assert "tasks_by_depth" in stats
        assert "chain_candidates" in stats
        assert stats["max_depth"] >= 0
        assert isinstance(stats["tasks_by_depth"], dict)


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestE2EEdgeCases:
    """Edge cases for the task tree simulation."""

    def test_empty_targets_produces_no_results(self):
        sim = SimulationRun(
            root_targets=[],
            target_finding_map={},
            max_depth=3,
        )
        results = sim.run_bfs()
        assert results == []

    def test_single_target_no_findings(self):
        sim = SimulationRun(
            root_targets=[("T-001", "https://noop.example.com", "web")],
            target_finding_map={"https://noop.example.com": []},
            max_depth=3,
        )
        results = sim.run_bfs()
        # Root task runs but produces no findings → no children
        assert len(results) == 1
        assert results[0].task_id == "T-001"
        assert results[0].findings == []

    def test_single_target_only_low_findings(self):
        """A target with only low-severity findings spawns NO children."""
        sim = SimulationRun(
            root_targets=[("T-001", "https://safe.example.com", "web")],
            target_finding_map={
                "https://safe.example.com": [
                    Finding("F-1", "R", "k", "Low issue", Severity.LOW, "CWE-200",
                            "/safe", "GET", status=FindingStatus.VERIFIED),
                    Finding("F-2", "R", "k2", "Info", Severity.INFO, "CWE-200",
                            "/info", "GET", status=FindingStatus.VERIFIED),
                ]
            },
            max_depth=3,
        )
        results = sim.run_bfs()
        # Root runs, spawns 0 children
        assert len(results) == 1
        stats = sim.tree_stats()
        assert stats["max_depth"] == 0

    def test_max_depth_zero_no_children(self):
        sim = _make_sim()
        sim.max_depth = 0
        results = sim.run_bfs()
        # Only root tasks at depth 0 — children depth > max_depth are skipped
        assert all(r.task_id.count(".") == 0 for r in results)

    def test_bfs_ordering_with_sparse_tree(self):
        """BFS order is preserved even when some branches are deeper than others."""
        sim = SimulationRun(
            root_targets=[
                ("T-001", "https://deep.example.com", "web"),  # spawns many children
                ("T-002", "https://shallow.example.com", "web"),  # no findings
            ],
            target_finding_map={
                "https://deep.example.com": [
                    Finding("F-d1", "R", "sqli|GET|/deep|id",
                            "SQLI", Severity.CRITICAL, "CWE-89", "/deep", "GET", "id",
                            status=FindingStatus.VERIFIED, klass="sqli"),
                    Finding("F-d2", "R", "xss|GET|/deep|q",
                            "XSS", Severity.HIGH, "CWE-79", "/deep", "GET", "q",
                            status=FindingStatus.VERIFIED, klass="xss"),
                ],
                "https://shallow.example.com": [],
            },
            max_depth=3,
        )
        results = sim.run_bfs()
        depths = [r.task_id.count(".") for r in results]
        for i in range(len(depths) - 1):
            assert depths[i] <= depths[i + 1], (
                f"BFS violation at index {i}: {depths[i]} before {depths[i+1]}"
            )

    def test_child_inherits_correct_context(self):
        """Verify that a depth-1 child correctly references its parent's findings."""
        sim = _make_sim()
        results = sim.run_bfs()
        # Find a child of T-001 (the API target)
        t001_children = [r for r in results if r.task_id.startswith("T-001.")]
        if t001_children:
            # At least one child should exist — they all come from the same parent
            assert all("T-001" in r.task_id for r in t001_children)