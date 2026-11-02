"""Tests for build_goal ledger context injection."""

from __future__ import annotations

import pytest

from hunter.engine.base import TargetSpec
from hunter.kernel.findings import Finding, Severity
from hunter.kernel.ledger import Ledger
from hunter.tools.scope import localhost_scope
from hunter.agent.prompts import build_goal


@pytest.fixture()
def make_ledger(tmp_path):
    created = []

    def _make(name="ledger.db"):
        led = Ledger(tmp_path / name)
        created.append(led)
        return led

    yield _make
    for led in created:
        led.close()


def _finding(**overrides):
    kwargs = dict(
        id="",
        run_id="r1",
        key="reflected-xss|GET|/search|q",
        title="Reflected XSS in q",
        severity=Severity.HIGH,
        cwe="CWE-79",
        endpoint="/search",
        method="GET",
        param="q",
        payload_used="<script>alert(1)</script>",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def test_build_goal_none_returns_original_style(make_ledger):
    target = TargetSpec(url="http://127.0.0.1:9/", scope=localhost_scope(), notes={})
    goal = build_goal(target, "basic")
    assert "Ledger context" not in goal
    assert "http://127.0.0.1:9" in goal
    # capability tiers were deleted: the legacy positional ``tier`` is accepted
    # for call-site compatibility but must change nothing in the goal text.
    assert "basic" not in goal.lower()
    assert "tier" not in goal.lower()
    assert goal == build_goal(target)
    assert goal == build_goal(target, "advanced")


def test_build_goal_with_ledger_candidate(make_ledger):
    led = make_ledger()
    led.create_run("r1", "http://127.0.0.1:9/", "deterministic", "scope-x")
    ev_id = led.add_evidence("r1", "http_response", {"status": 200, "body": "x"})
    led.create_finding(_finding(evidence_ids=(ev_id,)))
    target = TargetSpec(url="http://127.0.0.1:9/", scope=localhost_scope(), notes={})
    goal = build_goal(target, "basic", ledger=led, run_id="r1")
    assert "Ledger context" in goal
    # finding count present
    assert "Findings: 1 total" in goal
    assert "candidate=1" in goal or "candidate: 1" in goal or "candidate 1" in goal
    assert goal == build_goal(
        target, "advanced", ledger=led, run_id="r1"
    ), "a legacy tier argument never changes the ledger context"
