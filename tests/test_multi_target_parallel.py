"""Tests for the bounded parallel multi-target runner (gap-analysis point 7)."""

from __future__ import annotations

import threading
import time

import pytest

from hunter.workflow import multi_target as mt


class FakeScope:
    pass


class FakeRagLoop:
    """Records overlap so the test can prove real parallelism."""

    active = 0
    peak = 0
    seen: list[str] = []
    fail_targets: set[str] = set()
    _lock = threading.Lock()
    delay = 0.05

    def __init__(self, config) -> None:
        self.config = config

    def run(self) -> int:
        target = self.config.target
        with self._lock:
            type(self).active += 1
            type(self).peak = max(type(self).peak, type(self).active)
            type(self).seen.append(target)
        try:
            time.sleep(self.delay)
            if target in self.fail_targets:
                raise RuntimeError(f"boom {target}")
            return 0
        finally:
            with self._lock:
                type(self).active -= 1


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    FakeRagLoop.active = 0
    FakeRagLoop.peak = 0
    FakeRagLoop.seen = []
    FakeRagLoop.fail_targets = set()
    FakeRagLoop.delay = 0.05
    monkeypatch.setattr(mt, "RagLoop", FakeRagLoop)
    yield


def _specs(n: int) -> list[mt.TargetSpec]:
    return [mt.TargetSpec(f"t{i}", FakeScope()) for i in range(n)]


def _run(specs, **kwargs):
    return mt.run_targets(
        specs,
        state_dir=__import__("pathlib").Path("/tmp/hoh-mt-test"),
        engine="llm",
        time_budget_s=60.0,
        **kwargs,
    )


def test_parallel_runs_targets_concurrently():
    ok, failed, errors = _run(_specs(3), max_workers=3, parallel=True)
    assert (ok, failed, errors) == (3, 0, [])
    assert FakeRagLoop.peak > 1, "targets must actually overlap"
    assert set(FakeRagLoop.seen) == {"t0", "t1", "t2"}


def test_results_are_ordered_and_failures_contained():
    FakeRagLoop.fail_targets = {"t1"}
    ok, failed, errors = _run(_specs(3), parallel=True)
    assert (ok, failed) == (2, 1)
    assert len(errors) == 1 and "t1" in errors[0]


def test_sequential_mode_degrades_cleanly():
    ok, failed, _ = _run(_specs(3), parallel=False)
    assert (ok, failed) == (3, 0)
    assert FakeRagLoop.peak == 1, "sequential mode must never overlap"
    assert FakeRagLoop.seen == ["t0", "t1", "t2"]


def test_max_workers_caps_concurrency():
    ok, failed, _ = _run(_specs(6), max_workers=2, parallel=True)
    assert (ok, failed) == (6, 0)
    assert FakeRagLoop.peak <= 2


def test_empty_targets():
    assert _run([]) == (0, 0, [])
