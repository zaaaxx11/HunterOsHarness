"""M8 F4 — unlimited = 0 semantics (loader + RunBudget regression pins).

The loader must accept ``0`` for every budget key (unlimited hunting credit)
and keep refusing negatives; the concrete RunBudget already treats
non-positive limits as "off" — these tests pin that so it can never regress.
"""

from __future__ import annotations

import pytest

from hunter.errors import HunterError
from hunter.llm.budget import RunBudget
from hunter.llm.config import load_config


def test_loader_accepts_zero_max_iterations(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("budget:\n  max_iterations: 0\n", encoding="utf-8")
    cfg = load_config(path, env={}, home=tmp_path)
    assert cfg.budget.max_iterations == 0


def test_zero_iterations_means_unlimited():
    budget = RunBudget(max_iterations=0)
    assert all(budget.consume_iteration() for _ in range(500))
    assert budget.exhausted() is None


def test_zero_cost_means_unlimited():
    budget = RunBudget(max_cost_usd=0.0)
    budget.add_cost(999.0)
    assert budget.exhausted() is None
    assert budget.cost_breakpoint() is None


def test_zero_wall_means_unlimited():
    budget = RunBudget(wall_seconds=0.0)
    budget.start()
    assert budget.exhausted() is None


def test_env_zero_iterations_accepted_and_negative_refused(tmp_path):
    cfg = load_config(env={"HUNTEROS_MAX_ITERATIONS": "0"}, home=tmp_path)
    assert cfg.budget.max_iterations == 0
    with pytest.raises(HunterError) as excinfo:
        load_config(env={"HUNTEROS_MAX_ITERATIONS": "-1"}, home=tmp_path)
    assert excinfo.value.layer == "config"
    assert "HUNTEROS_MAX_ITERATIONS" in excinfo.value.message
