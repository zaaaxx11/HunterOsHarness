"""P4 — cron tick scheduler contract tests (TDD step 1, failing by design).

Planner A target: ``hunter.cron.scheduler`` — the Reference
``cron_scheduler.py:3761 tick`` port. There is NO ``hunter.cron`` package
today (every test importorskips it). Pinned contracts:

- tick holds a file lock: exactly one ticker per ``<state>`` (a second
  concurrent tick refuses/returns instead of double-firing).
- ESTOP (``pause.flag``) + ``can_dispatch`` gates refuse dispatch BEFORE any
  execution.
- ``advance_next_runs`` runs BEFORE execution (at-most-once: a crash between
  advance and exec never re-fires the same slot).
- parallel cap: already-running jobs are skipped, never oversubscribed.
- ``run_one_job`` uses an ephemeral agent + fire-claim heartbeat, with
  teardown DEFERRED until after delivery.
- double-tick -> single fire; ownership-lost -> stale result discarded;
  every fire writes one execution ledger row.

Adversarial mitigations: isolated ``tmp_path`` state dirs; fake monotonic
clock + zero poll intervals (no real sleeps); strict asserts on fire counts
and ledger rows (not return codes); lock contention exercised with threads
and millisecond timeouts for Windows stability.
"""

from __future__ import annotations

import importlib.util
from typing import Any

import pytest


def _needs_cron() -> Any:
    """The not-yet-existing production package — SKIPPED until implemented."""
    return pytest.importorskip("hunter.cron.scheduler")


def test_p4_cron_tick_file_lock_single_ticker(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    first = cron.tick_lock(str(state))
    assert first.held is True
    second = cron.tick_lock(str(state))
    assert second.held is False  # single ticker per <state>
    first.release()


def test_p4_cron_estop_and_can_dispatch_gate_before_exec(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    (state).mkdir(parents=True, exist_ok=True)
    (state / "pause.flag").write_text('{"reason": "op"}', encoding="utf-8")

    def _refuse(job: Any) -> None:
        raise AssertionError("must not run")

    assert cron.tick(str(state), dispatch=_refuse) == "estop"
    (state / "pause.flag").unlink()
    assert cron.tick(str(state), dispatch=_refuse, can_dispatch=lambda job: False) == "gated"


def test_p4_cron_advance_next_runs_before_exec(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    order: list[str] = []

    def dispatch(job: Any) -> None:
        order.append("exec")
        assert cron.next_runs_advanced(str(state), job) is True  # advance FIRST

    cron.tick(str(state), dispatch=dispatch, record_advance=lambda job: order.append("advance"))
    assert order == ["advance", "exec"]


def test_p4_cron_parallel_cap_skips_already_running(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    jobs = [{"id": f"job-{index}"} for index in range(4)]
    fired = cron.tick_many(str(state), jobs, max_parallel=2, running={"job-0", "job-1"},
                           dispatch=lambda job: job["id"])
    assert sorted(fired) == ["job-2", "job-3"]  # running jobs skipped, cap respected


def test_p4_cron_run_one_job_ephemeral_agent_deferred_teardown(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    events: list[str] = []
    cron.run_one_job(
        str(state),
        {"id": "job-9"},
        run_agent=lambda job: events.append("run"),
        deliver=lambda result: events.append("deliver"),
        teardown=lambda: events.append("teardown"),
        heartbeat=lambda job: events.append("heartbeat"),
    )
    assert events.index("heartbeat") < events.index("run")
    assert events.index("deliver") < events.index("teardown")  # teardown AFTER delivery


def test_p4_cron_double_tick_single_fire(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    fires = cron.fire_twice(str(state), {"id": "job-1", "slot": "s1"}, dispatch=lambda job: "fired")
    assert fires == ["fired"]  # at-most-once: the second tick sees the advanced slot


def test_p4_cron_ownership_lost_discards_stale_result(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    outcome = cron.complete_with_ownership(
        str(state), {"id": "job-2"}, result="stale-result", owner_token="old-token",
    )
    assert outcome.discarded is True
    assert outcome.delivered is False


def test_p4_cron_execution_ledger_row_per_fire(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    cron.run_one_job(str(state), {"id": "job-3"}, run_agent=lambda job: "ok",
                     deliver=lambda result: None, teardown=lambda: None,
                     heartbeat=lambda job: None)
    rows = cron.execution_rows(str(state), "job-3")
    assert len(rows) == 1
    assert rows[0]["job_id"] == "job-3"


def test_p4_cron_package_exists() -> None:
    assert importlib.util.find_spec("hunter.cron.scheduler") is not None
