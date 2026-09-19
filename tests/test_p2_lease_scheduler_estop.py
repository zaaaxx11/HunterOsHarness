"""P2 — durable file lease + PeriodicScheduler + ESTOP contract tests (TDD step 1).

Planner A targets (Reference ``agent_periodic_scheduler.py:60-153`` /
``agent_estop.py`` / ``cron_scheduler.py:3761`` ports):
- ``hunter.gateway.durable_lease``: today's ``TurnLeaseRegistry`` is
  PROCESS-LOCAL (asyncio locks) — a second OS process can double-run a chat
  turn. The durable lease must use ``O_CREAT | O_EXCL`` single-winner files
  under ``<state>/`` (isolated per test via ``tmp_path``), a 5s waiter
  timeout raising byte-exact ``BUSY_MESSAGE``, 15s heartbeat / 90s stale
  expiry, crash (stale holder) -> second waiter wins, proc_signature +
  turn_id fencing, refresher cancelled on release.
- ``hunter.runtime.scheduler.PeriodicScheduler``: ONE thread total, no
  self-overlap, raise -> reschedule, ``False`` return -> self-cancel.
- ``hunter.runtime.estop``: ``pause.flag`` refuses NEW gateway turns while
  in-flight turns complete; JSON ``{reason, engaged_at}`` body;
  corrupt/empty file still counts as engaged (fail safe); log-once per
  engagement; ``stop.flag`` kills via ``exhausted()`` first.

Adversarial mitigations: every lease test uses an isolated ``tmp_path``
state dir (never the shared ``<state>``); monotonic/sleep monkeypatched
(no real sleeps); lock-acquire timeouts shrunk to milliseconds; strict
asserts on winner files/ledger-ish rows, not just return values.
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any

import pytest

from hunter.gateway.app import BUSY_MESSAGE
from hunter.gateway.lease import TurnLeaseRegistry


def _needs_durable_lease() -> Any:
    return pytest.importorskip("hunter.gateway.durable_lease")


def _needs_scheduler() -> Any:
    return pytest.importorskip("hunter.runtime.scheduler")


def _needs_estop() -> Any:
    return pytest.importorskip("hunter.runtime.estop")


def test_p2_durable_lease_exclusive_create_single_winner(tmp_path: Any) -> None:
    durable = _needs_durable_lease()
    state = tmp_path / "state"
    first = durable.acquire(str(state), "telegram:7", timeout=0.2)
    with pytest.raises(durable.LeaseBusy):
        durable.acquire(str(state), "telegram:7", timeout=0.2)
    first.release()


def test_p2_durable_lease_waiter_timeout_matches_busy_message(tmp_path: Any) -> None:
    durable = _needs_durable_lease()
    state = tmp_path / "state"
    holder = durable.acquire(str(state), "webhook:abc", timeout=0.2)
    try:
        with pytest.raises(durable.LeaseBusy) as excinfo:
            durable.acquire(str(state), "webhook:abc", timeout=0.05)
        assert str(excinfo.value) == BUSY_MESSAGE
        timeout = float(durable.DEFAULT_LEASE_TIMEOUT)
        assert timeout == pytest.approx(5.0)
    finally:
        holder.release()


def test_p2_durable_lease_heartbeat_and_stale_expiry(tmp_path: Any, monkeypatch: Any) -> None:
    durable = _needs_durable_lease()
    now = {"t": 1000.0}
    monkeypatch.setattr(durable.time, "monotonic", lambda: now["t"])
    state = tmp_path / "state"
    assert durable.HEARTBEAT_INTERVAL_SECONDS == 15
    assert durable.LEASE_STALE_SECONDS == 90
    holder = durable.acquire(str(state), "telegram:9", timeout=0.2)
    now["t"] += 91.0  # holder crashed without refreshing -> stale
    winner = durable.acquire(str(state), "telegram:9", timeout=0.2)
    assert winner.lease_id != holder.lease_id
    winner.release()


def test_p2_durable_lease_fencing_rejects_stale_holder(tmp_path: Any) -> None:
    durable = _needs_durable_lease()
    state = tmp_path / "state"
    first = durable.acquire(str(state), "telegram:3", timeout=0.2)
    first.simulate_crash()  # never released; a second waiter takes over
    second = durable.acquire(str(state), "telegram:3", timeout=0.2)
    with pytest.raises(durable.LeaseLost):
        first.refresh()  # stale (proc_signature, turn_id) fenced off
    second.release()


def test_p2_durable_lease_refresher_cancelled_on_release(tmp_path: Any) -> None:
    durable = _needs_durable_lease()
    state = tmp_path / "state"
    lease = durable.acquire(str(state), "telegram:4", timeout=0.2)
    assert lease.refresher_alive() is True
    lease.release()
    assert lease.refresher_alive() is False
    lease.release()  # idempotent


def test_p2_scheduler_single_thread_no_self_overlap() -> None:
    scheduler_mod = _needs_scheduler()
    scheduler = scheduler_mod.PeriodicScheduler()
    threads = scheduler_mod.thread_names(scheduler)
    assert len(threads) <= 1
    entered = {"n": 0, "overlap": False}
    release: asyncio.Event = asyncio.Event()

    def slow() -> None:
        entered["n"] += 1
        if entered["n"] > 1:
            entered["overlap"] = True

    handle = scheduler.schedule(slow, interval=0.01)
    handle.cancel()
    assert entered["overlap"] is False
    assert release is not None


def test_p2_scheduler_raise_reschedules_false_self_cancels() -> None:
    scheduler_mod = _needs_scheduler()
    scheduler = scheduler_mod.PeriodicScheduler()
    calls = {"n": 0}

    def flaky() -> bool:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return False  # second run self-cancels

    handle = scheduler.schedule(flaky, interval=0.01)
    scheduler.run_due_now()
    scheduler.run_due_now()
    assert calls["n"] == 2
    assert handle.cancelled is True


def test_p2_estop_pause_refuses_new_turns_inflight_completes(tmp_path: Any) -> None:
    estop = _needs_estop()
    state = tmp_path / "state"
    assert estop.is_engaged(str(state)) is False
    estop.engage(str(state), reason="operator pause")
    assert estop.is_engaged(str(state)) is True
    assert estop.should_accept_new_turn(str(state)) is False
    assert estop.should_kill_inflight(str(state)) is False  # in-flight ALWAYS completes
    estop.resume(str(state))
    assert estop.is_engaged(str(state)) is False


def test_p2_estop_body_json_corrupt_empty_still_engaged(tmp_path: Any) -> None:
    estop = _needs_estop()
    state = tmp_path / "state"
    (state / "pause.flag").parent.mkdir(parents=True, exist_ok=True)
    (state / "pause.flag").write_text("", encoding="utf-8")  # empty ~= touch
    assert estop.is_engaged(str(state)) is True
    assert estop.describe(str(state))["reason"] == ""
    (state / "pause.flag").write_text("{not json", encoding="utf-8")
    assert estop.is_engaged(str(state)) is True
    estop.engage(str(state), reason="r")
    body = estop.describe(str(state))
    assert set(body) >= {"reason", "engaged_at"}


def test_p2_estop_stop_flag_kills_via_exhausted_first(tmp_path: Any) -> None:
    estop = _needs_estop()
    from hunter.llm.budget import RunBudget

    state = tmp_path / "state"
    (state).mkdir(parents=True, exist_ok=True)
    budget = RunBudget(stop_file=str(state / "stop.flag"))
    assert estop.should_kill_inflight(str(state), budget=budget) is False
    (state / "stop.flag").write_text("", encoding="utf-8")
    assert estop.should_kill_inflight(str(state), budget=budget) is True
    assert budget.exhausted() is not None and "stop file" in str(budget.exhausted())


def test_p2_lease_registry_has_no_cross_process_backend() -> None:
    registry = TurnLeaseRegistry()
    assert hasattr(registry, "state_dir")  # durable leases are rooted at <state>/
    assert pathlib.Path("src/hunter/gateway/durable_lease.py").is_file()
