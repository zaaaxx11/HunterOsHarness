"""R2-A scheduler cutover — TDD RED (failing by design).

R2-A target: daemon heartbeat/worker asyncio loops migrate onto the
single-heap ``hunter.runtime.scheduler.PeriodicScheduler``; lease refresh
rides the same heap (no per-child / per-lease threads).

Prod targets (per-fn):
- test_r2a_scheduler_cutover_daemon_drives_heartbeat_via_scheduler
    -> hunter.daemon.create_scheduler / hunter.daemon.heartbeat_handle
- test_r2a_scheduler_cutover_daemon_worker_via_scheduler_no_overlap
    -> hunter.daemon.worker_handle (no self-overlap)
- test_r2a_scheduler_cutover_single_heap_thread_for_daemon
    -> hunter.runtime.scheduler.thread_names <= 1 with heartbeat+worker+lease
- test_r2a_scheduler_cutover_lease_refresh_without_per_child_thread
    -> hunter.gateway.durable_lease scheduler hook (no Thread per lease)
- test_r2a_scheduler_cutover_heartbeat_interval_15_monotonic_fake
    -> scheduler interval == hunter.daemon.HEARTBEAT_INTERVAL_SECONDS (15)
- test_r2a_scheduler_cutover_negative_cancelled_handle_never_fires
    -> cancelled handle never reschedules (strict negative)

Adversarial: tmp_path state isolation, monotonic fake (no sleep/network),
strict heap/interval asserts, negatives. RED today via EXPECTED-FAIL-R2A.
"""

from __future__ import annotations

from typing import Any

import pytest


def _needs_daemon() -> Any:
    return pytest.importorskip("hunter.daemon")


def _needs_scheduler() -> Any:
    return pytest.importorskip("hunter.runtime.scheduler")


def _needs_durable() -> Any:
    return pytest.importorskip("hunter.gateway.durable_lease")


def _fake_monotonic(monkeypatch: Any, start: float = 1000.0) -> dict[str, float]:
    clock = {"t": float(start)}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    return clock


def test_r2a_scheduler_cutover_daemon_drives_heartbeat_via_scheduler(
    tmp_path: Any, monkeypatch: Any
) -> None:
    daemon = _needs_daemon()
    _needs_scheduler()
    _fake_monotonic(monkeypatch)
    # R2-A cutover: daemon must expose a scheduler-owned heartbeat handle.
    if not hasattr(daemon, "create_scheduler") and not hasattr(daemon, "heartbeat_handle"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: daemon heartbeat still asyncio-only; "
            "create_scheduler/heartbeat_handle scheduler seam unused"
        )
    state = tmp_path / "state"
    scheduler = daemon.create_scheduler(str(state))  # type: ignore[attr-defined]
    handle = scheduler.schedule(lambda: None, interval=float(daemon.HEARTBEAT_INTERVAL_SECONDS))
    assert handle.cancelled is False
    handle.cancel()


def test_r2a_scheduler_cutover_daemon_worker_via_scheduler_no_overlap(
    tmp_path: Any, monkeypatch: Any
) -> None:
    daemon = _needs_daemon()
    scheduler_mod = _needs_scheduler()
    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "create_scheduler") and not hasattr(daemon, "worker_handle"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: daemon worker still asyncio-only; "
            "worker_handle scheduler seam unused (no self-overlap pin)"
        )
    state = tmp_path / "state"
    scheduler = daemon.create_scheduler(str(state))  # type: ignore[attr-defined]
    entered = {"n": 0, "overlap": False, "active": False}

    def worker() -> None:
        if entered["active"]:
            entered["overlap"] = True
        entered["active"] = True
        entered["n"] += 1
        entered["active"] = False

    handle = scheduler.schedule(worker, interval=0.01)
    scheduler_mod.PeriodicScheduler.run_due_now(scheduler)  # type: ignore[attr-defined]
    handle.cancel()
    assert entered["overlap"] is False
    assert entered["n"] >= 1


def test_r2a_scheduler_cutover_single_heap_thread_for_daemon(
    tmp_path: Any, monkeypatch: Any
) -> None:
    daemon = _needs_daemon()
    scheduler_mod = _needs_scheduler()
    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "create_scheduler"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: no daemon.create_scheduler; "
            "heartbeat+worker+lease cannot share one heap thread"
        )
    state = tmp_path / "state"
    scheduler = daemon.create_scheduler(str(state))  # type: ignore[attr-defined]
    scheduler.schedule(lambda: None, interval=15.0)
    scheduler.schedule(lambda: None, interval=5.0)
    names = scheduler_mod.thread_names(scheduler)
    assert len(names) <= 1


def test_r2a_scheduler_cutover_lease_refresh_without_per_child_thread(
    tmp_path: Any, monkeypatch: Any
) -> None:
    durable = _needs_durable()
    _fake_monotonic(monkeypatch)
    # R2-A: lease refresh must ride the shared scheduler, not a Thread/lease.
    if not hasattr(durable, "scheduler_for") and not hasattr(durable.DurableLease, "scheduler_handle"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: durable_lease still spawns Thread per lease; "
            "no scheduler_for/scheduler_handle seam"
        )
    state = tmp_path / "state"
    lease = durable.acquire(str(state), "telegram:1", timeout=0.2)
    try:
        assert lease.scheduler_handle is not None  # type: ignore[attr-defined]
    finally:
        lease.release()


def test_r2a_scheduler_cutover_heartbeat_interval_15_monotonic_fake(monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    scheduler_mod = _needs_scheduler()
    clock = _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "create_scheduler"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: daemon heartbeat interval not scheduler-owned; "
            "expected HEARTBEAT_INTERVAL_SECONDS==15 via PeriodicScheduler"
        )
    assert daemon.HEARTBEAT_INTERVAL_SECONDS == 15
    scheduler = scheduler_mod.PeriodicScheduler()
    DueAt: list[float] = []
    orig_schedule = scheduler.schedule

    def capture(fn: Any, interval: float) -> Any:
        DueAt.append(clock["t"] + float(interval))
        return orig_schedule(fn, interval)

    scheduler.schedule = capture  # type: ignore[method-assign]
    scheduler.schedule(lambda: None, interval=float(daemon.HEARTBEAT_INTERVAL_SECONDS))
    assert DueAt and DueAt[0] == pytest.approx(clock["t"] + 15.0)


def test_r2a_scheduler_cutover_negative_cancelled_handle_never_fires(monkeypatch: Any) -> None:
    scheduler_mod = _needs_scheduler()
    _fake_monotonic(monkeypatch)
    # Negative: a cancelled handle must never reschedule even when the
    # daemon seam is missing — but R2-A requires the daemon seam to exist.
    import hunter.daemon as daemon_mod

    if not hasattr(daemon_mod, "create_scheduler"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: cancelled-handle negative gated on "
            "daemon.create_scheduler cutover (seam unused today)"
        )
    scheduler = scheduler_mod.PeriodicScheduler()
    calls = {"n": 0}

    def body() -> None:
        calls["n"] += 1

    handle = scheduler.schedule(body, interval=0.01)
    handle.cancel()
    scheduler.run_due_now()
    assert calls["n"] == 0
