"""R2-A liveness/drain — TDD RED (failing by design).

R2-A target: daemon exposes a scheduler-driven liveness probe; drain stops
new claims but lets in-flight complete; stop.file outranks drain/pause
(stop-file first); heartbeat reports drain/paused; drain leaves a
consumable restart marker / ledger row.

Prod targets (per-fn):
- test_r2a_liveness_probe_fresh_vs_stale -> hunter.daemon.liveness(state)
- test_r2a_liveness_drain_stops_claims_inflight_completes -> drain + hunt_worker
- test_r2a_liveness_stop_file_outranks_drain_pause -> stop precedence seam
- test_r2a_liveness_heartbeat_reports_drain_paused -> heartbeat drain/paused via scheduler
- test_r2a_liveness_drain_leaves_restart_marker -> drain_daemon restart.json / ledger row
- test_r2a_liveness_negative_stale_never_running -> stale heartbeat is NOT running

Adversarial: tmp_path isolation, monotonic fake (no sleep/network),
pid_alive/process_signature fakes, strict claim/drain asserts, negatives.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest


def _needs_daemon() -> Any:
    return pytest.importorskip("hunter.daemon")


def _fake_monotonic(monkeypatch: Any, start: float = 4000.0) -> dict[str, float]:
    clock = {"t": float(start)}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    return clock


def _write_pid(daemon: Any, state: Any, *, pid: int = 4242, sig: str = "sig-A") -> None:
    daemon.write_json_atomic(
        daemon.pid_path(state),
        {
            "pid": pid,
            "started_at": time.time() - 10.0,
            "proc_signature": sig,
            "harness_version": "0.6.0",
            "state_dir": str(state),
            "transports": [],
        },
    )


def _write_hb(daemon: Any, state: Any, *, pid: int = 4242, age: float = 0.0) -> None:
    daemon.write_json_atomic(
        daemon.heartbeat_path(state),
        {"pid": pid, "ts": time.time() - age, "queue_pending": 0, "active_task": None,
         "last_run_id": None},
    )


def test_r2a_liveness_probe_fresh_vs_stale(tmp_path: Any, monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "liveness"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: hunter.daemon.liveness probe missing; "
            "only daemon_running/daemon_status exist (no scheduler liveness)"
        )
    state = tmp_path / "state"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(daemon, state)
    _write_hb(daemon, state, age=4.0)
    assert daemon.liveness(str(state))["alive"] is True  # type: ignore[attr-defined]
    _write_hb(daemon, state, age=400.0)
    assert daemon.liveness(str(state))["alive"] is False  # type: ignore[attr-defined]


def test_r2a_liveness_drain_stops_claims_inflight_completes(tmp_path: Any, monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    import asyncio

    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "liveness"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: drain liveness unwired; "
            "hunt_worker drain path not scheduler-probed"
        )
    state = tmp_path / "state"
    task = {
        "task_id": "T-drain-1", "target": "http://127.0.0.1:9/",
        "scope": {"name": "loopback", "hosts": [], "allow_subdomains": False},
        "engine": "deterministic", "min_wall_seconds": 0.0,
        "max_wall_seconds": 60.0, "max_cost_usd": 1.0,
        "created_ts": time.time(), "claimed_by": None, "claimed_ts": None,
    }
    daemon.enqueue_task(state, task)

    def fake_run_hunt(target: Any, **kw: Any) -> Any:
        return SimpleNamespace(run_id="R-DRAIN", status="completed", findings=0, exit_code=0)

    monkeypatch.setattr(daemon, "run_hunt", fake_run_hunt)
    flag = daemon.stop_flag_path(state)
    hb: dict[str, Any] = {"pid": 1, "ts": time.time(), "queue_pending": 1}
    asyncio.run(daemon.hunt_worker(str(state), stop_path=flag, heartbeat=hb))
    assert len(list(daemon.queue_dir(state).glob("done-*.json"))) == 1
    # Now draining: new claims stop.
    daemon.drain_flag_path(state).parent.mkdir(parents=True, exist_ok=True)
    daemon.drain_flag_path(state).write_text("", encoding="utf-8")
    assert daemon._should_claim(state) is False


def test_r2a_liveness_stop_file_outranks_drain_pause(tmp_path: Any, monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "stop_precedence") and not hasattr(daemon, "should_kill_inflight"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: stop-file-first precedence seam missing; "
            "stop.flag must outrank drain.flag/pause.flag"
        )
    state = tmp_path / "state"
    (state / "daemon").mkdir(parents=True, exist_ok=True)
    (state / "daemon" / "drain.flag").write_text("", encoding="utf-8")
    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")
    (state / "daemon" / "stop.flag").write_text("", encoding="utf-8")
    assert daemon.stop_precedence(str(state)) == "stop"  # type: ignore[attr-defined]


def test_r2a_liveness_heartbeat_reports_drain_paused(tmp_path: Any, monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "liveness"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: scheduler heartbeat must report "
            "drain/paused; liveness seam missing"
        )
    state = tmp_path / "state"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(daemon, state)
    _write_hb(daemon, state)
    daemon.pause_flag_path(state).parent.mkdir(parents=True, exist_ok=True)
    daemon.pause_flag_path(state).write_text("", encoding="utf-8")
    probe = daemon.liveness(str(state))  # type: ignore[attr-defined]
    assert probe["paused"] is True


def test_r2a_liveness_drain_leaves_restart_marker(tmp_path: Any, monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    _fake_monotonic(monkeypatch)
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: False)
    state = tmp_path / "state"
    _write_pid(daemon, state, pid=9999)
    _write_hb(daemon, state, pid=9999)
    code = daemon.drain_daemon(state, timeout=0.1)
    assert code == 0
    # R2-A: a drained shutdown must leave a consumable restart marker or ledger row.
    marker = daemon.restart_marker_path(state)
    if not marker.is_file():
        pytest.fail(
            "EXPECTED-FAIL-R2A: drain_daemon left no restart.json; "
            "drain-first restart cannot suppress stale deliveries"
        )
    assert marker.is_file()


def test_r2a_liveness_negative_stale_never_running(tmp_path: Any, monkeypatch: Any) -> None:
    daemon = _needs_daemon()
    _fake_monotonic(monkeypatch)
    if not hasattr(daemon, "liveness"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: stale heartbeat must be NOT running via "
            "liveness probe (seam missing)"
        )
    state = tmp_path / "state"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(daemon, state)
    _write_hb(daemon, state, age=400.0)
    running, _reason = daemon.daemon_running(state)
    assert running is False
    assert daemon.liveness(str(state))["alive"] is False  # type: ignore[attr-defined]
