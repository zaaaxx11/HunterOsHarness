"""M8 F2 — ``hunter.daemon`` 24/7 state machine (test-first).

Every test fakes the process layer (``pid_alive`` / ``process_signature`` /
``subprocess.Popen`` monkeypatched) so nothing real is ever spawned or killed.
Pins the state layout under ``<state>/daemon/``, the pid/heartbeat schemas,
double-start refusal, staleness, PID-reuse guarding, atomic queue claims,
detached-spawn flags, and the stop-file -> RunBudget contract.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from hunter import daemon
from hunter.llm.budget import RunBudget

PID_TEMPLATE: dict[str, Any] = {
    "pid": 0,
    "started_at": 1760000000.0,
    "proc_signature": "sig-A",
    "harness_version": "0.5.0",
    "state_dir": "",
    "transports": ["telegram"],
}
HEARTBEAT_TEMPLATE: dict[str, Any] = {
    "pid": 0,
    "ts": 0.0,
    "queue_pending": 0,
    "active_task": None,
    "last_run_id": None,
}
TASK_TEMPLATE: dict[str, Any] = {
    "task_id": "T-1760000000-ab12cd",
    "target": "http://127.0.0.1:9/",
    "scope": {"name": "loopback", "hosts": [], "allow_subdomains": False},
    "engine": "deterministic",
    "min_wall_seconds": 0.0,
    "max_wall_seconds": 60.0,
    "max_cost_usd": 1.0,
    "created_ts": 0.0,
    "claimed_by": None,
    "claimed_ts": None,
}


def _write_pid(state, *, pid: int, signature: str = "sig-A", **extra: Any) -> None:
    daemon.write_json_atomic(
        daemon.pid_path(state),
        {
            **PID_TEMPLATE,
            "pid": pid,
            "proc_signature": signature,
            "state_dir": str(state),
            **extra,
        },
    )


def _write_heartbeat(state, *, pid: int, age_seconds: float = 0.0, **extra: Any) -> None:
    daemon.write_json_atomic(
        daemon.heartbeat_path(state),
        {**HEARTBEAT_TEMPLATE, "pid": pid, "ts": time.time() - age_seconds, **extra},
    )


def _fake_spawn(state, spawned: list[list[str]]):
    """A spawn_detached seam that self-registers like the real child: pid.json
    plus a fresh PID-matched heartbeat (the parent now validates both)."""

    def spawn(args: list[str], *, log_path, env=None) -> int:
        spawned.append(list(args))
        _write_pid(state, pid=4321, signature="sig-child")
        _write_heartbeat(state, pid=4321)
        return 4321

    return spawn


# -- state layout + schemas ---------------------------------------------------------


def test_daemon_state_layout_and_pid_file_schema(tmp_path):
    state = tmp_path / "state"
    assert daemon.daemon_dir(state) == state / "daemon"
    assert daemon.pid_path(state) == state / "daemon" / "pid.json"
    assert daemon.heartbeat_path(state) == state / "daemon" / "heartbeat.json"
    assert daemon.queue_dir(state) == state / "daemon" / "queue"
    assert daemon.stop_flag_path(state) == state / "daemon" / "stop.flag"
    assert daemon.log_path(state) == state / "daemon" / "daemon.log"
    assert daemon.read_pid(state) is None  # nothing written yet
    pid = {**PID_TEMPLATE, "pid": 4242, "state_dir": str(state)}
    daemon.write_json_atomic(daemon.pid_path(state), pid)
    assert daemon.read_pid(state) == pid
    assert daemon.DAEMON_STALE_SECONDS == 90
    assert daemon.HEARTBEAT_INTERVAL_SECONDS == 15


def test_double_start_refused_on_live_pid(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(state, pid=4242)
    _write_heartbeat(state, pid=4242)
    spawned: list[list[str]] = []
    monkeypatch.setattr(daemon, "spawn_detached", _fake_spawn(state, spawned))
    code = daemon.start_daemon(
        state,
        target="http://127.0.0.1:9/",
        scope={"name": "loopback", "hosts": []},
        engine="deterministic",
        min_wall_seconds=0.0,
        max_wall_seconds=60.0,
        max_cost_usd=1.0,
    )
    assert code == 3  # refused (already running, no --force)
    assert spawned == []
    assert list(daemon.queue_dir(state).glob("task-*.json")) == []


def test_stale_or_dead_pid_allows_start(tmp_path, monkeypatch):
    # a dead pid never blocks a start
    state = tmp_path / "state"
    # The pre-existing daemon is dead; only the spawned child (4321) is live
    # and carries a verifiable identity under the validated-start contract.
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: pid == 4321)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-child" if pid == 4321 else None)
    spawned: list[list[str]] = []
    monkeypatch.setattr(daemon, "spawn_detached", _fake_spawn(state, spawned))
    code = daemon.start_daemon(
        state,
        target="http://127.0.0.1:9/",
        scope={"name": "loopback", "hosts": []},
        engine="deterministic",
        min_wall_seconds=0.0,
        max_wall_seconds=60.0,
        max_cost_usd=1.0,
    )
    assert code == 0
    assert len(spawned) == 1
    assert len(list(daemon.queue_dir(state).glob("task-*.json"))) == 1

    # a live pid with a stale heartbeat (>90s) also allows a start
    state2 = tmp_path / "state2"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(
        daemon, "process_signature", lambda pid: "sig-A" if pid == 5150 else "sig-child"
    )
    _write_pid(state2, pid=5150)
    _write_heartbeat(state2, pid=5150, age_seconds=400.0)
    spawned2: list[list[str]] = []
    monkeypatch.setattr(daemon, "spawn_detached", _fake_spawn(state2, spawned2))
    code2 = daemon.start_daemon(
        state2,
        target="http://127.0.0.1:9/",
        scope={"name": "loopback", "hosts": []},
        engine="deterministic",
        min_wall_seconds=0.0,
        max_wall_seconds=60.0,
        max_cost_usd=1.0,
    )
    assert code2 == 0
    assert len(spawned2) == 1


def test_stop_flag_cooperative_stop_and_force_kill(tmp_path, monkeypatch):
    # cooperative: the daemon observes stop.flag and exits cleanly
    state = tmp_path / "state"
    alive = {"value": True}
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: alive["value"])
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(state, pid=6001)
    _write_heartbeat(state, pid=6001)

    def watcher() -> None:
        deadline = time.time() + 5
        while time.time() < deadline:
            if daemon.stop_flag_path(state).is_file():
                alive["value"] = False  # the fake loop honored the flag
                daemon.pid_path(state).unlink(missing_ok=True)
                return
            time.sleep(0.02)

    thread = threading.Thread(target=watcher, daemon=True)
    thread.start()
    assert daemon.stop_daemon(state, timeout=5.0) == 0
    thread.join(timeout=2)
    assert not daemon.stop_flag_path(state).exists()  # flag removed on clean stop
    assert not daemon.pid_path(state).exists()

    # a hung daemon WITHOUT --force is reported, not killed
    state2 = tmp_path / "state2"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    _write_pid(state2, pid=6002)
    _write_heartbeat(state2, pid=6002)
    hung_code = daemon.stop_daemon(state2, timeout=0.2)
    assert hung_code != 0
    assert daemon.pid_path(state2).is_file()  # nothing was killed or cleaned

    # WITH --force the kill path is taken and completes without hanging
    force_code = daemon.stop_daemon(state2, timeout=0.2, force=True)
    assert isinstance(force_code, int)
    assert not daemon.stop_flag_path(state2).exists()

    # stopping something that is not running reports "not running"
    state3 = tmp_path / "state3"
    assert daemon.stop_daemon(state3, timeout=0.1) == 1


def test_status_reports_running_stopped_stale(tmp_path, monkeypatch):
    state = tmp_path / "state"
    status = daemon.daemon_status(state)
    assert status["running"] is False
    assert status["pid"] is None
    assert status["queue_pending"] == 0 and status["queue_claimed"] == 0
    assert status["transports"] == []
    assert status["last_run"] is None
    assert status["stale"] is False

    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(
        state,
        pid=7001,
        started_at=time.time() - 3600.0,
        transports=["telegram", "discord"],
    )
    _write_heartbeat(state, pid=7001, age_seconds=4.0, queue_pending=0)
    daemon.queue_dir(state).mkdir(parents=True)
    (daemon.queue_dir(state) / "task-1-abcdef.json").write_text(
        json.dumps(TASK_TEMPLATE), encoding="utf-8"
    )
    status = daemon.daemon_status(state)
    assert status["running"] is True and status["pid"] == 7001
    assert status["stale"] is False
    assert status["uptime_seconds"] == pytest.approx(3600.0, abs=5.0)
    assert status["heartbeat_age_seconds"] == pytest.approx(4.0, abs=5.0)
    assert status["queue_pending"] == 1 and status["queue_claimed"] == 0
    assert status["transports"] == ["telegram", "discord"]

    _write_heartbeat(state, pid=7001, age_seconds=400.0)
    status = daemon.daemon_status(state)
    assert status["stale"] is True
    assert status["running"] is False  # a stale heartbeat is NOT a running daemon


def test_heartbeat_staleness_threshold():
    now = 1_000_000.0
    assert daemon.is_stale({"pid": 1, "ts": now - 89.0}, now=now, threshold=90.0) is False
    assert daemon.is_stale({"pid": 1, "ts": now - 91.0}, now=now, threshold=90.0) is True
    assert daemon.is_stale({"pid": 1, "ts": now - 90.0}, now=now, threshold=90.0) is True
    assert daemon.is_stale(None, now=now) is True  # no heartbeat at all = stale


def test_heartbeat_staleness_governs_daemon_running(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-A")
    _write_pid(state, pid=7100)
    _write_heartbeat(state, pid=7100, age_seconds=89.0)
    running, _reason = daemon.daemon_running(state)
    assert running is True
    _write_heartbeat(state, pid=7100, age_seconds=91.0)
    running, reason = daemon.daemon_running(state)
    assert running is False and reason


def test_pid_reuse_guard_via_process_signature(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    _write_pid(state, pid=8001, signature="sig-old")
    _write_heartbeat(state, pid=8001)
    # the OS reused the pid: the live process has a DIFFERENT creation signature
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-new-owner")
    running, reason = daemon.daemon_running(state)
    assert running is False and reason
    # matching signature -> alive
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "sig-old")
    running, _reason = daemon.daemon_running(state)
    assert running is True


def test_queue_task_claim_atomic_single_winner(tmp_path):
    state = tmp_path / "state"
    task = {**TASK_TEMPLATE, "created_ts": time.time()}
    path = daemon.enqueue_task(state, task)
    assert path.is_file()
    assert path.parent == daemon.queue_dir(state)
    results: list[dict[str, Any] | None] = []
    errors: list[BaseException] = []

    def claim() -> None:
        try:
            results.append(daemon.claim_task(state))
        except BaseException as exc:  # noqa: BLE001 — recorded, not swallowed
            errors.append(exc)

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    winners = [result for result in results if result is not None]
    assert len(winners) == 1  # the atomic rename has exactly one winner
    assert winners[0]["task_id"] == task["task_id"]
    claimed = list(daemon.queue_dir(state).glob("claimed-*.json"))
    assert len(claimed) == 1
    assert list(daemon.queue_dir(state).glob("task-*.json")) == []
    assert daemon.claim_task(state) is None  # empty queue


def test_detached_spawn_flags_per_platform(monkeypatch, tmp_path):
    import subprocess as subprocess_module

    recorded: list[tuple[list[str], dict[str, Any]]] = []

    class FakePopen:
        def __init__(self, args: list[str], **kwargs: Any) -> None:
            recorded.append((list(args), dict(kwargs)))
            self.pid = 4321

        def poll(self) -> int | None:
            return None

    monkeypatch.setattr(subprocess_module, "Popen", FakePopen)
    log = tmp_path / "daemon.log"
    pid = daemon.spawn_detached(["hunter-daemon", "--poll", "5"], log_path=log)
    assert pid == 4321
    args, kwargs = recorded[0]
    assert args == ["hunter-daemon", "--poll", "5"]
    assert kwargs.get("close_fds") is True
    assert kwargs.get("stdin") == subprocess_module.DEVNULL
    assert kwargs.get("stdout") is not None and kwargs.get("stderr") is not None
    if sys.platform == "win32":
        assert kwargs.get("creationflags", 0) != 0  # DETACHED | NEW_GROUP | NO_WINDOW
        assert "start_new_session" not in kwargs
    else:
        assert kwargs.get("start_new_session") is True
        assert "creationflags" not in kwargs


def test_stop_file_stops_in_flight_hunt_budget(tmp_path, monkeypatch):
    flag = daemon.stop_flag_path(tmp_path / "state")
    flag.parent.mkdir(parents=True, exist_ok=True)
    budget = RunBudget(stop_file=str(flag), max_cost_usd=5.0, max_iterations=100)
    assert budget.exhausted() is None
    flag.write_text("", encoding="utf-8")  # the user-issued kill
    reason = budget.exhausted()
    assert reason is not None and "stop file" in reason  # outranks cost/iterations

    # the worker passes the flag path through the run_hunt(budget=...) seam
    state = tmp_path / "state"
    task = {**TASK_TEMPLATE, "created_ts": time.time()}
    daemon.enqueue_task(state, task)
    captured: dict[str, Any] = {}

    def fake_run_hunt(target, *, scope=None, engine_name="", state_dir=None, budget=None, **_kw):
        captured["target"] = target
        captured["engine_name"] = engine_name
        captured["state_dir"] = state_dir
        captured["budget"] = budget
        return SimpleNamespace(run_id="R-STOPFILE", status="completed", findings=0, exit_code=0)

    monkeypatch.setattr(daemon, "run_hunt", fake_run_hunt)
    asyncio.run(
        daemon.hunt_worker(
            str(state),
            stop_path=flag,
            heartbeat={**HEARTBEAT_TEMPLATE, "pid": 1, "ts": time.time(), "queue_pending": 1},
        )
    )
    assert captured["target"] == task["target"]
    assert captured["engine_name"] == task["engine"]
    budget_used = captured["budget"]
    assert budget_used.stop_file == str(flag)
    assert budget_used.max_cost_usd == pytest.approx(task["max_cost_usd"])
    assert budget_used.min_wall_seconds == pytest.approx(task["min_wall_seconds"])
    assert budget_used.wall_seconds == pytest.approx(task["max_wall_seconds"])
    done = list(daemon.queue_dir(state).glob("done-*.json"))
    assert len(done) == 1
