"""M9-B persistent engine and chat queue grammar tests.

All process and queue boundaries are patched. These tests never start a child,
open a network socket, or run a real hunt; they pin the target-free engine,
atomic multi-target queue contract, and legacy chat fallback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hunter.chat.commands import CommandContext, safe_execute
from hunter.chat.sessions import ChatStore
from hunter.llm.config import default_config

LOCAL_A = "http://127.0.0.1:8941/"
LOCAL_B = "http://localhost:9000/"


def _patch_daemon(monkeypatch, name: str, fn) -> None:
    import hunter.daemon as daemon

    monkeypatch.setattr(daemon, name, fn, raising=False)
    import hunter.chat.commands as commands

    monkeypatch.setattr(commands, name, fn, raising=False)


def _ctx(store: ChatStore, tmp_path: Path, args: str) -> CommandContext:
    return CommandContext(
        store=store,
        config=default_config(),
        args=args,
        options={"state_dir": str(tmp_path), "session_id": "S-M9"},
    )


def _validating_spawn(monkeypatch, state: Path) -> list[Any]:
    """A spawn_detached seam that self-registers like the real child.

    ``start_daemon`` no longer treats a bare ``pid.json`` as success: it waits
    for a daemon that passes the identity + PID-matched non-stale heartbeat
    validation. This seam writes that registration (pid 4321, signature
    ``sig-child``, fresh heartbeat) and makes ``pid_alive``/``process_signature``
    agree, so the validated-start contract is exercised rather than bypassed.
    """
    import hunter.daemon as daemon

    spawned: list[Any] = []

    def spawn(args, *, log_path, env=None):
        spawned.append((args, log_path, env))
        daemon.write_json_atomic(
            daemon.pid_path(state),
            {
                "pid": 4321,
                "proc_signature": "sig-child",
                "state_dir": str(state),
                "started_at": 0,
            },
        )
        daemon.write_json_atomic(
            daemon.heartbeat_path(state),
            {"pid": 4321, "proc_signature": "sig-child", "ts": 9_999_999_999},
        )
        return 4321

    monkeypatch.setattr(daemon, "spawn_detached", spawn)
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: pid == 4321)
    monkeypatch.setattr(
        daemon, "process_signature", lambda pid: "sig-child" if pid == 4321 else None
    )
    return spawned


def _queue_tasks(state: Path) -> list[dict[str, Any]]:
    queue = state / "daemon" / "queue"
    return [json.loads(path.read_text(encoding="utf-8")) for path in queue.glob("task-*.json")]


def test_target_free_daemon_boot_writes_no_task(tmp_path, monkeypatch):
    from hunter.daemon import start_daemon

    spawned = _validating_spawn(monkeypatch, tmp_path)
    code = start_daemon(
        tmp_path,
        target=None,
        scope=None,
        engine="deterministic",
        min_wall_seconds=0.0,
        max_wall_seconds=0.0,
        max_cost_usd=0.0,
    )

    assert code == 0
    assert len(spawned) == 1
    assert not (tmp_path / "daemon" / "queue").exists() or list(
        (tmp_path / "daemon" / "queue").glob("task-*.json")
    ) == []


def test_optional_target_enqueue_persists_task_fields(tmp_path, monkeypatch):
    from hunter.daemon import start_daemon

    _validating_spawn(monkeypatch, tmp_path)
    code = start_daemon(
        tmp_path,
        target=LOCAL_A,
        scope={"name": "localhost-only", "hosts": []},
        engine="deterministic",
        min_wall_seconds=15.0,
        max_wall_seconds=90.0,
        max_cost_usd=0.0,
    )

    assert code == 0
    tasks = _queue_tasks(tmp_path)
    assert len(tasks) == 1
    assert tasks[0]["target"] == LOCAL_A
    assert tasks[0]["max_wall_seconds"] == pytest.approx(90.0)
    assert tasks[0]["min_wall_seconds"] == pytest.approx(15.0)
    assert tasks[0]["max_cost_usd"] == 0.0


def test_daemon_status_stays_running_after_empty_queue(tmp_path, monkeypatch):
    from hunter import daemon

    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    monkeypatch.setattr(daemon, "process_signature", lambda pid: "m9")
    daemon.write_json_atomic(
        daemon.pid_path(tmp_path), {"pid": 42, "proc_signature": "m9", "started_at": 0}
    )
    daemon.write_json_atomic(
        daemon.heartbeat_path(tmp_path), {"pid": 42, "proc_signature": "m9", "ts": 9_999_999_999}
    )
    status = daemon.daemon_status(tmp_path)

    assert status["running"] is True
    assert status["queue_pending"] == 0
    assert status["queue_claimed"] == 0


def test_hunt_parser_requires_target_and_time_for_new_grammar(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    try:
        missing_target = safe_execute("hunt", _ctx(store, tmp_path, "--time 90s"))
        missing_time = safe_execute("hunt", _ctx(store, tmp_path, f"{LOCAL_A} --budget 1"))
    finally:
        store.close()

    assert missing_target.data.get("hunt", {}).get("action") in {None, "usage", "invalid"}
    assert missing_time.data.get("hunt", {}).get("action") in {None, "usage", "invalid"}
    assert "usage" in missing_target.text.lower() or "target" in missing_target.text.lower()


def test_hunt_queue_multiple_targets_when_engine_running(tmp_path, monkeypatch):
    store = ChatStore(tmp_path / "chat.db")
    captured: list[dict[str, Any]] = []

    def enqueue_hunts(state_dir, tasks):
        captured.extend(dict(task) for task in tasks)
        return len(tasks)

    _patch_daemon(monkeypatch, "daemon_running", lambda state: (True, "running"))
    monkeypatch.setattr("hunter.chat.commands.daemon_running", lambda state: (True, "running"), raising=False)
    monkeypatch.setattr("hunter.chat.commands.enqueue_hunts", enqueue_hunts, raising=False)
    try:
        reply = safe_execute(
            "hunt", _ctx(store, tmp_path, f"{LOCAL_A} --time 90s {LOCAL_B} --budget 0")
        )
    finally:
        store.close()

    assert len(captured) == 2
    assert [task["target"] for task in captured] == [LOCAL_A, LOCAL_B]
    assert all(task["max_wall_seconds"] == pytest.approx(90.0) for task in captured)
    assert all(task["max_cost_usd"] == 0.0 for task in captured)
    assert reply.text == "queued 2 hunt(s) — time 2m budget $0.00 — `hunt status` to watch"
    assert reply.data["hunt"] == {
        "action": "queued",
        "count": 2,
        "time_seconds": 90.0,
        "budget_usd": 0.0,
        "targets": [LOCAL_A, LOCAL_B],
    }


def test_hunt_queue_reply_uses_exact_time_budget_watch_text(tmp_path, monkeypatch):
    store = ChatStore(tmp_path / "chat.db")
    monkeypatch.setattr("hunter.chat.commands.daemon_running", lambda state: (True, "running"), raising=False)
    monkeypatch.setattr("hunter.chat.commands.enqueue_hunts", lambda state, tasks: len(tasks), raising=False)
    try:
        reply = safe_execute("hunt", _ctx(store, tmp_path, f"{LOCAL_A} --time 60s --budget 12.5"))
    finally:
        store.close()

    assert reply.text == "queued 1 hunt(s) — time 1m budget $12.50 — `hunt status` to watch"


def test_hunt_budget_zero_is_unlimited_and_formats_as_zero(tmp_path, monkeypatch):
    store = ChatStore(tmp_path / "chat.db")
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr("hunter.chat.commands.daemon_running", lambda state: (True, "running"), raising=False)
    monkeypatch.setattr(
        "hunter.chat.commands.enqueue_hunts",
        lambda state, tasks: captured.extend(tasks) or len(tasks),
        raising=False,
    )
    try:
        reply = safe_execute("hunt", _ctx(store, tmp_path, f"{LOCAL_A} --time 1m --budget 0"))
    finally:
        store.close()

    assert captured[0]["max_cost_usd"] == 0.0
    assert reply.text.endswith("budget $0.00 — `hunt status` to watch")
    assert reply.data["hunt"]["budget_usd"] == 0.0


def test_hunt_queue_when_engine_off_is_exact_and_has_no_side_effects(tmp_path, monkeypatch):
    store = ChatStore(tmp_path / "chat.db")
    starts: list[Any] = []
    queues: list[Any] = []
    monkeypatch.setattr(
        "hunter.chat.commands.daemon_running", lambda state: (False, "not running"), raising=False
    )
    monkeypatch.setattr(
        "hunter.chat.commands.start_daemon", lambda *a, **k: starts.append((a, k)), raising=False
    )
    monkeypatch.setattr(
        "hunter.chat.commands.enqueue_hunts", lambda *a, **k: queues.append((a, k)), raising=False
    )
    try:
        reply = safe_execute("hunt", _ctx(store, tmp_path, f"{LOCAL_A} --time 90s"))
    finally:
        store.close()

    assert reply.text == "engine is off — run `hunt start` to boot the 24/7 engine"
    assert reply.data == {"hunt": {"action": "engine_off"}}
    assert starts == [] and queues == []
    assert _queue_tasks(tmp_path) == []


def test_hunt_bare_single_target_keeps_legacy_one_shot_fallback(tmp_path, monkeypatch):
    store = ChatStore(tmp_path / "chat.db")
    opened: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "hunter.chat.commands.enqueue_hunts",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError()),
        raising=False,
    )
    monkeypatch.setattr(
        "hunter.chat.commands._audit_target_reply",
        lambda ctx, command: opened.append({"args": ctx.args, "command": command}) or type(
            "Reply", (), {"text": "legacy one-shot", "data": {"hunt": {"action": "started"}}}
        )(),
    )
    try:
        reply = safe_execute("hunt", _ctx(store, tmp_path, LOCAL_A))
    finally:
        store.close()

    assert reply.text == "legacy one-shot"
    assert opened == [{"args": LOCAL_A, "command": "hunt"}]


def test_hunt_queue_refuses_non_localhost_without_partial_files(tmp_path):
    store = ChatStore(tmp_path / "chat.db")
    try:
        reply = safe_execute(
            "hunt", _ctx(store, tmp_path, "https://evil.example --time 1m https://127.0.0.1")
        )
    finally:
        store.close()

    assert "scope" in reply.text.lower() or "localhost" in reply.text.lower()
    assert list((tmp_path / "daemon" / "queue").glob("task-*.json")) == []


def test_hunt_queue_time_parsing_populates_task_fields(tmp_path, monkeypatch):
    store = ChatStore(tmp_path / "chat.db")
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr("hunter.chat.commands.daemon_running", lambda state: (True, "running"), raising=False)
    monkeypatch.setattr(
        "hunter.chat.commands.enqueue_hunts",
        lambda state, tasks: captured.extend(tasks) or len(tasks),
        raising=False,
    )
    try:
        reply = safe_execute("hunt", _ctx(store, tmp_path, f"--time 1h30m {LOCAL_A} --budget 2.25"))
    finally:
        store.close()

    assert reply.data["hunt"]["time_seconds"] == pytest.approx(5400.0)
    assert captured[0]["max_wall_seconds"] == pytest.approx(5400.0)
    assert captured[0]["max_cost_usd"] == pytest.approx(2.25)
    assert captured[0]["engine"]
    assert captured[0]["scope"]


def test_engine_remains_available_for_ordinary_chat(tmp_path):
    class Provider:
        name = "fake"

        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            from hunter.llm.base import TurnResult

            return TurnResult(text="ordinary chat remains available")

    from hunter.chat.repl import ChatEngine

    store = ChatStore(tmp_path / "chat.db")
    engine = ChatEngine(
        store=store,
        config=default_config(),
        provider=Provider(),
        options={"state_dir": str(tmp_path)},
    )
    try:
        reply = engine.handle_text("hello without a hunt")
    finally:
        engine.close()
        store.close()

    assert reply.text == "ordinary chat remains available"
