"""Tests for daemon health: zombie reaping, memory awareness, claim backpressure.

The motivating failure is real: a dozen pytest-spawned daemons whose temp
state dirs were cleaned up under them kept polling, ate the RAM a live hunt
needed, and the hunt died silently. These tests pin the conservative rules —
a live daemon is never reaped, and a held claim is the cheap failure.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hunter.daemon_health import (
    DEFAULT_MIN_AVAILABLE_MB,
    ClaimDecision,
    MemorySnapshot,
    claim_gate,
    find_zombie_daemons,
    memory_snapshot,
    reap_zombie_daemons,
)


# --------------------------------------------------------------------- memory


def test_memory_snapshot_reports_a_real_number():
    snap = memory_snapshot()
    # On Linux this is procfs and must be a sane positive figure.
    if snap.source == "procfs":
        assert snap.total_mb > 0
        assert snap.available_mb >= 0
        assert snap.used_mb >= 0
    else:
        # Unknown host: the snapshot must be permissive, never blocking.
        assert snap.available_mb == float("inf")


def test_pressure_bands_are_ordered():
    assert MemorySnapshot(100, 2000, 1900, "procfs").pressure == "critical"
    assert MemorySnapshot(200, 2000, 1800, "procfs").pressure == "high"
    assert MemorySnapshot(400, 2000, 1600, "procfs").pressure == "moderate"
    assert MemorySnapshot(1500, 2000, 500, "procfs").pressure == "low"


def test_unmeasurable_host_never_blocks_a_claim():
    decision = claim_gate(reap=False)
    if decision.memory.source == "unknown":
        assert decision.allowed is True
        assert "unmeasurable" in decision.reason


# --------------------------------------------------------------------- zombies


def test_live_daemon_is_never_a_zombie(tmp_path, monkeypatch):
    """A daemon whose state dir exists and whose pid.json names it is live."""
    state = tmp_path / "live-state"
    (state / "daemon").mkdir(parents=True)
    (state / "daemon" / "pid.json").write_text(json.dumps({"pid": 4242}), encoding="utf-8")

    from hunter import daemon_health as health

    def _cmdline(pid: int) -> str:
        # Only pid 4242 is a daemon; pid 1 is an unrelated process that must
        # be ignored entirely.
        if pid == 4242:
            return f"python -m hunter.daemon --state {state}"
        return "systemd --system"

    monkeypatch.setattr(health, "_proc_cmdline", _cmdline)
    monkeypatch.setattr(health.os, "listdir", lambda p: ["4242", "1"] if p == "/proc" else os.listdir(p))
    monkeypatch.setattr(
        health.Path, "exists", lambda self: str(self).startswith(str(state)) or str(self) == "/proc"
    )

    zombies = find_zombie_daemons()
    assert zombies == [], f"a live daemon must never be reaped: {zombies}"


def test_daemon_with_deleted_state_dir_is_a_zombie(tmp_path, monkeypatch):
    """The motivating case: test temp dir cleaned up under the daemon."""
    gone = tmp_path / "gone-state"  # deliberately never created

    from hunter import daemon_health as health

    monkeypatch.setattr(
        health, "_proc_cmdline", lambda pid: f"python -m hunter.daemon --state {gone}"
    )
    monkeypatch.setattr(health.os, "listdir", lambda p: ["777"] if p == "/proc" else os.listdir(p))

    zombies = find_zombie_daemons()
    assert len(zombies) == 1
    assert zombies[0].pid == 777
    assert "no longer exists" in zombies[0].reason


def test_daemon_whose_pid_json_names_someone_else_is_a_zombie(tmp_path, monkeypatch):
    """State dir survived but belongs to a different daemon."""
    state = tmp_path / "shared-state"
    (state / "daemon").mkdir(parents=True)
    (state / "daemon" / "pid.json").write_text(json.dumps({"pid": 999}), encoding="utf-8")

    from hunter import daemon_health as health

    monkeypatch.setattr(
        health, "_proc_cmdline", lambda pid: f"python -m hunter.daemon --state {state}"
    )
    monkeypatch.setattr(health.os, "listdir", lambda p: ["888"] if p == "/proc" else os.listdir(p))
    monkeypatch.setattr(
        health.Path, "exists", lambda self: str(self).startswith(str(state)) or str(self) == "/proc"
    )

    zombies = find_zombie_daemons()
    assert len(zombies) == 1
    assert zombies[0].pid == 888
    assert "claims pid 999" in zombies[0].reason


def test_non_daemon_process_is_ignored(tmp_path, monkeypatch):
    from hunter import daemon_health as health

    monkeypatch.setattr(health, "_proc_cmdline", lambda pid: "grep -r hunter.daemon /tmp")
    monkeypatch.setattr(health.os, "listdir", lambda p: ["555"] if p == "/proc" else os.listdir(p))

    assert find_zombie_daemons() == []


def test_daemon_without_state_flag_is_left_alone(monkeypatch):
    """No --state means the default state dir; not provably a zombie."""
    from hunter import daemon_health as health

    monkeypatch.setattr(health, "_proc_cmdline", lambda pid: "python -m hunter.daemon")
    monkeypatch.setattr(health.os, "listdir", lambda p: ["444"] if p == "/proc" else os.listdir(p))

    assert find_zombie_daemons() == []


def test_reap_terminates_and_reports(tmp_path, monkeypatch):
    gone = tmp_path / "gone-state"

    from hunter import daemon_health as health

    killed: list[tuple[int, int]] = []
    alive = {666}

    monkeypatch.setattr(
        health, "_proc_cmdline", lambda pid: f"python -m hunter.daemon --state {gone}"
    )
    monkeypatch.setattr(health.os, "listdir", lambda p: ["666"] if p == "/proc" else os.listdir(p))
    monkeypatch.setattr(
        health.os,
        "kill",
        lambda pid, sig: (killed.append((pid, sig)), alive.discard(pid)),
    )
    monkeypatch.setattr(health, "_proc_exists", lambda pid: pid in alive)

    reaped = reap_zombie_daemons()
    assert len(reaped) == 1
    assert reaped[0].pid == 666
    # SIGTERM is tried before SIGKILL.
    assert killed[0][1] == health_signal_term()
    # It exited on the first signal, so no SIGKILL was needed.
    assert len(killed) == 1


def health_signal_term():
    import signal

    return signal.SIGTERM


def test_reap_escalates_to_sigkill_when_ignored(tmp_path, monkeypatch):
    gone = tmp_path / "stubborn-state"

    from hunter import daemon_health as health

    signals: list[int] = []

    monkeypatch.setattr(
        health, "_proc_cmdline", lambda pid: f"python -m hunter.daemon --state {gone}"
    )
    monkeypatch.setattr(health.os, "listdir", lambda p: ["777"] if p == "/proc" else os.listdir(p))
    monkeypatch.setattr(health.os, "kill", lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(health, "_proc_exists", lambda pid: True)  # never dies
    import time as _time_mod

    monkeypatch.setattr(_time_mod, "sleep", lambda _s: None)  # skip the grace wait

    reap_zombie_daemons()
    import signal

    assert signal.SIGTERM in signals
    assert signal.SIGKILL in signals
    assert signals.index(signal.SIGTERM) < signals.index(signal.SIGKILL)


# ------------------------------------------------------------------ claim gate


def test_claim_held_when_memory_is_below_the_floor(monkeypatch):
    from hunter import daemon_health as health

    monkeypatch.setattr(
        health, "memory_snapshot", lambda: MemorySnapshot(120, 2000, 1880, "procfs")
    )
    decision = claim_gate(reap=False)
    assert decision.allowed is False
    assert "memory pressure" in decision.reason
    assert decision.memory.pressure == "critical"


def test_claim_allowed_when_memory_is_comfortable(monkeypatch):
    from hunter import daemon_health as health

    monkeypatch.setattr(
        health, "memory_snapshot", lambda: MemorySnapshot(1200, 2000, 800, "procfs")
    )
    decision = claim_gate(reap=False)
    assert decision.allowed is True
    assert decision.memory.pressure == "low"


def test_reaping_runs_before_the_memory_check(monkeypatch):
    """Freeing the zombies can turn a 'no' into a 'yes' on the same poll."""
    from hunter import daemon_health as health

    calls: list[str] = []

    def _fake_reap(**kwargs):
        calls.append("reap")
        return [object()]  # one zombie freed

    def _fake_memory():
        calls.append("memory")
        return MemorySnapshot(120, 2000, 1880, "procfs")

    monkeypatch.setattr(health, "reap_zombie_daemons", _fake_reap)
    monkeypatch.setattr(health, "memory_snapshot", _fake_memory)

    decision = claim_gate()
    assert calls == ["reap", "memory"], "reaping must precede the memory check"
    assert decision.zombies_reaped == 1
    assert decision.allowed is False  # still under the floor after one reap


def test_claim_gate_never_raises_when_reaping_fails(monkeypatch):
    from hunter import daemon_health as health

    def _boom(**kwargs):
        raise RuntimeError("procfs vanished")

    monkeypatch.setattr(health, "reap_zombie_daemons", _boom)
    monkeypatch.setattr(
        health, "memory_snapshot", lambda: MemorySnapshot(1500, 2000, 500, "procfs")
    )

    decision = claim_gate()
    assert decision.allowed is True
    assert decision.zombies_reaped == 0


def test_custom_floor_is_honoured(monkeypatch):
    from hunter import daemon_health as health

    monkeypatch.setattr(
        health, "memory_snapshot", lambda: MemorySnapshot(400, 2000, 1600, "procfs")
    )
    assert claim_gate(reap=False, min_available_mb=256).allowed is True
    assert claim_gate(reap=False, min_available_mb=1024).allowed is False


def test_decision_as_dict_is_json_safe(monkeypatch):
    from hunter import daemon_health as health

    monkeypatch.setattr(
        health, "memory_snapshot", lambda: MemorySnapshot(1500, 2000, 500, "procfs")
    )
    payload = claim_gate(reap=False).as_dict()
    assert payload["allowed"] is True
    assert payload["available_mb"] == 1500.0
    assert payload["pressure"] == "low"
    json.dumps(payload)  # must not raise


def test_infinite_memory_serialises_as_null(monkeypatch):
    from hunter import daemon_health as health

    monkeypatch.setattr(
        health,
        "memory_snapshot",
        lambda: MemorySnapshot(float("inf"), 0.0, 0.0, "unknown"),
    )
    payload = claim_gate(reap=False).as_dict()
    assert payload["available_mb"] is None
    json.dumps(payload)
