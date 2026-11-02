"""Daemon health: zombie reaping, memory awareness, and claim backpressure.

Two failure modes motivated this module.

**Zombie daemons.** A test run spawns a real daemon per case; when the test
teardown misses one (or the process outlives its temp state dir), it keeps
polling a directory that no longer exists. On a small VM a dozen of those eat
the RAM a real hunt needs — hunts then die with no error, just silence. The
zombie rule is deliberately conservative: a process is only reaped when its
state directory is GONE, or when no valid ``pid.json`` backs it. A daemon
whose state dir still exists is never touched, even if it looks idle.

**Memory pressure.** The worker loop used to claim the next task the moment
the previous one finished. Under memory pressure that is exactly wrong: the
new hunt allocates, the box swaps or the OOM killer fires, and the run dies
mid-flight with a corrupted ledger. The claim gate now refuses to claim while
available memory is below a floor, and re-arms on the next poll — the queue
is the backpressure, not a crash.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "MemorySnapshot",
    "memory_snapshot",
    "ZombieRecord",
    "find_zombie_daemons",
    "reap_zombie_daemons",
    "claim_gate",
    "DEFAULT_MIN_AVAILABLE_MB",
]

# Below this much available memory the worker refuses to claim new work.
# 256 MB is roughly what a Python interpreter plus one LLM turn needs to
# start; under it a new hunt is more likely to be OOM-killed than to finish.
DEFAULT_MIN_AVAILABLE_MB = 256


@dataclass(frozen=True)
class MemorySnapshot:
    """Available memory in MB, plus the raw figures for diagnostics."""

    available_mb: float
    total_mb: float
    used_mb: float
    source: str

    @property
    def pressure(self) -> str:
        if self.available_mb < 128:
            return "critical"
        if self.available_mb < DEFAULT_MIN_AVAILABLE_MB:
            return "high"
        if self.available_mb < 512:
            return "moderate"
        return "low"


def memory_snapshot() -> MemorySnapshot:
    """Best-effort available memory. Never raises.

    Linux reads ``/proc/meminfo`` (MemAvailable is the honest number — it
    already accounts for reclaimable page cache). Elsewhere it falls back to
    ``os.sysconf``, and if even that fails it reports a generous snapshot so a
    missing probe never blocks work it cannot measure.
    """
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if parts:
                    try:
                        info[key.strip()] = int(parts[0])  # kB
                    except ValueError:
                        continue
        total_kb = info.get("MemTotal", 0)
        avail_kb = info.get("MemAvailable")
        if avail_kb is None:
            # Older kernels without MemAvailable: free + buffers + cached is
            # the closest equivalent.
            avail_kb = (
                info.get("MemFree", 0)
                + info.get("Buffers", 0)
                + info.get("Cached", 0)
                + info.get("SReclaimable", 0)
            )
        if total_kb > 0:
            return MemorySnapshot(
                available_mb=avail_kb / 1024.0,
                total_mb=total_kb / 1024.0,
                used_mb=(total_kb - avail_kb) / 1024.0,
                source="procfs",
            )
    except OSError:
        pass

    try:  # pragma: no cover - non-Linux fallback
        page = os.sysconf("SC_PAGE_SIZE")
        total_pages = os.sysconf("SC_PHYS_PAGES")
        avail_pages = os.sysconf("SC_AVPHYS_PAGES")
        total_mb = total_pages * page / (1024 * 1024)
        avail_mb = avail_pages * page / (1024 * 1024)
        if total_mb > 0:
            return MemorySnapshot(
                available_mb=avail_mb,
                total_mb=total_mb,
                used_mb=total_mb - avail_mb,
                source="sysconf",
            )
    except (ValueError, OSError, AttributeError):
        pass

    return MemorySnapshot(
        available_mb=float("inf"),
        total_mb=0.0,
        used_mb=0.0,
        source="unknown",
    )


@dataclass(frozen=True)
class ZombieRecord:
    """A daemon process that is provably dead weight."""

    pid: int
    state_dir: str
    reason: str
    cmdline: str


def _proc_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            raw = handle.read()
    except OSError:
        return ""
    return " ".join(part for part in raw.decode("utf-8", "replace").split("\0") if part)


def _proc_exists(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def _is_daemon_process(cmdline: str) -> bool:
    if not cmdline:
        return False
    if "hunter.daemon" not in cmdline and "hunter-daemon" not in cmdline:
        return False
    # Never treat a grep/ps/editor line as a daemon.
    return "grep" not in cmdline and " rg " not in cmdline


def _state_dir_from_cmdline(cmdline: str) -> str | None:
    """Extract ``--state <dir>`` from a daemon command line."""
    parts = cmdline.split()
    for index, part in enumerate(parts):
        if part == "--state" and index + 1 < len(parts):
            return parts[index + 1]
        if part.startswith("--state="):
            return part.split("=", 1)[1]
    return None


def _read_pid_record(state_dir: str | None) -> int | None:
    """The pid a state dir's ``pid.json`` claims, if any."""
    if not state_dir:
        return None
    try:
        import json

        record = json.loads((Path(state_dir) / "daemon" / "pid.json").read_text(encoding="utf-8"))
        pid = record.get("pid")
        return int(pid) if pid is not None else None
    except (OSError, ValueError, TypeError):
        return None


def _heartbeat_claims_pid(state_dir: str | None, pid: int, *, max_age_s: float = 120.0) -> bool:
    """True when the state dir's heartbeat is FRESH and names this pid.

    A daemon that is alive writes ``heartbeat.json`` every poll. Some daemons
    never write ``pid.json`` at all (a half-started one, or an older layout),
    so pid.json alone cannot decide liveness — a fresh heartbeat naming the
    process is equally good evidence that it is live and must not be reaped.
    """
    if not state_dir:
        return False
    try:
        import json
        import time

        path = Path(state_dir) / "daemon" / "heartbeat.json"
        if not path.is_file():
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        if int(data.get("pid", 0) or 0) != pid:
            return False
        ts = float(data.get("ts", 0.0) or 0.0)
        if ts <= 0:
            return False
        return (time.time() - ts) <= max_age_s
    except (OSError, ValueError, TypeError):
        return False


def find_zombie_daemons(*, exclude_pid: int | None = None) -> list[ZombieRecord]:
    """Find daemon processes that are provably dead weight.

    A daemon is a zombie when EITHER:

    * its ``--state`` directory no longer exists (a test temp dir that was
      cleaned up under it), OR
    * that state directory holds no ``pid.json`` naming this pid — either the
      file is missing (the daemon never finished registering, which is how a
      half-started test daemon looks) or it names a different process.

    A daemon whose state dir exists AND whose ``pid.json`` claims it is left
    alone no matter how idle it looks — that is a live daemon, and killing it
    would abort real work.
    """
    zombies: list[ZombieRecord] = []
    me = exclude_pid if exclude_pid is not None else os.getpid()
    try:
        entries = [int(name) for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return zombies

    for pid in entries:
        if pid == me:
            continue
        cmdline = _proc_cmdline(pid)
        if not _is_daemon_process(cmdline):
            continue
        state_dir = _state_dir_from_cmdline(cmdline)
        if state_dir is None:
            # A daemon with no --state is using the default state dir; it is
            # not provably a zombie, so leave it.
            continue
        if not Path(state_dir).exists():
            zombies.append(
                ZombieRecord(
                    pid=pid,
                    state_dir=state_dir,
                    reason="state directory no longer exists",
                    cmdline=cmdline,
                )
            )
            continue
        recorded = _read_pid_record(state_dir)
        if recorded == pid:
            # Registered and claimed: live, however idle it looks.
            continue
        if recorded is None and _heartbeat_claims_pid(state_dir, pid):
            # No pid.json, but a FRESH heartbeat names this process. That is a
            # live daemon under an older layout — reaping it would abort real
            # work.
            continue
        if recorded is None:
            # No pid.json and no fresh heartbeat: the daemon never finished
            # registering, or it stopped writing long ago. Dead weight.
            zombies.append(
                ZombieRecord(
                    pid=pid,
                    state_dir=state_dir,
                    reason="no pid.json and no fresh heartbeat (never registered)",
                    cmdline=cmdline,
                )
            )
        else:
            # The state dir belongs to a different (or already-dead) daemon.
            zombies.append(
                ZombieRecord(
                    pid=pid,
                    state_dir=state_dir,
                    reason=f"pid.json claims pid {recorded}, not {pid}",
                    cmdline=cmdline,
                )
            )
    return zombies


def reap_zombie_daemons(*, exclude_pid: int | None = None) -> list[ZombieRecord]:
    """Terminate zombie daemons and return what was reaped.

    SIGTERM first, then a short grace period, then SIGKILL for whatever
    ignored it. A process that exits on its own is simply not reported as
    killed — the record is still returned so the caller can log it.
    """
    import signal
    import time

    zombies = find_zombie_daemons(exclude_pid=exclude_pid)
    if not zombies:
        return []

    for zombie in zombies:
        try:
            os.kill(zombie.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            continue

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if not any(_proc_exists(z.pid) for z in zombies):
            break
        time.sleep(0.2)

    for zombie in zombies:
        if _proc_exists(zombie.pid):
            try:
                os.kill(zombie.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    return zombies


@dataclass(frozen=True)
class ClaimDecision:
    """Whether the worker may claim the next task right now."""

    allowed: bool
    reason: str
    memory: MemorySnapshot
    zombies_reaped: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "available_mb": (
                None if self.memory.available_mb == float("inf") else round(self.memory.available_mb, 1)
            ),
            "pressure": self.memory.pressure,
            "source": self.memory.source,
            "zombies_reaped": self.zombies_reaped,
        }


def claim_gate(
    *,
    min_available_mb: int = DEFAULT_MIN_AVAILABLE_MB,
    reap: bool = True,
    exclude_pid: int | None = None,
) -> ClaimDecision:
    """Decide whether to claim new work, reaping zombies first.

    Zombie reaping runs BEFORE the memory check on purpose: the most common
    cause of pressure is the zombies themselves, so freeing them can turn a
    "no" into a "yes" without waiting for the next poll.
    """
    reaped = 0
    if reap:
        try:
            reaped = len(reap_zombie_daemons(exclude_pid=exclude_pid))
        except Exception:  # noqa: BLE001 — reaping must never block the loop
            reaped = 0

    memory = memory_snapshot()
    if memory.source != "unknown" and memory.available_mb < min_available_mb:
        return ClaimDecision(
            allowed=False,
            reason=(
                f"memory pressure: {memory.available_mb:.0f} MB available "
                f"(floor {min_available_mb} MB) — holding claims until the next poll"
            ),
            memory=memory,
            zombies_reaped=reaped,
        )
    return ClaimDecision(
        allowed=True,
        reason=(
            f"{memory.available_mb:.0f} MB available ({memory.pressure} pressure)"
            if memory.source != "unknown"
            else "memory unmeasurable on this host — proceeding"
        ),
        memory=memory,
        zombies_reaped=reaped,
    )


def _cli(argv: list[str] | None = None) -> int:  # pragma: no cover - operator tool
    """``python -m hunter.daemon_health`` — inspect and optionally reap."""
    import argparse
    import json

    parser = argparse.ArgumentParser(prog="hunter-daemon-health")
    parser.add_argument("--json", action="store_true", help="Machine-readable output.")
    parser.add_argument("--reap", action="store_true", help="Terminate zombie daemons.")
    parser.add_argument("--min-mb", type=int, default=DEFAULT_MIN_AVAILABLE_MB)
    args = parser.parse_args(argv)

    zombies = find_zombie_daemons()
    if args.reap:
        zombies = reap_zombie_daemons()
    decision = claim_gate(min_available_mb=args.min_mb, reap=False)

    payload = {
        "memory": {
            "available_mb": (
                None if decision.memory.available_mb == float("inf") else round(decision.memory.available_mb, 1)
            ),
            "total_mb": round(decision.memory.total_mb, 1),
            "pressure": decision.memory.pressure,
            "source": decision.memory.source,
        },
        "zombies": [
            {"pid": z.pid, "state_dir": z.state_dir, "reason": z.reason} for z in zombies
        ],
        "claim_allowed": decision.allowed,
        "claim_reason": decision.reason,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        mem = payload["memory"]
        print(f"memory: {mem['available_mb']} MB available / {mem['total_mb']} MB total ({mem['pressure']})")
        if zombies:
            print(f"zombie daemons: {len(zombies)}")
            for z in payload["zombies"]:
                print(f"  pid {z['pid']:>8}  {z['reason']}  ({z['state_dir']})")
        else:
            print("zombie daemons: none")
        print(f"claim: {'ALLOWED' if decision.allowed else 'HELD'} — {decision.reason}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_cli())
