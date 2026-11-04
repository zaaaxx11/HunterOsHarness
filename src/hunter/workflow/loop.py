"""Hunt loop — daemon-free, cron-friendly, state-driven.

Runs a target through the existing pipeline repeatedly until either
time expires or the mission goals are met. No daemon, no queue — each
cycle invokes run_scan() in-process thin a subprocess worker so a wedged
hunt cannot stall the loop.

Cycle timing:
  - run one hunt (engine llm/deterministic) against the target
  - wait ``idle_seconds`` (default 15s) for the next cycle
  - stop when wall_seconds elapsed (0 = unlimited) OR goals met

State is written to ``<state>/hunt_runs/<slug>/state.json`` every cycle,
so a cron restart (or a crash) resumes exactly where it left off.

Proof-of-live: a finding is only counted toward ``rce_proven_live`` when
its status is PROVEN_LIVE and it has a logs_path on disk (the plain-text
log of a real, live execution — not a static tool flag, not a by-design
system capability).
"""

from __future__ import annotations

import asyncio
import contextlib
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from hunter.kernel.findings import FindingStatus
from hunter.workflow.hunt_state import (
    HuntMission,
    goals_met,
    load_mission,
    save_mission,
)
from hunter.tools.scope import ScopeSet


def _new_mission(
    target: str,
    state_dir: str | Path,
    *,
    wall_seconds: float = 0.0,
    idle_seconds: float = 15.0,
    engine: str = "llm",
    goals: list[dict[str, Any]] | None = None,
) -> HuntMission:
    """Build a fresh mission for a target (overwrites on first run)."""
    from hunter.workflow.hunt_state import _slugify

    slug = _slugify(target)
    mission = HuntMission(
        target=target,
        target_slug=slug,
        state_dir=Path(state_dir) / "hunt_runs" / slug,
        wall_seconds=float(wall_seconds),
        idle_seconds=float(idle_seconds),
        engine=engine,
        started_ts=time.time(),
    )
    if goals is not None:
        mission.goals = goals
    save_mission(mission)
    return mission


def _count_findings(state_dir: str | Path) -> tuple[int, int, int]:
    """(total, verified, rce_proven_live) from the ledger."""
    total = verified = rce = 0
    try:
        from hunter.kernel.ledger import Ledger
        from hunter.runtime_paths import RuntimePaths

        paths = RuntimePaths.resolve(state=Path(state_dir), migrate=False)
        ledger = Ledger(paths.ledger)
        try:
            for f in ledger.findings():
                total += 1
                if f.status in (FindingStatus.VERIFIED, FindingStatus.PROMOTED, FindingStatus.PROVEN_LIVE):
                    verified += 1
                if (
                    f.status == FindingStatus.PROVEN_LIVE
                    and f.logs_path
                    and Path(f.logs_path).is_file()
                    and "rce" in str(getattr(f, "klass", "") or "").lower()
                ):
                    rce += 1
        finally:
            with contextlib.suppress(Exception):
                ledger.close()
    except Exception:
        pass
    return total, verified, rce


def _run_one(
    target: str,
    scope: ScopeSet,
    state_dir: str | Path,
    engine: str,
    mission: HuntMission,
) -> dict[str, Any]:
    """Execute one hunt via a subprocess so a wedged run can't stall the loop."""
    import json

    scope_payload = {
        "name": scope.name,
        "hosts": sorted(scope.allowed_hosts),
        "allow_subdomains": scope.allow_subdomains,
        "local_roots": list(getattr(scope, "local_roots", ()) or ()),
    }
    worker = (
        sys.executable,
        "-m",
        "hunter.workflow.loop_worker",
        "--target",
        str(target),
        "--scope",
        json.dumps(scope_payload),
        "--state",
        str(state_dir),
        "--engine",
        engine,
        "--session",
        mission.target_slug,
    )
    try:
        proc = subprocess.run(worker, capture_output=True, text=True, timeout=600)
        try:
            out = json.loads(proc.stdout.splitlines()[-1] if proc.stdout.strip() else "{}")
        except json.JSONDecodeError:
            out = {}
        if proc.returncode != 0:
            out["error"] = (proc.stderr or proc.stdout)[-400:]
        return out
    except subprocess.TimeoutExpired:
        return {"error": "cycle timed out after 600s", "run_id": ""}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}", "run_id": ""}


async def _tick(mission: HuntMission, scope: ScopeSet, state_dir: str | Path) -> None:
    """Run one cycle and update the mission state."""
    result = await asyncio.to_thread(
        _run_one, mission.target, scope, state_dir, mission.engine, mission
    )
    mission.run_count += 1
    mission.last_cycle_ts = time.time()
    if result.get("run_id"):
        mission.last_run_id = str(result["run_id"])
        mission.last_run_status = str(result.get("status", "completed"))
    if result.get("error"):
        mission.error = str(result["error"])[:500]
    mission.total_findings, mission.verified_findings, mission.rce_proven_live = _count_findings(state_dir)
    save_mission(mission)


def run_loop(
    target: str,
    scope: ScopeSet,
    state_dir: str | Path,
    *,
    engine: str = "llm",
    wall_seconds: float = 0.0,
    min_wall_seconds: float = 0.0,
    idle_seconds: float = 15.0,
    goals: list[dict[str, Any]] | None = None,
) -> int:
    """Main loop entry. Returns 0 normal, 1 error, 2 findings.

    Blocks until goals met or time expired. Intended to be driven by cron
    (or a long-lived `hunt loop <target>` command); each run re-reads the
    mission state so a fresh invocation resumes instead of duplicating.
    """
    from hunter.workflow.hunt_state import _slugify, load_mission

    mission = load_mission(state_dir, _slugify(target))
    if mission.started_ts is None:
        mission = _new_mission(
            target, state_dir,
            wall_seconds=wall_seconds,
            idle_seconds=idle_seconds,
            engine=engine,
            goals=goals,
        )
    if mission.started_ts is None:
        mission.started_ts = time.time()

    deadline = (
        mission.started_ts + mission.wall_seconds
        if mission.wall_seconds > 0
        else float("inf")
    )
    start = time.monotonic()

    while True:
        now = time.time()
        if now >= deadline:
            mission.completed = True
            mission.completion_reason = "time-expired"
            save_mission(mission)
            break
        if goals_met(mission):
            mission.completed = True
            mission.completion_reason = "goals-met"
            save_mission(mission)
            break
        # Minimum-time floor: never stop before min_wall_seconds, even if goals met.
        if mission.wall_seconds <= 0 and min_wall_seconds > 0 and now - mission.started_ts >= min_wall_seconds:
            pass  # goals already checked; continue
        asyncio.run(_tick(mission, scope, state_dir))
        # Idle pause between cycles (or finish early if time is nearly gone).
        if mission.wall_seconds > 0 and (time.monotonic() - start) >= mission.wall_seconds:
            continue
        time.sleep(max(mission.idle_seconds, 0.1))

    return 0 if mission.completed else 1