"""Hunt loop — daemon-free, cron-friendly, state-driven. PURE SYNC.

Runs a target through the existing pipeline repeatedly until either
time expires or the mission goals are met. No daemon, no queue, no
async — each cycle invokes a subprocess worker so a wedged hunt cannot
stall the loop.

Cycle timing:
  - run one hunt (engine llm/deterministic) against the target
  - wait ``idle_seconds`` (default 15s) for the next cycle
  - stop when wall_seconds elapsed (0 = unlimited) OR goals met

State is written to ``<state>/hunt_runs/<slug>/state.json`` every cycle,
so a cron restart (or a crash) resumes exactly where it left off.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from hunter.tools.scope import ScopeSet
from hunter.workflow.hunt_state import (
    HuntMission,
    goals_met,
    load_mission,
    save_mission,
    _slugify,
)


def _new_mission(
    target: str,
    state_dir: str | Path,
    *,
    wall_seconds: float = 0.0,
    idle_seconds: float = 15.0,
    engine: str = "llm",
    goals: list[dict[str, Any]] | None = None,
) -> HuntMission:
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


def _is_rce_klass(finding: Any) -> bool:
    """True when the finding's klass names an RCE-style class.

    The taxonomy uses several spellings (``rce``, ``arbitrary-code-execution``,
    ``remote-code-execution``, ``command-injection``); match on the
    normalised class string so a class rename does not silently zero the
    goal counter.
    """
    klass = str(getattr(finding, "klass", "") or "").lower()
    if not klass:
        return False
    return (
        "rce" in klass
        or "code-execution" in klass
        or "code_execution" in klass
        or "command-injection" in klass
        or "command_injection" in klass
    )


def _count_findings(state_dir: str | Path) -> tuple[int, int, int]:
    """(total, verified, rce_proven_live) from the ledger.

    ``rce_proven_live`` counts findings that carry REAL PROOF — not a
    static tool flag and not a by-design system capability:

    - the class is RCE-shaped (rce / code-execution / command-injection),
    - the finding is VERIFIED or better (>=2 bound evidence artifacts),
    - AND a proof artifact exists on disk (logs_path, else poc_path).

    Requiring the PROVEN_LIVE *status* here was wrong: the promotion ladder
    to PROVEN_LIVE is a manual operator action, so an automated hunt could
    never satisfy the goal and the loop ran forever on a zero counter.
    VERIFIED + a real artifact on disk IS the proof of live the doctrine
    asks for.
    """
    total = verified = rce = 0
    try:
        import contextlib
        from hunter.kernel.findings import FindingStatus
        from hunter.kernel.ledger import Ledger
        from hunter.runtime_paths import RuntimePaths

        paths = RuntimePaths.resolve(state=Path(state_dir), migrate=False)
        ledger = Ledger(paths.ledger)
        try:
            for f in ledger.findings():
                total += 1
                status = f.status
                strong = status in (
                    FindingStatus.VERIFIED,
                    FindingStatus.PROMOTED,
                    FindingStatus.PROVEN_LIVE,
                )
                if strong:
                    verified += 1
                if not strong or not _is_rce_klass(f):
                    continue
                # Real artifact on disk = proof of live execution.
                for artifact in (f.logs_path, f.poc_path):
                    if artifact and Path(artifact).is_file():
                        rce += 1
                        break
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
    """Execute one hunt via a subprocess — sync, blocks until done."""
    scope_payload = {
        "name": scope.name,
        "hosts": sorted(scope.allowed_hosts),
        "allow_subdomains": scope.allow_subdomains,
        "local_roots": list(getattr(scope, "local_roots", ()) or ()),
    }
    worker = [
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
    ]
    try:
        proc = subprocess.run(worker, capture_output=True, text=True, timeout=600)
        try:
            out = json.loads(
                proc.stdout.splitlines()[-1] if proc.stdout.strip() else "{}"
            )
        except json.JSONDecodeError:
            out = {}
        if proc.returncode != 0:
            out["error"] = (proc.stderr or proc.stdout)[-400:]
        return out
    except subprocess.TimeoutExpired:
        return {"error": "cycle timed out after 600s", "run_id": ""}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "run_id": ""}


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
    """Main loop entry — pure sync, no async, no daemon. Blocks until done."""
    slug = _slugify(target)
    mission = load_mission(state_dir, slug)
    if mission.started_ts is None:
        mission = _new_mission(
            target,
            state_dir,
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

    print(
        f"Hunt loop: {mission.target_slug} · engine={engine} · "
        f"wall={mission.wall_seconds}s · idle={mission.idle_seconds}s · "
        f"goals={mission.goals}",
        flush=True,
    )

    while True:
        now = time.time()
        if now >= deadline:
            mission.completed = True
            mission.completion_reason = "time-expired"
            save_mission(mission)
            print("time-expired — stopping", flush=True)
            break
        if goals_met(mission):
            mission.completed = True
            mission.completion_reason = "goals-met"
            save_mission(mission)
            print("goals-met — stopping", flush=True)
            break

        result = _run_one(target, scope, state_dir, engine, mission)
        mission.run_count += 1
        mission.last_cycle_ts = time.time()
        if result.get("run_id"):
            mission.last_run_id = str(result["run_id"])
            mission.last_run_status = str(result.get("status", "completed"))
        if result.get("error"):
            mission.error = str(result["error"])[:500]
        total, verified, rce = _count_findings(state_dir)
        mission.total_findings = total
        mission.verified_findings = verified
        mission.rce_proven_live = rce
        save_mission(mission)

        print(
            f"cycle {mission.run_count}: findings={total} verified={verified} "
            f"rce={rce} · {mission.last_run_id} ({mission.last_run_status})",
            flush=True,
        )

        time.sleep(max(mission.idle_seconds, 0.1))

    return 0 if mission.completed else 1