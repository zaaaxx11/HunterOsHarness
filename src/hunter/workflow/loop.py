"""Hunt loop — daemon-free, cron-friendly, state-driven. PURE SYNC.

Runs a target through the existing pipeline repeatedly until either
time expires or ALL mission goals are met. No daemon, no queue, no
async — each cycle invokes a subprocess worker so a wedged hunt cannot
stall the loop.

**Time has priority over goals.** If wall_seconds expires before every
goal is met, the loop stops with ``completion_reason="time-expired"``
and writes a final state summary which the caller/operator can read.
The intent is: ``--time 20000 --goals rce:1,all-vulns:100`` means the
loop MUST stop after 20,000 seconds regardless of whether RCE or the
vuln threshold was reached — and the result of either outcome is always
auditable from the state file.

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


def _is_exploitable_klass(finding: Any) -> bool:
    """True when the finding's klass names a live-exploitable vector.

    Matches RCE (``rce``, ``code-execution``, ``command-injection``),
    ``reentrancy`` (the most common live-exploitable vector in bridge
    protocols), and ``access-control`` bypass. A finding that passes this
    gate AND has real proof on disk (poc_path / logs_path) IS proof of
    live execution — not a static tool flag, not a by-design system
    capability.
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
        or "reentrancy" in klass
        or "access-control" in klass
        or "access_control" in klass
        or "privilege-escalation" in klass
    )


def _is_rce_only_klass(finding: Any) -> bool:
    """True ONLY for RCE-specific klass — code-exec / command-injection / rce.

    Narrower than _is_exploitable_klass: does NOT match reentrancy or
    access-control. Used for the ``rce-min`` goal counter.
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


def _count_findings(state_dir: str | Path) -> tuple[int, int, int, int]:
    """(total, verified, exploitable, rce) from the ledger.

    ``exploitable`` — VERIFIED+ findings with ANY live-exploitable klass
    (RCE / reentrancy / access-control) AND real proof on disk.

    ``rce`` — same but ONLY for RCE klass (code-exec / command-injection /
    arbitrary-code-exec), tracked independently for ``rce-min`` goals.
    """
    total = verified = exploitable = rce = 0
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
                # Gate: must be live-exploitable klass AND have real proof.
                if not strong or not _is_exploitable_klass(f):
                    continue
                has_proof = False
                for artifact in (f.logs_path, f.poc_path):
                    if artifact and Path(artifact).is_file():
                        has_proof = True
                        break
                if not has_proof:
                    continue
                # Count toward both goals: exploitable-min AND rce-min.
                exploitable += 1
                if _is_rce_only_klass(f):
                    rce += 1
        finally:
            with contextlib.suppress(Exception):
                ledger.close()
    except Exception:
        pass
    return total, verified, exploitable, rce


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
        total, verified, exploitable, rce = _count_findings(state_dir)
        mission.total_findings = total
        mission.verified_findings = verified
        mission.exploitable = exploitable
        mission.rce = rce
        save_mission(mission)

        print(
            f"cycle {mission.run_count}: findings={mission.total_findings} "
            f"verified={mission.verified_findings} "
            f"exploitable={mission.exploitable} rce={mission.rce} · "
            f"{mission.last_run_id} ({mission.last_run_status})",
            flush=True,
        )

        time.sleep(max(mission.idle_seconds, 0.1))

    return 0 if mission.completed else 1