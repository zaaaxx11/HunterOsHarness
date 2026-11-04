"""Hunt state — per-target mission file (JSON), goals-aware.

Every target gets a folder ``<state_dir>/hunt_runs/<slug>/`` with:

  state.json       — goals, budget, run history, result summary
  logs/
  findings/

The loop reads/writes this file; no daemon, no queue.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Canonical goal vocabulary — the loop stops when a goal's condition is met.
# All other findings are collected regardless; RCE (proven-live) is the
# primary stop signal.
GOAL_RCE_PROVEN_LIVE = "rce-proven-live"       # at least 1 PROVEN_LIVE RCE finding
GOAL_FINDINGS_MIN = "findings-min"              # at least N total findings
GOAL_VERIFIED_MIN = "verified-min"              # at least N VERIFIED+ findings

DEFAULT_GOALS: list[dict[str, Any]] = [
    {"kind": GOAL_RCE_PROVEN_LIVE, "count": 1},
]


@dataclass
class HuntMission:
    """What the loop is trying to achieve, serialised to state.json."""

    target: str                                       # canonical path or URL
    target_slug: str                                  # safe dir-name
    state_dir: Path                                   # where state.json + logs/ live
    goals: list[dict[str, Any]] = field(default_factory=lambda: list(DEFAULT_GOALS))
    wall_seconds: float = 0.0                         # 0 = unlimited
    min_wall_seconds: float = 0.0                     # minimum time floor before early stop
    idle_seconds: float = 15.0                        # pause between cycles
    engine: str = "llm"

    # Runtime counters (updated every cycle)
    run_count: int = 0
    started_ts: float | None = None                   # first loop tick
    last_cycle_ts: float | None = None
    total_findings: int = 0
    verified_findings: int = 0
    rce_proven_live: int = 0
    last_run_id: str = ""
    last_run_status: str = ""
    error: str = ""
    completed: bool = False
    completion_reason: str = ""                       # "goals-met" | "time-expired" | "stopped"


def mission_path(state_dir: str | Path, slug: str) -> Path:
    """Where the per-target state.json lives."""
    return Path(state_dir) / "hunt_runs" / slug / "state.json"


def load_mission(state_dir: str | Path, slug: str) -> HuntMission:
    """Read existing mission, or return a fresh one."""
    mp = mission_path(state_dir, slug)
    if mp.is_file():
        try:
            data = json.loads(mp.read_text(encoding="utf-8"))
            return HuntMission(**{k: data.get(k) for k in HuntMission.__dataclass_fields__})
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return HuntMission(
        target=slug.replace("-", "/"),
        target_slug=slug,
        state_dir=Path(state_dir) / "hunt_runs" / slug,
    )


def save_mission(mission: HuntMission) -> None:
    sd = Path(mission.state_dir) if not isinstance(mission.state_dir, Path) else mission.state_dir
    # state_dir may be the target folder OR the root; normalize to root.
    if sd.name == mission.target_slug and sd.parent.name == "hunt_runs":
        base = sd.parent.parent
    else:
        base = sd
    mp = mission_path(base, mission.target_slug)
    mp.parent.mkdir(parents=True, exist_ok=True)
    data = {
        k: getattr(mission, k)
        for k in HuntMission.__dataclass_fields__
    }
    tmp = mp.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(mp)


def goals_met(mission: HuntMission) -> bool:
    """Check whether every declared goal is satisfied."""
    for g in mission.goals:
        kind = g.get("kind", "")
        need = int(g.get("count", 1))
        if kind == GOAL_RCE_PROVEN_LIVE and mission.rce_proven_live < need:
            return False
        if kind == GOAL_FINDINGS_MIN and mission.total_findings < need:
            return False
        if kind == GOAL_VERIFIED_MIN and mission.verified_findings < need:
            return False
    return bool(mission.goals)  # at least one goal must exist


def _slugify(target: str) -> str:
    """Filesystem-safe name from a path or URL."""
    safe = "".join(c if c.isalnum() or c in "_-." else "-" for c in target)
    safe = safe.strip("-").lower()
    return safe[:64] or "hunt"