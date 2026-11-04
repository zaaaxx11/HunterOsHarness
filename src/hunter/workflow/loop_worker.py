"""One-shot hunt worker for the loop (subprocess). JSON on stdout.

Invoked by: python -m hunter.workflow.loop_worker --target ... --scope ...
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from hunter.hunt import run_hunt
from hunter.llm.budget import RunBudget
from hunter.tools.scope import ScopeSet


def _main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--engine", default="llm")
    p.add_argument("--session", default="")
    args = p.parse_args()

    scope_data = json.loads(args.scope)
    scope = ScopeSet(
        frozenset(str(h) for h in scope_data.get("hosts", [])),
        bool(scope_data.get("allow_subdomains", False)),
        name=str(scope_data.get("name", "loop")),
        local_roots=tuple(str(r) for r in (scope_data.get("local_roots", ()) or ())),
    )

    budget = RunBudget(
        max_cost_usd=0.0,
        wall_seconds=600.0,           # each cycle max 10m
        min_wall_seconds=30.0,
        max_iterations=0,
    )

    try:
        outcome = run_hunt(
            args.target,
            scope=scope,
            engine_name=args.engine,
            state_dir=args.state,
            budget=budget,
            config={
                "state_dir": str(args.state),
                "approval_auto_allow": True,
                "session": args.session,
            },
        )
        result: dict[str, Any] = {
            "run_id": outcome.run_id,
            "status": outcome.status,
            "findings": outcome.findings,
        }
    except Exception as exc:
        result = {"run_id": "", "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    _main()