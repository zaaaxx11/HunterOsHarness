"""Doctor FIX — auto-repair engine for HunterOS issues.

Triggered by ``hunter doctor --fix``. For every FAIL row the doctor
collects, this module applies one known fix (if any), then re-checks.

Design contract
---------------
* ``attempt_fixes(checks) -> list[FixResult]`` — one pass, idempotent.
* Each fix is named and tagged so the operator knows what changed.
* Never deletes user data (ledger rows, config keys, chat sessions).
* A fix that requires network (reinstall, pull) signals an opt-in note.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hunter.cli.doctor_core import Check

__all__ = ["FixResult", "attempt_fixes"]

_HUNT_HOME = Path(os.path.expanduser("~/.hunter"))


@dataclass
class FixResult:
    label: str
    action: str            # "applied" | "skipped" | "failed" | "needs_network"
    detail: str = ""


# ════════════════════════════════════════════════════════════════════
# Per-check fixers (check label → fix function)
# ════════════════════════════════════════════════════════════════════


def _fix_missing_dep(check: Check) -> FixResult:
    """Install a missing pip dependency (opt-in network)."""
    dep = check.label.replace("dep:", "")
    if not dep:
        return FixResult(check.label, "skipped", "narrow dependency name")
    # never install without asking — signal it
    return FixResult(check.label, "needs_network",
                     f"pip install {dep} required (run `pip install -e .[llm]` or reinstall)")


def _fix_corrupt_hunt_state(check: Check) -> FixResult:
    """Delete a corrupt hunt_state.json so a fresh hunt can start."""
    path = _HUNT_HOME / "hunt_state.json"
    if path.exists():
        try:
            import json
            json.loads(path.read_text(encoding="utf-8"))
            return FixResult(check.label, "skipped",
                             "JSON reads back now — was it already fixed?")
        except (json.JSONDecodeError, OSError):
            backup = path.with_suffix(path.suffix + ".corrupt." +
                                     str(int(__import__("time").time())))
            import shutil
            shutil.move(str(path), str(backup))
            return FixResult(check.label, "applied",
                             f"renamed corrupt file to {backup}")
    return FixResult(check.label, "skipped", "no corrupt file on disk")


def _fix_missing_target_json(check: Check) -> FixResult:
    """Create a skeleton target.json where the state directory lives."""
    ws = Path(os.environ.get("HUNTER_STATE_DIR") or os.path.expanduser("~/.hunter"))
    path = ws / "target.json"
    if path.exists():
        return FixResult(check.label, "skipped", "already exists")
    import json
    skeleton = {
        "target": {
            "name": "placeholder", "url": "", "type": "web2",
            "scope": {"in_scope": [], "out_of_scope": [], "excluded_bugs": []},
            "rules": {}, "rewards": {}, "stack_hints": [], "auth": {},
            "repo_hints": [], "api_hints": [], "contracts": [], "mobile": [],
            "contacts": [], "notes": ["skeleton — fill before hunting"],
        },
        "seed_leads": [], "open_questions": [],
        "recon_confidence": 0, "input_kind": "text",
    }
    path.write_text(json.dumps(skeleton, indent=2, ensure_ascii=False))
    return FixResult(check.label, "applied",
                     f"wrote skeleton {path} — fill hosts/urls and re-run")


def _fix_loop_v4_import(check: Check) -> FixResult:
    """When loop_v4 / phase0_recon cannot be imported, diagnose the PYTHONPATH."""
    pyver = sys.version_info
    detail = f"Python {pyver.major}.{pyver.minor} — "
    try:
        import hunter  # noqa: F401
        detail += "hunter package found, submodule may be missing from install"
    except ImportError:
        detail += "hunter package not in sys.path"
    return FixResult(check.label, "needs_network",
                     detail + " — reinstall with pip install -e /path/to/HunterOsHarness")


def _fix_hunt_state_schema(check: Check) -> FixResult:
    """Ensure hunt_state.json carries the expected schema_version ≥ 1."""
    path = _HUNT_HOME / "hunt_state.json"
    if not path.exists():
        return FixResult(check.label, "skipped", "no file to fix")
    try:
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _fix_corrupt_hunt_state(check)
    changed = False
    if isinstance(data, dict):
        for field, default in (
            ("schema_version", 1),
            ("phase0_done", False),
            ("target_json_path", ""),
            ("findings", []),
            ("chains", []),
        ):
            if field not in data:
                data[field] = default
                changed = True
    if changed:
        import json as _j
        path.write_text(_j.dumps(data, indent=2, ensure_ascii=False))
        return FixResult(check.label, "applied", "added missing schema fields")
    return FixResult(check.label, "skipped", "schema is current")


# ── mapping: check label prefix → fixer ───────────────────────────

_FIXERS: dict[str, Any] = {
    "dep:": _fix_missing_dep,
    "v4:hunt-state": _fix_hunt_state_schema,
    "v4:target-json": _fix_missing_target_json,
    "v4:loop_v4": _fix_loop_v4_import,
    "v4:phase0_recon": _fix_loop_v4_import,
    "v4:verify_l1": _fix_loop_v4_import,
}


def _match(prefix: str, label: str) -> bool:
    return label.lower().startswith(prefix.lower())


# ── public API ─────────────────────────────────────────────────────

def attempt_fixes(checks: list[Check]) -> list[FixResult]:
    """For each FAIL check, try one known fix. Returns results."""
    results: list[FixResult] = []
    for check in checks:
        if check.status != "fail":
            continue
        matched = None
        for prefix, fixer in _FIXERS.items():
            if _match(prefix, check.label):
                matched = fixer
                break
        if matched is None:
            results.append(FixResult(check.label, "skipped",
                                     "no known fix — diagnose manually"))
            continue
        try:
            result = matched(check)
        except Exception as exc:
            result = FixResult(check.label, "failed",
                               f"{type(exc).__name__}: {exc}")
        results.append(result)
    return results