"""Learning loop over the hunt ledger — post-hunt review and memory.

Deterministic, no network/LLM. Reads findings and hunt_memory rows, writes
negative memory and (via the ledger) nothing else.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from hunter.kernel.events import canonical_json


class LearningLoop:
    def __init__(self, ledger: Any) -> None:
        self.ledger = ledger

    # -- review --------------------------------------------------------------
    def review(self, run_id: Any) -> dict[str, list]:
        # Skill patches: klass values appearing in >=2 distinct runs.
        runs_by_klass: dict[str, set[Any]] = defaultdict(set)
        for finding in self.ledger.findings():
            klass = getattr(finding, "klass", None) or "unknown"
            runs_by_klass[str(klass)].add(getattr(finding, "run_id", None))

        skill_patches: list[str] = []
        promotions: list[dict[str, Any]] = []
        for klass in sorted(runs_by_klass):
            runs = {r for r in runs_by_klass[klass] if r is not None}
            if len(runs) >= 2 and self.promote_pattern(klass, sorted(runs)):
                skill_patches.append(klass)
                promotions.append({"klass": klass, "runs": sorted(runs)})

        # Negative memory: recorded facts + ruled-out findings.
        negative_memory: list[dict[str, Any]] = []
        seen: set[tuple[tuple[str, Any], ...]] = set()

        def _add(entry: dict[str, Any]) -> None:
            sig = tuple(sorted(entry.items()))
            if sig in seen:
                return
            seen.add(sig)
            negative_memory.append(entry)

        # Recorded facts in hunt_memory.
        try:
            with self.ledger._lock:
                rows = self.ledger._conn.execute(
                    "SELECT run_id, key, payload FROM hunt_memory WHERE kind = ?",
                    ("negative",),
                ).fetchall()
        except Exception:
            rows = []
        for row_run_id, key, payload_raw in rows:
            if run_id is not None and row_run_id != run_id:
                continue
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            reason = ""
            if isinstance(payload, dict):
                reason = payload.get("reason", "")
                if reason is None:
                    reason = ""
            _add(
                {
                    "run_id": row_run_id,
                    "klass": key,
                    "reason": str(reason),
                }
            )

        # Ruled-out findings (reason from the status-change trail).
        reason_by_finding: dict[Any, str] = {}
        try:
            for event in self.ledger.events():
                kind = getattr(event, "kind", None)
                kind_val = getattr(kind, "value", kind)
                payload = getattr(event, "payload", None) or {}
                if not isinstance(payload, dict):
                    continue
                if str(kind_val) != "finding_status_changed":
                    continue
                if str(payload.get("new_status", "")).lower() != "ruled_out":
                    continue
                fid = payload.get("finding_id")
                reason_by_finding[fid] = payload.get("reason", "") or ""

        except Exception:
            reason_by_finding = {}

        try:
            findings = self.ledger.findings()
        except Exception:
            findings = []
        for finding in findings:
            status = getattr(finding, "status", None)
            status_val = getattr(status, "value", status)
            if str(status_val).lower() != "ruled_out":
                continue
            f_run_id = getattr(finding, "run_id", None)
            if run_id is not None and f_run_id != run_id:
                continue
            reason = reason_by_finding.get(getattr(finding, "id", None))
            if not reason:
                reason = getattr(finding, "falsifier", "") or ""
            if not reason:
                reason = getattr(finding, "description", "") or ""
            _add(
                {
                    "run_id": f_run_id,
                    "klass": getattr(finding, "klass", "unknown") or "unknown",
                    "reason": str(reason),
                }
            )

        return {
            "skill_patches": skill_patches,
            "promotions": promotions,
            "negative_memory": negative_memory,
        }

    # -- memory helpers ------------------------------------------------------
    def record_negative(self, run_id: Any, klass: Any, reason: Any) -> None:
        with self.ledger._write() as conn:
            mid = self.ledger._next_id(conn, "hunt_memory", "HM")
            conn.execute(
                "INSERT INTO hunt_memory (id, run_id, kind, key, payload, created_seq) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    mid,
                    run_id,
                    "negative",
                    str(klass),
                    canonical_json({"reason": reason}),
                    None,
                ),
            )

    def skill_use_count(self, skill_name: Any) -> int:
        with self.ledger._lock:
            row = self.ledger._conn.execute(
                "SELECT COUNT(*) FROM hunt_memory WHERE kind = ? AND key = ?",
                ("skill_use", str(skill_name)),
            ).fetchone()
        return int(row[0]) if row else 0

    def promote_pattern(self, klass: Any, runs: Any) -> bool:
        try:
            return len(list(runs)) >= 2
        except TypeError:
            return False
