"""RAG workflow — Recursive Autonomous Grind on top of the existing hunt pipeline.

RAG is NOT a parallel workflow. It reuses ``hunter.workflow.pipeline.run_scan``
and the daemon queue: it keeps the queue at a high-water mark, turns findings
into follow-up hunts (4 per finding), and never lets the daemon go idle while
the time budget lasts.
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from hunter.daemon import (
    drain_daemon,
    enqueue_task,
    queue_dir,
    start_daemon,
    stop_flag_path,
)
from hunter.kernel.findings import Finding
from hunter.kernel.ledger import Ledger
from hunter.runtime_paths import RuntimePaths
from hunter.tools.scope import ScopeSet

__all__ = [
    "RagConfig",
    "RagLoop",
    "derive_child_targets",
    "existing_targets",
    "followed_findings",
    "mark_followed",
    "normalize_finding_target",
    "wonder_followups",
]


def _state_path(state_dir: Path) -> Path:
    return Path(state_dir) / "rag-state.json"


def load_rag_state(state_dir: Path) -> dict[str, Any]:
    path = _state_path(state_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {"followed": [], "cycle": 0, "last_ts": None, "last_finding_count": 0}
    if not isinstance(data, dict):
        return {"followed": [], "cycle": 0, "last_ts": None, "last_finding_count": 0}
    data.setdefault("followed", [])
    data.setdefault("cycle", 0)
    data.setdefault("last_ts", None)
    data.setdefault("last_finding_count", 0)
    return data


def save_rag_state(state_dir: Path, state: dict[str, Any]) -> None:
    path = _state_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{id(state)}.tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    import os

    os.replace(tmp, path)


def existing_targets(state_dir: Path) -> set[str]:
    """All targets already in the queue (task/claimed/done)."""
    folder = queue_dir(state_dir)
    folder.mkdir(parents=True, exist_ok=True)
    targets: set[str] = set()
    for path in folder.glob("*.json"):
        try:
            import json as _json

            data = _json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if isinstance(data, dict) and data.get("target"):
            targets.add(str(data["target"]))
    return targets


def followed_findings(state_dir: Path) -> set[str]:
    state = load_rag_state(state_dir)
    return {str(x) for x in (state.get("followed") or [])}


def mark_followed(state_dir: Path, finding_id: str) -> None:
    state = load_rag_state(state_dir)
    followed = [str(x) for x in (state.get("followed") or [])]
    if finding_id not in followed:
        followed.append(finding_id)
    state["followed"] = followed
    save_rag_state(state_dir, state)


def normalize_finding_target(finding: Finding, origin: str) -> str | None:
    """Turn a finding endpoint into an in-scope absolute URL (best effort)."""
    endpoint = str(getattr(finding, "endpoint", "") or "").strip()
    if not endpoint:
        return None
    # Already absolute.
    if "://" in endpoint:
        return endpoint
    # Relative path -> attach to origin.
    base = origin.rstrip("/")
    if endpoint.startswith("/"):
        return f"{base}{endpoint}"
    # Bare host or path without leading slash: try origin + /.
    return f"{base}/{endpoint.lstrip('/')}"


def derive_child_targets(finding: Finding, scope: ScopeSet, origin: str) -> list[str]:
    """Deterministic in-scope child targets derived from a finding endpoint."""
    # Dir-mode origins (a filesystem path, not a URL) have no meaningful
    # endpoint concatenation — fail closed to an empty target list.
    if not origin.lower().startswith(("http://", "https://")):
        return []
    target = normalize_finding_target(finding, origin)
    if not target:
        return []
    out: list[str] = []
    try:
        scope.check_url(target)
    except Exception:  # noqa: BLE001
        return []
    out.append(target)
    # A few deterministic siblings (path parent) when applicable.
    parsed = urlparse(target)
    path = parsed.path or "/"
    if path not in ("", "/"):
        parent = path.rstrip("/").rsplit("/", 1)[0] or "/"
        if parent != path:
            sibling = urlunparse((parsed.scheme, parsed.netloc, parent, "", parsed.query, ""))
            try:
                scope.check_url(sibling)
                if sibling != target:
                    out.append(sibling)
            except Exception:  # noqa: BLE001
                pass
    # Dedup preserve order.
    seen: set[str] = set()
    uniq: list[str] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def _parse_json_list(text: str) -> list[str]:
    text = (text or "").strip()
    if text.startswith("```"):
        # strip markdown fence
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    # Find a JSON array anywhere in the text.
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [str(x).strip() for x in data if str(x).strip()]


def wonder_followups(provider: Any, finding: Finding, scope: ScopeSet, origin: str) -> list[str]:
    """Ask the LLM (utility tier) for exactly 4 in-scope follow-up targets."""
    if provider is None:
        return []
    endpoint = str(getattr(finding, "endpoint", "") or "")
    title = str(getattr(finding, "title", "") or "")
    severity = getattr(getattr(finding, "severity", None), "value", str(getattr(finding, "severity", "")))
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security-hunt planner. Given one finding, propose EXACTLY 4 "
                "in-scope follow-up URLs to hunt next (deeper variants, siblings, "
                "parameters). Return ONLY a JSON array of 4 strings. No prose."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Finding: {title}\nSeverity: {severity}\nEndpoint: {endpoint}\n"
                f"Origin: {origin}\nAllowed hosts: {sorted(scope.allowed_hosts)}\n"
                "Return JSON array of exactly 4 URLs."
            ),
        },
    ]
    try:
        turn = provider.complete("utility", messages, budget=None)
    except Exception:  # noqa: BLE001
        return []
    text = getattr(turn, "text", "") or ""
    candidates = _parse_json_list(text)
    out: list[str] = []
    seen: set[str] = set()
    for cand in candidates:
        try:
            scope.check_url(cand)
        except Exception:  # noqa: BLE001
            continue
        if cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
        if len(out) >= 4:
            break
    return out


@dataclass
class RagConfig:
    state_dir: Path
    target: str
    scope: ScopeSet
    engine: str = "llm"
    time_budget_s: float = 6 * 3600
    # Wall-clock slice for ONE child hunt. Every enqueued task gets this as both
    # its max_wall and its min_time floor, so a child works the whole slice
    # instead of yielding after a few minutes. Keep it well under
    # time_budget_s so one wedged child cannot monopolise the queue.
    child_time_s: float = 20 * 60
    interval_s: float = 45.0
    high_water: int = 8
    max_seed_variants: int = 8
    dry_run: bool = False
    once: bool = False
    manage_daemon: bool = True
    provider: Any = None


class RagLoop:
    def __init__(self, config: RagConfig) -> None:
        self.config = config
        self.state_dir = Path(config.state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _ledger(self) -> Ledger:
        db = RuntimePaths.resolve(state=self.state_dir, migrate=False).ledger
        return Ledger(db)

    def _origin(self) -> str:
        parsed = urlparse(self.config.target)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return self.config.target.rstrip("/")

    def _enqueue(self, target: str, parent_finding_id: str | None = None) -> bool:
        from hunter.daemon import _validate_hunt_task

        task = {
            "target": str(target),
            "scope": {
                "name": str(self.config.scope.name),
                "hosts": sorted(self.config.scope.allowed_hosts),
                "allow_subdomains": bool(self.config.scope.allow_subdomains),
            },
            "engine": str(self.config.engine),
            "max_wall_seconds": float(self.config.time_budget_s),
            "max_cost_usd": 0.0,
            # A RAG child must not carry the FULL remaining budget as its own
            # max_wall: one stuck child would then monopolise the queue for the
            # whole mandate. Give it a slice, and give it the same slice as a
            # min-time floor so it actually uses it instead of calling
            # finish_scan after three minutes (floor 0.0 used to mean "no
            # floor", so children stopped as soon as the model felt done).
            "max_iterations": 0,
        }
        slice_s = min(
            float(self.config.time_budget_s),
            float(self.config.child_time_s) if self.config.child_time_s else float(self.config.time_budget_s),
        )
        task["max_wall_seconds"] = slice_s
        task["min_wall_seconds"] = slice_s
        if parent_finding_id:
            task["parent_finding_id"] = str(parent_finding_id)
        try:
            _validate_hunt_task(task)
        except ValueError:
            return False
        if self.config.dry_run:
            print(f"[dry-run] would enqueue {target}")
            return True
        try:
            enqueue_task(self.state_dir, task)
        except Exception:  # noqa: BLE001
            return False
        return True

    def _cycle(self) -> list[str]:
        """One feeder cycle. Returns list of enqueued targets."""
        enqueued: list[str] = []
        state = load_rag_state(self.state_dir)
        followed = {str(x) for x in (state.get("followed") or [])}
        existing = existing_targets(self.state_dir)

        ledger = self._ledger()
        try:
            findings = ledger.findings()
        except Exception:  # noqa: BLE001
            findings = []
        finally:
            with contextlib.suppress(Exception):
                ledger.close()

        pending = len(list(queue_dir(self.state_dir).glob("task-*.json")))

        # Smart scheduling. The old rule was a flat "4 hunters per finding",
        # which turns a few hundred candidates into a few thousand queued
        # hunts on a 2 GB box — the queue becomes its own denial of service.
        # The budget is sized from available memory and the existing backlog,
        # and each finding's allowance comes from its severity.
        from hunter.workflow.scheduler import plan_children, task_budget

        budget = task_budget(high_water=self.config.high_water, pending=pending)
        plan = plan_children(
            findings,
            followed=followed,
            existing=existing,
            budget=budget,
            high_water=self.config.high_water,
            pending=pending,
        )

        # Finding-driven work: allowance per finding, not a fixed four.
        for finding, allowance in plan:
            fid = str(getattr(finding, "id", "") or "")
            origin = self._origin()
            targets = list(wonder_followups(self.config.provider, finding, self.config.scope, origin))
            # Pad to the allowance with deterministic derivations when possible.
            if len(targets) < allowance:
                for t in derive_child_targets(finding, self.config.scope, origin):
                    if t not in targets:
                        targets.append(t)
                    if len(targets) >= allowance:
                        break
            # If still short, pad with the finding endpoint itself (already included) — stop.
            enqueued_for_finding = 0
            for target in targets:
                if pending >= budget.max_total_pending:
                    break
                if target in existing:
                    continue
                if self._enqueue(target, parent_finding_id=fid):
                    enqueued.append(target)
                    existing.add(target)
                    pending += 1
                    enqueued_for_finding += 1
            # Mark followed only when real work happened: children were
            # enqueued, or every derived target is already in the queue.
            already_queued = bool(targets) and all(t in existing for t in targets)
            if enqueued_for_finding > 0 or already_queued:
                mark_followed(self.state_dir, fid)
                followed.add(fid)

        # High-water guard: fill with REAL scope targets, not the seed URL
        # wearing a query-string hat. `?rag-cycle=N` dials the same endpoint
        # N times with a junk parameter — that is not hunting, it is a
        # self-inflicted DoS on our own budget. Every host in the approved
        # scope is a legitimate target; walk them instead.
        origin = self._origin()
        cycle = int(state.get("cycle", 0) or 0)
        # Dedup on (scheme, host), not the raw string: `http://example.com`
        # and `https://example.com/` are the same host, and a string-set
        # would happily queue both.
        seen_hosts = {
            (urlparse(t).scheme, urlparse(t).hostname or "")
            for t in existing
        }
        for host in sorted(self.config.scope.allowed_hosts):
            if pending >= budget.max_total_pending:
                break
            if cycle >= self.config.max_seed_variants:
                break
            candidate = f"https://{host}/"
            if ("https", host) in seen_hosts:
                continue  # already queued under either scheme
            try:
                self.config.scope.check_url(candidate)
            except Exception:  # noqa: BLE001
                continue
            if self._enqueue(candidate):
                cycle += 1
                enqueued.append(candidate)
                existing.add(candidate)
                seen_hosts.add(("https", host))
                pending += 1

        state["cycle"] = cycle
        state["last_ts"] = time.time()
        state["last_finding_count"] = len(findings)
        save_rag_state(self.state_dir, state)
        return enqueued

    def run(self) -> int:
        if self.config.manage_daemon and not self.config.dry_run:
            # A daemon that fails to start must be LOUD. Swallowing it here
            # produced a RAG loop that enqueued tasks into a queue nothing
            # was consuming — the operator saw a running process and an
            # idle ledger with no way to tell which half was broken.
            try:
                from hunter.daemon import daemon_running

                running, detail = daemon_running(self.state_dir)
                if not running:
                    start_daemon(
                        self.state_dir,
                        target=self.config.target,
                        scope=self.config.scope,
                        engine=self.config.engine,
                        max_wall_seconds=float(self.config.time_budget_s),
                        max_cost_usd=0.0,
                        # The daemon-level floor governs how long the SUPERVISOR
                        # keeps refilling the queue; it is not a per-task floor
                        # (each task carries its own, see _enqueue). Passing 0
                        # here made the whole RAG mandate yield to the first
                        # quiet cycle.
                        min_wall_seconds=float(self.config.time_budget_s),
                        force=False,
                    )
                    running, detail = daemon_running(self.state_dir)
                    if not running:
                        print(
                            f"[rag] BLOCKED: daemon did not start ({detail}) — "
                            f"tasks will be queued but nothing will run them. "
                            f"check: hunt status --state {self.state_dir}",
                            flush=True,
                        )
                        return 3
            except Exception as exc:  # noqa: BLE001
                print(f"[rag] BLOCKED: daemon start raised {type(exc).__name__}: {exc}",
                      flush=True)
                return 3

        deadline = time.monotonic() + float(self.config.time_budget_s)
        last_finding_count = 0
        cycles = 0
        total_enqueued = 0
        while True:
            if stop_flag_path(self.state_dir).exists():
                print(f"[rag] stop flag present — winding down after {cycles} cycle(s)",
                      flush=True)
                break
            if time.monotonic() >= deadline:
                break
            enqueued = self._cycle()
            cycles += 1
            total_enqueued += len(enqueued)
            # Track new findings for the closing report.
            try:
                ledger = self._ledger()
                current_count = len(ledger.findings())
                ledger.close()
            except Exception:  # noqa: BLE001
                current_count = last_finding_count
            delta = current_count - last_finding_count
            last_finding_count = current_count

            # Every cycle reports itself. A silent loop is indistinguishable
            # from a dead one, and the operator cannot tell "nothing found"
            # from "nothing ran" without it.
            pending = len(list(queue_dir(self.state_dir).glob("task-*.json")))
            line = (f"[rag] cycle {cycles}: enqueued={len(enqueued)} "
                    f"pending={pending} findings={current_count}")
            if delta > 0:
                line += f" (+{delta} new)"
            print(line, flush=True)

            if self.config.once:
                break
            # Sleep interval but wake on deadline.
            sleep_for = min(float(self.config.interval_s), max(0.0, deadline - time.monotonic()))
            if sleep_for <= 0:
                break
            time.sleep(sleep_for)

        # Deadline handling: drain, let in-flight finish.
        if not self.config.dry_run:
            with contextlib.suppress(Exception):
                drain_daemon(self.state_dir, timeout=15.0)

        # Closing summary, printed in EVERY mode including --once. Without it
        # a single-cycle run exits 0 with no output at all, which reads as
        # "nothing happened" whether or not tasks were queued.
        try:
            ledger = self._ledger()
            final_findings = len(ledger.findings())
            ledger.close()
        except Exception:  # noqa: BLE001
            final_findings = last_finding_count
        print(
            f"[rag] done: cycles={cycles} enqueued={total_enqueued} "
            f"findings={final_findings} state={self.state_dir}",
            flush=True,
        )

        # Deadline reached. Report honestly rather than prompting for an
        # extension this loop cannot honour: the deadline is a monotonic
        # bound captured before the while-loop, so answering "y" here used
        # to fall into an empty branch and change nothing. The daemon is
        # left running (drained above) so the operator can re-run
        # `hunter rag` with a fresh --time if they want more.
        if not self.config.dry_run and not self.config.once:
            try:
                ledger = self._ledger()
                current_count = len(ledger.findings())
                ledger.close()
            except Exception:  # noqa: BLE001
                current_count = 0
            if current_count > 0:
                print(
                    f"waktu habis — {current_count} finding tercatat. "
                    f"daemon dibiarkan berjalan; jalankan `hunter hunt` lagi "
                    f"dengan --time lebih besar untuk melanjutkan."
                )
        return 0


def run_rag(config: RagConfig) -> int:
    return RagLoop(config).run()
