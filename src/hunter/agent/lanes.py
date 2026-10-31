"""Lightweight "lane" abstraction for fanning out audit work.

A :class:`Lane` is a small budgeted bucket of findings (recon, web2, web3,
network, chainer, verifier, curator, ...).  :class:`LaneRunner` runs a work
function over a set of lanes, enforcing per-lane budgets plus an optional
global cap, and can flatten the resulting findings.

Pure logic: no network, no LLM.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Lane:
    """A budgeted lane of work.

    ``budget`` is the *remaining* budget for this lane; :meth:`consume`
    decrements it.  ``findings`` collects whatever the lane produces and
    ``context`` carries arbitrary per-lane state.
    """

    name: str
    budget: int = 0
    findings: list[Any] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = str(self.name)
        self.budget = _as_int(self.budget, 0)
        if self.findings is None:
            self.findings = []
        if not isinstance(self.findings, list):
            self.findings = list(self.findings)
        if self.context is None:
            self.context = {}
        if not isinstance(self.context, dict):
            self.context = dict(self.context)

    def consume(self, n: int = 1) -> bool:
        """Consume ``n`` units of budget.  False (no mutation) when exhausted."""
        n = _as_int(n, 1)
        if n <= 0:
            return True
        if self.budget < n:
            return False
        self.budget -= n
        return True

    def remaining(self) -> int:
        return int(self.budget)

    # Convenience aliases some callers/tests may use.
    def remaining_budget(self) -> int:
        return self.remaining()

    def is_exhausted(self) -> bool:
        return self.budget <= 0


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


class LaneRunner:
    """Runs work across multiple lanes with per-lane + global budgets."""

    def __init__(
        self,
        global_budget: Any = None,
        *,
        lanes: Any = None,
        **kwargs: Any,
    ) -> None:
        # Allow ``LaneRunner([...lanes...])``.
        if isinstance(global_budget, (list, tuple)):
            lanes = list(global_budget)
            global_budget = None

        cap = _first_not_none(
            kwargs.pop("cap", None),
            kwargs.pop("global_cap", None),
            kwargs.pop("max_global", None),
            kwargs.pop("max_budget", None),
            kwargs.pop("total", None),
            kwargs.pop("global", None),
            kwargs.pop("budget", None),
            global_budget,
        )
        # If a dict of lanes was passed via kwargs, accept it.
        if lanes is None:
            lanes = kwargs.pop("lanes_list", None)

        self.global_budget = None if cap is None else _as_int(cap, 0)
        self.lanes: list[Lane] = list(lanes) if lanes else []
        self._global_remaining: int | None = self.global_budget
        self._stopped: set[int] = set()

    # -- global budget helpers ---------------------------------------------
    @property
    def global_remaining(self) -> int | None:
        return self._global_remaining

    @property
    def cap(self) -> int | None:
        return self.global_budget

    def remaining_global(self) -> int | None:
        return self._global_remaining

    def consume_global(self, n: int = 1) -> bool:
        if self._global_remaining is None:
            return True
        n = _as_int(n, 1)
        if n <= 0:
            return True
        if self._global_remaining < n:
            return False
        self._global_remaining -= n
        return True

    def reset_global(self) -> None:
        self._global_remaining = self.global_budget

    # -- fan out -----------------------------------------------------------
    def fan_out(self, lanes: Any = None, work_fn: Callable[[Lane], Any] = None) -> list[Any]:
        if work_fn is None and callable(lanes):
            # Allow fan_out(work_fn) when lanes already stored.
            work_fn = lanes
            lanes = self.lanes
        if lanes is None:
            lanes = self.lanes
        lanes = list(lanes) if lanes is not None else []
        if work_fn is None:
            raise ValueError("work_fn is required")

        self._global_remaining = self.global_budget
        results: list[Any] = []
        for lane in lanes:
            # Global cap: stop scheduling further lanes once exhausted.
            if self._global_remaining is not None and self._global_remaining <= 0:
                results.append(None)
                continue
            # Enforce the global cap without corrupting the lane's own budget:
            # run work_fn against a proxy whose budget is capped, then mirror
            # the consumed amount + findings/context back onto the real lane.
            if self._global_remaining is not None and isinstance(lane, Lane):
                proxy = Lane(
                    name=lane.name,
                    budget=min(lane.budget, self._global_remaining),
                    findings=lane.findings,
                    context=lane.context,
                )
            else:
                proxy = lane
            before_lane = lane.budget if isinstance(lane, Lane) else 0
            proxy_before = proxy.budget if isinstance(proxy, Lane) else 0
            try:
                result = work_fn(proxy)
            except Exception:  # noqa: BLE001 - lanes are independent
                result = None
            results.append(result)
            if isinstance(lane, Lane):
                if proxy is not lane:
                    consumed = proxy_before - (proxy.budget if isinstance(proxy, Lane) else 0)
                    if consumed < 0:
                        consumed = 0
                    lane.budget = max(0, lane.budget - consumed)
                    lane.findings = proxy.findings
                    lane.context = proxy.context
                else:
                    consumed = before_lane - lane.budget
                    if consumed < 0:
                        consumed = 0
                if self._global_remaining is not None:
                    self._global_remaining -= consumed
                    if self._global_remaining < 0:
                        self._global_remaining = 0
                if lane.remaining() <= 0:
                    self._stopped.add(id(lane))
        return results

    def run_lane(self, lane: Lane, work_fn: Callable[[Lane], Any]) -> Any:
        return work_fn(lane)

    def stop_lane(self, lane: Lane) -> None:
        self._stopped.add(id(lane))
        if isinstance(lane, Lane):
            lane.budget = 0

    def is_stopped(self, lane: Lane) -> bool:
        return id(lane) in self._stopped or (isinstance(lane, Lane) and lane.remaining() <= 0)

    # -- merge -------------------------------------------------------------
    @staticmethod
    def merge(results: Any) -> list[Any]:
        return merge(results)

    # Back-compat: some callers may expect a method named merge_findings.
    def merge_findings(self, results: Any) -> list[Any]:
        return merge(results)


def _extract_findings(item: Any, out: list[Any]) -> None:
    """Recursively flatten findings from a fan_out result item."""
    if item is None:
        return
    if isinstance(item, Lane):
        for f in item.findings:
            _extract_findings(f, out)
        return
    if isinstance(item, (list, tuple)):
        for sub in item:
            _extract_findings(sub, out)
        return
    if isinstance(item, dict):
        if "findings" in item:
            _extract_findings(item.get("findings"), out)
            return
        # A dict that is itself a finding.
        out.append(item)
        return
    findings_attr = getattr(item, "findings", None)
    if findings_attr is not None and findings_attr is not item:
        for f in (findings_attr if isinstance(findings_attr, (list, tuple)) else [findings_attr]):
            _extract_findings(f, out)
        return
    out.append(item)


def merge(results: Any) -> list[Any]:
    """Flatten findings from fan_out results (module-level helper)."""
    out: list[Any] = []
    if results is None:
        return out
    if isinstance(results, (list, tuple)):
        for item in results:
            _extract_findings(item, out)
    else:
        _extract_findings(results, out)
    return out


_DEFAULT_SPECS: tuple[tuple[str, int], ...] = (
    ("recon", 20),
    ("web2", 50),
    ("web3", 50),
    ("network", 30),
    ("chainer", 40),
    ("verifier", 30),
    ("curator", 10),
)


def default_lanes() -> list[Lane]:
    return [Lane(name=name, budget=budget) for name, budget in _DEFAULT_SPECS]


__all__ = [
    "Lane",
    "LaneRunner",
    "default_lanes",
    "merge",
]
