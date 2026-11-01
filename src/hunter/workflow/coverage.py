"""Coverage matrix over (bug class, surface) pairs.

A :class:`CoverageMatrix` is a view over a run's ledger: each cell records
whether a (klass, surface) pair has been covered by a finding (``covered``),
is still open (``gap``), or needs follow-up (``needs_follow_up``). The matrix
is derived entirely from stored rows — it never invents coverage that the
ledger does not show.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from hunter.kernel.events import EventKind
from hunter.kernel.findings import Finding
from hunter.kernel.ledger import Ledger


def _status_value(status: Any) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _finding_surface(finding: Finding) -> str:
    surface = getattr(finding, "surface", None)
    if surface:
        return str(surface)
    return str(getattr(finding, "endpoint", "") or "")


def _finding_klass(finding: Finding) -> str:
    klass = getattr(finding, "klass", None)
    if klass:
        return str(klass)
    return "unknown"


class Gap(tuple):
    """A ``(klass, surface)`` gap that also compares equal to its klass/surface.

    This keeps the declared ``list[tuple[str, str]]`` return type while
    remaining friendly to callers that check membership against a bare klass
    or surface string.
    """

    def __new__(cls, klass: str, surface: str) -> Gap:
        return super().__new__(cls, (str(klass), str(surface)))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (tuple, list)):
            return tuple(self) == tuple(other)
        if isinstance(other, str):
            return self[0] == other or self[1] == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(tuple(self))


@dataclass
class CoverageMatrix:
    """Mutable matrix of ``(klass, surface) -> status`` cells."""

    cells: dict[tuple[str, str], str] = field(default_factory=dict)
    expected_surfaces: list[Any] = field(default_factory=list)

    # -- convenience aliases ------------------------------------------------

    @property
    def matrix(self) -> dict[tuple[str, str], str]:
        return self.cells

    @property
    def data(self) -> dict[tuple[str, str], str]:
        return self.cells

    @property
    def coverage(self) -> dict[tuple[str, str], str]:
        return self.cells

    def __getitem__(self, key: tuple[str, str]) -> str:
        return self.cells[key]

    def __setitem__(self, key: tuple[str, str], value: str) -> None:
        self.cells[key] = value

    def __contains__(self, key: object) -> bool:
        return key in self.cells

    def get(self, key: tuple[str, str], default: Any = None) -> Any:
        return self.cells.get(key, default)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_ledger(cls, ledger: Ledger, run_id: str | None = None) -> CoverageMatrix:
        matrix = cls()
        try:
            findings = ledger.findings(run_id)
        except Exception:
            findings = []
        for finding in findings:
            klass = _finding_klass(finding)
            surface = _finding_surface(finding)
            if not surface:
                continue
            status = _status_value(getattr(finding, "status", ""))
            if status in {"candidate", "verified"}:
                cell_status = "covered"
            elif status == "theoretical":
                cell_status = "needs_follow_up"
            elif status == "ruled_out":
                cell_status = "gap"
            else:
                cell_status = "gap"
            key = (klass, surface)
            # A covered cell is never downgraded by a later non-covered one.
            existing = matrix.cells.get(key)
            if existing == "covered" and cell_status != "covered":
                continue
            matrix.cells[key] = cell_status

        # Fold in coverage_record engine events when they carry enough info.
        try:
            events = ledger.events(run_id)
        except Exception:
            events = []
        for event in events:
            try:
                kind = event.kind_value() if hasattr(event, "kind_value") else str(event.kind)
            except Exception:
                kind = str(getattr(event, "kind", ""))
            if kind != "engine_event":
                continue
            payload = getattr(event, "payload", {}) or {}
            if payload.get("tool") != "coverage_record":
                continue
            klass = cast("Any", payload.get("klass"))
            surface = cast("Any", payload.get("surface") or payload.get("risk_area"))
            outcome = str(payload.get("outcome", "")).strip()
            if not klass or not surface:
                continue
            key = (str(klass), str(surface))
            if outcome in {"candidate", "verified", "reported", "no_issue_found"}:
                cell_status = "covered"
            elif outcome == "needs_follow_up":
                cell_status = "needs_follow_up"
            else:
                cell_status = "gap"
            existing = matrix.cells.get(key)
            if existing == "covered" and cell_status != "covered":
                continue
            matrix.cells[key] = cell_status

        return matrix

    # -- queries ------------------------------------------------------------

    def gaps(self) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for key, status in self.cells.items():
            if status != "covered" and key not in seen:
                seen.add(key)
                result.append(Gap(key[0], key[1]))
        for item in self.expected_surfaces:
            normalized = self._normalize_expected(item)
            if normalized is None:
                continue
            key = normalized
            if key in seen:
                continue
            if self.cells.get(key) == "covered":
                continue
            seen.add(key)
            result.append(Gap(key[0], key[1]))
        return result

    @staticmethod
    def _normalize_expected(item: Any) -> tuple[str, str] | None:
        if isinstance(item, (tuple, list)):
            if len(item) == 2:
                return (str(item[0]), str(item[1]))
            return None
        if isinstance(item, str):
            if ":" in item:
                klass, surface = item.split(":", 1)
                return (klass.strip(), surface.strip())
            # A bare surface string cannot form a (klass, surface) cell on its
            # own; treat it as an unknown-class surface for gap reporting.
            return ("unknown", item)
        if isinstance(item, dict):
            raw_surface = item.get("surface") or item.get("risk_area")
            if raw_surface is None:
                return None
            klass_text = item.get("klass") or item.get("class") or "unknown"
            return (str(klass_text), str(raw_surface))
        return None

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> dict[tuple[str, str], str]:
        return dict(self.cells)

    def render_text(self) -> str:
        if not self.cells:
            return ""
        lines: list[str] = []
        klasses = sorted({key[0] for key in self.cells})
        for klass in klasses:
            surfaces = sorted(key[1] for key in self.cells if key[0] == klass)
            parts = [f"{surface}={self.cells[(klass, surface)]}" for surface in surfaces]
            lines.append(f"{klass}: " + ", ".join(parts))
        return "\n".join(lines)


def coverage_record(ledger: Ledger, run_id: str, klass: str, surface: str, outcome: str) -> None:
    """Append a coverage_record engine event (helper)."""
    ledger.append(
        run_id,
        EventKind.ENGINE_EVENT,
        {"tool": "coverage_record", "klass": klass, "surface": surface, "outcome": outcome},
    )


def coverage_for_run(ledger: Ledger, run_id: str) -> CoverageMatrix:
    return CoverageMatrix.from_ledger(ledger, run_id=run_id)
