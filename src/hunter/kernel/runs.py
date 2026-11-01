"""Run lifecycle — closing a run seals it (RETENTION-SPEC Part A).

A *run* is one hunt against one target. While open it is writable: evidence,
findings and status changes may be appended. Closing it is a one-way seal:
``runs.closed_at`` is stamped, a summary is written, and a ``run_closed``
event joins the hash chain. After that, ``assert_run_writable`` refuses every
mutation for that run — reads (replay, reports, verify) are untouched.

The seal is deliberately WEAKER than the append-only triggers in
:mod:`hunter.kernel.ledger`: it is an application-layer guard because the
``runs`` row is the only mutable row in the schema. It never deletes anything.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from .findings import FindingStatus, Severity
from .ledger import Ledger

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass

__all__ = [
    "OUTCOMES",
    "PROVABLE_SEVERITIES",
    "RunAlreadyClosed",
    "RunClosure",
    "RunClosed",
    "RunLifecycleError",
    "RunNotFound",
    "assert_run_writable",
    "close_run",
    "is_run_closed",
    "run_is_closed",
]

#: Outcomes accepted by `hunt close --outcome`.
OUTCOMES = frozenset({"proven", "partial", "blocked", "abandoned"})

#: Severities that make a proven-live finding promotion-eligible (Part C).
PROVABLE_SEVERITIES = frozenset({Severity.CRITICAL.value, Severity.HIGH.value})

_RUN_CLOSED_KIND = "run_closed"


class RunLifecycleError(Exception):
    """Base class for run-lifecycle refusals."""


class RunNotFound(RunLifecycleError):
    """No row in ``runs`` for that id (or the ledger has no runs table)."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(f"run '{run_id}' not found")


class RunAlreadyClosed(RunLifecycleError):
    """``closed_at IS NOT NULL`` — closing twice is refused, first seal kept."""

    def __init__(self, run_id: str, closed_at: float | None = None) -> None:
        self.run_id = run_id
        self.closed_at = closed_at
        when = f" at {closed_at}" if closed_at is not None else ""
        super().__init__(f"run '{run_id}' is already closed{when}")


class RunClosed(RunLifecycleError):
    """A mutation was attempted against a closed run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(
            f"run '{run_id}' is closed — it accepts no new evidence, findings or"
            " status changes (reads still work)"
        )


@dataclass(frozen=True, slots=True)
class RunClosure:
    """Immutable record of a seal. Mirrors the persisted ``summary_json``."""

    run_id: str
    outcome: str
    started_ts: float | None
    ended_ts_real: float
    closed_at: float
    findings_total: int = 0
    findings_proven: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    evidence_total: int = 0
    events_total: int = 0
    promotions: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """The dict persisted in ``runs.summary_json`` and the event payload."""
        return asdict(self)

    def to_json(self) -> str:
        from .events import canonical_json

        return canonical_json(self.summary())


# -- internals ------------------------------------------------------------------


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _run_row(ledger: Ledger, run_id: str) -> dict[str, Any] | None:
    conn = ledger._conn  # noqa: SLF001 - kernel-internal, same package
    try:
        row = conn.execute(
            "SELECT run_id, target, engine, scope_name, started_ts, ended_ts, status,"
            " outcome, closed_at, summary_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    except Exception:  # noqa: BLE001 - pre-v3 db without the columns/migration
        return None
    if row is None:
        return None
    keys = (
        "run_id",
        "target",
        "engine",
        "scope_name",
        "started_ts",
        "ended_ts",
        "status",
        "outcome",
        "closed_at",
        "summary_json",
    )
    return dict(zip(keys, row, strict=False))


def run_is_closed(ledger: Ledger, run_id: str) -> bool:
    """True when the run row exists AND carries a ``closed_at`` stamp."""
    with ledger._lock:  # noqa: SLF001
        row = _run_row(ledger, run_id)
    return row is not None and row.get("closed_at") is not None


#: Public alias matching the spec's ``is_run_closed(...)`` wording.
is_run_closed = run_is_closed


def assert_run_writable(ledger: Ledger, run_id: str) -> None:
    """Raise :class:`RunClosed` when ``run_id`` has been sealed.

    An unknown run id is NOT an error here: some write paths (transcripts,
    memory rows) carry synthetic run ids that never got a ``runs`` row, and
    those were writable before this guard existed. Only a *closed* run blocks.
    """
    if run_is_closed(ledger, run_id):
        raise RunClosed(run_id)


def _derive_outcome(findings: list[Any]) -> str:
    if any(
        _enum_value(f.status) == FindingStatus.VERIFIED.value
        and _enum_value(f.severity) in PROVABLE_SEVERITIES
        for f in findings
    ):
        return "proven"
    if findings:
        return "partial"
    return "blocked"


def _promotions(findings: list[Any]) -> list[str]:
    """Promotion candidates (Part C eligibility): proven-live + critical/high."""
    keys = [
        str(f.key)
        for f in findings
        if _enum_value(f.status) == FindingStatus.VERIFIED.value
        and _enum_value(f.severity) in PROVABLE_SEVERITIES
    ]
    return sorted(set(keys))


def close_run(ledger: Ledger, run_id: str, *, outcome: str | None = None) -> RunClosure:
    """Seal ``run_id``: stamp outcome/closed_at/summary_json + append the event.

    One ``BEGIN IMMEDIATE`` transaction covers the ``runs`` UPDATE and the
    chained ``run_closed`` event — a crash between them is impossible, and a
    refusal (unknown/closed run, bad outcome) leaves the ledger untouched.
    """
    if outcome is not None:
        outcome = str(outcome).strip().lower()
        if outcome not in OUTCOMES:
            raise ValueError(
                f"invalid outcome {outcome!r}; choose from {sorted(OUTCOMES)}"
            )

    with ledger._write() as conn:
        row = _run_row(ledger, run_id)
        if row is None:
            raise RunNotFound(run_id)
        if row.get("closed_at") is not None:
            raise RunAlreadyClosed(run_id, row.get("closed_at"))

        findings = ledger.findings(run_id)
        by_severity: dict[str, int] = {}
        for f in findings:
            sev = _enum_value(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
        by_severity = dict(sorted(by_severity.items(), key=lambda kv: kv[0]))

        now = time.time()
        resolved = outcome or _derive_outcome(findings)
        closure = RunClosure(
            run_id=run_id,
            outcome=resolved,
            started_ts=row.get("started_ts"),
            ended_ts_real=now,
            closed_at=now,
            findings_total=len(findings),
            findings_proven=sum(
                1
                for f in findings
                if _enum_value(f.status) == FindingStatus.VERIFIED.value
            ),
            findings_by_severity=by_severity,
            evidence_total=int(
                conn.execute(
                    "SELECT COUNT(*) FROM evidence WHERE run_id = ?", (run_id,)
                ).fetchone()[0]
            ),
            events_total=int(
                conn.execute(
                    "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
                ).fetchone()[0]
            ),
            promotions=_promotions(findings),
        )

        cursor = conn.execute(
            "UPDATE runs SET outcome = ?, closed_at = ?, summary_json = ?"
            " WHERE run_id = ? AND closed_at IS NULL",
            (closure.outcome, closure.closed_at, closure.to_json(), run_id),
        )
        if cursor.rowcount != 1:
            # A concurrent writer sealed it between our read and UPDATE.
            raise RunAlreadyClosed(run_id)
        # Audit trail last, in the same transaction: the event reports a
        # seal that provably committed.
        ledger._append_event(
            conn,
            run_id,
            _RUN_CLOSED_KIND,
            {"outcome": closure.outcome, "summary": closure.summary()},
        )
    return closure
