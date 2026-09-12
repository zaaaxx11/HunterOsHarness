"""HunterOS phase machine — the soul of the pipeline, enforced by the ledger.

Doctrine (FRAMEWORK.md, L2 PIPELINE): ``SCORE → RECON → CLASSIFY → HUNTING →
VERIFY → REPORT → RETRO`` — "a phase transition is refused until that phase's
exit gate is satisfied". IDEA.md, "GATES AND THE LEDGER — THE ONE RULE": "The
database is the only ledger ... what is not in the db does not exist." Both
are implemented here literally:

- **Events-only phase state.** No schema change: the current phase is computed
  from ``phase_started`` / ``phase_ended`` events. Canonical closes carry a
  ``gate`` payload; aborts carry ``aborted: true``. Engine sub-phase events
  (``recon`` / ``probe`` / ``collect``) are DETAIL events — the adapter
  (:class:`PhaseState.observe` / ``observe_tool`` / ``engine_run_done``) folds
  them into canonical transitions.
- **Gates read ONLY the ledger.** Every :data:`GATES` function derives its
  verdict from stored rows (events, findings, evidence). Nothing in memory can
  open a gate the ledger does not show.
- **Gate failures are recorded facts.** Default (``strict=False``): a failed
  gate is appended as ``phase_ended {"gate": {"passed": false, ...}}``, the
  phase is marked failed, and the run continues (counted in
  ``stats["gates_failed"]``). ``strict=True`` records the same event and then
  raises :class:`hunter.errors.HunterError` with code ``phase.gate_failed`` —
  never papered over, never a silent skip.

The machine never re-orders, never skips, and never re-opens a closed phase;
violations raise ``phase.out_of_order`` / ``phase.unknown`` /
``phase.invalid_transition``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hunter.errors import HunterError
from hunter.kernel.events import Event, EventKind
from hunter.kernel.findings import FindingStatus

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.engine.base import EngineResult
    from hunter.kernel.ledger import Ledger

__all__ = [
    "PHASE_ORDER",
    "PHASE_RANK",
    "GATES",
    "GateFn",
    "GateResult",
    "PhaseSnapshot",
    "PhaseState",
    "RetroReport",
    "check_gate",
    "compute_retro",
    "current_phase",
    "mark_report_rendered",
    "phase_snapshots",
    "record_classification",
    "record_retro",
    "render_phase_progress",
    "render_run_phase_line",
]


# -- canonical pipeline -------------------------------------------------------------

PHASE_ORDER = ("score", "recon", "classify", "hunting", "verify", "report", "retro")
PHASE_RANK: dict[str, int] = {phase: index for index, phase in enumerate(PHASE_ORDER)}

_LANE_BY_TIER = {"basic": "passive", "advanced": "active"}
_COVERAGE_CLOSED_OUTCOMES = frozenset({"reported", "no_issue_found", "ruled_out", "not_applicable"})
_CLASS_LIST_CAP = 12  # gate evidence payload keeps at most this many classes


@dataclass(frozen=True)
class GateResult:
    """Verdict of one exit gate, read from the ledger only."""

    phase: str
    passed: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class PhaseSnapshot:
    """One canonical phase's state, computed from events only."""

    phase: str
    state: str  # "done" | "failed" | "active" | "pending"
    gate_passed: bool | None
    detail: str


GateFn = Callable[["Ledger", str], GateResult]


# -- lazy probe-tier access ---------------------------------------------------------


def _probe_tiers() -> dict[str, str]:
    """PROBE_TIERS from the agent registry, lazily (phases.py must stay
    importable without dragging the agent/engine stack). Empty when absent —
    the classification then carries no tier-derived lanes."""
    try:
        from hunter.agent.tools import PROBE_TIERS  # noqa: PLC0415 — lazy by design
    except ImportError:  # pragma: no cover - same package, defensive only
        return {}
    return dict(PROBE_TIERS)


def _classification_classes(check_ids: list[str], source: str) -> list[dict[str, str]]:
    """Dedupe check_ids (order kept) into class rows with PROBE_TIERS lanes."""
    tiers = _probe_tiers()
    classes: list[dict[str, str]] = []
    seen: set[str] = set()
    for check_id in check_ids:
        if check_id in seen:
            continue
        seen.add(check_id)
        classes.append(
            {
                "check_id": check_id,
                "lane": _LANE_BY_TIER.get(tiers.get(check_id), "unclassified"),
                "source": source,
            }
        )
    return classes


def _status_value(finding: Any) -> str:
    status = finding.status
    return status.value if hasattr(status, "value") else str(status)


# -- deterministic gates (ledger-only) -----------------------------------------------


def _gate_score(ledger: Ledger, run_id: str) -> GateResult:
    run_row = next((row for row in ledger.runs() if row["run_id"] == run_id), None)
    if run_row is None:
        return GateResult(phase="score", passed=False, reason="no run row exists for this run id")
    started = next((e for e in ledger.events(run_id) if e.kind_value() == "run_started"), None)
    if started is None:
        return GateResult(phase="score", passed=False, reason="no run_started event recorded")
    payload = started.payload
    target = str(payload.get("target") or "").strip()
    scope = payload.get("scope") or {}
    if not target:
        return GateResult(phase="score", passed=False, reason="run_started event carries no target")
    if not scope:
        return GateResult(phase="score", passed=False, reason="run_started event carries an empty scope")
    evidence = {"target": target, "engine": run_row["engine"], "scope": dict(scope)}
    return GateResult(phase="score", passed=True, evidence=evidence)


def _gate_recon(ledger: Ledger, run_id: str) -> GateResult:
    events = ledger.events(run_id)
    for event in events:
        if event.kind_value() == "phase_ended" and event.payload.get("phase") == "recon":
            pages = event.payload.get("pages")
            if isinstance(pages, (int, float)) and pages >= 1:
                evidence = {
                    "pages": pages,
                    "links": event.payload.get("links", 0),
                    "forms": event.payload.get("forms", 0),
                }
                return GateResult(phase="recon", passed=True, evidence=evidence)
    surface_facts = 0
    for event in events:
        kind = event.kind_value()
        if kind == "evidence_stored" or (
            kind == "engine_event" and event.payload.get("tool") == "http_request"
        ):
            surface_facts += 1
    if surface_facts >= 1:
        return GateResult(phase="recon", passed=True, evidence={"surface_facts": surface_facts})
    return GateResult(
        phase="recon",
        passed=False,
        reason="no recon surface facts: no phase_ended recon with pages>=1, no evidence, no http requests",
    )


def _gate_classify(ledger: Ledger, run_id: str) -> GateResult:
    last = None
    for event in ledger.events(run_id):
        if event.kind_value() == "classification_recorded":
            last = event
    if last is None:
        return GateResult(phase="classify", passed=False, reason="no classification recorded for this run")
    classes = last.payload.get("classes") or []
    if not classes:
        return GateResult(phase="classify", passed=False, reason="classification has an empty class list")
    evidence_classes = [
        {"check_id": row.get("check_id", ""), "lane": row.get("lane", ""), "source": row.get("source", "")}
        for row in classes[:_CLASS_LIST_CAP]
        if isinstance(row, dict)
    ]
    evidence = {"classes": evidence_classes, "source": last.payload.get("source", "")}
    return GateResult(phase="classify", passed=True, evidence=evidence)


def _gate_hunting(ledger: Ledger, run_id: str) -> GateResult:
    probe_ids: set[str] = set()
    agent_probes = 0
    coverage_rows = 0
    candidates = 0
    for event in ledger.events(run_id):
        kind = event.kind_value()
        payload = event.payload
        if kind == "probe_result":
            if payload.get("check_id"):
                probe_ids.add(str(payload["check_id"]))
        elif kind == "engine_event":
            tool = payload.get("tool")
            if tool == "run_probe":
                agent_probes += 1
                if payload.get("check_id"):
                    probe_ids.add(str(payload["check_id"]))
            elif tool == "coverage_record":
                coverage_rows += 1
        elif kind == "finding_created":
            candidates += 1
    if probe_ids or agent_probes or coverage_rows or candidates:
        evidence = {
            "probes_run": len(probe_ids),
            "agent_probes": agent_probes,
            "coverage_rows": coverage_rows,
            "candidates": candidates,
        }
        return GateResult(phase="hunting", passed=True, evidence=evidence)
    return GateResult(
        phase="hunting",
        passed=False,
        # the zeroed tally is recorded with the failure: the ledger shows the
        # gate was failed by the ABSENCE of evidence, not by an unreadable one
        evidence={"probes_run": 0, "agent_probes": 0, "coverage_rows": 0, "candidates": 0},
        reason="no probes run, no coverage rows, and no findings recorded",
    )


def _gate_verify(ledger: Ledger, run_id: str) -> GateResult:
    replay_failed: set[str] = set()
    for event in ledger.events(run_id):
        payload = event.payload
        if (
            event.kind_value() == "engine_event"
            and payload.get("stage") == "verify"
            and payload.get("replay") is False
            and payload.get("finding_id")
        ):
            replay_failed.add(str(payload["finding_id"]))
    findings = ledger.findings(run_id)
    verified = 0
    ruled_out = 0
    unresolved: list[str] = []
    for finding in findings:
        status = _status_value(finding)
        if status == FindingStatus.VERIFIED.value:
            verified += 1
        elif status == FindingStatus.RULED_OUT.value:
            ruled_out += 1
        elif finding.id not in replay_failed:
            unresolved.append(finding.id)
    evidence = {
        "findings": len(findings),
        "verified": verified,
        "ruled_out": ruled_out,
        "unresolved": list(unresolved),
    }
    if not unresolved:
        return GateResult(phase="verify", passed=True, evidence=evidence)
    shown = ", ".join(unresolved[:3])
    more = "" if len(unresolved) <= 3 else f" (+{len(unresolved) - 3} more)"
    return GateResult(
        phase="verify",
        passed=False,
        evidence=evidence,
        reason=f"{len(unresolved)} finding(s) unresolved: {shown}{more}",
    )


def _last_event_of(events: list[Event], kind: str) -> Event | None:
    last = None
    for event in events:
        if event.kind_value() == kind:
            last = event
    return last


def _gate_report(ledger: Ledger, run_id: str) -> GateResult:
    last = _last_event_of(ledger.events(run_id), "report_rendered")
    if last is None:
        return GateResult(phase="report", passed=False, reason="no rendered report recorded for this run")
    payload = last.payload
    evidence = {
        "fmt": payload.get("fmt", ""),
        "sha256": payload.get("sha256", ""),
        "chars": payload.get("chars", 0),
    }
    return GateResult(phase="report", passed=True, evidence=evidence)


def _gate_retro(ledger: Ledger, run_id: str) -> GateResult:
    last = _last_event_of(ledger.events(run_id), "retro_recorded")
    if last is None or not last.payload.get("stats"):
        return GateResult(phase="retro", passed=False, reason="no retro recorded for this run")
    lessons = len(last.payload.get("lessons") or [])
    return GateResult(phase="retro", passed=True, evidence={"lessons": lessons})


GATES: dict[str, GateFn] = {
    "score": _gate_score,
    "recon": _gate_recon,
    "classify": _gate_classify,
    "hunting": _gate_hunting,
    "verify": _gate_verify,
    "report": _gate_report,
    "retro": _gate_retro,
}


def check_gate(ledger: Ledger, run_id: str, phase: str) -> GateResult:
    """Evaluate one exit gate against the ledger ONLY (never memory)."""
    gate = GATES.get(phase)
    if gate is None:
        return GateResult(phase=phase, passed=False, reason=f"unknown phase {phase!r}")
    return gate(ledger, run_id)


# -- snapshots from events ------------------------------------------------------------


def phase_snapshots(ledger: Ledger, run_id: str) -> list[PhaseSnapshot]:
    """Compute every canonical phase's state from events only.

    Canonical closes are ``phase_ended`` events carrying ``gate`` (or
    ``aborted``); engine detail closes (no gate payload) never close a
    canonical phase. The hunting snapshot's detail carries ``"<run>/<total>"``
    probe progress for the renderer.
    """
    events = ledger.events(run_id)
    probes: set[str] = set()
    for event in events:
        payload = event.payload
        is_probe = event.kind_value() == "probe_result" or (
            event.kind_value() == "engine_event" and payload.get("tool") == "run_probe"
        )
        if is_probe and payload.get("check_id"):
            probes.add(str(payload["check_id"]))
    total_probes = len(_probe_tiers())

    states: dict[str, dict[str, Any]] = {
        phase: {"open": False, "gate_passed": None, "failed": False, "reason": ""} for phase in PHASE_ORDER
    }
    for event in events:
        kind = event.kind_value()
        if kind not in ("phase_started", "phase_ended"):
            continue
        payload = event.payload
        phase = payload.get("phase")
        if phase not in states:
            continue  # engine detail phases (plan/probe/collect) are not canonical
        state = states[phase]
        if kind == "phase_started":
            if not state["open"]:
                state["open"] = True
        elif payload.get("aborted"):
            state["open"] = False
            state["failed"] = True
            state["gate_passed"] = None
            state["reason"] = "aborted"
        elif isinstance(payload.get("gate"), dict):
            gate = payload["gate"]
            state["open"] = False
            state["gate_passed"] = bool(gate.get("passed"))
            state["failed"] = not gate.get("passed")
            state["reason"] = str(gate.get("reason") or "")
        # else: engine detail close — not a canonical transition.

    snapshots: list[PhaseSnapshot] = []
    for phase in PHASE_ORDER:
        state = states[phase]
        if state["open"]:
            snapshot_state = "active"
        elif state["failed"]:
            snapshot_state = "failed"
        elif state["gate_passed"] is True:
            snapshot_state = "done"
        else:
            snapshot_state = "pending"
        detail = state["reason"] if snapshot_state == "failed" else ""
        if phase == "hunting" and total_probes and snapshot_state != "failed":
            detail = f"{len(probes)}/{total_probes}"
        snapshots.append(
            PhaseSnapshot(phase=phase, state=snapshot_state, gate_passed=state["gate_passed"], detail=detail)
        )
    return snapshots


def current_phase(ledger: Ledger, run_id: str) -> str | None:
    """The phase currently open for ``run_id`` (events only), else None."""
    for snapshot in phase_snapshots(ledger, run_id):
        if snapshot.state == "active":
            return snapshot.phase
    return None


# -- the machine ---------------------------------------------------------------------


class PhaseState:
    """Ledger-enforced cursor over the canonical phase order for one run.

    Every transition is an appended event; the cursor is rebuilt by replaying
    the run's events in :meth:`__init__`, so a machine can be re-mounted on an
    in-flight run (``workflow._failed_run`` does exactly that for aborts).
    """

    _AGENT_RECON_TOOLS = frozenset({"http_request", "run_probe", "coverage_record"})

    def __init__(self, ledger: Ledger, run_id: str, *, strict: bool = False) -> None:
        self._ledger = ledger
        self._run_id = run_id
        self._strict = bool(strict)
        self._current: str | None = None
        self._cursor = 0  # rank of the next phase that may start
        self._in_emit = False  # true while the machine itself is appending
        self._engine_recon_seen = False
        self._recon_detail: dict[str, Any] = {}
        self._replay(ledger.events(run_id))

    # -- introspection ------------------------------------------------------

    @property
    def current(self) -> str | None:
        return self._current

    @property
    def strict(self) -> bool:
        return self._strict

    # -- transitions ----------------------------------------------------------

    def start(self, phase: str) -> Event | None:
        """Open ``phase``; returns its ``phase_started`` Event.

        Idempotent when the phase is already open (returns None, appends
        nothing). Violations raise: unknown name -> ``phase.unknown``; a skip
        ahead -> ``phase.out_of_order``; a re-open of a closed phase or a
        start while another phase is open -> ``phase.invalid_transition``.
        """
        rank = PHASE_RANK.get(phase)
        if rank is None:
            raise HunterError(
                code="phase.unknown",
                layer="engine",
                message=f"unknown phase {phase!r} (canonical phases: {', '.join(PHASE_ORDER)})",
                hint="Use a canonical HunterOS phase from PHASE_ORDER.",
            )
        if self._current is not None:
            if phase == self._current:
                return None  # idempotent re-open: no event, no state change
            raise HunterError(
                code="phase.invalid_transition",
                layer="engine",
                message=f"cannot start phase {phase!r} while {self._current!r} is still open",
                hint="close_current() the open phase first — the machine never interleaves phases.",
            )
        if rank < self._cursor:
            raise HunterError(
                code="phase.invalid_transition",
                layer="engine",
                message=f"phase {phase!r} is already closed; phases never re-open",
                hint="The machine is append-only: a closed phase stays closed.",
            )
        if rank > self._cursor:
            expected = PHASE_ORDER[self._cursor] if self._cursor < len(PHASE_ORDER) else None
            raise HunterError(
                code="phase.out_of_order",
                layer="engine",
                message=f"phase {phase!r} skips ahead of the pipeline (expected {expected!r})",
                hint=f"Canonical order: {' -> '.join(PHASE_ORDER)}.",
            )
        event = self._append(EventKind.PHASE_STARTED, {"phase": phase})
        self._current = phase
        return event

    def close_current(self) -> Event:
        """Gate-check the open phase and append its canonical close.

        The gate reads ONLY the ledger. Default (strict=False): a failed gate
        is still recorded (``gate.passed == false`` in the payload) and the
        machine moves on — the failure is a recorded fact, counted by the
        pipeline. strict=True records the same event, then raises
        ``phase.gate_failed``.
        """
        if self._current is None:
            raise HunterError(
                code="phase.invalid_transition",
                layer="engine",
                message="no phase is open; close_current() would double-close",
                hint="start() a phase before closing it.",
            )
        phase = self._current
        gate = check_gate(self._ledger, self._run_id, phase)
        payload = {
            "phase": phase,
            "gate": {"passed": gate.passed, "reason": gate.reason, "evidence": gate.evidence},
        }
        event = self._append(EventKind.PHASE_ENDED, payload)
        self._current = None
        self._cursor = PHASE_RANK[phase] + 1
        if not gate.passed and self._strict:
            raise HunterError(
                code="phase.gate_failed",
                layer="engine",
                message=f"phase {phase!r} failed its exit gate: {gate.reason}",
                hint="Satisfy the gate (evidence, coverage, verification) — never the gate itself.",
            )
        return event

    def advance(self, phase: str, *, gate_evidence: dict[str, Any] | None = None) -> Event:
        """close_current() then start(phase).

        ``gate_evidence`` is reserved for a future gate-hint mechanism and
        deliberately ignored: gates read ONLY the ledger.
        """
        del gate_evidence
        self.close_current()
        started = self.start(phase)
        if started is None:  # pragma: no cover — impossible right after a close
            raise HunterError(
                code="phase.invalid_transition",
                layer="engine",
                message=f"phase {phase!r} could not be opened after closing the previous phase",
            )
        return started

    # -- adapters (engine detail events -> canonical transitions) -------------

    def observe(self, kind: str, payload: dict[str, Any]) -> None:
        """Fold one observed event into the machine.

        Engine ``phase_ended recon`` detail payloads are cached as recon gate
        narrative; engine ``phase_started probe`` while recon is open drives
        the canonical recon → classify → hunting transition (classification
        recorded with all PROBE_TIERS lanes, source "engine"). Everything else
        is a detail event and is ignored.
        """
        if self._in_emit:
            return  # never observe the machine's own appends
        if not isinstance(payload, dict):
            return
        phase = payload.get("phase")
        if kind == "phase_ended" and phase == "recon":
            self._engine_recon_seen = True
            self._recon_detail = dict(payload)
            return
        if kind == "phase_started" and phase == "recon":
            self._engine_recon_seen = True
            return
        if (
            kind == "phase_started"
            and phase == "probe"
            and self._current == "recon"
            and self._engine_recon_seen
        ):
            # The engine moved from recon into probing. The pipeline's own
            # "probe" wrapper event is payload-identical to the engine's, so
            # the transition waits until the engine's recon sub-phase has
            # actually been observed — otherwise recon would close before the
            # engine produced a single surface fact.
            self.close_current()
            self.start("classify")
            record_classification(
                self._ledger,
                self._run_id,
                classes=_classification_classes(sorted(_probe_tiers()), source="engine"),
                source="engine",
            )
            self.close_current()
            self.start("hunting")

    def observe_tool(self, tool: str) -> None:
        """Fold one agent tool call into the machine.

        While recon is open, the first surface tool (``http_request`` /
        ``run_probe`` / ``coverage_record``) drives the same recon → classify
        → hunting transition, with source "agent".
        """
        if self._current != "recon" or tool not in self._AGENT_RECON_TOOLS:
            return
        self.close_current()
        self.start("classify")
        record_classification(
            self._ledger,
            self._run_id,
            classes=_classification_classes(sorted(_probe_tiers()), source="agent"),
            source="agent",
        )
        self.close_current()
        self.start("hunting")

    def engine_run_done(self, result: EngineResult) -> None:
        """Adapter for engines that emitted no sub-phase events.

        Closes recon (honest gate — engines with no surface facts fail it),
        starts+closes classify (classification from the result's candidate
        keys plus the PROBE_TIERS lanes), and starts hunting LEFT OPEN — the
        pipeline closes it before verify. A machine already past recon (the
        engine drove the transitions itself via observe) is left untouched.
        """
        if self._current != "recon":
            return
        self.close_current()
        check_ids = [str(candidate.key).split("|", 1)[0] for candidate in result.candidates]
        check_ids.extend(sorted(_probe_tiers()))
        self.start("classify")
        record_classification(
            self._ledger,
            self._run_id,
            classes=_classification_classes(check_ids, source="engine"),
            source="engine",
        )
        self.close_current()
        self.start("hunting")

    def abort(self) -> None:
        """Close the open phase with ``aborted: true`` (no gate — honesty)."""
        if self._current is None:
            return
        payload = {"phase": self._current, "aborted": True}
        self._append(EventKind.PHASE_ENDED, payload)
        self._current = None

    # -- internals ------------------------------------------------------------

    def _append(self, kind: EventKind | str, payload: dict[str, Any]) -> Event:
        self._in_emit = True
        try:
            return self._ledger.append(self._run_id, kind, payload)
        finally:
            self._in_emit = False

    def _replay(self, events: list[Event]) -> None:
        for event in events:
            self._replay_event(event)

    def _replay_event(self, event: Event) -> None:
        kind = event.kind_value()
        payload = event.payload
        phase = payload.get("phase") if isinstance(payload, dict) else None
        if phase not in PHASE_RANK:
            return
        if kind == "phase_started":
            if self._current is None and PHASE_RANK[phase] == self._cursor:
                self._current = phase  # adopt the canonical open
            elif phase == "recon":
                self._engine_recon_seen = True
        elif kind == "phase_ended":
            if payload.get("aborted") or isinstance(payload.get("gate"), dict):
                if self._current == phase:
                    self._current = None
                    self._cursor = max(self._cursor, PHASE_RANK[phase] + 1)
            elif phase == "recon":
                self._engine_recon_seen = True
                self._recon_detail = dict(payload)


# -- one-shot recorders ---------------------------------------------------------------


def record_classification(ledger: Ledger, run_id: str, *, classes: list[dict], source: str) -> Event:
    """Record the classify phase's lane assignment (IDEA.md: "every surface
    has a skill/lane assignment") as a CLASSIFICATION_RECORDED event."""
    payload = {"classes": [dict(row) for row in classes], "source": source}
    return ledger.append(run_id, EventKind.CLASSIFICATION_RECORDED, payload)


def mark_report_rendered(
    ledger: Ledger, run_id: str, *, fmt: str, sha256: str, chars: int, out: str = ""
) -> Event:
    """Record that a report artifact was rendered, digest-stamped."""
    payload = {"fmt": fmt, "sha256": sha256, "chars": chars, "out": out}
    return ledger.append(run_id, EventKind.REPORT_RENDERED, payload)


# -- retro ----------------------------------------------------------------------------


@dataclass
class RetroReport:
    """Ledger-only retrospective for one run (L5 KNOWLEDGE — retro loop)."""

    run_id: str
    stats: dict[str, Any]
    coverage_pct: float | None
    gaps: list[str]
    lessons: list[str]

    def to_payload(self) -> dict[str, Any]:
        return {
            "stats": dict(self.stats),
            "coverage_pct": self.coverage_pct,
            "gaps": list(self.gaps),
            "lessons": list(self.lessons),
        }


def compute_retro(ledger: Ledger, run_id: str) -> RetroReport:
    """Compute the retro from stored rows only — the report is a view."""
    events = ledger.events(run_id)
    run_row = next((row for row in ledger.runs() if row["run_id"] == run_id), None)
    duration_s: float | None = None
    if run_row is not None and run_row.get("started_ts") is not None and run_row.get("ended_ts") is not None:
        duration_s = round(float(run_row["ended_ts"]) - float(run_row["started_ts"]), 3)

    requests = 0
    engine_tallies: dict[str, int] = {}
    probes: set[str] = set()
    coverage_total = 0
    coverage_closed = 0
    followups = 0
    for event in events:
        kind = event.kind_value()
        payload = event.payload
        if kind == "http_request" or (kind == "engine_event" and payload.get("tool") == "http_request"):
            requests += 1
        elif kind == "probe_result" or (kind == "engine_event" and payload.get("tool") == "run_probe"):
            if payload.get("check_id"):
                probes.add(str(payload["check_id"]))
        elif kind == "engine_event" and payload.get("tool") == "engine_stats":
            # The pipeline appends the engine's own counters right after
            # engine.run ({"tool": "engine_stats", **result.stats}). They are
            # authoritative for wire traffic the ledger does not mirror as
            # per-request events; only keys the engine actually reports
            # override the per-event fallback above (older ledgers have no
            # such event and keep their 0/exact defaults).
            for key in ("requests", "blocked", "errors"):
                value = payload.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    engine_tallies[key] = int(value)
        elif kind == "engine_event" and payload.get("tool") == "coverage_record":
            coverage_total += 1
            outcome = str(payload.get("outcome", ""))
            if outcome in _COVERAGE_CLOSED_OUTCOMES:
                coverage_closed += 1
            elif outcome == "needs_follow_up":
                followups += 1
    if "requests" in engine_tallies:
        requests = engine_tallies["requests"]

    findings = ledger.findings(run_id)
    verified = sum(1 for finding in findings if _status_value(finding) == FindingStatus.VERIFIED.value)
    ruled_out = sum(1 for finding in findings if _status_value(finding) == FindingStatus.RULED_OUT.value)
    unresolved = [
        finding.id for finding in findings if _status_value(finding) == FindingStatus.CANDIDATE.value
    ]

    stats = {
        "duration_s": duration_s,
        "requests": requests,
        "blocked": engine_tallies.get("blocked", 0),
        "errors": engine_tallies.get("errors", 0),
        "probes_run": len(probes),
        "verified": verified,
        "ruled_out": ruled_out,
        "coverage_closed": coverage_closed,
    }
    coverage_pct = None if coverage_total == 0 else round(100.0 * coverage_closed / coverage_total, 1)

    snapshots = phase_snapshots(ledger, run_id)
    gates_failed = [snapshot.phase for snapshot in snapshots if snapshot.state == "failed"]
    gaps: list[str] = []
    for snapshot in snapshots:
        if snapshot.state == "failed":
            reason = snapshot.detail or "no reason recorded"
            gaps.append(f"gate failed: {snapshot.phase} — {reason}")
    if unresolved:
        shown = ", ".join(unresolved[:3])
        more = "" if len(unresolved) <= 3 else f" (+{len(unresolved) - 3} more)"
        gaps.append(f"{len(unresolved)} finding(s) still candidate: {shown}{more}")
    if followups:
        gaps.append(f"{followups} coverage row(s) need follow-up")

    lessons: list[str] = []
    if not findings:
        if coverage_total:
            lessons.append(
                f"No findings across {coverage_total} recorded coverage rows — "
                "target hardened or scope too narrow."
            )
        else:
            lessons.append("No findings and no coverage recorded — the run cannot show what was reviewed.")
    if gates_failed:
        lessons.append(
            f"Phase gate(s) failed ({', '.join(gates_failed)}) — widen recon before trusting coverage."
        )
    if ruled_out:
        lessons.append(
            f"{ruled_out} candidates ruled out by replay — "
            "the debunk pass earned its keep; keep the rechecks."
        )
    if verified:
        lessons.append(
            f"{verified} finding(s) verified by independent replay — the evidence ladder held end to end."
        )
    return RetroReport(run_id=run_id, stats=stats, coverage_pct=coverage_pct, gaps=gaps, lessons=lessons)


def record_retro(ledger: Ledger, run_id: str) -> RetroReport:
    """Compute the retro and append it (re-record = refresh; append-only)."""
    report = compute_retro(ledger, run_id)
    ledger.append(run_id, EventKind.RETRO_RECORDED, report.to_payload())
    return report


# -- renderers --------------------------------------------------------------------------

_GLYPHS = {"done": "✓", "failed": "✗", "active": "▶", "pending": "○"}
_ASCII_GLYPHS = {"done": "ok", "failed": "x", "active": ">", "pending": "-"}
_BAR_RE = re.compile(r"(\d+)/(\d+)")


def render_phase_progress(snapshots: list[PhaseSnapshot], *, width: int = 12, use_ascii: bool = False) -> str:
    """One human line: every phase with its state glyph.

    The hunting snapshot renders a probe-progress bar (``width`` cells, filled
    proportionally to its ``"<run>/<total>"`` detail) when available.
    """
    glyphs = _ASCII_GLYPHS if use_ascii else _GLYPHS
    filled_char, empty_char = ("#", "-") if use_ascii else ("█", "·")
    parts: list[str] = []
    for snapshot in snapshots:
        piece = f"{snapshot.phase} {glyphs.get(snapshot.state, '-')}"
        if snapshot.phase == "hunting":
            match = _BAR_RE.fullmatch(snapshot.detail or "")
            if match:
                run, total = int(match.group(1)), int(match.group(2))
                filled = 0 if total <= 0 else min(int(width), max(0, round(int(width) * run / total)))
                empty = max(0, int(width) - filled)
                bar = filled_char * filled + empty_char * empty
                piece = f"{snapshot.phase} {bar} {run}/{total}"
        parts.append(piece)
    return " | ".join(parts)


def render_run_phase_line(ledger: Ledger, run_id: str, *, use_ascii: bool = False) -> str:
    """Phase line for ``run_id``, straight from the ledger."""
    return render_phase_progress(phase_snapshots(ledger, run_id), use_ascii=use_ascii)
