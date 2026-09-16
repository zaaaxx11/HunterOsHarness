"""Scan pipeline — the ONLY path from an engine to the ledger.

Engines never touch the ledger: they receive a scope-gated HTTP client and an
emit callback, and return :class:`CandidateFinding` objects. This pipeline is
the single component that:

1. opens a run (``run_started``) and closes it (``run_ended``),
2. drives the engine phases (plan / probe / collect / verify) and persists
   every engine-emitted event verbatim into the hash chain,
3. applies the claim gate at the boundary — binds EVERY candidate evidence
   via ``add_evidence`` (deep-redacted by the ledger, RULE-E3) and creates
   findings through ``create_finding`` (RULE-E1: no evidence, no claim),
4. runs the verification ladder — a successful independent ``engine.replay``
   binds a second, replay-flagged ``http_exchange`` evidence and promotes the
   finding to VERIFIED (RULE-E2). A failed or crashed replay leaves the
   finding a candidate; it is never silently dropped.

A candidate that the claim gate refuses never crashes the run: it is counted
in ``stats["gate_blocked"]`` and recorded as an ``error`` event. Only a fatal
failure (engine crash, ledger failure) marks the run ``failed``.
"""

from __future__ import annotations

import contextlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hunter import __version__
from hunter.engine.base import EngineContext, TargetSpec
from hunter.kernel.claimgate import ClaimGateBlocked
from hunter.kernel.events import Event, EventKind, sha256_hex
from hunter.kernel.findings import Finding, FindingStatus
from hunter.kernel.ledger import Ledger
from hunter.phases import (
    PhaseSnapshot,
    PhaseState,
    mark_report_rendered,
    phase_snapshots,
    record_retro,
    render_phase_progress,
)
from hunter.reporting.markdown import ReportBlocked, render_markdown
from hunter.tools.http_client import Exchange, ScopedHttpClient
from hunter.tools.registry import get_engine

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Callable

    from hunter.engine.base import CandidateFinding, EngineDriver, EngineResult, ScanPlan
    from hunter.llm.base import RunBudget
    from hunter.tools.scope import ScopeSet

__all__ = ["RunSummary", "run_scan"]


@dataclass
class RunSummary:
    """Final state of one scan run, read back from the ledger (fresh)."""

    run_id: str
    target: str
    engine: str
    status: str  # "completed" | "failed"
    findings: list[Finding]  # FINAL states read back from the ledger
    verified: int
    candidates: int
    stats: dict[str, Any]  # engine stats + elapsed_ms + requests (+ additive fields)
    # Additive v0.3 phase-machine fields (defaults keep every v0.2 consumer):
    phases: list[PhaseSnapshot] = field(default_factory=list)  # one per canonical phase
    phase_line: str = ""  # render_phase_progress() over `phases`
    report_markdown: str = ""  # the rendered Markdown report ("" when blocked)


def _ledger_db_path(state_dir: str | Path | None) -> str | Path | None:
    """Map the ``state_dir`` argument onto the Ledger db path convention.

    ``None`` keeps the Ledger default convention (env HUNTER_STATE_DIR or
    CWD/.hunter); otherwise the state directory holds ``ledger.db``.
    """
    if state_dir is None:
        return None
    from hunter.runtime_paths import RuntimePaths

    return RuntimePaths.resolve(state=state_dir, migrate=False).ledger


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _ReplayRecorder:
    """Wraps a :class:`ScopedHttpClient` and records the exchanges made during
    a replay, so the pipeline can bind the replay's own ``http_exchange``
    evidence (RULE-E2) without the engine having to return it. Everything
    else delegates to the wrapped client."""

    def __init__(self, client: ScopedHttpClient) -> None:
        self._client = client
        self.exchanges: list[Exchange] = []

    def request(self, method: str, url: str, **kwargs: Any) -> Exchange:
        exchange = self._client.request(method, url, **kwargs)
        self.exchanges.append(exchange)
        return exchange

    def get(self, url: str, **kwargs: Any) -> Exchange:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Exchange:
        return self.request("POST", url, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def run_scan(
    target_url: str,
    *,
    engine_name: str = "deterministic",
    scope: ScopeSet,
    state_dir: str | Path | None = None,
    config: dict[str, Any] | None = None,
    budget: RunBudget | None = None,
) -> RunSummary:
    """Run one full scan against ``target_url`` and persist it in the ledger.

    Phases (all events hash-chained in the ledger):

    - **plan** — ``engine.plan(target)`` recorded as an engine_event.
    - **probe** — ``engine.run`` on a fresh :class:`ScopedHttpClient`; every
      engine-emitted event is appended verbatim.
    - **collect** — every candidate's evidence is bound via ``add_evidence``
      (stamped with ``finding_key``), then the claim is created through
      ``create_finding`` (RULE-E1). Gate refusals are recorded and counted in
      ``stats["gate_blocked"]`` — they never crash the run.
    - **verify** — each finding's candidate is replayed independently on a
      fresh client; success binds replay evidence and promotes the finding to
      VERIFIED (RULE-E2), failure leaves it a candidate with a note event.

    Fatal failures (engine crash, ledger failure) still close the run
    cleanly: ``finish_run("failed")`` + ``run_ended``, and a ``RunSummary``
    with ``status="failed"`` is returned instead of raising.

    Args:
        target_url: Base URL of the target (must be inside ``scope``).
        engine_name: Registry name (``deterministic`` | ``mock`` | ``llm``).
        scope: Fail-closed scope; the gate lives in the HTTP client.
        state_dir: Directory for ``ledger.db``; ``None`` keeps the Ledger
            default convention (env HUNTER_STATE_DIR or CWD/.hunter).
        config: Forwarded verbatim to :class:`EngineContext.config`.
        budget: Optional :class:`hunter.llm.base.RunBudget` handed to the
            engine (M8 shared plumbing — the LLM engine's loop governor).
            ``None`` keeps the pre-v0.5 behavior exactly.
    """
    run_id = f"R-{uuid.uuid4().hex[:12]}"
    engine: EngineDriver = get_engine(engine_name, budget=budget)  # ValueError before any write
    ledger = Ledger(_ledger_db_path(state_dir))
    t0 = time.perf_counter()
    try:
        return _execute_scan(ledger, run_id, engine, engine_name, target_url, scope, config, t0)
    except Exception as exc:
        return _failed_run(ledger, run_id, engine_name, target_url, exc, t0)
    finally:
        ledger.close()


def _failed_run(
    ledger: Ledger,
    run_id: str,
    engine_name: str,
    target_url: str,
    exc: Exception,
    t0: float,
) -> RunSummary:
    """Close a fatally broken run: error event, phase abort, failed finish."""
    message = f"{type(exc).__name__}: {exc}"
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    snapshots: list[PhaseSnapshot] = []
    phase_line = ""
    with contextlib.suppress(Exception):  # the ledger itself may be unusable
        ledger.append(run_id, EventKind.ERROR, {"stage": "pipeline", "error": message})
        if ledger.events(run_id):
            # The phase machine must record the abort as a fact: whatever
            # canonical phase was open ends as {"aborted": true} — no gate,
            # no lie. Then the run fails and ends.
            with contextlib.suppress(Exception):
                machine = PhaseState(ledger, run_id)
                machine.abort()
                snapshots = phase_snapshots(ledger, run_id)
                phase_line = render_phase_progress(snapshots)
        ledger.finish_run(run_id, "failed")
        ledger.append(
            run_id,
            EventKind.RUN_ENDED,
            {"status": "failed", "error": message, "elapsed_ms": elapsed_ms},
        )
    return RunSummary(
        run_id=run_id,
        target=target_url,
        engine=engine_name,
        status="failed",
        findings=[],
        verified=0,
        candidates=0,
        stats={"requests": 0, "blocked": 0, "errors": 0, "elapsed_ms": elapsed_ms, "error": message},
        phases=snapshots,
        phase_line=phase_line,
    )


def _execute_scan(
    ledger: Ledger,
    run_id: str,
    engine: EngineDriver,
    engine_name: str,
    target_url: str,
    scope: ScopeSet,
    config: dict[str, Any] | None,
    t0: float,
) -> RunSummary:
    """Drive one run through score -> recon -> classify -> hunting -> verify -> report -> retro.

    Raises on fatal failures (the caller turns that into a failed run);
    per-candidate gate refusals and replay failures are absorbed here.

    The canonical HunterOS phase machine (:mod:`hunter.phases`) is mounted
    here: the machine's own transitions are appended directly to the ledger,
    and every other event flows through ``emit`` first, then into
    ``machine.observe`` — so engine sub-phase events (plan/probe/collect,
    recon detail) fold into canonical transitions without ever bypassing a
    gate. The old plan/probe/collect wrapper phase events are kept as engine
    detail events; the canonical verify phase is owned by the machine.
    """

    ledger.create_run(run_id, target_url, engine_name, scope.name)
    machine = PhaseState(ledger, run_id)

    def emit(kind: str, payload: dict[str, Any]) -> Event:
        event = ledger.append(run_id, kind, payload)
        machine.observe(event.kind_value(), event.payload)
        return event

    emit(
        EventKind.RUN_STARTED,
        {
            "target": target_url,
            "engine": engine_name,
            "scope": scope.summary(),
            "harness_version": __version__,
            "started": _utc_now_iso(),
        },
    )
    # Canonical pipeline head: score must open first and pass its gate (the
    # run row + run_started event above are exactly its evidence).
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    target = TargetSpec(url=target_url, scope=scope, notes={})

    # -- plan -------------------------------------------------------------------
    emit(EventKind.PHASE_STARTED, {"phase": "plan"})
    plan: ScanPlan = engine.plan(target)
    emit(
        EventKind.ENGINE_EVENT,
        {
            "stage": "plan",
            "engine": engine_name,
            "phases": list(plan.phases),
            "notes": dict(plan.notes),
        },
    )
    emit(EventKind.PHASE_ENDED, {"phase": "plan"})

    # -- probe (the engine emits its own phase/probe events through emit) --------
    emit(EventKind.PHASE_STARTED, {"phase": "probe"})
    with ScopedHttpClient(scope) as http:
        # ledger/run_id are additive v0.2 bindings for ledger-backed engines
        # (the LLM agent); deterministic/mock engines ignore them. The phase
        # machine rides config so agent tools can fold their surface actions
        # into the canonical transitions (hunter.phases.observe_tool).
        ctx = EngineContext(
            http=http,
            emit=emit,
            config={**dict(config or {}), "phase_machine": machine},
            ledger=ledger,
            run_id=run_id,
        )
        result: EngineResult = engine.run(target, ctx)
    emit(EventKind.PHASE_ENDED, {"phase": "probe", "candidates": len(result.candidates)})
    # Engine tallies (requests / blocked / errors / ...) are ledger facts too.
    # The retro is computed from EVENTS only, so the engine's own counters must
    # land in the hash chain BEFORE hunting closes — otherwise engines that do
    # not mirror every request as its own event (deterministic recon/probes)
    # would make `hunter retro` report requests: 0 while the run summary shows
    # the real traffic (v0.3 QA red audit).
    emit(EventKind.ENGINE_EVENT, {"tool": "engine_stats", **result.stats})

    # Engines that emitted no sub-phase events (mock, a silent agent) leave
    # recon open: the adapter closes it against the ledger (honest gate),
    # records the classification, and opens hunting. An engine whose events
    # already drove the machine (deterministic) leaves hunting open too —
    # engine_run_done is a no-op there.
    if machine.current is not None:
        machine.engine_run_done(result)

    # -- collect: bind evidence, create findings through the claim gate -----------
    emit(EventKind.PHASE_STARTED, {"phase": "collect"})
    gate_blocked = 0
    created: list[tuple[Finding, CandidateFinding]] = []
    seen_keys: set[str] = set()
    for candidate in result.candidates:
        if candidate.key in seen_keys:
            continue  # pipeline-level dedupe: first candidate wins
        seen_keys.add(candidate.key)
        evidence_ids = tuple(
            ledger.add_evidence(run_id, evidence.kind, {**evidence.data, "finding_key": candidate.key})
            for evidence in candidate.evidence
        )
        claim = Finding(
            id="",
            run_id=run_id,
            key=candidate.key,
            title=candidate.title,
            severity=candidate.severity,
            cwe=candidate.cwe,
            endpoint=candidate.endpoint,
            method=candidate.method,
            param=candidate.param,
            payload_used=candidate.payload_used,
            description=candidate.description,
            impact=candidate.impact,
            remediation=candidate.remediation,
            evidence_ids=evidence_ids,
        )
        try:
            stored = ledger.create_finding(claim)
        except ClaimGateBlocked as blocked:
            # A refused claim never crashes the run — it is recorded and counted.
            gate_blocked += 1
            emit(
                EventKind.ERROR,
                {"stage": "collect", "key": candidate.key, "gate_blocked": str(blocked)},
            )
            continue
        created.append((stored, candidate))
    emit(
        EventKind.PHASE_ENDED,
        {"phase": "collect", "findings": len(created), "gate_blocked": gate_blocked},
    )

    # -- verify (ladder): independent replay promotes candidate -> verified -------
    # Canonical phases: hunting closes FIRST (its gate reads the probe events
    # already appended), then verify opens. The machine owns these events.
    machine.close_current()
    machine.start("verify")
    verified = 0
    replay_requests = 0
    for finding, candidate in created:
        reproduced, error_text, replay_exchange, requests = _replay_candidate(
            engine, target, scope, emit, config, candidate
        )
        replay_requests += requests
        if not reproduced:
            payload: dict[str, Any] = {
                "stage": "verify",
                "finding_id": finding.id,
                "key": finding.key,
                "replay": False,
            }
            if error_text:
                payload["error"] = error_text
            emit(EventKind.ENGINE_EVENT, payload)
            continue
        # RULE-E2: bind the replay's own exchange as a second, replay-flagged
        # http_exchange evidence. The kind is always "http_exchange" — the
        # ledger's replay lookup filters on it — even when an engine replays
        # without wire traffic (data then carries a note instead of an exchange).
        if replay_exchange is not None:
            replay_data: dict[str, Any] = dict(replay_exchange)
        else:
            replay_data = {"note": "engine.replay reproduced the signal without HTTP traffic"}
        replay_data["check_id"] = candidate.key.split("|", 1)[0]
        replay_data["replay"] = True
        replay_data["finding_id"] = finding.id
        try:
            ledger.add_evidence(run_id, "http_exchange", replay_data)
            ledger.set_finding_status(
                finding.id, FindingStatus.VERIFIED, "independent replay succeeded"
            )
            verified += 1
        except ClaimGateBlocked as blocked:
            emit(
                EventKind.ERROR,
                {"stage": "verify", "finding_id": finding.id, "gate_blocked": str(blocked)},
            )
    machine.close_current()  # verify: every finding verified|ruled_out or replay-failed on record

    # -- finish: report and retro are canonical phases too ---------------------------
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    stats: dict[str, Any] = dict(result.stats)
    engine_elapsed = stats.pop("elapsed_ms", None)
    if engine_elapsed is not None:
        stats["engine_elapsed_ms"] = engine_elapsed
    stats["elapsed_ms"] = elapsed_ms
    stats["gate_blocked"] = gate_blocked
    stats["replay_requests"] = replay_requests
    stats.setdefault("requests", 0)
    stats.setdefault("blocked", 0)
    stats.setdefault("errors", 0)
    run_events = ledger.events(run_id)
    stats["gates_failed"] = sum(
        1
        for event in run_events
        if event.kind_value() == "phase_ended"
        and isinstance(event.payload.get("gate"), dict)
        and event.payload["gate"].get("passed") is False
    )
    stats["coverage_rows"] = sum(
        1
        for event in run_events
        if event.kind_value() == "engine_event" and event.payload.get("tool") == "coverage_record"
    )
    ledger.finish_run(run_id, "completed")
    machine.start("report")
    report_text = ""
    try:
        report_text = render_markdown(ledger, run_id)
        mark_report_rendered(
            ledger, run_id, fmt="markdown", sha256=sha256_hex(report_text), chars=len(report_text)
        )
    except ReportBlocked:
        # A blocked render is recorded honestly: no REPORT_RENDERED event is
        # appended, so the report gate fails at close and the run continues.
        pass
    machine.close_current()
    machine.start("retro")
    record_retro(ledger, run_id)
    machine.close_current()
    emit(
        EventKind.RUN_ENDED,
        {
            "status": "completed",
            "findings": len(created),
            "verified": verified,
            "gate_blocked": gate_blocked,
            "gates_failed": stats["gates_failed"],
            "elapsed_ms": elapsed_ms,
        },
    )

    findings = ledger.findings(run_id)  # fresh statuses straight from the ledger
    snapshots = phase_snapshots(ledger, run_id)
    return RunSummary(
        run_id=run_id,
        target=target_url,
        engine=engine_name,
        status="completed",
        findings=list(findings),
        verified=sum(1 for f in findings if f.status is FindingStatus.VERIFIED),
        candidates=sum(1 for f in findings if f.status is FindingStatus.CANDIDATE),
        stats=stats,
        phases=snapshots,
        phase_line=render_phase_progress(snapshots),
        report_markdown=report_text,
    )


def _replay_candidate(
    engine: EngineDriver,
    target: TargetSpec,
    scope: ScopeSet,
    emit: Callable[[str, dict[str, Any]], Event],
    config: dict[str, Any] | None,
    candidate: CandidateFinding,
) -> tuple[bool, str, dict[str, Any] | None, int]:
    """Replay one candidate on a FRESH scope-gated client.

    Returns ``(reproduced, error_text, last_exchange_dict, request_count)``.
    Never raises: a crashed replay counts as "not reproduced" and its error is
    recorded by the caller as an engine_event.
    """
    try:
        with ScopedHttpClient(scope) as replay_http:
            recorder = _ReplayRecorder(replay_http)
            ctx = EngineContext(http=recorder, emit=emit, config=dict(config or {}))
            reproduced = bool(engine.replay(target, ctx, candidate))
            requests = replay_http.stats.requests
    except Exception as exc:  # noqa: BLE001 - a broken replay must not kill the run
        return False, f"{type(exc).__name__}: {exc}", None, 0
    exchange = recorder.exchanges[-1].to_dict() if recorder.exchanges else None
    return reproduced, "", exchange, requests
