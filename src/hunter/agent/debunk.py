"""Debunk pass — the deterministic challenger for candidate findings.

For every finding still CANDIDATE after the agent loop ends, re-run the
check that produced it (``check_id = finding.key.split("|")[0]``) through the
deterministic probe recheck machinery. This is RULE-E2's enforcement point
for the LLM path: a finding only reaches VERIFIED when an independent
replay — its own fresh exchange bound as ``http_exchange`` evidence with
``replay: true`` + ``finding_id`` — reproduces the signal.

Outcomes:
- "verified"        — signal reproduced; replay evidence bound, status VERIFIED.
- "ruled_out"       — no signal; status RULED_OUT (kept for the audit trail,
  RULE-E4), the replay exchange bound as plain evidence, and a ruled_out
  coverage row appended.
- "needs_follow_up" — transport error or no replay handler for the check_id;
  the finding stays CANDIDATE and a needs_follow_up coverage row is appended.

P1 hook: ``provider`` (a ChatProvider or challenger callable) may be passed
to produce an adversarial review note ("argue why this finding is wrong")
before the replay runs. The note is recorded (coverage row + run notes) but
the replay remains the final authority — a model can never talk a finding
into (or out of) the verified state.
"""

from __future__ import annotations

import inspect
from typing import Any

import httpx

from hunter.engine.base import EngineContext
from hunter.engine.deterministic.probes import RECHECKS
from hunter.kernel.findings import Finding, FindingStatus
from hunter.tools.http_client import Exchange

from .tools_base import ToolContext

__all__ = ["debunk_pass"]


class _ExchangeRecorder:
    """Wraps the scope-gated client and records the exchanges made during the
    replay, so the debunk can bind the replay's OWN exchange as evidence
    (same pattern as the pipeline's _ReplayRecorder)."""

    def __init__(self, client: Any) -> None:
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


def _coverage_row(
    ctx: ToolContext,
    finding: Finding,
    check_id: str,
    outcome: str,
    note: str,
    evidence_ids: list[str],
) -> None:
    coverage: list[dict[str, Any]] = ctx.state.setdefault("coverage", [])
    coverage.append(
        {
            "surface": finding.endpoint or "/",
            "risk_area": check_id,
            "outcome": outcome,
            "note": note,
            "evidence_ids": evidence_ids,
        }
    )
    ctx.emit(
        "engine_event",
        {"tool": "debunk_pass", "finding_id": finding.id, "check_id": check_id, "outcome": outcome},
    )


def _normalize_challenger_result(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    text = getattr(result, "text", None)
    if isinstance(text, str):
        return text
    if isinstance(result, dict):
        for key in ("note", "review", "text", "output", "message", "content"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return str(result)


def _invoke_challenger(challenger: Any, finding: Finding, ctx: ToolContext, check_id: str) -> str:
    """Invoke a provider/challenger callable (or ChatProvider) and return its
    adversarial review note as text. Never raises: failures become a note."""
    # ChatProvider-style object (has .complete, not itself callable).
    complete = getattr(challenger, "complete", None)
    if callable(complete) and not callable(challenger):
        try:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an adversarial reviewer. Argue why the following "
                        "finding is wrong or a false positive. Be concise."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"check_id={check_id}\nfinding_id={finding.id}\n"
                        f"key={finding.key}\ntitle={finding.title}\n"
                        f"endpoint={finding.endpoint}\nmethod={finding.method}"
                    ),
                },
            ]
            result = complete("verifier", messages, tools=None)
            return _normalize_challenger_result(result)
        except Exception as exc:  # noqa: BLE001 - challenger must not break replay
            return f"challenger error: {type(exc).__name__}: {exc}"

    if not callable(challenger):
        return str(challenger)

    available = {
        "finding": finding,
        "ctx": ctx,
        "context": ctx,
        "check_id": check_id,
        "finding_id": finding.id,
    }

    # Prefer an explicit signature match when possible.
    try:
        sig = inspect.signature(challenger)
        params = list(sig.parameters.values())
        # Build kwargs from named parameters.
        kwargs: dict[str, Any] = {}
        for p in params:
            if p.name in available:
                kwargs[p.name] = available[p.name]
            elif p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            else:
                kwargs = {}
                break
        filtered = [
            p for p in params
            if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        ]
        if kwargs and len(kwargs) == len(filtered):
            try:
                return _normalize_challenger_result(challenger(**kwargs))
            except TypeError:
                pass
    except (TypeError, ValueError):
        pass

    # Fall back to common calling conventions (exactly one invocation).
    attempts = (
        lambda: challenger(finding, ctx),
        lambda: challenger(finding),
        lambda: challenger(ctx, finding),
        lambda: challenger(ctx),
        lambda: challenger(),
    )
    for attempt in attempts:
        try:
            return _normalize_challenger_result(attempt())
        except TypeError:
            continue
    # Last resort: pass everything positionally.
    try:
        return _normalize_challenger_result(challenger(finding, ctx, check_id))
    except Exception as exc:  # noqa: BLE001
        return f"challenger error: {type(exc).__name__}: {exc}"


def _record_challenger_note(ctx: ToolContext, note: str) -> None:
    if not note:
        return
    notes: list[dict[str, Any]] = ctx.state.setdefault("notes", [])
    seq = int(ctx.state.get("note_seq", 0)) + 1
    ctx.state["note_seq"] = seq
    notes.append({"id": f"N-{seq:04d}", "text": note, "tags": ["challenger", "debunk"]})
    ctx.state["challenger_note"] = note
    ctx.state.setdefault("challenger_notes", []).append(note)


def debunk_pass(
    finding: Finding,
    ctx: ToolContext,
    provider: Any = None,
    challenger: Any = None,
    *args: Any,
    **kwargs: Any,
) -> str:
    """Deterministically challenge one finding. Returns "verified",
    "ruled_out", or "needs_follow_up" (see module docstring).

    ``provider`` / ``challenger`` (optional) is invoked before the replay to
    produce an adversarial review note. The replay remains the final authority.
    """
    # Allow challenger to be passed positionally under either name or via kwargs.
    if challenger is None:
        challenger = kwargs.pop("challenger", None)
    if challenger is None:
        challenger = provider
    if challenger is None and args:
        challenger = args[0]
    if challenger is None:
        challenger = kwargs.pop("provider", None)

    check_id = finding.key.split("|", 1)[0]

    # Invoke the adversarial challenger (if any) BEFORE the replay.
    challenger_note = ""
    if challenger is not None:
        challenger_note = _invoke_challenger(challenger, finding, ctx, check_id)
        _record_challenger_note(ctx, challenger_note)

    recheck = RECHECKS.get(check_id)
    if recheck is None:
        note = f"no replay handler for check '{check_id}'; stays candidate"
        if challenger_note:
            note = f"{note} (challenger: {challenger_note})"
        _coverage_row(
            ctx, finding, check_id, "needs_follow_up",
            note,
            [],
        )
        return "needs_follow_up"

    recorder = _ExchangeRecorder(ctx.http)
    # _ExchangeRecorder records every exchange while delegating to the real
    # client; it satisfies the ScopedHttpClient protocol structurally.
    engine_ctx = EngineContext(http=recorder, emit=ctx.emit)  # type: ignore[arg-type]
    try:
        reproduced = bool(recheck(engine_ctx, ctx.target_url.rstrip("/"), finding))
    except httpx.HTTPError as exc:
        note = f"replay transport error: {type(exc).__name__}: {exc}"
        if challenger_note:
            note = f"{note} (challenger: {challenger_note})"
        _coverage_row(
            ctx, finding, check_id, "needs_follow_up",
            note,
            [],
        )
        return "needs_follow_up"

    if reproduced:
        if recorder.exchanges:
            data: dict[str, Any] = {
                **recorder.exchanges[-1].to_dict(),
                "check_id": check_id,
                "replay": True,
                "finding_id": finding.id,
            }
        else:  # defensive: a check reproduced without wire traffic
            data = {
                "note": "replay reproduced the signal without HTTP traffic",
                "check_id": check_id,
                "replay": True,
                "finding_id": finding.id,
            }
        if challenger_note:
            data["challenger_note"] = challenger_note
        evidence_id = ctx.ledger.add_evidence(ctx.run_id, "http_exchange", data)
        ctx.emit(
            "evidence_stored",
            {"evidence_id": evidence_id, "kind": "http_exchange", "tool": "debunk_pass"},
        )
        ctx.ledger.set_finding_status(finding.id, FindingStatus.VERIFIED, "independent replay succeeded")
        note = "debunk replay reproduced the signal; finding verified"
        if challenger_note:
            note = f"{note} (challenger: {challenger_note})"
        _coverage_row(
            ctx, finding, check_id, "reported",
            note,
            [evidence_id],
        )
        return "verified"

    # No signal: bind the replay exchange as plain (non-replay) evidence and
    # rule the finding out — the audit trail keeps it, never deletes (RULE-E4).
    evidence_ids: list[str] = []
    if recorder.exchanges:
        data = {
            **recorder.exchanges[-1].to_dict(),
            "check_id": check_id,
            "replay": False,
            "finding_id": finding.id,
            "purpose": "debunk replay — signal did not reproduce",
        }
        if challenger_note:
            data["challenger_note"] = challenger_note
        evidence_id = ctx.ledger.add_evidence(ctx.run_id, "http_exchange", data)
        ctx.emit(
            "evidence_stored",
            {"evidence_id": evidence_id, "kind": "http_exchange", "tool": "debunk_pass"},
        )
        evidence_ids = [evidence_id]
    ctx.ledger.set_finding_status(
        finding.id, FindingStatus.RULED_OUT, "debunk replay did not reproduce the signal"
    )
    note = "debunk replay did not reproduce the signal"
    if challenger_note:
        note = f"{note} (challenger: {challenger_note})"
    _coverage_row(
        ctx, finding, check_id, "ruled_out",
        note,
        evidence_ids,
    )
    return "ruled_out"
