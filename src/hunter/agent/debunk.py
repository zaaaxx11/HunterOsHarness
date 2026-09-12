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

P1 hook: ``provider`` (a ChatProvider) is accepted for a future adversarial
LLM challenger pass ("argue why this finding is wrong") but is deliberately
UNUSED in v0.2 core — verification is deterministic only, so a model can
never talk a finding into (or out of) the verified state.
"""

from __future__ import annotations

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


def debunk_pass(finding: Finding, ctx: ToolContext, provider: Any = None) -> str:
    """Deterministically challenge one finding. Returns "verified",
    "ruled_out", or "needs_follow_up" (see module docstring).

    ``provider`` is reserved for the P1 adversarial challenger and is unused
    in v0.2 core.
    """
    check_id = finding.key.split("|", 1)[0]
    recheck = RECHECKS.get(check_id)
    if recheck is None:
        _coverage_row(
            ctx, finding, check_id, "needs_follow_up",
            f"no replay handler for check '{check_id}'; stays candidate",
            [],
        )
        return "needs_follow_up"

    recorder = _ExchangeRecorder(ctx.http)
    engine_ctx = EngineContext(http=recorder, emit=ctx.emit)
    try:
        reproduced = bool(recheck(engine_ctx, ctx.target_url.rstrip("/"), finding))
    except httpx.HTTPError as exc:
        _coverage_row(
            ctx, finding, check_id, "needs_follow_up",
            f"replay transport error: {type(exc).__name__}: {exc}",
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
        evidence_id = ctx.ledger.add_evidence(ctx.run_id, "http_exchange", data)
        ctx.emit(
            "evidence_stored",
            {"evidence_id": evidence_id, "kind": "http_exchange", "tool": "debunk_pass"},
        )
        ctx.ledger.set_finding_status(finding.id, FindingStatus.VERIFIED, "independent replay succeeded")
        _coverage_row(
            ctx, finding, check_id, "reported",
            "debunk replay reproduced the signal; finding verified",
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
        evidence_id = ctx.ledger.add_evidence(ctx.run_id, "http_exchange", data)
        ctx.emit(
            "evidence_stored",
            {"evidence_id": evidence_id, "kind": "http_exchange", "tool": "debunk_pass"},
        )
        evidence_ids = [evidence_id]
    ctx.ledger.set_finding_status(
        finding.id, FindingStatus.RULED_OUT, "debunk replay did not reproduce the signal"
    )
    _coverage_row(
        ctx, finding, check_id, "ruled_out",
        "debunk replay did not reproduce the signal",
        evidence_ids,
    )
    return "ruled_out"
