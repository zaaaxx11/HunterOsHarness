"""Agent tools — the ONLY capabilities the LLM brain has (agent T1-T5).

Every capability is a :class:`ToolSpec`; the model never touches the ledger,
network, or filesystem directly. Governance invariants implemented here:

- ALL network access goes through ``ctx.http`` (the fail-closed scope gate).
- ALL persistence goes through ``ctx.ledger`` (RULE-E1 is re-checked below
  the agent by ``Ledger.create_finding`` — this handler never trusts the
  model's claim that evidence exists; it re-resolves and re-hashes it).
- Evidence-id mechanism (the ONE documented contract between tools and the
  loop): handlers return ``result_for_model`` WITHOUT evidence ids, and set
  ``ToolOutcome.evidence`` to either a single ``{"kind", "data"}`` dict or a
  LIST of such dicts. The LOOP persists each artifact via
  ``ledger.add_evidence`` and appends ``evidence_id: EV-xxxx`` lines to the
  tool message in artifact order. Handlers must never persist evidence or
  fabricate ids themselves; the model must never type an id it was not shown.
- Tier gating is HANDLER-level for advanced content (tools_base T2 note):
  all v0.2 specs register at ``min_tier="basic"`` so the schema list is
  identical across tiers; refusals happen inside the handlers with stable
  BLOCKED codes. The two gates:
    * ``http_request`` — non-passive methods (anything but GET/HEAD/OPTIONS)
      require tier "advanced" (code ``tier.passive_only``).
    * ``run_probe`` — active probes require tier "advanced" per PROBE_TIERS
      (code ``tier.capability_locked``).
- ``think`` is the single silent tool: its scratchpad content never reaches
  the ledger (zero side effects; no emit), so chain-of-thought cannot leak
  into the hash chain.
"""

from __future__ import annotations

import json
import random
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from hunter.engine.base import CandidateFinding
from hunter.kernel.events import canonical_json, sha256_hex
from hunter.kernel.findings import Finding, Severity, dedupe_key
from hunter.kernel.redaction import redact_text
from hunter.tools.http_client import Exchange
from hunter.tools.scope import ScopeViolation

from .approval import classify_shell_command
from .browser import (
    BROWSER_TOOL_NAMES,
    PLAYWRIGHT_INSTALL_HINT,
    BrowserInputError,
    BrowserScopeRedirectBlocked,
    BrowserSession,
    BrowserTimeout,
    BrowserUnavailable,
    load_playwright,
    sanitize_browser_text,
    validate_selector,
    validate_url,
)
from .inventory import inventory_binaries
from .tools_base import TIER_ORDER, ToolContext, ToolOutcome, ToolRegistry, ToolSpec

__all__ = [
    "ACTIVE_PROBES",
    "PASSIVE_METHODS",
    "PASSIVE_PROBES",
    "PROBE_TIERS",
    "build_registry",
]

PASSIVE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Probe tier map — the advanced gate for run_probe (see module docstring).
ACTIVE_PROBES = frozenset(
    {"sql-error", "path-traversal", "unauth-action", "auth-bypass", "reflected-xss", "form-injection"}
)
PASSIVE_PROBES = frozenset(
    {"missing-headers", "dir-listing", "open-redirect", "sensitive-file", "method-tamper", "idor-heuristic"}
)
PROBE_TIERS: dict[str, str] = {
    **{check_id: "advanced" for check_id in sorted(ACTIVE_PROBES)},
    **{check_id: "basic" for check_id in sorted(PASSIVE_PROBES)},
}
_AUTO = object()

COVERAGE_OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up")
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")

# Outcomes whose coverage rows must cite at least one resolvable evidence id.
_COVERAGE_NEEDS_EVIDENCE = frozenset({"ruled_out", "not_applicable"})

_FINISHED_COVERAGE_WARNING = (
    "WARNING: No coverage was recorded for this scan. The report cannot show "
    "which surfaces were reviewed and cleared — only what was found."
)


# -- small helpers -------------------------------------------------------------


def _blocked(code: str, message: str) -> ToolOutcome:
    """A structured refusal: the model may read it and self-correct."""
    return ToolOutcome(ok=False, blocked=True, code=code, result_for_model=f"BLOCKED [{code}] {message}")


def _tier_level(ctx: ToolContext) -> int:
    return TIER_ORDER.get(str(ctx.config.get("tier", "basic")), 0)


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _evidence_rows(ctx: ToolContext) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in ctx.ledger.evidence(ctx.run_id)}


def _observe_tool(ctx: ToolContext, name: str) -> None:
    """Additive v0.3 hook: fold one tool call into the canonical phase machine.

    The pipeline mounts a :class:`hunter.phases.PhaseState` in
    ``ctx.config["phase_machine"]``; while recon is open, the first surface
    tool drives recon -> classify -> hunting (source "agent"). Without a
    mounted machine every tool behaves exactly as in v0.2.
    """
    machine = ctx.config.get("phase_machine")
    if machine is None:
        return
    machine.observe_tool(name)


def _normalize_evidence_ids(raw: Any) -> list[str]:
    """Accept a list of ids or a single id string; dedupe, keep order."""
    if raw is None:
        return []
    items = raw if isinstance(raw, (list, tuple)) else [raw]
    ids = [_as_str(item).strip() for item in items if _as_str(item).strip()]
    return list(dict.fromkeys(ids))


# -- basic tools: reasoning + notes ----------------------------------------------


def _think(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    """Private reasoning scratchpad. Deliberately emits NOTHING: the ledger
    must never receive chain-of-thought."""
    return ToolOutcome(result_for_model="noted.")


def _note_add(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    text = _as_str(args.get("text", "")).strip()
    if not text:
        return _blocked("note.text_required", "note_add requires non-empty 'text'.")
    notes: list[dict[str, Any]] = ctx.state.setdefault("notes", [])
    seq = int(ctx.state.get("note_seq", 0)) + 1
    ctx.state["note_seq"] = seq
    tags_raw = args.get("tags") or []
    tags = [_as_str(t) for t in tags_raw] if isinstance(tags_raw, (list, tuple)) else [_as_str(tags_raw)]
    note = {"id": f"N-{seq:04d}", "text": text, "tags": tags}
    notes.append(note)
    ctx.emit("engine_event", {"tool": "note_add", "note_id": note["id"]})
    return ToolOutcome(result_for_model=f"note {note['id']} recorded.")


def _note_list(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    notes: list[dict[str, Any]] = ctx.state.get("notes", [])
    ctx.emit("engine_event", {"tool": "note_list", "count": len(notes)})
    if not notes:
        return ToolOutcome(result_for_model="no notes recorded yet.")
    lines = [f"{n['id']}: {n['text'][:160]}" for n in notes[:25]]
    return ToolOutcome(result_for_model="\n".join(lines))


def _note_get(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    note_id = _as_str(args.get("id", "")).strip()
    if not note_id:
        return _blocked("note.id_required", "note_get requires 'id' (see note_list).")
    ctx.emit("engine_event", {"tool": "note_get", "note_id": note_id})
    for note in ctx.state.get("notes", []):
        if note["id"] == note_id:
            return ToolOutcome(result_for_model=f"{note['id']}: {note['text']}")
    return ToolOutcome(ok=False, code="note.not_found", result_for_model=f"no note with id {note_id!r}.")


# -- basic tools: coverage + threat model ----------------------------------------


def _coverage_record(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    surface = _as_str(args.get("surface", "")).strip()
    risk_area = _as_str(args.get("risk_area", "")).strip()
    outcome = _as_str(args.get("outcome", "")).strip()
    if not surface or not risk_area:
        return _blocked("coverage.field_required", "coverage_record requires 'surface' and 'risk_area'.")
    if outcome not in COVERAGE_OUTCOMES:
        return _blocked(
            "coverage.outcome_invalid",
            f"outcome must be one of {', '.join(COVERAGE_OUTCOMES)} (got {outcome!r}).",
        )
    evidence_ids = _normalize_evidence_ids(args.get("evidence_ids"))
    if outcome in _COVERAGE_NEEDS_EVIDENCE:
        rows = _evidence_rows(ctx)
        missing = [eid for eid in evidence_ids if eid not in rows]
        if not evidence_ids or missing:
            return _blocked(
                "coverage.evidence_required",
                f"outcome '{outcome}' is a closure claim and requires at least one RESOLVABLE "
                f"evidence_id (missing/unknown: {missing or 'none provided'}). "
                "'I moved on' is not a closure state; cite the exchange that justifies it.",
            )
    coverage: list[dict[str, Any]] = ctx.state.setdefault("coverage", [])
    for row in coverage:
        if row["surface"] == surface and row["risk_area"] == risk_area:
            return _blocked(
                "coverage.duplicate_row",
                f"coverage row for {surface!r} / {risk_area!r} already exists "
                f"(outcome: {row['outcome']}). Use the update pattern: record a new row "
                "with a different risk_area or rule it out.",
            )
    row = {
        "surface": surface,
        "risk_area": risk_area,
        "outcome": outcome,
        "note": _as_str(args.get("note", "")).strip(),
        "evidence_ids": evidence_ids,
    }
    coverage.append(row)
    ctx.emit(
        "engine_event",
        {"tool": "coverage_record", "surface": surface, "risk_area": risk_area, "outcome": outcome},
    )
    _observe_tool(ctx, "coverage_record")
    return ToolOutcome(
        result_for_model=(
            f"coverage recorded: {surface} / {risk_area} -> {outcome}"
            + (f" (evidence: {', '.join(evidence_ids)})" if evidence_ids else "")
        )
    )


def _coverage_list(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    rows: list[dict[str, Any]] = ctx.state.get("coverage", [])
    ctx.emit("engine_event", {"tool": "coverage_list", "count": len(rows)})
    if not rows:
        return ToolOutcome(result_for_model="no coverage rows recorded yet — use coverage_record as you go.")
    lines = [
        f"- {r['surface']} / {r['risk_area']} -> {r['outcome']}"
        + (f" (evidence: {', '.join(r['evidence_ids'])})" if r["evidence_ids"] else "")
        + (f" — {r['note'][:100]}" if r["note"] else "")
        for r in rows
    ]
    return ToolOutcome(result_for_model="\n".join(lines))


def _threat_model_get(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    blocks: list[str] = ctx.state.get("threat_model", [])
    ctx.emit("engine_event", {"tool": "threat_model_get", "blocks": len(blocks)})
    if not blocks:
        return ToolOutcome(result_for_model="(no threat model recorded yet — use threat_model_amend)")
    return ToolOutcome(result_for_model="\n\n".join(blocks)[:8000])


def _threat_model_amend(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    text = _as_str(args.get("text", "")).strip()
    if not text:
        return _blocked("threat.text_required", "threat_model_amend requires non-empty 'text'.")
    note = _as_str(args.get("note", "")).strip()
    blocks: list[str] = ctx.state.setdefault("threat_model", [])
    if not blocks:
        blocks.append(text)
        attribution = "base threat model"
    else:
        blocks.append(f"[amendment {len(blocks)} by agent" + (f"; {note}" if note else "") + f"] {text}")
        attribution = f"amendment {len(blocks) - 1}"
    ctx.emit("engine_event", {"tool": "threat_model_amend", "attribution": attribution})
    return ToolOutcome(result_for_model=f"threat model updated ({attribution}).")


# -- network tools ----------------------------------------------------------------


def _http_request(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    method = _as_str(args.get("method", "GET")).strip().upper() or "GET"
    url = _as_str(args.get("url", "")).strip()
    if not url:
        ctx.emit("engine_event", {"tool": "http_request", "code": "http.url_required"})
        return _blocked("http.url_required", "http_request requires 'url'.")
    if method not in PASSIVE_METHODS and _tier_level(ctx) < TIER_ORDER["advanced"]:
        ctx.emit("engine_event", {"tool": "http_request", "code": "tier.passive_only"})
        return _blocked(
            "tier.passive_only",
            f"method {method} is an active request; tier "
            f"'{ctx.config.get('tier', 'basic')}' is passive-only (GET/HEAD/OPTIONS). "
            "Elevate the tier to send it.",
        )
    # Planner B T2 bounds: timeout 1..30s, max_body_chars <=40000, manual redirects.
    try:
        timeout = int(args.get("timeout", 10))
    except (TypeError, ValueError):
        timeout = -1
    if timeout < 1 or timeout > 30:
        ctx.emit("engine_event", {"tool": "http_request", "code": "http.timeout_bounds"})
        return _blocked(
            "http.timeout_bounds",
            f"timeout must be between 1 and 30 seconds (got {args.get('timeout', 10)!r}).",
        )
    try:
        max_body = int(args.get("max_body_chars", 40_000))
    except (TypeError, ValueError):
        max_body = 40_000
    max_body = max(1, min(40_000, max_body))
    follow = bool(args.get("follow_redirects", False))
    headers_raw = args.get("headers") or {}
    headers = (
        {_as_str(k): _as_str(v) for k, v in headers_raw.items()} if isinstance(headers_raw, dict) else {}
    )
    body = args.get("body")
    body = _as_str(body) if body is not None else None
    purpose = _as_str(args.get("purpose", "")).strip()
    # Manual redirect chain: max 3 hops, per-hop scope gate, fail-closed abort.
    current_url = url
    current_method = method
    hops = 0
    exchange: Exchange | None = None
    try:
        while True:
            exchange = ctx.http.request(
                current_method, current_url, headers=headers or None, body=body
            )
            if not follow:
                break
            if exchange.status not in (301, 302, 303, 307, 308):
                break
            location = (
                exchange.response_headers.get("location", "")
                or exchange.response_headers.get("Location", "")
            )
            if not location or hops >= 3:
                break
            from urllib.parse import urljoin as _urljoin  # noqa: PLC0415 — local, cheap

            nxt = _urljoin(current_url, str(location))
            try:
                ctx.scope.check_url(nxt)
            except ScopeViolation as exc:
                ctx.emit(
                    "engine_event",
                    {"tool": "http_request", "code": "scope.target_out_of_scope", "hops": hops},
                )
                _observe_tool(ctx, "http_request")
                return _blocked("scope.target_out_of_scope", str(exc))
            current_url = nxt
            # Redirects become GET (except 307/308 preserve); body dropped on GET.
            if exchange.status in (301, 302, 303):
                current_method = "GET"
                body = None
            hops += 1
            if hops > 3:
                break
    except ScopeViolation as exc:
        ctx.emit("engine_event", {"tool": "http_request", "code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        ctx.emit(
            "engine_event",
            {"tool": "http_request", "code": "http.transport_error", "url": current_url},
        )
        return ToolOutcome(
            ok=False,
            code="http.transport_error",
            result_for_model=f"[ERROR tool] {method} {url} failed: {type(exc).__name__}: {exc}",
        )
    assert exchange is not None
    ctx.emit(
        "engine_event",
        {"tool": "http_request", "method": method, "url": url, "status": exchange.status, "hops": hops},
    )
    _observe_tool(ctx, "http_request")
    resp_body = exchange.response_body or ""
    truncated = len(resp_body) > max_body
    if truncated:
        resp_body = resp_body[:max_body] + f"...[body truncated at {max_body} chars]"
    data = exchange.to_dict()
    data["response_body"] = resp_body
    data["truncated"] = truncated or len(exchange.response_body or "") > max_body
    result = (
        f"{method} {url} -> {exchange.status} ({exchange.elapsed_ms} ms)\n"
        f"response_body[:400]: {resp_body[:400]!r}\n"
        + ("[truncated]\n" if truncated else "")
        + "evidence: this exchange is persisted by the loop as http_exchange evidence "
        "(its evidence_id is appended below)."
    )
    return ToolOutcome(
        result_for_model=result,
        evidence={"kind": "http_exchange", "data": {**data, "purpose": purpose}},
    )


def _run_probe(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    # Lazy import: probe modules drag the whole deterministic engine in.
    from hunter.engine.base import EngineContext
    from hunter.engine.deterministic import probes
    from hunter.engine.deterministic.recon import run_recon

    check_id = _as_str(args.get("check_id", "")).strip()
    if check_id not in PROBE_TIERS:
        return _blocked(
            "probe.unknown_check_id",
            f"unknown check_id {check_id!r}. Known checks: {', '.join(PROBE_TIERS)}.",
        )
    required_tier = PROBE_TIERS[check_id]
    if TIER_ORDER[required_tier] > _tier_level(ctx):
        return _blocked(
            "tier.capability_locked",
            f"probe '{check_id}' is an ACTIVE check requiring tier '{required_tier}' "
            f"(current tier '{ctx.config.get('tier', 'basic')}').",
        )
    module = next(p for p in probes.PROBES if check_id == p.CHECK_ID)
    engine_ctx = EngineContext(http=ctx.http, emit=ctx.emit)
    recon = ctx.state.get("recon")
    if recon is None:
        recon = run_recon(ctx.http, ctx.target_url.rstrip("/"))
        ctx.state["recon"] = recon
    candidates: list[CandidateFinding] = module.run(engine_ctx, ctx.target_url.rstrip("/"), recon)

    artifacts: list[dict[str, Any]] = []
    lines = [f"probe {check_id}: {len(candidates)} candidate(s)"]
    for index, candidate in enumerate(candidates, start=1):
        count = len(candidate.evidence)
        for evidence in candidate.evidence:
            artifacts.append({"kind": "http_exchange", "data": dict(evidence.data)})
        param = f" (param {candidate.param})" if candidate.param else ""
        lines.append(
            f"{index}. [{candidate.severity.value}] {candidate.key} — "
            f"{candidate.method} {candidate.endpoint}{param} — "
            f"evidence artifacts: {count} (evidence_id lines follow in order)"
        )
    if not candidates:
        lines.append(
            "no signal. Record coverage with outcome no_issue_found — or ruled_out, "
            "which requires citing an evidence_id from this run."
        )
    ctx.emit(
        "engine_event",
        {"tool": "run_probe", "check_id": check_id, "candidates": len(candidates)},
    )
    _observe_tool(ctx, "run_probe")
    return ToolOutcome(
        result_for_model="\n".join(lines),
        evidence=artifacts if artifacts else None,
    )


# -- ledger read tools --------------------------------------------------------------


def _list_findings(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    findings = ctx.ledger.findings(ctx.run_id)
    ctx.emit("engine_event", {"tool": "list_findings", "count": len(findings)})
    if not findings:
        return ToolOutcome(result_for_model="no findings in the ledger for this run.")
    lines = [
        f"{f.id} [{f.severity.value}] ({f.status.value}) {f.key} — {f.method} {f.endpoint}"
        for f in findings[:25]
    ]
    return ToolOutcome(result_for_model="\n".join(lines))


def _ledger_search(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    query = _as_str(args.get("query", "")).strip()
    if not query:
        return _blocked("ledger.query_required", "ledger_search requires 'query'.")
    try:
        limit = max(1, min(int(args.get("limit", 10)), 10))
    except (TypeError, ValueError):
        limit = 10
    ctx.emit("engine_event", {"tool": "ledger_search", "query": query[:100]})
    needle = query.lower()
    rows: list[str] = []
    for row in ctx.ledger.evidence(ctx.run_id):
        blob = canonical_json(row["data"])
        if needle in row["id"].lower() or needle in row["kind"].lower() or needle in blob.lower():
            rows.append(f"EV {row['id']} [{row['kind']}] {blob[:150]}")
            if len(rows) >= limit:
                break
    if len(rows) < limit:
        for finding in ctx.ledger.findings(ctx.run_id):
            haystack = (
                f"{finding.id} {finding.key} {finding.title} {finding.endpoint} {finding.description}".lower()
            )
            if needle in haystack:
                rows.append(f"F {finding.id} [{finding.severity.value}] {finding.key} {finding.title}"[:200])
                if len(rows) >= limit:
                    break
    if not rows:
        return ToolOutcome(result_for_model=f"no ledger rows match {query!r}.")
    return ToolOutcome(result_for_model="\n".join(r[:200] for r in rows))


# -- THE GOVERNANCE TOOL --------------------------------------------------------
#
# Validation order is R1..R6 (each failure returns a BLOCKED outcome naming
# the rule). R2 re-resolves every evidence id against the ledger and
# recomputes its sha256 over the stored (redacted) data — the model cannot
# bind evidence it was never shown, and cannot bind evidence that was
# tampered with. R3 hardens RULE-E1: an http_exchange is mandatory, so a
# self-written note can never carry a finding. R4 has two halves: the
# endpoint must be in scope, AND it must be the path of a bound
# http_exchange (R4b, checked after R6 so the field-scale refusals stay the
# first feedback) — real evidence for /search can never carry a claim about
# /admin.


def _create_finding_request(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    check_id = _as_str(args.get("check_id", "")).strip()
    title = _as_str(args.get("title", "")).strip()
    endpoint = _as_str(args.get("endpoint", "")).strip()
    method = (_as_str(args.get("method", "GET")).strip() or "GET").upper()
    param = _as_str(args.get("param", "")).strip() or None
    payload_used = _as_str(args.get("payload_used", "")).strip() or None
    description = _as_str(args.get("description", "")).strip()
    impact = _as_str(args.get("impact", "")).strip()
    severity_justification = _as_str(args.get("severity_justification", "")).strip()
    counterevidence = _as_str(args.get("counterevidence", "")).strip()
    confidence = _as_str(args.get("confidence", "")).strip().lower()
    severity = _as_str(args.get("severity", "")).strip().lower()
    cwe = _as_str(args.get("cwe", "")).strip()

    # R1 — required prose and structural fields present.
    missing = [
        name
        for name, value in (
            ("check_id", check_id),
            ("endpoint", endpoint),
            ("title", title),
            ("description", description),
            ("impact", impact),
            ("severity_justification", severity_justification),
            ("counterevidence", counterevidence),
        )
        if not value
    ]
    if missing:
        return _blocked(
            "finding.r1_required_fields",
            f"RULE-R1: required fields missing or empty: {', '.join(missing)}. "
            "A claim without reasoning is prose, not a finding.",
        )

    # R2 — evidence ids resolve in the ledger and their stored digests match.
    evidence_ids = _normalize_evidence_ids(args.get("evidence_ids"))
    if not evidence_ids:
        return _blocked(
            "finding.r2_evidence_missing",
            "RULE-E1: evidence_ids must be a non-empty list of ids you were shown in "
            "tool results. Never invent, guess, or reuse another run's ids.",
        )
    rows = _evidence_rows(ctx)
    unresolved = [eid for eid in evidence_ids if eid not in rows]
    if unresolved:
        return _blocked(
            "finding.r2_evidence_missing",
            f"RULE-E1: evidence id(s) {unresolved} do not exist in the ledger for this run. "
            "Never invent or guess an id — only cite evidence_id lines returned by tools.",
        )
    for eid in evidence_ids:
        row = rows[eid]
        if sha256_hex(canonical_json(row["data"])) != row["sha256"]:
            return _blocked(
                "finding.r2_chain_integrity",
                f"RULE-E1: evidence {eid} failed the chain-integrity check (stored sha256 does "
                "not match recomputed digest). The ledger refuses tampered evidence.",
            )

    # R3 — kind-fit: at least one http_exchange (a note alone is NEVER sufficient).
    if not any(rows[eid]["kind"] == "http_exchange" for eid in evidence_ids):
        kinds = {rows[eid]["kind"] for eid in evidence_ids}
        return _blocked(
            "finding.r3_evidence_kind",
            f"RULE-E1: bound evidence kinds {sorted(kinds)} — at least one 'http_exchange' "
            "is required. A note alone is NEVER sufficient for a finding.",
        )

    # R4 — scope: the endpoint must belong to the target origin or an allowed host.
    scope_ok, scope_detail = _endpoint_in_scope(ctx, endpoint)
    if not scope_ok:
        return _blocked("scope.target_out_of_scope", scope_detail)

    # R5 — dedupe against existing findings for this run.
    key = dedupe_key(check_id, method, endpoint, param)
    existing = next((f for f in ctx.ledger.findings(ctx.run_id) if f.key == key), None)
    if existing is not None:
        return _blocked(
            "finding.r5_duplicate",
            f"a finding with key {key} already exists ({existing.id}). Use list_findings; "
            "findings are immutable in v0.2 (update_finding lands later).",
        )

    # R6 — severity/confidence must use the fixed scales.
    if severity not in SEVERITIES:
        return _blocked(
            "finding.r6_severity_invalid",
            f"severity must be one of {', '.join(SEVERITIES)} (got {severity!r}).",
        )
    if confidence not in CONFIDENCES:
        return _blocked(
            "finding.r6_confidence_invalid",
            f"confidence must be one of {', '.join(CONFIDENCES)} (got {confidence!r}).",
        )

    full_description = (
        f"{description}\n\n"
        f"Severity justification: {severity_justification}\n\n"
        f"Counterevidence: {counterevidence}\n\n"
        f"Confidence: {confidence}"
    )
    # R4b — evidence/endpoint consistency (QA red-audit v0.2): the claimed
    # endpoint must be the request path of at least one bound http_exchange.
    # Without this, a model can cite a REAL exchange for /search while
    # claiming a fabricated /admin finding — a half-unbacked claim the
    # ledger would happily store. Runs last so R1-R6 refusal codes stay
    # the first, most specific feedback.
    if not _endpoint_backed_by_evidence(endpoint, evidence_ids, rows):
        return _blocked(
            "finding.r4_endpoint_mismatch",
            f"RULE-R4: endpoint {endpoint!r} is not the path of any bound http_exchange "
            f"({', '.join(evidence_ids)}). A claim may only cite the endpoint the bound "
            "exchange actually hit — re-request it or fix the endpoint.",
        )
    claim = Finding(
        id="",
        run_id=ctx.run_id,
        key=key,
        title=title,
        severity=Severity(severity),
        cwe=cwe,
        endpoint=endpoint,
        method=method,
        param=param,
        payload_used=payload_used,
        description=full_description,
        impact=impact,
        evidence_ids=tuple(evidence_ids),
    )
    try:
        created = ctx.ledger.create_finding(claim)
    except Exception as exc:  # the claim gate below us has the final word
        from hunter.errors import build_error_surface  # noqa: PLC0415

        surface = build_error_surface(exc)
        return ToolOutcome(
            ok=False,
            blocked=True,
            code="finding.claim_gate_blocked",
            result_for_model=(
                f"BLOCKED [finding.claim_gate_blocked] the ledger refused this claim: {surface['message']} "
                "(RULE-E1 is enforced again at the storage layer — evidence or nothing)."
            ),
        )
    ctx.emit(
        "engine_event",
        {"tool": "create_finding_request", "finding_id": created.id, "key": created.key},
    )
    return ToolOutcome(
        result_for_model=(
            f"finding {created.id} created (status candidate) with {len(evidence_ids)} bound "
            "evidence artifact(s) — the ledger decides verification; continue or finish_scan."
        )
    )


def _claim_target(endpoint: str) -> str:
    """Path(+query) a claim is about: the endpoint itself for same-origin
    paths, the URL's path for absolute claims."""
    if "://" in endpoint or endpoint.startswith("//"):
        parsed = urlparse("http:" + endpoint if endpoint.startswith("//") else endpoint)
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"
        return target
    return endpoint


def _endpoint_backed_by_evidence(
    endpoint: str, evidence_ids: list[str], rows: dict[str, dict[str, Any]]
) -> bool:
    """R4b: at least one bound http_exchange must have hit the claimed
    endpoint (path match; a claim carrying a query must match path+query)."""
    claim = _claim_target(endpoint)
    for eid in evidence_ids:
        row = rows[eid]
        if row["kind"] != "http_exchange":
            continue
        raw_url = str(row["data"].get("url", ""))
        try:
            parsed = urlparse(raw_url)
            path = parsed.path or "/"
        except ValueError:
            continue
        candidates = {path}
        if parsed.query:
            candidates.add(f"{path}?{parsed.query}")
        if claim in candidates:
            return True
    return False


def _endpoint_in_scope(ctx: ToolContext, endpoint: str) -> tuple[bool, str]:
    """R4: relative paths are same-origin by construction; absolute or
    protocol-relative URLs must resolve to the target origin or a host the
    ScopeSet allows (localhost is always allowed)."""
    if endpoint.startswith("//"):  # protocol-relative — netloc hides in the path
        endpoint = "http:" + endpoint
    if "://" not in endpoint:
        if not endpoint.startswith("/"):
            return False, (
                f"endpoint {endpoint!r} is neither a same-origin path (starting with '/') "
                "nor an absolute in-scope URL."
            )
        return True, ""
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or not host:
        return False, f"endpoint {endpoint!r} is not a parseable http(s) URL."
    if ctx.scope.allows_host(host):
        return True, ""
    return False, (
        f"endpoint {endpoint!r} (host {host!r}) is outside the authorized scope "
        f"(scope={ctx.scope.name!r}, target={ctx.target_url!r})."
    )


# -- R2-B B1: R-spec version gate + R4c on-chain bind ------------------------------
#
# R_SPEC_VERSION defaults to 1 (v1 semantics preserved: old runs without a
# version validate exactly as before). r_spec_version 2 unlocks web3
# kind-fit (contract_call with replay evidence) but keeps storage/state-diff
# behind advanced tier and requires a chain_scope + rpc_manifest. R4c binds
# one on-chain read: exact lower-compare address, readonly method allowlist
# (sends never bind), and rpc-host scope proof.

R_SPEC_VERSION = 1

_RSPEC_STORAGE_METHODS = frozenset({"eth_getStorageAt", "eth_getProof", "debug_traceCall"})
_R4C_READONLY_METHODS = frozenset({"eth_call", "eth_getCode", "eth_getBalance", "eth_getStorageAt"})


def _rspec_version(args: dict[str, Any], ctx: Any) -> int:
    raw = args.get("r_spec_version")
    if raw is None:
        try:
            raw = (getattr(ctx, "config", {}) or {}).get("r_spec_version", 1)
        except Exception:
            raw = 1
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 1


def validate_rspec_gate(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """R-spec gate: v1 default; v2 needs manifest + advanced for storage reads."""
    version = _rspec_version(args, ctx)
    method = str(args.get("method", "") or "").strip()
    if version < 2:
        return {"ok": True, "blocked": False, "code": "ok", "sufficient": True,
                "r_spec_version": 1,
                "result_for_model": "R-spec v1 semantics: web2/http_exchange evidence sufficient."}
    if method in _RSPEC_STORAGE_METHODS:
        try:
            tier = str((getattr(ctx, "config", {}) or {}).get("tier", "basic"))
        except Exception:
            tier = "basic"
        if tier != "advanced":
            return {"ok": False, "blocked": True, "code": "tier.capability_locked",
                    "result_for_model":
                    f"BLOCKED [tier.capability_locked] method '{method}' needs advanced tier (r_spec v2)."}
    try:
        cfg = getattr(ctx, "config", {}) or {}
        chain_scope = cfg.get("chain_scope") or []
        rpc_manifest = cfg.get("rpc_manifest") or {}
    except Exception:
        chain_scope, rpc_manifest = [], {}
    if method and (not chain_scope or not (rpc_manifest or {}).get("hosts")):
        return {"ok": False, "blocked": True, "code": "rspec.manifest_required",
                "result_for_model":
                "BLOCKED [rspec.manifest_required] r_spec_version 2 requires chain_scope + rpc_manifest."}
    return {"ok": True, "blocked": False, "code": "ok", "sufficient": True,
            "r_spec_version": 2, "result_for_model": "R-spec v2 gate passed."}


def _r4c_onchain_bind(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """R4c: bind one readonly on-chain read to scope + manifest."""
    chain_id = args.get("chain_id")
    address = str(args.get("address", "") or "").strip()
    method = str(args.get("method", "") or "").strip()
    rpc_url = str(args.get("rpc_url", "") or "").strip()
    if method not in _R4C_READONLY_METHODS:
        return {"ok": False, "blocked": True, "code": "r4c.method_not_allowlisted",
                "result_for_model": f"BLOCKED [r4c.method_not_allowlisted] {method!r} is not readonly."}
    try:
        cid = int(chain_id)
    except (TypeError, ValueError):
        return {"ok": False, "blocked": True, "code": "r4c.scope_mismatch",
                "result_for_model": "BLOCKED [r4c.scope_mismatch] bad chain_id."}
    allowed = False
    try:
        entries = (getattr(ctx, "config", {}) or {}).get("chain_scope", []) or []
    except Exception:
        entries = []
    want = address.lower()
    for entry in entries:
        try:
            if int(entry.get("chain_id")) == cid and str(entry.get("address", "")).strip().lower() == want:
                allowed = True
                break
        except (TypeError, ValueError, AttributeError):
            continue
    if not allowed:
        return {"ok": False, "blocked": True, "code": "r4c.scope_mismatch",
                "result_for_model": "BLOCKED [r4c.scope_mismatch] address not in chain_scope."}
    try:
        ctx.scope.check_url(rpc_url)
    except ScopeViolation as exc:
        return {"ok": False, "blocked": True, "code": "scope.target_out_of_scope",
                "result_for_model": f"BLOCKED [scope.target_out_of_scope] {exc}"}
    try:
        exchange = ctx.http.request("POST", rpc_url, headers={"Content-Type": "application/json"},
                                    body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method}))
        _ = exchange.status
    except ScopeViolation as exc:
        return {"ok": False, "blocked": True, "code": "scope.target_out_of_scope",
                "result_for_model": f"BLOCKED [scope.target_out_of_scope] {exc}"}
    except httpx.HTTPError as exc:
        return {"ok": False, "blocked": False, "code": "http.transport_error",
                "result_for_model": f"R4c bind transport error: {type(exc).__name__}"}
    return {"ok": True, "blocked": False, "code": "ok",
            "result_for_model": f"R4c bind ok: chain {cid} {want} via manifest host."}


# -- lifecycle tools ----------------------------------------------------------


def _finish_scan(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    rows: list[dict[str, Any]] = ctx.state.get("coverage", [])
    lines: list[str] = []
    if not rows:
        lines.append(_FINISHED_COVERAGE_WARNING)
    followups = [r for r in rows if r.get("outcome") == "needs_follow_up"]
    if followups:
        lines.append("unresolved needs_follow_up coverage rows:")
        lines.extend(f"- {r['surface']} / {r['risk_area']}: {r.get('note', '')}" for r in followups)
    findings = ctx.ledger.findings(ctx.run_id)
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    total = len(findings)
    lines.append(
        f"findings: {total} (critical: {counts['critical']}, high: {counts['high']}, "
        f"medium: {counts['medium']}, low: {counts['low']}, info: {counts['info']})"
    )
    # v0.3 phase line: the canonical machine's progress, straight from the
    # ledger (ImportError-safe so a missing phases module can never break the
    # lifecycle tool).
    phase_now = "-"
    try:
        from hunter.phases import (  # noqa: PLC0415 — lazy, same package
            current_phase,
            phase_snapshots,
            render_phase_progress,
        )

        lines.append(render_phase_progress(phase_snapshots(ctx.ledger, ctx.run_id)))
        phase_now = current_phase(ctx.ledger, ctx.run_id) or "-"
    except ImportError:  # pragma: no cover - same package, defensive only
        pass
    ctx.emit(
        "engine_event",
        {"tool": "finish_scan", "findings": total, "coverage_rows": len(rows), "phase": phase_now},
    )
    return ToolOutcome(result_for_model="\n".join(lines), lifecycle_finish=True)


def _respond_to_user(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    message = _as_str(args.get("message", "")).strip()
    if not message:
        return _blocked("respond.message_required", "respond_to_user requires non-empty 'message'.")
    ctx.emit("engine_event", {"tool": "respond_to_user"})
    return ToolOutcome(result_for_model="yielded to user.", lifecycle_yield=message)


# -- shell + inventory tools (M8 F1) ----------------------------------------------
#
# shell_exec is the ONLY way the model runs local processes, and it is
# triple-gated: (1) the dispatch approval gate (catastrophic denylist FIRST,
# then approval), (2) the handler's own denylist pass (defense-in-depth),
# (3) the cwd jail + minimal env + 16k redacted output cap below. Every run
# — allowed or blocked — lands a ledger engine_event (no unlogged side
# effects). shell=False + shlex.split only: no pipelines, no redirects, no
# shell injection surface.

_SHELL_MIN_TIMEOUT = 1
_SHELL_MAX_TIMEOUT = 600
_SHELL_DEFAULT_TIMEOUT = 120
_SHELL_OUTPUT_LIMIT = 16_384
_SHELL_TRUNCATION_MARKER = f"...[output truncated at {_SHELL_OUTPUT_LIMIT} chars]"

# env-leak mitigation: ONLY these pass through to the child process.
_SHELL_ENV_ALLOWLIST = (
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "COMSPEC",
    "PATHEXT",
    "SYSTEMDRIVE",
    "WINDIR",
)


def _minimal_shell_env(cwd: str) -> dict[str, str]:
    import os  # noqa: PLC0415 — local import keeps the module import light

    env: dict[str, str] = {}
    for key in _SHELL_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env["HOME"] = cwd  # the child's HOME is the jail, never the operator's
    env["HUNTER_SANDBOX"] = "1"
    return env


def _shell_state_dir(ctx: ToolContext) -> Any:
    return ctx.config.get("state_dir")


def _shell_cwd(args: dict[str, Any], ctx: ToolContext) -> tuple[str | None, str | None]:
    """Resolve the execution directory inside the state-dir jail.

    Returns ``(cwd, error_code)``. A provided cwd must resolve (symlinks and
    '..' included) strictly inside the resolved state dir. Opsi B: argv
    paths in ``command`` get the same jail check via the shared approval
    helper, so direct handler calls cannot bypass the gate."""
    state_raw = _shell_state_dir(ctx)
    if not state_raw:
        return None, "shell.cwd_outside_state"
    try:
        state_dir = Path(state_raw).resolve()
    except OSError:
        return None, "shell.cwd_outside_state"
    requested = args.get("cwd")
    if requested in (None, ""):
        cwd_str = str(state_dir)
    else:
        candidate = Path(str(requested))
        if not candidate.is_absolute():
            candidate = state_dir / candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            return None, "shell.cwd_outside_state"
        if resolved != state_dir and state_dir not in resolved.parents:
            return None, "shell.cwd_outside_state"
        cwd_str = str(resolved)
    try:
        from .approval import _shell_argv_escapes_jail as _escapes

        if _escapes(str(args.get("command", "")), state_raw, requested):
            return None, "shell.cwd_outside_state"
    except Exception:  # noqa: BLE001 — helper failure must not open the jail
        pass
    return cwd_str, None


def _shell_event(
    ctx: ToolContext,
    *,
    command: str,
    exit_code: int | None,
    timed_out: bool,
    duration_ms: float,
    cwd: str,
) -> None:
    ctx.emit(
        "engine_event",
        {
            "tool": "shell_exec",
            "command": redact_text(str(command))[:500],
            "command_class": classify_shell_command(command),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": round(float(duration_ms), 2),
            "cwd": cwd,
            "approval_id": ctx.config.get("approval_id"),
        },
    )


def _shell_exec(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    command = _as_str(args.get("command", ""))
    started = time.perf_counter()
    cwd, cwd_error = _shell_cwd(args, ctx)

    # Defense in depth: the gate is authoritative. A direct handler call must
    # not release a catastrophic command, and an approved retry must carry the
    # transient class marker set by the gate.
    command_class = classify_shell_command(command)
    if command_class == "catastrophic" and ctx.config.get("approval_class") != "catastrophic":
        _shell_event(
            ctx, command=command, exit_code=None, timed_out=False,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            cwd=cwd or "",
        )
        return _blocked(
            "approval.unavailable",
            "command requires the configured approval gate before execution.",
        )
    if cwd_error is not None or cwd is None:
        _shell_event(
            ctx, command=command, exit_code=None, timed_out=False,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            cwd=str(cwd or ""),
        )
        return _blocked(
            "shell.cwd_outside_state",
            "cwd must resolve strictly inside the run's state directory "
            "(no '..', no absolute paths outside it, no symlink escapes).",
        )

    timeout_raw = args.get("timeout_seconds", _SHELL_DEFAULT_TIMEOUT)
    try:
        timeout = int(timeout_raw)
    except (TypeError, ValueError):
        timeout = -1
    if timeout < _SHELL_MIN_TIMEOUT or timeout > _SHELL_MAX_TIMEOUT:
        _shell_event(
            ctx, command=command, exit_code=None, timed_out=False,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            cwd=cwd,
        )
        return _blocked(
            "shell.timeout_bounds",
            f"timeout_seconds must be between {_SHELL_MIN_TIMEOUT} and "
            f"{_SHELL_MAX_TIMEOUT} (got {timeout_raw!r}; default "
            f"{_SHELL_DEFAULT_TIMEOUT}s).",
        )

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        _shell_event(
            ctx, command=command, exit_code=None, timed_out=False,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            cwd=cwd,
        )
        return _blocked(
            "shell.command_unparseable",
            f"command is not parseable without a shell ({exc}); plain argv only — "
            "no pipelines, redirects, or shell syntax.",
        )
    if not argv:
        _shell_event(
            ctx, command=command, exit_code=None, timed_out=False,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            cwd=cwd,
        )
        return _blocked("shell.command_unparseable", "command is empty after parsing.")

    timed_out = False
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    try:
        completed = subprocess.run(
            argv,
            shell=False,
            cwd=cwd,
            env=_minimal_shell_env(cwd),
            timeout=timeout,
            capture_output=True,
            text=True,
            errors="replace",
        )
        exit_code = completed.returncode
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
    except OSError as exc:
        _shell_event(
            ctx, command=command, exit_code=None, timed_out=False,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            cwd=cwd,
        )
        return ToolOutcome(
            ok=False,
            code="shell.spawn_error",
            result_for_model=f"[ERROR tool] could not start the process: "
            f"{type(exc).__name__}: {exc}",
        )

    if timed_out:
        combined = f"$ {command}\n[stdout]\n{stdout}\n[stderr]\n{stderr}\n[timed out after {timeout}s]"
    else:
        combined = f"$ {command}\n[stdout]\n{stdout}\n[stderr]\n{stderr}"
    truncated = len(combined) > _SHELL_OUTPUT_LIMIT
    safe = sanitize_browser_text(combined, limit=_SHELL_OUTPUT_LIMIT)
    if truncated:
        safe = f"{safe}\n{_SHELL_TRUNCATION_MARKER}"
    _shell_event(
        ctx,
        command=command,
        exit_code=exit_code,
        timed_out=timed_out,
        duration_ms=(time.perf_counter() - started) * 1000.0,
        cwd=cwd,
    )
    if timed_out:
        return ToolOutcome(
            ok=False,
            code="shell.timeout",
            result_for_model=safe,
        )
    return ToolOutcome(result_for_model=safe)


def _as_text(value: Any) -> str:
    """TimeoutExpired output can be bytes (POSIX) or str (Windows)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _runtime_inventory(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    payload = ctx.state.get("runtime_inventory")
    if payload is None:
        payload = inventory_binaries()
        ctx.state["runtime_inventory"] = payload  # at most one which-scan per run
    ctx.emit(
        "engine_event",
        {"tool": "runtime_inventory", "available_count": len(payload["available"])},
    )
    return ToolOutcome(result_for_model=json.dumps(payload, sort_keys=True))


# -- browser tools --------------------------------------------------------------


def _browser_permission(ctx: ToolContext) -> ToolOutcome | None:
    if ctx.config.get("hunt_permission") is not True:
        return _blocked(
            "permission.hunt_required",
            "browser actions require an explicitly authorized governed hunt.",
        )
    return None


def _browser_outcome(ctx: ToolContext, action: Any, selector: str = "") -> ToolOutcome:
    data: dict[str, Any] = {
        "action": action.action,
        "url": action.url,
        "title": action.title,
    }
    if action.action == "snapshot":
        data.update({"snapshot": action.snapshot, "truncated": action.truncated})
        result = f"browser snapshot at {action.url}\n{action.snapshot}"
    elif action.action == "type":
        data.update({"selector": selector, "text_length": action.text_length})
        result = f"browser type completed at {action.url}; text_length={action.text_length}"
    else:
        data.update({"selector": selector} if selector else {})
        result = f"browser {action.action} completed at {action.url}; call browser_snapshot for visible text."
    ctx.emit("engine_event", {"tool": f"browser_{action.action}", **data})
    return ToolOutcome(result_for_model=result, evidence={"kind": "browser_event", "data": data})


BROWSER_TIMEOUT_CODE = "browser.timeout"
BROWSER_SCOPE_REDIRECT_BLOCKED_CODE = "browser.scope_redirect_blocked"


def _browser_error(exc: Exception) -> ToolOutcome:
    # Planner B T3 reliability codes: timeout is retryable (ok=False, blocked=False);
    # out-of-scope redirect landings are BLOCKED under a distinct code.
    if isinstance(exc, BrowserScopeRedirectBlocked):
        return _blocked(
            "browser.scope_redirect_blocked",
            "browser redirect landing was outside the authorized scope.",
        )
    if isinstance(exc, (BrowserTimeout, TimeoutError)):
        return ToolOutcome(
            ok=False,
            code="browser.timeout",
            result_for_model="[ERROR tool] browser action timed out (retryable)",
        )
    if isinstance(exc, ScopeViolation):
        return _blocked("scope.target_out_of_scope", "browser request was outside the authorized scope.")
    if isinstance(exc, BrowserInputError):
        message = str(exc)
        if "exactly one" in message:
            code = "browser.selector_not_unique"
        elif "url" in message.lower() or "javascript" in message.lower():
            code = "browser.url_invalid"
        else:
            code = "browser.selector_invalid"
        return _blocked(code, message[:300])
    if isinstance(exc, BrowserUnavailable):
        return _blocked("browser.unavailable", PLAYWRIGHT_INSTALL_HINT)
    # Playwright-style timeouts surface as TimeoutError subclasses or "*timeout*"
    # messages even when the optional dep is faked in tests.
    if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
        return ToolOutcome(
            ok=False,
            code="browser.timeout",
            result_for_model="[ERROR tool] browser action timed out (retryable)",
        )
    return ToolOutcome(
        ok=False,
        code="browser.action_error",
        result_for_model="[ERROR tool] browser action failed",
    )


def _browser_factory(ctx: ToolContext, module: Any = None) -> Any:
    # M8 F5 wiring: cloak defaults ON (config key agent.browser_cloak); an
    # explicit seed makes the fingerprint deterministic for a whole run.
    kwargs: dict[str, Any] = {"cloak": bool(ctx.config.get("browser_cloak", True))}
    seed = ctx.config.get("browser_cloak_seed")
    if seed is not None:
        kwargs["cloak_rng"] = random.Random(str(seed))
    return BrowserSession(ctx.scope, playwright_module=module, **kwargs)


def _ensure_browser(ctx: ToolContext, module: Any = _AUTO) -> Any:
    factory = None if module is _AUTO else lambda: _browser_factory(ctx, module)
    return ctx.ensure_browser(factory)


def _browser_navigate(args: dict[str, Any], ctx: ToolContext, module: Any = _AUTO) -> ToolOutcome:
    denied = _browser_permission(ctx)
    if denied is not None:
        return denied
    try:
        validate_url(args.get("url", ""))
        ctx.scope.check_url(args.get("url", ""))
        action = _ensure_browser(ctx, module).navigate(args.get("url", ""))
        return _browser_outcome(ctx, action)
    except Exception as exc:
        return _browser_error(exc)


def _browser_snapshot(args: dict[str, Any], ctx: ToolContext, module: Any = _AUTO) -> ToolOutcome:
    denied = _browser_permission(ctx)
    if denied is not None:
        return denied
    try:
        action = _ensure_browser(ctx, module).snapshot()
        return _browser_outcome(ctx, action)
    except Exception as exc:
        return _browser_error(exc)


def _browser_click(args: dict[str, Any], ctx: ToolContext, module: Any = _AUTO) -> ToolOutcome:
    denied = _browser_permission(ctx)
    if denied is not None:
        return denied
    selector = args.get("selector", "")
    try:
        validate_selector(selector)
        action = _ensure_browser(ctx, module).click(selector)
        return _browser_outcome(ctx, action, selector=selector)
    except Exception as exc:
        return _browser_error(exc)


def _browser_type(args: dict[str, Any], ctx: ToolContext, module: Any = _AUTO) -> ToolOutcome:
    denied = _browser_permission(ctx)
    if denied is not None:
        return denied
    selector = args.get("selector", "")
    try:
        validate_selector(selector)
        action = _ensure_browser(ctx, module).type(selector, args.get("text", ""))
        return _browser_outcome(ctx, action, selector=selector)
    except Exception as exc:
        return _browser_error(exc)


# -- registry assembly -----------------------------------------------------------


def build_registry(
    tier: str = "basic",
    *,
    browser_enabled: bool = False,
    playwright_module: Any = _AUTO,
) -> ToolRegistry:
    """Assemble the v0.2 agent tool registry.

    ``tier`` is validated and recorded (``registry.built_for_tier``) but does
    NOT filter specs: per tools_base T2, all v0.2 specs register at
    ``min_tier="basic"`` and advanced content is refused INSIDE the handlers
    (``http_request`` non-passive methods -> ``tier.passive_only``;
    ``run_probe`` active checks -> ``tier.capability_locked`` via
    PROBE_TIERS). The schema list differs by tier: basic exposes 16 tools,
    advanced exposes 17 with ``shell_exec`` advanced-only (plus basic
    ``runtime_inventory``).
    """
    if tier not in TIER_ORDER:
        raise ValueError(f"unknown tier {tier!r} (use basic|advanced)")
    registry = ToolRegistry()
    registry.built_for_tier = tier  # type: ignore[attr-defined] — introspection only

    specs = [
        ToolSpec(
            name="think",
            description="Private reasoning scratchpad. Zero side effects; content never reaches the ledger.",
            parameters=_schema({"thought": {"type": "string"}}, []),
            handler=_think,
        ),
        ToolSpec(
            name="note_add",
            description="Record a run-scoped note (hypotheses, observations). Ledgered as an event.",
            parameters=_schema(
                {"text": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}},
                ["text"],
            ),
            handler=_note_add,
        ),
        ToolSpec(
            name="note_list",
            description="List your run-scoped notes.",
            parameters=_schema({}, []),
            handler=_note_list,
        ),
        ToolSpec(
            name="note_get",
            description="Fetch one note by id.",
            parameters=_schema({"id": {"type": "string"}}, ["id"]),
            handler=_note_get,
        ),
        ToolSpec(
            name="coverage_record",
            description=(
                "Record audit coverage for one surface + risk_area. Outcome ruled_out/"
                "not_applicable REQUIRE at least one resolvable evidence_id."
            ),
            parameters=_schema(
                {
                    "surface": {"type": "string"},
                    "risk_area": {"type": "string"},
                    "outcome": {"type": "string", "enum": list(COVERAGE_OUTCOMES)},
                    "note": {"type": "string"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                ["surface", "risk_area", "outcome"],
            ),
            handler=_coverage_record,
        ),
        ToolSpec(
            name="coverage_list",
            description="List recorded coverage rows.",
            parameters=_schema({}, []),
            handler=_coverage_list,
        ),
        ToolSpec(
            name="threat_model_get",
            description="Read the run-scoped threat model.",
            parameters=_schema({}, []),
            handler=_threat_model_get,
        ),
        ToolSpec(
            name="threat_model_amend",
            description="Append attributed text to the run-scoped threat model.",
            parameters=_schema({"text": {"type": "string"}, "note": {"type": "string"}}, ["text"]),
            handler=_threat_model_amend,
        ),
        ToolSpec(
            name="http_request",
            description=(
                "Send one scope-checked HTTP request. GET/HEAD/OPTIONS at basic tier; other "
                "methods require advanced. follow_redirects defaults false (raw 3xx); when true "
                "the tool walks manually (max 3 hops, per-hop scope gate). "
                "The exchange becomes http_exchange evidence."
            ),
            parameters=_schema(
                {
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                    "purpose": {"type": "string"},
                    "follow_redirects": {"type": "boolean"},
                    "max_body_chars": {"type": "integer", "minimum": 1, "maximum": 40000},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
                },
                ["method", "url"],
            ),
            handler=_http_request,
        ),
        ToolSpec(
            name="run_probe",
            description=(
                "Run one deterministic probe by check_id. Active checks (see PROBE_TIERS) "
                "require advanced tier. Returned exchanges become evidence."
            ),
            parameters=_schema(
                {
                    "check_id": {"type": "string", "enum": sorted(PROBE_TIERS)},
                    "endpoint": {"type": "string"},
                    "param": {"type": "string"},
                },
                ["check_id"],
            ),
            handler=_run_probe,
        ),
        ToolSpec(
            name="list_findings",
            description="List ledger findings for this run (id, severity, status, key, endpoint).",
            parameters=_schema({}, []),
            handler=_list_findings,
        ),
        ToolSpec(
            name="ledger_search",
            description="Substring-search evidence and findings (bounded: <=10 rows, <=200 chars each).",
            parameters=_schema({"query": {"type": "string"}, "limit": {"type": "integer"}}, ["query"]),
            handler=_ledger_search,
        ),
        ToolSpec(
            name="create_finding_request",
            description=(
                "Propose a finding. Machine-validated (R1 prose, R2 evidence resolves + chain "
                "integrity, R3 http_exchange required, R4 scope, R5 dedupe, R6 scales). "
                "The ledger has the final word."
            ),
            parameters=_schema(
                {
                    "check_id": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "cwe": {"type": "string"},
                    "endpoint": {"type": "string"},
                    "method": {"type": "string"},
                    "param": {"type": "string"},
                    "payload_used": {"type": "string"},
                    "description": {"type": "string"},
                    "impact": {"type": "string"},
                    "severity_justification": {"type": "string"},
                    "counterevidence": {"type": "string"},
                    "confidence": {"type": "string", "enum": list(CONFIDENCES)},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                [
                    "check_id",
                    "title",
                    "severity",
                    "cwe",
                    "endpoint",
                    "method",
                    "description",
                    "impact",
                    "severity_justification",
                    "counterevidence",
                    "confidence",
                    "evidence_ids",
                ],
            ),
            handler=_create_finding_request,
        ),
        ToolSpec(
            name="finish_scan",
            description=(
                "End the audit: reconciles coverage (warns when none recorded), lists "
                "needs_follow_up rows, summarizes findings by severity."
            ),
            parameters=_schema({}, []),
            handler=_finish_scan,
            lifecycle="finish_scan",
        ),
        ToolSpec(
            name="respond_to_user",
            description="Yield a message to the user (the only way to hand control back mid-audit).",
            parameters=_schema({"message": {"type": "string"}}, ["message"]),
            handler=_respond_to_user,
            lifecycle="respond_to_user",
        ),
        ToolSpec(
            name="shell_exec",
            description=(
                "Run ONE local command inside the run's sandboxed state directory: "
                "plain argv only (shlex-split, no shell, no pipes/redirects), minimal "
                "environment, output redacted and capped at 16384 chars. cwd defaults "
                "to the state dir and must stay inside it. Catastrophic commands "
                "(rm -rf, format, disk writes, power control) are refused in ALL "
                "modes; other runs need user approval (/approve <request id>)."
            ),
            parameters=_schema(
                {
                    "command": {"type": "string", "minLength": 1, "maxLength": 4000},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600},
                    "cwd": {"type": "string"},
                },
                ["command"],
            ),
            handler=_shell_exec,
            min_tier="advanced",
            danger="approval",
        ),
        ToolSpec(
            name="runtime_inventory",
            description=(
                "Passive capability read: which audit binaries (nmap, sqlmap, ...) "
                "exist on this machine. No side effects; cached for the run."
            ),
            parameters=_schema({}, []),
            handler=_runtime_inventory,
            min_tier="basic",
        ),
    ]
    for spec in specs:
        registry.register(spec)

    if browser_enabled:
        module = load_playwright() if playwright_module is _AUTO else playwright_module
        if module is None:
            for name in BROWSER_TOOL_NAMES:
                registry.register_unavailable(name, "browser.unavailable", PLAYWRIGHT_INSTALL_HINT)
        else:
            registry.register(
                ToolSpec(
                    name="browser_navigate",
                    description=(
                        "Navigate the headless browser to one absolute in-scope http(s) URL. "
                        "Redirects and all subrequests are scope-checked; no cookies or headers are returned."
                    ),
                    parameters=_schema(
                        {"url": {"type": "string", "minLength": 1, "maxLength": 2048}}, ["url"]
                    ),
                    handler=lambda args, ctx, module=module: _browser_navigate(args, ctx, module),
                )
            )
            registry.register(
                ToolSpec(
                    name="browser_snapshot",
                    description=(
                        "Return a bounded, redacted visible-text snapshot of the current page. "
                        "Cookies, storage, headers, and arbitrary page code are never exposed."
                    ),
                    parameters=_schema({}, []),
                    handler=lambda args, ctx, module=module: _browser_snapshot(args, ctx, module),
                )
            )
            registry.register(
                ToolSpec(
                    name="browser_click",
                    description=(
                        "Click exactly one bounded CSS selector on the current in-scope page. "
                        "Explicit link/form destinations and resulting redirects are scope-checked."
                    ),
                    parameters=_schema(
                        {"selector": {"type": "string", "minLength": 1, "maxLength": 512}}, ["selector"]
                    ),
                    handler=lambda args, ctx, module=module: _browser_click(args, ctx, module),
                )
            )
            registry.register(
                ToolSpec(
                    name="browser_type",
                    description=(
                        "Fill exactly one bounded CSS selector on the current in-scope page. "
                        "The typed value is never returned or recorded; resulting requests "
                        "remain scope-checked."
                    ),
                    parameters=_schema(
                        {
                            "selector": {"type": "string", "minLength": 1, "maxLength": 512},
                            "text": {"type": "string", "maxLength": 4000},
                        },
                        ["selector", "text"],
                    ),
                    handler=lambda args, ctx, module=module: _browser_type(args, ctx, module),
                )
            )
    else:
        for name in BROWSER_TOOL_NAMES:
            registry.register_unavailable(
                name,
                "browser.disabled",
                "browser tools are disabled; enable agent.browser for a governed hunt.",
            )
    return registry
