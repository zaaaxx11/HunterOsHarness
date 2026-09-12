"""Agent tools — the ONLY capabilities the LLM brain has (hermes T1-T5).

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

from typing import Any
from urllib.parse import urlparse

import httpx

from hunter.engine.base import CandidateFinding
from hunter.kernel.events import canonical_json, sha256_hex
from hunter.kernel.findings import Finding, Severity, dedupe_key
from hunter.tools.http_client import Exchange
from hunter.tools.scope import ScopeViolation

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
        return _blocked("http.url_required", "http_request requires 'url'.")
    if method not in PASSIVE_METHODS and _tier_level(ctx) < TIER_ORDER["advanced"]:
        return _blocked(
            "tier.passive_only",
            f"method {method} is an active request; tier "
            f"'{ctx.config.get('tier', 'basic')}' is passive-only (GET/HEAD/OPTIONS). "
            "Elevate the tier to send it.",
        )
    headers_raw = args.get("headers") or {}
    headers = (
        {_as_str(k): _as_str(v) for k, v in headers_raw.items()} if isinstance(headers_raw, dict) else {}
    )
    body = args.get("body")
    body = _as_str(body) if body is not None else None
    purpose = _as_str(args.get("purpose", "")).strip()
    try:
        exchange: Exchange = ctx.http.request(method, url, headers=headers or None, body=body)
    except ScopeViolation as exc:
        return _blocked("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        return ToolOutcome(
            ok=False,
            code="http.transport_error",
            result_for_model=f"[ERROR tool] {method} {url} failed: {type(exc).__name__}: {exc}",
        )
    ctx.emit(
        "engine_event", {"tool": "http_request", "method": method, "url": url, "status": exchange.status}
    )
    result = (
        f"{method} {url} -> {exchange.status} ({exchange.elapsed_ms} ms)\n"
        f"response_body[:400]: {exchange.response_body[:400]!r}\n"
        "evidence: this exchange is persisted by the loop as http_exchange evidence "
        "(its evidence_id is appended below)."
    )
    return ToolOutcome(
        result_for_model=result,
        evidence={"kind": "http_exchange", "data": {**exchange.to_dict(), "purpose": purpose}},
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
    ctx.emit("engine_event", {"tool": "finish_scan", "findings": total, "coverage_rows": len(rows)})
    return ToolOutcome(result_for_model="\n".join(lines), lifecycle_finish=True)


def _respond_to_user(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    message = _as_str(args.get("message", "")).strip()
    if not message:
        return _blocked("respond.message_required", "respond_to_user requires non-empty 'message'.")
    ctx.emit("engine_event", {"tool": "respond_to_user"})
    return ToolOutcome(result_for_model="yielded to user.", lifecycle_yield=message)


# -- registry assembly -----------------------------------------------------------


def build_registry(tier: str = "basic") -> ToolRegistry:
    """Assemble the v0.2 agent tool registry.

    ``tier`` is validated and recorded (``registry.built_for_tier``) but does
    NOT filter specs: per tools_base T2, all v0.2 specs register at
    ``min_tier="basic"`` and advanced content is refused INSIDE the handlers
    (``http_request`` non-passive methods -> ``tier.passive_only``;
    ``run_probe`` active checks -> ``tier.capability_locked`` via
    PROBE_TIERS). The schema list the model sees is therefore identical for
    basic and advanced tiers in v0.2.
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
                "methods require advanced. The exchange becomes http_exchange evidence."
            ),
            parameters=_schema(
                {
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                    "purpose": {"type": "string"},
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
    ]
    for spec in specs:
        registry.register(spec)
    return registry
