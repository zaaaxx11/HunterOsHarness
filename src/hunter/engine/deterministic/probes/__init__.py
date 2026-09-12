"""Deterministic probes — fixed-request checks with baseline-diff signals.

Every probe module exposes:

    CHECK_ID: str
    run(ctx, base_url, recon) -> list[CandidateFinding]
    recheck(ctx, base_url, candidate) -> bool   # minimal replay of the signal

Shared rules:

* ALL requests go through ``ctx.http`` (the scope gate — fail-closed).
* Baseline-first: fetch the clean baseline, then the payload; a signal only
  counts when the payload response differs from the baseline.
* ``guarded_run`` emits ``probe_started`` / ``probe_result`` and converts
  ``httpx.HTTPError`` into an ERROR event so one dead endpoint never kills a
  scan. Replay (``recheck``) emits nothing — evidence capture belongs to the
  pipeline.
* The shared ``_finding`` helper builds a :class:`CandidateFinding` with a
  stable ``dedupe_key`` and ``http_exchange`` evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

import httpx

from hunter.kernel.findings import Severity, dedupe_key
from hunter.tools.http_client import Exchange

from ...base import CandidateFinding, Evidence

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import EngineContext

__all__ = [
    "CHECK_IDS",
    "PROBES",
    "RECHECKS",
    "_finding",
    "guarded_run",
]


def _finding(
    *,
    check_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    method: str,
    endpoint: str,
    param: str | None = None,
    payload_used: str | None = None,
    description: str = "",
    impact: str = "",
    remediation: str = "",
    exchanges: Iterable[Exchange] = (),
) -> CandidateFinding:
    """Build one candidate with a stable dedupe key and exchange evidence."""
    key = dedupe_key(check_id, method, endpoint, param)
    evidence = tuple(
        Evidence(kind="http_exchange", data={**exchange.to_dict(), "check_id": check_id})
        for exchange in exchanges
    )
    return CandidateFinding(
        key=key,
        title=title,
        severity=severity,
        cwe=cwe,
        endpoint=endpoint,
        method=method.upper(),
        param=param,
        payload_used=payload_used,
        description=description,
        impact=impact,
        remediation=remediation,
        evidence=evidence,
    )


def guarded_run(
    ctx: EngineContext,
    check_id: str,
    logic: Callable[[], list[CandidateFinding]],
) -> list[CandidateFinding]:
    """Emit probe_started, run the probe logic, emit probe_result.

    Transport-level failures (httpx.HTTPError) are retried once — probes are
    read-only/idempotent by contract, so one flaky packet (e.g. Windows
    loopback WinError 10053) must not silently cost a finding. Every failed
    attempt is emitted as an ERROR event; if the retry fails too, the probe
    continues empty-handed and the scan never dies on one bad endpoint.
    """
    ctx.emit("probe_started", {"check_id": check_id})
    findings: list[CandidateFinding] = []
    for attempt in (1, 2):
        try:
            findings = list(logic())
            break
        except httpx.HTTPError as exc:
            ctx.emit(
                "error",
                {"check_id": check_id, "attempt": attempt, "error": f"{type(exc).__name__}: {exc}"},
            )
    ctx.emit(
        "probe_result",
        {"check_id": check_id, "candidates": len(findings), "hit": bool(findings)},
    )
    return findings


# Probe modules are imported AFTER the helpers above so their
# `from . import _finding, guarded_run` resolves against this partially
# initialized package namespace without an import cycle. The E402 noqa is
# deliberate: import order here is load-bearing.
from . import (  # noqa: E402
    cookie_tamper,
    dir_listing,
    exposed_files,
    form_injection,
    headers,
    idor_heuristic,
    method_tamper,
    open_redirect,
    path_traversal,
    reflected_xss,
    sql_error,
    unauth_action,
)

# Stable probe execution order.
PROBES = [
    headers,
    dir_listing,
    reflected_xss,
    sql_error,
    path_traversal,
    open_redirect,
    exposed_files,
    unauth_action,
    cookie_tamper,
    method_tamper,
    idor_heuristic,
    form_injection,
]

CHECK_IDS = [probe.CHECK_ID for probe in PROBES]

# Replay dispatch: check_id -> minimal re-execution of that check's signal.
RECHECKS: dict[str, Callable[..., bool]] = {
    headers.CHECK_ID: headers.recheck,
    dir_listing.CHECK_ID: dir_listing.recheck,
    reflected_xss.CHECK_ID: reflected_xss.recheck,
    sql_error.CHECK_ID: sql_error.recheck,
    path_traversal.CHECK_ID: path_traversal.recheck,
    open_redirect.CHECK_ID: open_redirect.recheck,
    exposed_files.CHECK_ID: exposed_files.recheck,
    unauth_action.CHECK_ID: unauth_action.recheck,
    cookie_tamper.CHECK_ID: cookie_tamper.recheck,
    "cookie-flags": cookie_tamper.recheck_cookie_flags,
    method_tamper.CHECK_ID: method_tamper.recheck,
    idor_heuristic.CHECK_ID: idor_heuristic.recheck,
    form_injection.CHECK_ID: form_injection.recheck,
}
