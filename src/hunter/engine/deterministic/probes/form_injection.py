"""form-injection — GET forms that reflect canary input unescaped.

Kept minimal by design (the /search case is covered by reflected-xss): the
probe runs only when recon actually found a <form method="get">, and it fires
only when the canary's HTML tags survive unescaped in the response — and were
NOT already present in the clean baseline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlsplit

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "form-injection"
CANARY = "hun<x>ter<b>q9"

SEVERITY = Severity.HIGH
CWE = "CWE-79"


def _raw_echo(body: str) -> bool:
    return "hun<x>ter" in body and "ter<b>q9" in body


def _path_of(url: str) -> str:
    path = urlsplit(url).path
    return path or "/"


def _collect(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []
    for form in recon.forms:
        if form.method != "get" or not form.fields:
            continue
        endpoint = _path_of(form.action)
        baseline = ctx.http.get(form.action)
        url = f"{form.action}?{urlencode({field: CANARY for field in form.fields})}"
        payload = ctx.http.get(url)
        if not _raw_echo(payload.response_body) or _raw_echo(baseline.response_body):
            continue
        findings.append(
            _finding(
                check_id=CHECK_ID,
                title=f"Unescaped reflection in GET form at {endpoint}",
                severity=SEVERITY,
                cwe=CWE,
                method="GET",
                endpoint=endpoint,
                param=form.fields[0],
                payload_used=CANARY,
                description=(
                    f"Submitting the canary to the GET form on {form.page_url} reflects it "
                    f"unescaped via {urlsplit(form.action).path}."
                ),
                impact="Attacker-controlled script can execute in victims' browsers.",
                remediation="HTML-encode reflected input; prefer POST for actions.",
                exchanges=[baseline, payload],
            )
        )
    return findings


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url, recon))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    endpoint = candidate.endpoint or "/search"
    param = candidate.param or "q"
    canary = candidate.payload_used or CANARY
    url = f"{base_url}{endpoint}?{urlencode({param: canary})}"
    return _raw_echo(ctx.http.get(url).response_body)
