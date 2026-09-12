"""sensitive-file — well-known sensitive paths served with telling content.

Each hit is reported separately, keyed by the concrete path (e.g.
``sensitive-file|GET|/backup/users.sql|-``). Content markers guard against
soft-404 pages that return 200 with generic HTML.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from hunter.kernel.findings import Severity

from . import _finding, guarded_run

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...base import CandidateFinding, EngineContext
    from ..recon import Recon

CHECK_ID = "sensitive-file"


def _env_marker(body: str) -> bool:
    return bool(re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", body, re.MULTILINE))


# path -> title, (markers, case-insensitive)
TARGETS: dict[str, tuple[str, tuple[str, ...]]] = {
    "/backup/users.sql": (
        "User database backup",
        ("username,", "insert into", "create table"),
    ),
    "/.env": ("Environment file", ()),  # marker handled by _env_marker
    "/.git/HEAD": ("Git repository metadata", ("ref: refs/",)),
    "/.htaccess": ("Apache access control file", ("rewriterule", "rewriteengine", "deny from", "authtype")),
}

SEVERITY = Severity.HIGH
CWE = "CWE-538"


def _markers_for(path: str) -> tuple[str, ...]:
    return TARGETS.get(path, ("", ()))[1]


def _hit(path: str, status: int, body: str) -> bool:
    if status != 200:
        return False
    if path == "/.env":
        return _env_marker(body)
    lowered = body.lower()
    return any(marker in lowered for marker in _markers_for(path))


def _collect(ctx: EngineContext, base_url: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []
    for path, (title, _markers) in TARGETS.items():
        exchange = ctx.http.get(base_url + path)
        if not _hit(path, exchange.status, exchange.response_body):
            continue
        findings.append(
            _finding(
                check_id=CHECK_ID,
                title=f"Sensitive file exposed: {title}",
                severity=SEVERITY,
                cwe=CWE,
                method="GET",
                endpoint=path,
                description=f"GET {path} returns 200 with content matching a sensitive {title.lower()}.",
                impact="Secrets, credentials or source structure leak to anonymous users.",
                remediation="Serve only intended assets; block dotfiles and backup paths at the web server.",
                exchanges=[exchange],
            )
        )
    return findings


def run(ctx: EngineContext, base_url: str, recon: Recon) -> list[CandidateFinding]:
    return guarded_run(ctx, CHECK_ID, lambda: _collect(ctx, base_url))


def recheck(ctx: EngineContext, base_url: str, candidate) -> bool:
    path = candidate.endpoint
    exchange = ctx.http.get(base_url + path)
    return _hit(path, exchange.status, exchange.response_body)
