"""Markdown report renderer — ledger-only, tamper-evident.

The report is a VIEW over the ledger, never over prose: every finding section,
every evidence row is rendered from stored rows, and the whole render is
refused (:class:`ReportBlocked`) unless the run's hash chain verifies. If the
chain is broken, the ledger has been tampered with and no report may be
produced from it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from hunter.kernel.findings import SEVERITY_ORDER, FindingStatus

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.kernel.ledger import Ledger

__all__ = ["ReportBlocked", "render_markdown"]


class ReportBlocked(PermissionError):
    """Raised when a report cannot be rendered because the hash chain of the
    run fails verification — tamper-evidence wins over convenience."""


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _cell(value: Any) -> str:
    """Make a string safe inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(ledger: Ledger, run_id: str) -> str:
    """Render the full Markdown report for ``run_id`` from ledger rows only.

    Raises:
        ReportBlocked: when ``ledger.verify_chain(run_id)`` fails.
        KeyError: when the run does not exist in the ledger.
    """
    chain = ledger.verify_chain(run_id)
    if not chain.ok:
        details = "; ".join(chain.details) or "no detail recorded"
        raise ReportBlocked(
            f"BLOCKED: hash chain verification FAILED for run {run_id!r} "
            f"(broken at seq {chain.broken_at_seq}): {details}. "
            "The ledger may have been tampered with — no report is rendered."
        )
    run_row = next((row for row in ledger.runs() if row["run_id"] == run_id), None)
    if run_row is None:
        raise KeyError(f"run {run_id!r} not found in the ledger")

    events = ledger.events(run_id)
    findings = sorted(
        ledger.findings(run_id),
        key=lambda f: (-SEVERITY_ORDER[f.severity.value], f.id),
    )
    evidence_by_id = {row["id"]: row for row in ledger.evidence(run_id)}
    run_started = next((e for e in events if e.kind_value() == "run_started"), None)
    scope_payload: dict[str, Any] = dict(run_started.payload.get("scope") or {}) if run_started else {}

    lines: list[str] = [f"# HunterOs Report — run {run_id}", ""]

    # -- chain verification line --------------------------------------------------
    lines.append(
        f"**Chain verification: OK** — {chain.checked} events hash-verified (tamper-evident)."
    )
    lines.append("")

    # -- metadata table ------------------------------------------------------------
    scope_name = scope_payload.get("name") or run_row["scope_name"]
    hosts = [str(host) for host in (scope_payload.get("hosts") or [])]
    hosts_text = ", ".join(hosts) if hosts else "none beyond loopback"
    lines += [
        "| Field | Value |",
        "| --- | --- |",
        f"| Target | {_cell(run_row['target'])} |",
        f"| Engine | {_cell(run_row['engine'])} |",
        f"| Scope | {_cell(scope_name)} (hosts: {_cell(hosts_text)}) |",
        f"| Started | {_fmt_ts(run_row['started_ts'])} |",
        f"| Ended | {_fmt_ts(run_row['ended_ts'])} |",
        f"| Status | {_cell(run_row['status'])} |",
        "",
    ]

    # -- summary table ---------------------------------------------------------------
    verified = sum(1 for f in findings if f.status is FindingStatus.VERIFIED)
    candidates = sum(1 for f in findings if f.status is FindingStatus.CANDIDATE)
    by_severity: dict[str, dict[str, int]] = {}
    for finding in findings:
        row = by_severity.setdefault(finding.severity.value, {"total": 0, "verified": 0, "candidate": 0})
        row["total"] += 1
        if finding.status is FindingStatus.VERIFIED:
            row["verified"] += 1
        elif finding.status is FindingStatus.CANDIDATE:
            row["candidate"] += 1
    lines += [
        "## Summary",
        "",
        "| Severity | Findings | Verified | Candidates |",
        "| --- | --- | --- | --- |",
    ]
    for severity in sorted(by_severity, key=lambda s: -SEVERITY_ORDER[s]):
        row = by_severity[severity]
        lines.append(
            f"| {severity} | {row['total']} | {row['verified']} | {row['candidate']} |"
        )
    lines += [
        f"| **Total** | **{len(findings)}** | **{verified}** | **{candidates}** |",
        "",
    ]

    # -- one section per finding -------------------------------------------------------
    if not findings:
        lines += ["_No findings recorded for this run._", ""]
    for finding in findings:
        param = finding.param if finding.param is not None else "-"
        lines += [
            f"## {finding.id} — {_cell(finding.title)}",
            "",
            f"- **Severity:** {finding.severity.value}",
            f"- **Status:** {finding.status.value}",
            f"- **CWE:** {finding.cwe}",
            f"- **Endpoint:** `{finding.method} {finding.endpoint}` (param: `{param}`)",
            "",
        ]
        if finding.description:
            lines += [f"**Description:** {finding.description}", ""]
        if finding.impact:
            lines += [f"**Impact:** {finding.impact}", ""]
        if finding.remediation:
            lines += [f"**Remediation:** {finding.remediation}", ""]
        lines += [
            "### Evidence",
            "",
            "| ID | Kind | SHA-256 | Replay | Excerpt |",
            "| --- | --- | --- | --- | --- |",
        ]
        for evidence_id in finding.evidence_ids:
            lines.append(_evidence_row(evidence_by_id.get(evidence_id), evidence_id))
        lines.append("")

    # -- footer -------------------------------------------------------------------------
    lines += ["---", "", "*Rendered from ledger evidence only — hash-chained, tamper-evident.*", ""]
    return "\n".join(lines)


def _evidence_row(row: dict[str, Any] | None, evidence_id: str) -> str:
    """Render one evidence table row from the stored evidence row."""
    if row is None:
        # Evidence rows are append-only, so a bound-but-missing row means the
        # ledger is inconsistent; still render the binding instead of lying.
        return f"| {evidence_id} | ? | - | - | evidence row missing from ledger |"
    data = row["data"] if isinstance(row["data"], dict) else {}
    replay = "yes" if data.get("replay") is True else "no"
    if "method" in data and "url" in data:
        excerpt = f"{data.get('method')} {data.get('url')} -> {data.get('status')}"
    else:
        excerpt = str(data.get("note") or row["kind"])
    return (
        f"| {row['id']} | {row['kind']} | {row['sha256'][:12]} | {replay} | {_cell(excerpt)} |"
    )
