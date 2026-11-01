"""Part C — promotion of PROVEN-LIVE critical/high findings into reusable
skills and tools.

Eligibility rule (RETENTION-SPEC.md Part C):

    PROVEN-LIVE + severity IN (critical, high)  -> eligible
    PROVEN-LIVE + medium/low/info               -> NOT eligible
    any UNPROVEN status                         -> NEVER eligible

A "proven-live" finding is one whose status is the top of the evidence ladder
(the doctrine: theoretical -> promoted -> proven-live).  In the current schema
the raw string stored in `findings.status` is the canonical label; the ladder
may be driven through verifier-transcript + adversary-challenge evidence even
when no explicit `FindingStatus.PROVEN_LIVE` enum member exists yet.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from hunter.errors import HunterError
from hunter.kernel.findings import Finding, FindingStatus, Severity, finding_id
from hunter.kernel.ledger import Ledger
from hunter.taxonomy import load_klasses

# -- public surface -----------------------------------------------------------

class NotEligible(HunterError):
    """Raised when a finding does not meet the promotion gate."""

    def __init__(self, finding_key: str, reason: str) -> None:
        super().__init__(
            code="promotion.not_eligible",
            layer="claim",
            message=f"finding '{finding_key}' is not eligible for promotion: {reason}",
            exit_code=6,
        )
        self.finding_key = finding_key
        self.reason = reason


@dataclass(frozen=True)
class PromotionCandidate:
    finding_id: str
    finding_key: str
    title: str
    severity: str
    status: str
    klass: str
    endpoint: str
    description: str
    impact: str
    remediation: str
    poc_path: str | None
    evidence_ids: tuple[str, ...]
    method: str | None = None
    param: str | None = None


# -- helpers ------------------------------------------------------------------

def _is_proven_live(status: str) -> bool:
    return str(status).strip().lower().replace(" ", "_").replace("-", "_") == "proven_live"


def _eligible_severity(severity: str) -> bool:
    return str(severity).strip().lower() in {"critical", "high"}


def _klass_label(klass: str) -> str:
    """Resolve a class id to a human-readable class label."""
    klasses = load_klasses()
    entry = klasses.get(str(klass))
    if entry:
        return str(entry.get("label") or str(klass))
    return str(klass)


def _target_class(finding: Finding) -> str:
    """Extract a stable target CLASS — never the literal hostname."""
    raw = str(finding.klass or "").strip()
    return raw if raw else "unknown"


def _minify(text: str | None) -> str:
    text = str(text or "")
    text = " ".join(text.split())
    return text[:400]


_URL_RE = re.compile(r"https?://[^\s)\]]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s)\]]*)?", re.IGNORECASE)


def _sanitize_text(text: str | None) -> str:
    return _URL_RE.sub("[REDACTED]", str(text or ""))


def _sanitized_evidence_summary(finding: Finding) -> str:
    """Summarize what we proved, from evidence already bound to the finding."""
    # The evidence payload lives in the ledger and is already redacted; we never
    # re-emit raw request bodies/tokens.  Here we just surface the *count* and
    # the high-level technique, not the payload.
    count = len(tuple(finding.evidence_ids or ()))
    klass = _target_class(finding)
    return (
        f"{count} evidence artifact(s) bound; technique class: {klass}."
    )


def _sanitized_endpoint(endpoint: str) -> str:
    """Strip any scheme/host from an endpoint so only the path remains."""
    raw = str(endpoint or "").strip()
    # strip scheme://host
    m = re.match(r"^(?:[a-z][a-z0-9+.-]*://)[^/\s]+(/.*)?$", raw)
    if m:
        return m.group(1) or "/"
    return raw


# -- skill writer -------------------------------------------------------------

def _skill_name(title: str, klass: str) -> str:
    words = re.findall(r"[a-z0-9]+", f"{title} {klass}".lower())
    # drop words that only serve as the class id (keep the id if there are no
    # other words, so we don't end up with an empty slug).
    seen: list[str] = []
    want = [w for w in re.findall(r"[a-z0-9]+", klass.lower()) if w]
    for w in words:
        if w in want and seen:
            continue
        seen.append(w)
    slug = "-".join(seen)[:48].strip("-")
    return slug or "promoted-skill"


def _skill_description(title: str, klass: str, severity: str) -> str:
    cls = _klass_label(klass)
    label = "critical" if str(severity).lower() == "critical" else "high"
    # The title is free text from the source finding and routinely carries the
    # live target host (e.g. "Error-based SQLi on app.example.com"): a promoted
    # skill must never leak the target it came from, so redact BEFORE
    # shortening (redacting after truncation can slice a hostname in half and
    # leave a recognisable fragment).
    short = " ".join(_sanitize_text(str(title or "")).split())
    if not short:
        # A finding may have no title at all. Never emit an empty description:
        # YAML turns it into ``description: null`` and the card is unloadable.
        short = f"{cls} technique"
    if len(short) > 80:
        short = short[:77].rstrip() + "..."
    prefix = f"{cls} ({label}) technique promoted from a proven-live audit finding"
    description = f"{prefix}: {short}"
    # Hard ceiling: a pathological title must not push us past the parser's cap.
    return description[:199].rstrip()


def _build_skill_body(finding: Finding, klass: str) -> str:
    target_cls = _target_class(finding)
    endpoint = _sanitized_endpoint(finding.endpoint)
    evidence_line = _sanitized_evidence_summary(finding)
    lane = load_klasses().get(klass, {}).get("lane", "")

    lines = [
        f"# {finding.title}",
        "",
        "## Do not use outside scope",
        "",
        "This card encodes a **reproducible** verified-live technique. It is inert "
        "outside the attack surface it was proven against. It must not be used "
        "against systems that are not in scope and explicitly authorized.",
        "",
        "## Class",
        "",
        f"- Class: `{target_cls}` ({_klass_label(klass)})",
        f"- Lane: `{lane}`" if lane else "",
        f"- Endpoint pattern: `{endpoint}`",
        f"- Method: `{finding.method or 'GET'}`",
        f"- Parameter: `{finding.param or '-'}`",
        "",
        "## Evidence summary",
        "",
        evidence_line,
        "",
        "## Technique summary",
        "",
        _sanitize_text(_minify(finding.description)) or "No description recorded.",
        "",
        "## Impact",
        "",
        _sanitize_text(_minify(finding.impact)) or "Impact recorded in the source finding.",
        "",
        "## Remediation",
        "",
        _sanitize_text(_minify(finding.remediation)) or "Remediation recorded in the source finding.",
        "",
        "## Reproduction",
        "",
        "This card documents the finding, not a payload. Reproduce from the "
        "original PoC artifact referenced by the ledger row; do not paste raw "
        "request bodies here.",
        "",
        "## Provenance",
        "",
        f"- Source finding: `{finding.id}` (state: proven-live)",
        f"- Dedupe key: `{finding.key}`",
    ]

    if finding.poc_path:
        lines.append(f"- PoC path (ledger reference): `{finding.poc_path}`")

    lines += [
        "",
        "## Falsifier",
        "",
        _sanitize_text(_minify(finding.falsifier))
        or "Apply the recommended remediation and re-run the same probe.",
    ]
    return "\n".join(lines)


def _render_skill_md(name: str, description: str, body: str, tags: tuple[str, ...]) -> str:
    tag_block = "\n".join(f"- {t}" for t in tags)
    # JSON-quote the description so free-text colons / quotes never split the
    # YAML mapping and the card stays parseable after every write.
    safe_description = json.dumps(description, ensure_ascii=False)
    return (
        "---\n"
        f"name: {name}\n"
        f"description: {safe_description}\n"
        "version: 0.1.0\n"
        "metadata:\n"
        "  min_tier: basic\n"
        "tags:\n"
        f"{tag_block}\n"
        "---\n\n"
        f"{body}\n"
    )


# -- public API ---------------------------------------------------------------

def eligible_promotions(ledger: Ledger) -> list[PromotionCandidate]:
    """Return findings that are proven-live AND critical/high."""
    results: list[PromotionCandidate] = []
    for finding in ledger.findings():
        status = str(finding.status.value if isinstance(finding.status, FindingStatus) else finding.status)
        if not _is_proven_live(status):
            continue
        sev = finding.severity.value if isinstance(finding.severity, Severity) else finding.severity
        if not _eligible_severity(sev):
            continue
        results.append(
            PromotionCandidate(
                finding_id=str(finding.id),
                finding_key=str(finding.key),
                title=str(finding.title),
                severity=str(
                    finding.severity.value
                    if isinstance(finding.severity, Severity)
                    else finding.severity
                ),
                status=status,
                klass=str(finding.klass),
                endpoint=str(_sanitized_endpoint(finding.endpoint)),
                description=str(finding.description),
                impact=str(finding.impact),
                remediation=str(finding.remediation),
                poc_path=finding.poc_path,
                evidence_ids=tuple(finding.evidence_ids or []),
            )
        )
    return results


def promote_to_skill(ledger: Ledger, finding_key: str, *, skills_dir: Path) -> Path:
    """Promote an eligible finding into a SKILL.md card.

    Idempotent: re-promoting overwrites the file in place; no duplicates.
    """
    target = _resolve_target(ledger, finding_key)
    candidate = _as_candidate(target)

    name = _skill_name(candidate.title, candidate.klass)
    description = _skill_description(candidate.title, candidate.klass, candidate.severity)
    body = _build_skill_body(target, candidate.klass)
    tags = (
        "promoted",
        f"severity-{candidate.severity.lower()}",
        f"class-{candidate.klass.lower()}",
    )
    text = _render_skill_md(name, description, body, tags)

    skills_dir.mkdir(parents=True, exist_ok=True)
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    target_file = skill_dir / "SKILL.md"
    if target_file.exists():
        existing = target_file.read_text(encoding="utf-8")
        if existing != text:
            raise HunterError(
                code="promotion.conflict",
                layer="claim",
                message=(
                    f"refusing to overwrite existing skill at {target_file}"
                    f" (different finding key {finding_key!r})"
                ),
                exit_code=6,
            )
    target_file.write_text(text, encoding="utf-8")
    return target_file


def promote_to_tool(ledger: Ledger, finding_key: str, *, tools_dir: Path) -> Path:
    """Promote an eligible finding into a small Python tool script."""
    target = _resolve_target(ledger, finding_key)
    candidate = _as_candidate(target)

    name = _skill_name(candidate.title, candidate.klass)
    target_cls = _target_class(target)
    endpoint = _sanitized_endpoint(candidate.endpoint)
    script = _tool_body(candidate, target_cls, endpoint)

    tools_dir.mkdir(parents=True, exist_ok=True)
    target_file = tools_dir / f"{name}.py"
    target_file.write_text(script, encoding="utf-8")
    return target_file


def _tool_body(candidate: PromotionCandidate, target_cls: str, endpoint: str) -> str:
    return "\n".join(
        [
            'from __future__ import annotations',
            '',
            '"""Proven-live tool stub generated by hunter promote."""',
            '',
            '__all__ = ["main"]',
            '',
            f"FINDING_ID = {candidate.finding_id!r}",
            f"FINDING_KEY = {candidate.finding_key!r}",
            f"CLASS = {candidate.klass!r}",
            f"TARGET_CLASS = {target_cls!r}",
            f"ENDPOINT_PATTERN = {endpoint!r}",
            f"METHOD = {candidate.method or 'GET'!r}",
            f"PARAM = {candidate.param or '-'!r}",
            f"SEVERITY = {candidate.severity.lower()!r}",
            f"POC_REFERENCE = {candidate.poc_path or ''!r}",
            "",
            "",
            "def main() -> None:",
            "    print(",
            '        f"promoted-tool {FINDING_ID} {FINDING_KEY} "',
            '        f"class={TARGET_CLASS} severity={SEVERITY} endpoint={ENDPOINT_PATTERN}"',
            "    )",
            "",
            "",
            'if __name__ == "__main__":',
            "    main()",
        ]
    )


def target_class(finding: Finding) -> str:
    """Public: extract the stable target class for a finding (never the hostname)."""
    return _target_class(finding)


__all__ = [
    "NotEligible",
    "PromotionCandidate",
    "eligible_promotions",
    "promote_to_skill",
    "promote_to_tool",
    "target_class",
]

def _resolve_target(ledger: Ledger, finding_key: str) -> Finding:
    """Resolve a finding by ledger id ("F-0001"), key, or bare number ("1").

    Operators copy the id they see in the ledger/report ("F-3"), while the
    dedupe key is the long ``check_id|METHOD|endpoint|param`` string. Accepting
    both keeps `hunter promote skill F-3` usable without forcing the caller to
    look up an opaque key first.
    """
    wanted = str(finding_key).strip()
    # "F-0001" / "f-1" / "0001" / "1" all collapse onto the numeric id.
    numeric: int | None = None
    match = re.fullmatch(r"(?:[Ff]-)?0*(\d+)", wanted)
    if match:
        numeric = int(match.group(1))

    for finding in ledger.findings():
        if str(finding.key) == wanted:
            return finding
        if numeric is not None and str(getattr(finding, "id", "")) == finding_id(numeric):
            return finding
    raise KeyError(f"finding '{finding_key}' not found in ledger")


def _as_candidate(finding: Finding) -> PromotionCandidate:
    status = str(finding.status.value if isinstance(finding.status, FindingStatus) else finding.status)
    if not _is_proven_live(status):
        raise NotEligible(
            finding.key,
            f"status is {status!r}; only proven-live findings may be promoted",
        )
    sev = str(finding.severity.value if isinstance(finding.severity, Severity) else finding.severity)
    if not _eligible_severity(sev):
        raise NotEligible(
            finding.key,
            f"severity is {sev!r}; only critical/high findings may be promoted",
        )
    return PromotionCandidate(
        finding_id=str(finding.id),
        finding_key=str(finding.key),
        title=str(finding.title),
        severity=sev,
        status=status,
        klass=str(finding.klass),
        endpoint=str(finding.endpoint),
        description=str(finding.description),
        impact=str(finding.impact),
        remediation=str(finding.remediation),
        poc_path=finding.poc_path,
        evidence_ids=tuple(finding.evidence_ids or []),
        method=str(finding.method) if getattr(finding, "method", None) else None,
        param=str(finding.param) if getattr(finding, "param", None) else None,
    )
