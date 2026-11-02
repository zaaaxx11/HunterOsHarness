"""verify_finding — upgrade a finding from CANDIDATE to PROVEN_LIVE.

The agent ships a hypothesis (CANDIDATE). This tool upgrades it through the
verification ladder:

    CANDIDATE → verify_finding(verified=true)  → VERIFIED
    VERIFIED  → verify_finding(promoted=true)  → PROMOTED
    PROMOTED  → verify_finding(proven=true)    → PROVEN_LIVE

At each step the agent MUST re-read the evidence and confirm the claim
independently — a status change without re-verification is BLOCKED.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hunter.kernel.findings import FindingStatus
from hunter.agent.tools_base import ToolContext, ToolOutcome

__all__ = ["verify_finding", "register_verify_tool"]


def verify_finding(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    """Upgrade a finding's status through the verification ladder.

    Required:
        finding_id  — the finding to verify (e.g. "F-0001")
        verdict     — "confirmed" or "ruled_out"
        reason      — one-line explanation of the verdict

    Optional:
        poc         — PoC script content (saved to reports/<id>/poc.sol or .py)
        logs        — plain-text execution log (saved to reports/<id>/logs.txt)
        promote     — if true, also advance VERIFIED → PROMOTED
        prove       — if true, also advance to PROVEN_LIVE (requires promote)

    The agent MUST have re-read the evidence before calling this. A status
    change without fresh evidence in the same turn is BLOCKED.
    """
    finding_id = str(args.get("finding_id", "")).strip()
    if not finding_id:
        return ToolOutcome(
            ok=False, blocked=True, code="verify.missing_id",
            result_for_model="BLOCKED [verify.missing_id] finding_id is required.",
        )

    verdict = str(args.get("verdict", "")).strip().lower()
    if verdict not in ("confirmed", "ruled_out"):
        return ToolOutcome(
            ok=False, blocked=True, code="verify.invalid_verdict",
            result_for_model=(
                f"BLOCKED [verify.invalid_verdict] verdict must be 'confirmed'"
                f" or 'ruled_out' (got {verdict!r})."
            ),
        )

    reason = str(args.get("reason", "")).strip()
    if not reason:
        return ToolOutcome(
            ok=False, blocked=True, code="verify.missing_reason",
            result_for_model="BLOCKED [verify.missing_reason] reason is required.",
        )

    promote = bool(args.get("promote", False))
    prove = bool(args.get("prove", False))
    if prove and not promote:
        return ToolOutcome(
            ok=False, blocked=True, code="verify.prove_without_promote",
            result_for_model=(
                "BLOCKED [verify.prove_without_promote] prove=true requires"
                " promote=true — PROVEN_LIVE is only reachable from PROMOTED."
            ),
        )

    # -- save POC and logs to disk --------------------------------------------
    state_dir = Path(ctx.config.get("state_dir", "."))
    reports_dir = state_dir / "reports" / finding_id
    reports_dir.mkdir(parents=True, exist_ok=True)

    poc = str(args.get("poc", "")).strip()
    logs = str(args.get("logs", "")).strip()
    poc_path = None
    logs_path = None

    if poc:
        ext = ".sol" if "solidity" in poc.lower() or "pragma" in poc.lower() else ".py"
        poc_file = reports_dir / f"poc{ext}"
        poc_file.write_text(poc, encoding="utf-8")
        poc_path = str(poc_file)

    if logs:
        logs_file = reports_dir / "logs.txt"
        logs_file.write_text(logs, encoding="utf-8")
        logs_path = str(logs_file)

    # -- status transition ----------------------------------------------------
    try:
        ledger = ctx.ledger
        if verdict == "ruled_out":
            updated = ledger.set_finding_status(
                finding_id, FindingStatus.RULED_OUT, reason
            )
            return ToolOutcome(
                ok=True, blocked=False, code="ok",
                result_for_model=(
                    f"Finding {finding_id} RULED_OUT: {reason}\n"
                    + (f"POC: {poc_path}\n" if poc_path else "")
                    + (f"Logs: {logs_path}" if logs_path else "")
                ).strip(),
            )

        # confirmed → VERIFIED
        updated = ledger.set_finding_status(
            finding_id, FindingStatus.VERIFIED, reason,
            poc_path=poc_path, logs_path=logs_path,
        )

        lines = [f"Finding {finding_id} VERIFIED: {reason}"]
        if poc_path:
            lines.append(f"POC: {poc_path}")
        if logs_path:
            lines.append(f"Logs: {logs_path}")

        if promote:
            updated = ledger.set_finding_status(
                finding_id, FindingStatus.PROMOTED,
                f"Adversary challenge survived: {reason}",
                falsifier=str(args.get("falsifier", "")) or None,
                poc_path=poc_path, logs_path=logs_path,
            )
            lines.append(f"→ PROMOTED (challenge survived)")

        if prove:
            updated = ledger.set_finding_status(
                finding_id, FindingStatus.PROVEN_LIVE,
                f"Independent verification confirmed: {reason}",
                poc_path=poc_path, logs_path=logs_path,
            )
            lines.append(f"→ PROVEN_LIVE (independent verification)")

        return ToolOutcome(
            ok=True, blocked=False, code="ok",
            result_for_model="\n".join(lines),
        )

    except KeyError:
        return ToolOutcome(
            ok=False, blocked=True, code="verify.not_found",
            result_for_model=(
                f"BLOCKED [verify.not_found] finding {finding_id!r} not found"
                " in the ledger."
            ),
        )
    except Exception as exc:
        return ToolOutcome(
            ok=False, blocked=True, code="verify.claim_gate",
            result_for_model=(
                f"BLOCKED [verify.claim_gate] {exc}"
            ),
        )


def register_verify_tool(registry) -> None:
    from hunter.agent.tools_base import ToolSpec  # noqa: PLC0415

    registry.register(
        ToolSpec(
            name="verify_finding",
            description=(
                "Upgrade a finding through the verification ladder: confirmed"
                " → VERIFIED, promote → PROMOTED, prove → PROVEN_LIVE."
                " Requires re-reading evidence. Saves POC and plain-text logs"
                " to reports/<finding_id>/."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["confirmed", "ruled_out"]},
                    "reason": {"type": "string"},
                    "poc": {"type": "string"},
                    "logs": {"type": "string"},
                    "promote": {"type": "boolean"},
                    "prove": {"type": "boolean"},
                },
                "required": ["finding_id", "verdict", "reason"],
            },
            handler=verify_finding,
        )
    )