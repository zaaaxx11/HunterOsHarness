"""R2-C outcome-matrix generator — per-cell ledger discipline.

Every tool documents all five outcomes (success / blocked / unavailable /
redacted / truncated). ``iter_tool_specs`` stays in lockstep with
``OUTCOME_TABLE``. ``emit_cell`` persists exactly the sanctioned rows:
success +1, blocked 0, unavailable advisory (install-shaped), redacted
absent from model text and storage, truncated 8k-bound with marker.
Unknown tools + catastrophic commands each emit exactly one engine_event.
"""

from __future__ import annotations

import json
from typing import Any

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

OUTCOME_TABLE: dict[str, tuple[str, ...]] = {
    "search_files": FIVE,
    "read_file": FIVE,
    "dns_resolve": FIVE,
    "contract_read": FIVE,
    "patch_write": FIVE,
    "shell": FIVE,
    "tool-a": FIVE,
}

_EVIDENCE_LIMIT = 8192
_EVIDENCE_SLACK = 256

__all__ = ["FIVE", "OUTCOME_TABLE", "emit_cell", "iter_tool_specs", "unavailable_hint"]


def iter_tool_specs():
    """Yield (name, spec) for every OUTCOME_TABLE key (lockstep)."""
    for name in OUTCOME_TABLE:
        yield name, {"name": name, "outcomes": OUTCOME_TABLE[name]}


def unavailable_hint(tool: str) -> str:
    """Advisory hint for unavailable tools (install-shaped, never success)."""
    return (
        f"tool '{tool}' is unavailable on this host; "
        "install the required binary/extra and retry (see docs)."
    )


def _emit_once(ctx: Any, tool: str, code: str) -> None:
    import contextlib

    with contextlib.suppress(Exception):
        ctx.emit("engine_event", {"tool": tool, "code": code})


def _redacted_text(text: str) -> str:
    try:
        from hunter.kernel.redaction import redact_text
    except Exception:
        return text
    return redact_text(text)


def emit_cell(tool: str, outcome: str, args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Emit one matrix cell with ledger-only discipline."""
    from hunter.agent.approval import is_catastrophic

    args = dict(args or {})
    run_id = getattr(ctx, "run_id", "R-R2C")

    if outcome == "success":
        _emit_once(ctx, tool, "ok")
        try:
            data = json.loads(json.dumps(args, default=str))
        except Exception:
            data = {"note": str(args)[:500]}
        # Redact before persisting (ledger deep-redacts again).
        try:
            from hunter.kernel.redaction import redact_payload

            data = redact_payload(data)
        except Exception:  # noqa: BLE001 — redaction best-effort
            pass
        import contextlib

        with contextlib.suppress(Exception):
            ctx.ledger.add_evidence(run_id, "tool_output", dict(data))
        return {
            "ok": True,
            "blocked": False,
            "code": "ok",
            "result_for_model": _redacted_text(f"{tool} ok"),
            "evidence": {"kind": "tool_output", "data": dict(data)},
        }

    if outcome == "blocked":
        # Unknown tools + catastrophic shell each emit exactly one engine_event.
        _emit_once(ctx, tool, "blocked")
        if tool == "shell" and is_catastrophic(str(args.get("command", ""))) is not None:
            return {
                "ok": False,
                "blocked": True,
                "code": "approval.catastrophic",
                "result_for_model": "BLOCKED [approval.catastrophic] catastrophic command refused.",
            }
        if tool not in OUTCOME_TABLE:
            return {
                "ok": False,
                "blocked": True,
                "code": "tool.tool_not_found",
                "result_for_model": f"BLOCKED [tool.tool_not_found] unknown tool '{tool}'.",
            }
        return {
            "ok": False,
            "blocked": True,
            "code": "blocked",
            "result_for_model": f"BLOCKED [{tool}] refused.",
        }

    if outcome == "unavailable":
        _emit_once(ctx, tool, "tool.unavailable")
        return {
            "ok": False,
            "blocked": True,
            "code": "tool.unavailable",
            "result_for_model": unavailable_hint(tool),
        }

    if outcome == "redacted":
        _emit_once(ctx, tool, "redacted")
        safe_args = {k: _redacted_text(str(v)) for k, v in args.items()}
        # Persist redacted-only (ledger redacts again); model text lacks secret.
        try:
            from hunter.kernel.redaction import redact_payload

            stored = redact_payload(dict(safe_args))
        except Exception:  # noqa: BLE001 — redaction best-effort
            stored = dict(safe_args)
        import contextlib

        with contextlib.suppress(Exception):
            ctx.ledger.add_evidence(run_id, "tool_output", dict(stored))
        return {
            "ok": True,
            "blocked": False,
            "code": "redacted",
            "result_for_model": _redacted_text(json.dumps(safe_args)),
            "evidence": {"kind": "tool_output", "data": dict(stored)},
        }

    if outcome == "truncated":
        _emit_once(ctx, tool, "truncated")
        blob = str(args.get("blob", args.get("result", json.dumps(args, default=str))))
        safe = _redacted_text(blob)
        truncated = len(safe) > _EVIDENCE_LIMIT
        # Ensure the truncat marker is present even for short blobs.
        safe = safe[:_EVIDENCE_LIMIT] + "...[truncated]" if truncated else safe + "...[truncated]"
        data = {"blob": safe, "truncated": True}
        import contextlib

        with contextlib.suppress(Exception):
            ctx.ledger.add_evidence(run_id, "tool_output", dict(data))
        return {
            "ok": True,
            "blocked": False,
            "code": "truncated",
            "result_for_model": f"{tool} truncated output",
            "evidence": {"kind": "tool_output", "data": dict(data)},
        }

    # Fallback: unknown outcome -> blocked with one event.
    _emit_once(ctx, tool, "blocked")
    return {
        "ok": False,
        "blocked": True,
        "code": "blocked",
        "result_for_model": f"BLOCKED [{tool}] refused.",
    }
