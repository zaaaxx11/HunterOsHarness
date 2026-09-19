"""R2-B B3 — heavy opt-in tools: slither (static-only) + cast (readonly).

Separation of privilege by construction:

- ``slither_audit`` is static analysis ONLY: it never executes chain data,
  never opens a socket, and requires tier ``advanced`` (``danger="approval"``).
  Input contracts are hash-verified (``source_sha256``); outputs are redacted
  and bounded at 8k.
- ``cast_call`` is readonly (``danger="none"``, tier ``basic``): it rides
  ``ctx.http`` through the scope gate against a manifest host. Send verbs
  (``cast_send`` / ``cast_publish`` / ``cast_tx`` / ``eth_sendTransaction``)
  are NEVER registered — this module has no code path that signs, sends, or
  publishes a transaction.
- Every handler emits exactly one ``engine_event``, even on error paths.

``register_heavy_tools`` is conditional: when the binary is missing the tool
surfaces as ``tool.unavailable`` with the SAME install-hint message the web3
hints use; only a present binary registers the real spec.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator
from typing import Any

import httpx

from hunter.kernel.redaction import redact_text
from hunter.tools.scope import ScopeViolation

__all__ = [
    "CAST_CALL_SPEC",
    "OUTCOME_TABLE",
    "SLITHER_AUDIT_SPEC",
    "SPEC_NAMES",
    "SPECS",
    "cast_call",
    "iter_tool_specs",
    "register_heavy_tools",
    "slither_audit",
]

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

OUTCOME_TABLE: dict[str, tuple[str, ...]] = {
    "slither_audit": FIVE,
    "cast_call": FIVE,
}

_EVIDENCE_LIMIT = 8192
_EVIDENCE_SLACK = 256

SLITHER_INSTALL_HINT = (
    "slither is not installed; install with: pip install slither-analyzer && slither --version"
)
CAST_INSTALL_HINT = (
    "cast is not installed; install with: curl -L https://foundry.paradigm.xyz | bash && foundryup"
)

SLITHER_AUDIT_SPEC: dict[str, Any] = {
    "name": "slither_audit",
    "description": "Static-only Solidity audit hint (no exec, no network). Approval-gated, advanced tier.",
    "danger": "approval",
    "min_tier": "advanced",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "source_sha256": {"type": "string"},
        },
        "required": ["path", "source_sha256"],
        "additionalProperties": True,
    },
}

CAST_CALL_SPEC: dict[str, Any] = {
    "name": "cast_call",
    "description": "Readonly cast call against a manifest RPC host (no sends). Basic tier.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "chain_id": {"type": "integer"},
            "address": {"type": "string"},
            "calldata": {"type": "string"},
            "rpc_url": {"type": "string"},
        },
        "required": ["chain_id", "address", "rpc_url"],
        "additionalProperties": True,
    },
}

SPECS = (SLITHER_AUDIT_SPEC, CAST_CALL_SPEC)
SPEC_NAMES = tuple(s["name"] for s in SPECS)


def iter_tool_specs() -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(name, spec)`` in lockstep with :data:`OUTCOME_TABLE` keys."""
    by_name = {s["name"]: s for s in SPECS}
    for name in OUTCOME_TABLE:
        yield name, by_name[name]


def _emit(ctx: Any, tool: str, extra: dict[str, Any] | None = None) -> None:
    try:
        payload = {"tool": tool}
        if extra:
            payload.update(extra)
        ctx.emit("engine_event", payload)
    except Exception:
        pass


def _tier(ctx: Any) -> str:
    try:
        return str((getattr(ctx, "config", {}) or {}).get("tier", "basic"))
    except Exception:
        return "basic"


def _bound(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Bound evidence data at 8k; returns ``(data, truncated)``."""
    blob = json.dumps(data)
    if len(blob) > _EVIDENCE_LIMIT:
        cut = dict(data)
        cut["result"] = str(data.get("result", ""))[: _EVIDENCE_LIMIT - 512]
        cut["truncated"] = True
        cut["truncation_marker"] = f"...[truncated at {_EVIDENCE_LIMIT} chars]"
        return cut, True
    return data, False


def slither_audit(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Static-only audit hint. Never executes chain data, never touches net."""
    path = redact_text(str(args.get("path", "") or ""))[:500]
    sha = str(args.get("source_sha256", "") or "").strip().lower()
    if _tier(ctx) != "advanced":
        _emit(ctx, "slither_audit", {"code": "tier.capability_locked"})
        return {
            "ok": False,
            "blocked": True,
            "code": "tier.capability_locked",
            "result_for_model": "BLOCKED [tier.capability_locked] slither_audit needs advanced tier.",
        }
    if not path or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        _emit(ctx, "slither_audit", {"code": "slither.input_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "slither.input_required",
            "result_for_model": "slither_audit requires 'path' + 64-hex 'source_sha256'.",
        }
    data = {
        "path": path,
        "source_sha256": sha,
        "mode": "static",
        "executed_chain_data": False,
        "note": "static hint only: no execution, no network; verify vs pinned hash.",
    }
    data, truncated = _bound(data)
    _emit(ctx, "slither_audit", {"code": "ok", "truncated": truncated})
    model = redact_text(f"slither static hint for {path} (sha {sha[:12]})"
                        + (" [truncated]" if truncated else ""))
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "mode": "static",
        "executed_chain_data": False,
        "result_for_model": model,
        "evidence": {"kind": "slither_audit", "data": data},
    }


def cast_call(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Readonly RPC read through the scope gate. No send path exists."""
    rpc_url = str(args.get("rpc_url", "") or "").strip()
    address = redact_text(str(args.get("address", "") or "").strip().lower())[:100]
    calldata = str(args.get("calldata", "") or "").strip() or "0x"
    chain_id = args.get("chain_id")
    try:
        ctx.scope.check_url(rpc_url)
    except ScopeViolation as exc:
        _emit(ctx, "cast_call", {"code": "scope.target_out_of_scope"})
        return {
            "ok": False,
            "blocked": True,
            "code": "scope.target_out_of_scope",
            "result_for_model": f"BLOCKED [scope.target_out_of_scope] {redact_text(str(exc))[:300]}",
        }
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                       "params": [{"to": address, "data": calldata}, "latest"]})
    try:
        ex = ctx.http.request("POST", rpc_url, headers={"Content-Type": "application/json"}, body=body)
    except ScopeViolation as exc:
        _emit(ctx, "cast_call", {"code": "scope.target_out_of_scope"})
        return {
            "ok": False,
            "blocked": True,
            "code": "scope.target_out_of_scope",
            "result_for_model": f"BLOCKED [scope.target_out_of_scope] {redact_text(str(exc))[:300]}",
        }
    except httpx.HTTPError as exc:
        _emit(ctx, "cast_call", {"code": "http.transport_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.transport_error",
            "result_for_model": f"cast call failed: {type(exc).__name__}",
        }
    if ex.status != 200:
        _emit(ctx, "cast_call", {"code": "http.transport_error", "status": ex.status})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.transport_error",
            "result_for_model": f"cast call failed: HTTP {ex.status}",
        }
    result = redact_text(ex.response_body or "")
    truncated = len(result) > _EVIDENCE_LIMIT
    if truncated:
        result = result[:_EVIDENCE_LIMIT] + f"...[truncated at {_EVIDENCE_LIMIT} chars]"
    data = {
        "chain_id": chain_id,
        "address": address,
        "result": result,
        "truncated": truncated,
    }
    data, _ = _bound(data)
    _emit(ctx, "cast_call", {"code": "ok", "truncated": truncated})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result_for_model": redact_text(f"cast eth_call {address}: {result[:200]!r}")
        + (" [truncated]" if truncated else ""),
        "evidence": {"kind": "cast_call", "data": data},
    }


def register_heavy_tools(
    registry: Any,
    which_fn: Callable[[str], str | None] | None = None,
) -> Any:
    """Conditionally register heavy tools: present binary -> real spec,
    missing binary -> ``tool.unavailable`` with the shared install hint."""
    from hunter.agent.tools_base import ToolContext, ToolOutcome, ToolSpec  # noqa: PLC0415

    lookup = shutil.which if which_fn is None else which_fn

    def _wrap(name: str, fn: Any):  # type: ignore[no-untyped-def]
        def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
            out = fn(args, ctx)
            if out.get("blocked"):
                return ToolOutcome(ok=False, blocked=True, code=str(out.get("code", "blocked")),
                                   result_for_model=str(out.get("result_for_model", "blocked")))
            if not out.get("ok"):
                return ToolOutcome(ok=False, code=str(out.get("code", "error")),
                                   result_for_model=str(out.get("result_for_model", "error")),
                                   evidence=out.get("evidence"))
            return ToolOutcome(result_for_model=str(out.get("result_for_model", "ok")),
                               evidence=out.get("evidence"))

        return handler

    candidates = (
        ("slither_audit", SLITHER_AUDIT_SPEC, slither_audit, "slither", SLITHER_INSTALL_HINT),
        ("cast_call", CAST_CALL_SPEC, cast_call, "cast", CAST_INSTALL_HINT),
    )
    for name, spec, fn, binary, hint in candidates:
        try:
            present = bool(lookup(binary))
        except Exception:
            present = False
        if present:
            registry.register(
                ToolSpec(
                    name=name,
                    description=str(spec["description"]),
                    parameters=dict(spec["parameters"]),
                    handler=_wrap(name, fn),
                    min_tier=str(spec["min_tier"]),
                    danger=str(spec["danger"]),
                )
            )
        else:
            registry.register_unavailable(name, "tool.unavailable", hint)
    return registry
