"""Planner B T4 — readonly on-chain audit tools (no sends, no web3 dep).

Scope is EXACT (chain_id, lowercase address); RPC rides ctx.http through the
scope gate. eth_getStorageAt needs advanced tier. Every handler emits exactly
one engine_event. contract_call evidence is coverage-only (never R3).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from hunter.kernel.redaction import redact_text
from hunter.tools.scope import ScopeViolation

__all__ = [
    "CONTRACT_READ_METHODS",
    "EXPLORER_ALLOWLIST",
    "OUTCOME_TABLE",
    "RPC_BREAKER",
    "RPC_CACHE",
    "SPEC_NAMES",
    "SPECS",
    "abi_decode_hint",
    "build_web3_registry",
    "contract_read",
    "contract_source_fetch",
    "ladder_read",
    "load_rpc_key",
    "register_web3_tools",
    "validate_web3_kind_fit",
]

CONTRACT_READ_METHODS = ("eth_call", "eth_getCode", "eth_getBalance", "eth_getStorageAt")
_BASIC_METHODS = frozenset({"eth_call", "eth_getCode", "eth_getBalance"})

EXPLORER_ALLOWLIST = frozenset(
    {
        "api.etherscan.io",
        "etherscan.io",
        "api-sepolia.etherscan.io",
        "sepolia.etherscan.io",
        "api-arbiscan.io",
        "arbiscan.io",
        "api.bscscan.com",
        "bscscan.com",
        "api.polygonscan.com",
        "polygonscan.com",
    }
)

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

OUTCOME_TABLE: dict[str, tuple[str, ...]] = {
    "contract_read": FIVE,
    "contract_source_fetch": FIVE,
    "abi_decode_hint": FIVE,
    "ladder_read": FIVE,
}

# R2-B B2 live-ladder state: module dicts are the introspection seam
# (existence pin); per-run counting lives in ctx.state so parallel runs
# stay isolated.
RPC_CACHE: dict[str, Any] = {}
RPC_BREAKER: dict[str, Any] = {"failures": {}}
RPC_BUDGET_CAP = 100
RPC_RESULT_LIMIT = 16384

_CONTRACT_READ_SPEC: dict[str, Any] = {
    "name": "contract_read",
    "description": "Readonly JSON-RPC contract read (no sends) behind exact on-chain scope.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "chain_id": {"type": "integer"},
            "address": {"type": "string"},
            "method": {"type": "string", "enum": list(CONTRACT_READ_METHODS)},
            "rpc_url": {"type": "string"},
            "calldata": {"type": "string"},
        },
        "required": ["chain_id", "address", "method", "rpc_url"],
        "additionalProperties": False,
    },
}
_SOURCE_SPEC: dict[str, Any] = {
    "name": "contract_source_fetch",
    "description": "Fetch verified contract source from an explorer allowlist host.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "chain_id": {"type": "integer"},
            "address": {"type": "string"},
            "explorer": {"type": "string"},
        },
        "required": ["chain_id", "address", "explorer"],
        "additionalProperties": False,
    },
}
_ABI_SPEC: dict[str, Any] = {
    "name": "abi_decode_hint",
    "description": "Pure-stdlib ABI decode hint (no network, no scope).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "sig": {"type": "string"},
            "calldata": {"type": "string"},
        },
        "required": ["sig", "calldata"],
        "additionalProperties": False,
    },
}

SPECS = (_CONTRACT_READ_SPEC, _SOURCE_SPEC, _ABI_SPEC)
SPEC_NAMES = tuple(s["name"] for s in SPECS)


def _emit(ctx: Any, tool: str, extra: dict[str, Any] | None = None) -> None:
    try:
        payload = {"tool": tool}
        if extra:
            payload.update(extra)
        ctx.emit("engine_event", payload)
    except Exception:
        pass


def _blocked(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "blocked": True, "code": code, "result_for_model": message}


def _tier(ctx: Any) -> str:
    try:
        return str((getattr(ctx, "config", {}) or {}).get("tier", "basic"))
    except Exception:
        return "basic"


def _chain_scope(ctx: Any) -> list[dict[str, Any]]:
    try:
        raw = (getattr(ctx, "config", {}) or {}).get("chain_scope", [])
    except Exception:
        return []
    return list(raw) if isinstance(raw, list) else []


def _onchain_allowed(ctx: Any, chain_id: Any, address: Any) -> bool:
    try:
        cid = int(chain_id)
    except (TypeError, ValueError):
        return False
    addr = str(address or "").strip().lower()
    for entry in _chain_scope(ctx):
        try:
            if int(entry.get("chain_id")) == cid and str(entry.get("address", "")).strip().lower() == addr:
                return True
        except (TypeError, ValueError, AttributeError):
            continue
    return False


def contract_read(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    chain_id = args.get("chain_id")
    address = str(args.get("address", "") or "").strip()
    method = str(args.get("method", "") or "").strip()
    rpc_url = str(args.get("rpc_url", "") or "").strip()
    calldata = str(args.get("calldata", "") or "").strip() or "0x"
    if method not in CONTRACT_READ_METHODS:
        _emit(ctx, "contract_read", {"code": "contract.unknown_method"})
        return {
            "ok": False,
            "blocked": False,
            "code": "contract.unknown_method",
            "result_for_model": f"unknown method {method!r}; allowed: {', '.join(CONTRACT_READ_METHODS)}",
        }
    if not _onchain_allowed(ctx, chain_id, address):
        _emit(ctx, "contract_read", {"code": "scope.onchain_out_of_scope"})
        return _blocked(
            "scope.onchain_out_of_scope",
            f"BLOCKED [scope.onchain_out_of_scope] (chain_id={chain_id}, address={address}) "
            "is not in the on-chain scope manifest.",
        )
    try:
        ctx.scope.check_url(rpc_url)
    except ScopeViolation as exc:
        _emit(ctx, "contract_read", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    if method not in _BASIC_METHODS and _tier(ctx) != "advanced":
        _emit(ctx, "contract_read", {"code": "tier.capability_locked", "method": method})
        return _blocked(
            "tier.capability_locked",
            f"BLOCKED [tier.capability_locked] method '{method}' needs advanced tier.",
        )
    addr = address.lower()
    if method == "eth_call":
        params: list[Any] = [{"to": addr, "data": calldata}, "latest"]
    elif method == "eth_getCode" or method == "eth_getBalance":
        params = [addr, "latest"]
    else:  # eth_getStorageAt
        params = [addr, "0x0", "latest"]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    try:
        ex = ctx.http.request("POST", rpc_url, headers={"Content-Type": "application/json"}, body=body)
    except ScopeViolation as exc:
        _emit(ctx, "contract_read", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        _emit(ctx, "contract_read", {"code": "http.transport_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.transport_error",
            "result_for_model": f"RPC failed: {type(exc).__name__}: {exc}",
        }
    if ex.status != 200:
        _emit(ctx, "contract_read", {"code": "http.transport_error", "status": ex.status})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.transport_error",
            "result_for_model": f"RPC failed: HTTP {ex.status}",
        }
    try:
        payload = json.loads(ex.response_body or "{}")
        result = str(payload.get("result", "")) if isinstance(payload, dict) else ""
    except ValueError:
        result = ""
    result = redact_text(result)
    truncated = len(result) > 8000
    if truncated:
        result = result[:8000] + "...[truncated]"
    _emit(ctx, "contract_read", {"code": "ok", "method": method})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result_for_model": f"{method} {addr}: {result[:400]!r}",
        "evidence": {
            "kind": "contract_call",
            "data": {
                "chain_id": chain_id,
                "address": addr,
                "method": method,
                "result": result,
                "truncated": truncated,
            },
        },
    }


def contract_source_fetch(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    chain_id = args.get("chain_id")
    address = str(args.get("address", "") or "").strip()
    explorer = str(args.get("explorer", "") or "").strip()
    if not _onchain_allowed(ctx, chain_id, address):
        _emit(ctx, "contract_source_fetch", {"code": "scope.onchain_out_of_scope"})
        return _blocked(
            "scope.onchain_out_of_scope",
            f"BLOCKED [scope.onchain_out_of_scope] (chain_id={chain_id}, address={address}) not in scope.",
        )
    try:
        host = (urlparse(explorer).hostname or "").lower()
    except ValueError:
        host = ""
    if not explorer or host not in EXPLORER_ALLOWLIST:
        _emit(ctx, "contract_source_fetch", {"code": "scope.explorer_not_allowlisted"})
        return _blocked(
            "scope.explorer_not_allowlisted",
            f"BLOCKED [scope.explorer_not_allowlisted] explorer host {host!r} is not allowlisted.",
        )
    try:
        ctx.scope.check_url(explorer)
    except ScopeViolation as exc:
        _emit(ctx, "contract_source_fetch", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    try:
        ex = ctx.http.request("GET", explorer)
    except ScopeViolation as exc:
        _emit(ctx, "contract_source_fetch", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        _emit(ctx, "contract_source_fetch", {"code": "http.transport_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.transport_error",
            "result_for_model": f"source fetch failed: {exc}",
        }
    if ex.status != 200:
        _emit(ctx, "contract_source_fetch", {"code": "http.transport_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.transport_error",
            "result_for_model": f"source fetch failed: HTTP {ex.status}",
        }
    blob = redact_text(ex.response_body or "")[:8000]
    _emit(ctx, "contract_source_fetch", {"code": "ok"})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result_for_model": f"source for {address}: {len(blob)} chars",
        "evidence": {
            "kind": "contract_source",
            "data": {"chain_id": chain_id, "address": address.lower(), "source": blob[:4000]},
        },
    }


def abi_decode_hint(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    # Pure stdlib: no network, no scope. Never touches ctx.http.
    sig = str(args.get("sig", "") or "").strip()
    calldata = str(args.get("calldata", "") or "").strip().lower()
    if calldata.startswith("0x"):
        calldata = calldata[2:]
    selector = calldata[:8] if len(calldata) >= 8 else calldata
    words = [calldata[i : i + 64] for i in range(8, len(calldata), 64) if calldata[i : i + 64]]
    hint = {
        "sig": sig,
        "selector": "0x" + selector,
        "words": words[:8],
        "note": "offline hint only: selector + 32-byte words; verify against the ABI.",
    }
    _emit(ctx, "abi_decode_hint", {"code": "ok"})
    return {"ok": True, "blocked": False, "code": "ok", "hint": hint, "result_for_model": f"abi hint: {hint}"}


# -- R2-B B1: R-spec v2 kind-fit gate -------------------------------------------
#
# Pure function (no network): decides whether bound evidence kinds satisfy
# the R decision gate. v1: web3 contract_call alone is BLOCKED (R3 needs an
# http_exchange); v2: contract_call is sufficient only with replay evidence.
# A source-hash mismatch, or any second-host divergence, is fail-closed to
# needs_follow_up — never verified, never ruled_out.

_WEB3_KINDS = frozenset({"contract_call", "contract_read", "contract_source", "cast_call"})


def validate_web3_kind_fit(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    kinds = [str(k or "").strip().lower() for k in (args.get("kinds") or [])]
    try:
        version = int(args.get("r_spec_version", 1))
    except (TypeError, ValueError):
        version = 1
    replay = bool(args.get("replay", False))
    source_hash_match = args.get("source_hash_match", True)
    has_web3 = any(k in _WEB3_KINDS for k in kinds)
    has_http = "http_exchange" in kinds

    def _done(out: dict[str, Any]) -> dict[str, Any]:
        if ctx is not None:
            _emit(ctx, "validate_web3_kind_fit",
                  {"sufficient": bool(out.get("sufficient")),
                   "verdict": str(out.get("verdict", ""))})
        return out

    if source_hash_match is False:
        return _done({
            "sufficient": False,
            "verdict": "needs_follow_up",
            "reason": redact_text("contract source-hash mismatch: provenance unverified; needs_follow_up"),
        })
    if not has_web3:
        return _done({"sufficient": True, "verdict": "covered",
                      "reason": "web2/http_exchange evidence is sufficient under R-spec v1 and v2"})
    if version < 2:
        return _done({
            "sufficient": False,
            "verdict": "needs_follow_up",
            "reason": redact_text(
                "R-spec v1: contract_call alone is BLOCKED; bind an http_exchange (R3) "
                "or re-run under r_spec_version 2 with replay evidence"),
        })
    if not (replay and has_http):
        return _done({
            "sufficient": False,
            "verdict": "needs_follow_up",
            "reason": "R-spec v2: contract_call requires replay evidence plus a bound http_exchange",
        })
    return _done({"sufficient": True, "verdict": "verified",
                  "reason": "R-spec v2: contract_call with byte-equal replay and http_exchange"})


# -- R2-B B2: live ladder L0 -> L1 -----------------------------------------------
#
# Keyless preferred; keyed RPC only via keys.env (never YAML, never a URL —
# userinfo in rpc_url is BLOCKED as credential_in_url). Host-only evidence
# (no key persisted), per-run eth_getCode cache, call budget cap, and a
# 3-strike breaker that fails closed to rpc.circuit_open. Malformed or
# oversized envelopes yield rpc.bad_envelope with NO evidence stored.

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")


def load_rpc_key(env_file: str = "keys.env") -> dict[str, str]:
    """keys.env seam for keyed RPC (never YAML, never URL). Returns {} keyless."""
    try:
        from pathlib import Path  # noqa: PLC0415

        from hunter.llm.keys import parse_keys_env  # noqa: PLC0415

        text = Path(env_file).read_text(encoding="utf-8")
        keys = parse_keys_env(text)
        return {k: v for k, v in keys.items() if "RPC" in k or "KEY" in k or "TOKEN" in k}
    except Exception:
        return {}


def _ladder_state(ctx: Any) -> dict[str, Any]:
    try:
        return ctx.state if isinstance(getattr(ctx, "state", None), dict) else {}
    except Exception:
        return {}


def _ladder_breaker_count(state: dict[str, Any], host: str) -> int:
    return int(((state.get("__ladder_breaker") or {}).get(host, 0)) or 0)


def _ladder_breaker_note(state: dict[str, Any], host: str, count: int) -> None:
    try:
        table = state.setdefault("__ladder_breaker", {})
        table[host] = count
        RPC_BREAKER["failures"] = dict(table)
    except Exception:
        pass


def ladder_read(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    chain_id = args.get("chain_id")
    address = str(args.get("address", "") or "").strip()
    method = str(args.get("method", "") or "eth_call").strip()
    rpc_url = str(args.get("rpc_url", "") or "").strip()
    calldata = str(args.get("calldata", "") or "").strip() or "0x"
    state = _ladder_state(ctx)

    def _fail(code: str, message: str, **extra: Any) -> dict[str, Any]:
        _emit(ctx, "ladder_read", {"code": code, **extra})
        return {"ok": False, "blocked": code.startswith("scope") or "credential" in code
                or code in ("rpc.budget_exhausted", "rpc.circuit_open"),
                "code": code, "result_for_model": redact_text(message)[:2000]}

    # Adversarial: credentials must never ride the URL (keys.env only).
    try:
        parsed = urlparse(rpc_url)
        if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
            return _fail("rpc.credential_in_url",
                         "BLOCKED [rpc.credential_in_url] rpc_url carries userinfo; "
                         "keyless preferred, keyed only via keys.env (never YAML/URL).")
        rpc_host = (parsed.hostname or "").lower()
    except ValueError:
        return _fail("rpc.credential_in_url", "BLOCKED [rpc.credential_in_url] unparseable rpc_url.")
    # Double-gate: explicit check_url now AND inside ctx.http.request later.
    try:
        ctx.scope.check_url(rpc_url)
    except ScopeViolation as exc:
        return _fail("scope.target_out_of_scope", str(exc))
    if not _onchain_allowed(ctx, chain_id, address):
        return _fail("scope.onchain_out_of_scope",
                     f"BLOCKED [scope.onchain_out_of_scope] (chain_id={chain_id}, address={address}) "
                     "is not in the on-chain scope manifest.")
    if method not in CONTRACT_READ_METHODS:
        return _fail("contract.unknown_method", f"unknown method {method!r} not allowlisted.")
    if method not in _BASIC_METHODS and _tier(ctx) != "advanced":
        return _fail("tier.capability_locked",
                     f"BLOCKED [tier.capability_locked] '{method}' needs advanced tier.")
    # Replay analog short-circuit: diverging hosts never rule out (fail-closed).
    prior = args.get("prior_result")
    fresh = args.get("fresh_result")
    if prior is not None and fresh is not None and str(prior).strip().lower() != str(fresh).strip().lower():
        _emit(ctx, "ladder_read", {"code": "rpc.second_host_divergence", "verdict": "needs_follow_up"})
        return {"ok": True, "blocked": False, "code": "rpc.second_host_divergence",
                "verdict": "needs_follow_up",
                "result_for_model": "second-host divergence: needs_follow_up (never ruled_out)."}
    # Budget cap: at most RPC_BUDGET_CAP calls per run, then fail closed.
    try:
        budget = int(state.get("__ladder_budget", 0)) + 1
        state["__ladder_budget"] = budget
    except Exception:
        budget = 1
    if budget > RPC_BUDGET_CAP:
        return _fail("rpc.budget_exhausted",
                     f"BLOCKED [rpc.budget_exhausted] per-run RPC budget ({RPC_BUDGET_CAP}) exhausted.")
    # Breaker: 3 transport failures on one host open the circuit (retryable later).
    if _ladder_breaker_count(state, rpc_host) >= 3:
        return _fail("rpc.circuit_open",
                     "BLOCKED [rpc.circuit_open] RPC circuit open after 3 transport errors (fail-closed).")
    # Per-run cache for eth_getCode (byte-equal within the run).
    cache_key = f"{chain_id}|{address.lower()}|{method}|{calldata.lower()}"
    try:
        cache: dict[str, Any] = state.setdefault("__rpc_cache", {})
    except Exception:
        cache = {}
    if method == "eth_getCode" and cache_key in cache:
        _emit(ctx, "ladder_read", {"code": "ok", "cached": True, "method": method})
        return dict(cache[cache_key])
    if method == "eth_call":
        params: list[Any] = [{"to": address.lower(), "data": calldata}, "latest"]
    elif method == "eth_getCode" or method == "eth_getBalance":
        params = [address.lower(), "latest"]
    else:  # eth_getStorageAt
        params = [address.lower(), "0x0", "latest"]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    try:
        ex = ctx.http.request("POST", rpc_url, headers={"Content-Type": "application/json"}, body=body)
    except ScopeViolation as exc:
        return _fail("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        _ladder_breaker_note(state, rpc_host, _ladder_breaker_count(state, rpc_host) + 1)
        _emit(ctx, "ladder_read", {"code": "http.transport_error"})
        return {"ok": False, "blocked": False, "code": "http.transport_error",
                "result_for_model": f"RPC failed: {type(exc).__name__}: {redact_text(str(exc))[:300]}"}
    _ladder_breaker_note(state, rpc_host, 0)
    if ex.status != 200:
        _emit(ctx, "ladder_read", {"code": "http.transport_error", "status": ex.status})
        return {"ok": False, "blocked": False, "code": "http.transport_error",
                "result_for_model": f"RPC failed: HTTP {ex.status}"}
    try:
        payload = json.loads(ex.response_body or "{}")
        result = payload.get("result", "") if isinstance(payload, dict) else ""
        result = str(result)
    except ValueError:
        result = ""
    if not _HEX_RE.match(result) or len(result) > RPC_RESULT_LIMIT:
        _emit(ctx, "ladder_read", {"code": "rpc.bad_envelope"})
        return {"ok": False, "blocked": False, "code": "rpc.bad_envelope",
                "result_for_model": "RPC returned a malformed or oversized envelope (no evidence stored)."}
    result = redact_text(result)
    truncated = len(result) > 8000
    if truncated:
        result = result[:8000] + "...[truncated]"
    _emit(ctx, "ladder_read", {"code": "ok", "method": method})
    out: dict[str, Any] = {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result": result,
        "result_for_model": f"{method} {address.lower()}: {result[:400]!r}",
        # Host-only evidence: never persist keys, tokens, or full URLs.
        "evidence": {"kind": "contract_call",
                     "data": {"chain_id": chain_id, "address": address.lower(), "method": method,
                              "result": result, "rpc_host": rpc_host, "truncated": truncated}},
    }
    if method == "eth_getCode":
        try:
            cache[cache_key] = dict(out)
            RPC_CACHE[cache_key] = {"rpc_host": rpc_host, "truncated": truncated}
        except Exception:
            pass
    return out


def register_web3_tools(registry: Any) -> Any:
    from hunter.agent.tools_base import ToolContext, ToolOutcome, ToolSpec  # noqa: PLC0415

    fns = {
        "contract_read": contract_read,
        "contract_source_fetch": contract_source_fetch,
        "abi_decode_hint": abi_decode_hint,
    }
    spec_by_name = {s["name"]: s for s in SPECS}

    def _wrap(name: str):  # type: ignore[no-untyped-def]
        fn = fns[name]

        def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
            out = fn(args, ctx)
            if out.get("blocked"):
                return ToolOutcome(
                    ok=False,
                    blocked=True,
                    code=str(out.get("code", "blocked")),
                    result_for_model=str(out.get("result_for_model", "blocked")),
                )
            if not out.get("ok"):
                return ToolOutcome(
                    ok=False,
                    code=str(out.get("code", "error")),
                    result_for_model=str(out.get("result_for_model", "error")),
                    evidence=out.get("evidence"),
                )
            return ToolOutcome(
                result_for_model=str(out.get("result_for_model", "ok")),
                evidence=out.get("evidence"),
            )

        return handler

    for name, spec in spec_by_name.items():
        registry.register(
            ToolSpec(
                name=name,
                description=str(spec["description"]),
                parameters=dict(spec["parameters"]),
                handler=_wrap(name),
                min_tier="basic",
                danger="none",
            )
        )
    registry.register_unavailable(
        "slither_hint",
        "tool.unavailable",
        "slither is not installed; install with: pip install slither-analyzer && slither --version",
    )
    registry.register_unavailable(
        "cast_hint",
        "tool.unavailable",
        "cast is not installed; install with: curl -L https://foundry.paradigm.xyz | bash && foundryup",
    )
    return registry


def build_web3_registry(tier: str = "basic") -> Any:
    from hunter.agent.tools_base import ToolRegistry  # noqa: PLC0415

    registry = ToolRegistry()
    register_web3_tools(registry)
    registry.built_for_tier = tier  # type: ignore[attr-defined]
    return registry
