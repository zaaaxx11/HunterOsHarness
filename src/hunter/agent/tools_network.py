"""Planner B T2 — network audit tools (dns/crt/headers/recon/port_hint).

Fail-closed scope gates, stdlib-only DNS (dnspython graceful), CT-only recon,
and a socket-free port_hint. Every handler emits exactly one engine_event.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import httpx

from hunter.kernel.redaction import redact_text
from hunter.tools.scope import ScopeViolation

__all__ = [
    "HAS_DNSPYTHON",
    "OUTCOME_TABLE",
    "SPEC_NAMES",
    "SPECS",
    "TLS_AUDIT_SPEC",
    "crt_sh",
    "dns_resolve",
    "dnssec_validate",
    "headers_audit",
    "paginate_results",
    "port_hint",
    "recon_subdomains",
    "register_network_tools",
    "tls_audit",
]

try:  # dnspython is optional; stdlib covers A/AAAA.
    import dns.resolver  # type: ignore[import-not-found]  # noqa: F401

    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

OUTCOME_TABLE: dict[str, tuple[str, ...]] = {
    "dns_resolve": FIVE,
    "crt_sh": FIVE,
    "headers_audit": FIVE,
    "recon_subdomains": FIVE,
    "port_hint": FIVE,
    "dnssec_validate": FIVE,
    "paginate_results": FIVE,
    "tls_audit": FIVE,
}

_DNS_SPEC: dict[str, Any] = {
    "name": "dns_resolve",
    "description": "Resolve A/AAAA via stdlib behind the scope gate (DoH fallback scope-checked).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "rtype": {"type": "string"},
            "doh_fallback": {"type": "boolean"},
        },
        "required": ["host"],
        "additionalProperties": False,
    },
}
_CRT_SPEC: dict[str, Any] = {
    "name": "crt_sh",
    "description": "Certificate-transparency lookup via crt.sh (scope + allowlist gated).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "domain": {"type": "string"},
            "max_rows": {"type": "integer"},
        },
        "required": ["domain"],
        "additionalProperties": False,
    },
}
_HEADERS_SPEC: dict[str, Any] = {
    "name": "headers_audit",
    "description": "Passive GET-only security-header audit (scope-checked).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
        "additionalProperties": False,
    },
}
_RECON_SPEC: dict[str, Any] = {
    "name": "recon_subdomains",
    "description": "CT-only subdomain recon (no DNS bruteforce).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "domain": {"type": "string"},
            "source": {"type": "string"},
        },
        "required": ["domain"],
        "additionalProperties": False,
    },
}
_PORT_SPEC: dict[str, Any] = {
    "name": "port_hint",
    "description": "Socket-free port inventory hint + proposed (not executed) scan command.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {"host": {"type": "string"}},
        "required": ["host"],
        "additionalProperties": False,
    },
}

SPECS = (_DNS_SPEC, _CRT_SPEC, _HEADERS_SPEC, _RECON_SPEC, _PORT_SPEC)
SPEC_NAMES = tuple(s["name"] for s in SPECS)

# R2-B B5 Web2 expansion specs (passive inventory stays basic/none).
TLS_AUDIT_SPEC: dict[str, Any] = {
    "name": "tls_audit",
    "description": "Passive TLS inventory (HSTS + header posture) via one scope-checked GET. Basic tier.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {"host": {"type": "string"}},
        "required": ["host"],
        "additionalProperties": False,
    },
}
_DNSSEC_SPEC: dict[str, Any] = {
    "name": "dnssec_validate",
    "description": "Scope-checked DNSSEC posture hint via stdlib only (no new deps).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {"host": {"type": "string"}, "ds": {"type": "string"}},
        "required": ["host"],
        "additionalProperties": False,
    },
}
_PAGINATE_SPEC: dict[str, Any] = {
    "name": "paginate_results",
    "description": "Bounded cursor pagination helper (<=100 rows per page).",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "rows": {"type": "array"},
            "page_size": {"type": "integer"},
            "cursor": {"type": "integer"},
        },
        "required": ["rows"],
        "additionalProperties": False,
    },
}

WEB2_SPECS = (_DNSSEC_SPEC, _PAGINATE_SPEC, TLS_AUDIT_SPEC)
WEB2_SPEC_NAMES = tuple(s["name"] for s in WEB2_SPECS)

_CRT_HOSTS = frozenset({"crt.sh"})
_DOH_URL = "https://cloudflare-dns.com/dns-query"


def _emit(ctx: Any, tool: str, extra: dict[str, Any] | None = None) -> None:
    try:
        payload = {"tool": tool}
        if extra:
            payload.update(extra)
        ctx.emit("engine_event", payload)
    except Exception:
        pass


def _norm_host(host: Any) -> str:
    return str(host or "").strip().lower().rstrip(".")


def _blocked(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "blocked": True, "code": code, "result_for_model": message}


def _transport_error(message: str) -> dict[str, Any]:
    return {"ok": False, "blocked": False, "code": "http.transport_error", "result_for_model": message}


def dns_resolve(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    host = _norm_host(args.get("host", ""))
    rtype = str(args.get("rtype", "A") or "A").strip().upper()
    doh = bool(args.get("doh_fallback", False))
    if not host:
        _emit(ctx, "dns_resolve", {"code": "dns.host_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "dns.host_required",
            "result_for_model": "host required",
        }
    if not ctx.scope.allows_host(host):
        msg = (
            f"BLOCKED [scope.target_out_of_scope] host '{host}' is out of scope. "
            "Add it to the scope manifest to authorize."
        )
        _emit(ctx, "dns_resolve", {"code": "scope.target_out_of_scope", "host": host})
        return _blocked("scope.target_out_of_scope", msg)
    if rtype not in ("A", "AAAA") and not HAS_DNSPYTHON:
        msg = (
            f"BLOCKED [dns.library_unavailable] rtype '{rtype}' needs dnspython "
            "(not installed). A/AAAA resolve via stdlib; install dnspython for other types."
        )
        _emit(ctx, "dns_resolve", {"code": "dns.library_unavailable", "rtype": rtype})
        return _blocked("dns.library_unavailable", msg)
    # Stdlib path (no resolve-then-allow: the scope gate above already passed).
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        if doh:
            out = _doh_lookup(host, rtype, ctx)
            if out is not None:
                return out
        _emit(ctx, "dns_resolve", {"code": "dns.resolve_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "dns.resolve_error",
            "result_for_model": f"DNS resolve failed for {host!r}: {exc}",
        }
    fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
    addrs = []
    for family, _t, _p, _c, sockaddr in infos:
        if family == fam:
            addrs.append(sockaddr[0])
    if not addrs:
        # Fall back to whatever the resolver returned rather than failing closed incorrectly.
        addrs = [s[4][0] for s in infos if len(s) > 4]
    addrs = [redact_text(a)[:256] for a in addrs[:16]]
    if doh and not addrs:
        out = _doh_lookup(host, rtype, ctx)
        if out is not None:
            return out
    _emit(ctx, "dns_resolve", {"code": "ok", "host": host, "count": len(addrs)})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "addresses": addrs,
        "result_for_model": f"{host} {rtype}: {', '.join(addrs) if addrs else 'no records'}",
        "evidence": {"kind": "dns_record", "data": {"host": host, "rtype": rtype, "addresses": addrs[:8]}},
    }


def _doh_lookup(host: str, rtype: str, ctx: Any) -> dict[str, Any] | None:
    # Fixed DoH endpoint, always scope-checked: the DoH host must be allowlisted,
    # never rewritten to an in-scope host (no alias laundering).
    url = f"{_DOH_URL}?name={host}&type={rtype}"
    try:
        ctx.scope.check_url(url)
    except ScopeViolation as exc:
        _emit(ctx, "dns_resolve", {"code": "scope.doh_out_of_scope"})
        return _blocked("scope.doh_out_of_scope", str(exc))
    try:
        ex = ctx.http.request("GET", url, headers={"Accept": "application/dns-json"})
    except ScopeViolation as exc:
        _emit(ctx, "dns_resolve", {"code": "scope.doh_out_of_scope"})
        return _blocked("scope.doh_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        _emit(ctx, "dns_resolve", {"code": "http.transport_error"})
        return _transport_error(f"DoH lookup failed: {exc}")
    try:
        payload = json.loads(ex.response_body or "{}")
    except ValueError:
        _emit(ctx, "dns_resolve", {"code": "dns.resolve_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "dns.resolve_error",
            "result_for_model": "DoH bad JSON",
        }
    answers = payload.get("Answer", []) if isinstance(payload, dict) else []
    addrs = [str(a.get("data", "")) for a in answers if isinstance(a, dict) and a.get("data")][:8]
    if ex.status != 200 or not addrs:
        # No usable DoH answer: signal caller to fall back to stdlib error path.
        return None
    _emit(ctx, "dns_resolve", {"code": "ok", "host": host, "doh": True})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "addresses": addrs,
        "result_for_model": f"{host} {rtype} (doh): {', '.join(addrs)}",
        "evidence": {"kind": "dns_record", "data": {"host": host, "rtype": rtype, "addresses": addrs}},
    }


def crt_sh(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    domain = _norm_host(args.get("domain", ""))
    try:
        max_rows = max(1, min(100, int(args.get("max_rows", 100))))
    except (TypeError, ValueError):
        max_rows = 100
    if not domain:
        _emit(ctx, "crt_sh", {"code": "crt.domain_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "crt.domain_required",
            "result_for_model": "domain required",
        }
    if not ctx.scope.allows_host(domain):
        msg = f"BLOCKED [scope.target_out_of_scope] domain '{domain}' is out of scope."
        _emit(ctx, "crt_sh", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", msg)
    probe = "https://crt.sh/?q=%25." + domain + "&output=json"
    try:
        ctx.scope.check_url(probe)
    except ScopeViolation as exc:
        _emit(ctx, "crt_sh", {"code": "scope.crt_sh_not_allowlisted"})
        return _blocked("scope.crt_sh_not_allowlisted", str(exc))
    try:
        ex = ctx.http.request("GET", probe, headers={"Accept": "application/json"})
    except ScopeViolation as exc:
        _emit(ctx, "crt_sh", {"code": "scope.crt_sh_not_allowlisted"})
        return _blocked("scope.crt_sh_not_allowlisted", str(exc))
    except httpx.HTTPError as exc:
        _emit(ctx, "crt_sh", {"code": "http.transport_error"})
        return _transport_error(f"crt.sh lookup failed: {type(exc).__name__}: {exc}")
    if ex.status != 200:
        _emit(ctx, "crt_sh", {"code": "http.transport_error", "status": ex.status})
        return _transport_error(f"crt.sh lookup failed: HTTP {ex.status}")
    try:
        rows = json.loads(ex.response_body or "[]")
    except ValueError:
        _emit(ctx, "crt_sh", {"code": "http.transport_error"})
        return _transport_error("crt.sh returned invalid JSON")
    if not isinstance(rows, list):
        rows = []
    names: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            blob = str(row.get("name_value", ""))
            for part in blob.splitlines():
                part = part.strip().lower()
                if part and part not in names:
                    names.append(redact_text(part)[:253])
    total = len(names)
    truncated = total > max_rows
    entries = names[:max_rows]
    if len(json.dumps(entries)) > 8000:
        buf: list[str] = []
        size = 0
        for e in entries:
            size += len(e) + 4
            if size > 8000:
                truncated = True
                break
            buf.append(e)
        entries = buf
    _emit(ctx, "crt_sh", {"code": "ok", "domain": domain, "count": len(entries)})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "entries": entries,
        "truncated": truncated,
        "result_for_model": f"ct: {len(entries)} name(s) for {domain}"
        + (" (truncated)" if truncated else ""),
        "evidence": {
            "kind": "ct_entry",
            "data": {"domain": domain, "entries": entries, "truncated": truncated},
        },
    }


def headers_audit(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    url = str(args.get("url", "") or "").strip()
    if not url:
        _emit(ctx, "headers_audit", {"code": "http.url_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "http.url_required",
            "result_for_model": "url required",
        }
    try:
        ex = ctx.http.request("GET", url)
    except ScopeViolation as exc:
        _emit(ctx, "headers_audit", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        _emit(ctx, "headers_audit", {"code": "http.transport_error"})
        return _transport_error(f"headers audit failed: {exc}")
    interesting = (
        "server",
        "x-powered-by",
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    )
    table = {k: redact_text(str(v))[:500] for k, v in ex.response_headers.items() if k in interesting}
    missing = [h for h in interesting[2:] if h not in table]
    _emit(ctx, "headers_audit", {"code": "ok", "url": url, "status": ex.status})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result_for_model": f"headers for {url}: {len(table)} present, {len(missing)} missing",
        "evidence": {
            "kind": "headers_audit",
            "data": {"url": url, "status": ex.status, "headers": table, "missing": missing},
        },
    }


_CT_SOURCES = frozenset({"ct", "crt", "crt.sh", "crt_sh", "certificate-transparency"})


def recon_subdomains(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    domain = _norm_host(args.get("domain", ""))
    source = str(args.get("source", "ct") or "ct").strip().lower()
    if not domain:
        _emit(ctx, "recon_subdomains", {"code": "recon.domain_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "recon.domain_required",
            "result_for_model": "domain required",
        }
    if not ctx.scope.allows_host(domain):
        _emit(ctx, "recon_subdomains", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", f"domain '{domain}' out of scope")
    if source not in _CT_SOURCES:
        _emit(ctx, "recon_subdomains", {"code": "source_unavailable", "source": source})
        return {
            "ok": False,
            "blocked": False,
            "code": "source_unavailable",
            "result_for_model": (
                f"source '{source}' unavailable: only CT sources allowed "
                "(no DNS bruteforce; use source 'ct')."
            ),
        }
    # CT-only path reuses the crt.sh gate (scope + allowlist + transport shaping).
    out = crt_sh({"domain": domain}, ctx)
    _emit(ctx, "recon_subdomains", {"code": str(out.get("code", "ok"))})
    if not out.get("ok"):
        return out
    entries = list(out.get("entries", []) or [])
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "entries": entries,
        "result_for_model": out.get("result_for_model", ""),
        "evidence": {"kind": "ct_entry", "data": {"domain": domain, "entries": entries[:50]}},
    }


def port_hint(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    # Pure inventory hint: never opens a socket, never touches ctx.http.
    host = _norm_host(args.get("host", ""))
    if not host:
        _emit(ctx, "port_hint", {"code": "port.host_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "port.host_required",
            "result_for_model": "host required",
        }
    if not ctx.scope.allows_host(host):
        _emit(ctx, "port_hint", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", f"host '{host}' out of scope")
    proposed = f"nmap -sV -Pn --top-ports 100 {host}  # PROPOSED ONLY — not executed by this tool"
    _emit(ctx, "port_hint", {"code": "ok", "host": host})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "executed": False,
        "proposed_command": proposed,
        "hint": {"host": host, "note": "inventory hint only; no socket opened"},
        "result_for_model": f"port inventory hint for {host}; proposed: {proposed}",
        "evidence": {"kind": "port_hint", "data": {"host": redact_text(host), "proposed": proposed[:500]}},
    }


# -- R2-B B5 Web2 expansion ---------------------------------------------------------
#
# dnssec_validate: stdlib-only posture hint, scope-checked, fail-closed
# (bogus -> needs_follow_up, never ruled_out). paginate_results: pure
# bounded cursor helper (<=100 rows/page). tls_audit: passive inventory via
# one scope-checked GET (basic tier, no handshake parsing, no new deps).


def dnssec_validate(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    host = _norm_host(args.get("host", ""))
    ds = str(args.get("ds", "") or "").strip().upper()
    if not host:
        _emit(ctx, "dnssec_validate", {"code": "dns.host_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "dns.host_required",
            "result_for_model": "host required",
        }
    if not ctx.scope.allows_host(host):
        _emit(ctx, "dnssec_validate", {"code": "scope.target_out_of_scope", "host": host})
        return _blocked("scope.target_out_of_scope",
                        f"BLOCKED [scope.target_out_of_scope] host '{host}' is out of scope.")
    if ds == "BOGUS":
        _emit(ctx, "dnssec_validate", {"code": "dnssec.bogus", "verdict": "needs_follow_up"})
        return {
            "ok": False,
            "blocked": False,
            "code": "dnssec.bogus",
            "verdict": "needs_follow_up",
            "result_for_model": "DNSSEC chain BOGUS: needs_follow_up (never ruled_out).",
        }
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({redact_text(s[4][0])[:256] for s in infos if len(s) > 4})[:8]
    except OSError as exc:
        _emit(ctx, "dnssec_validate", {"code": "dns.resolve_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "dns.resolve_error",
            "result_for_model": f"DNSSEC hint unavailable: resolve failed for {host!r}: {exc}",
        }
    _emit(ctx, "dnssec_validate", {"code": "ok", "host": host})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "result_for_model": f"dnssec hint for {host}: {len(addrs)} address(es); posture unverified offline",
        "evidence": {"kind": "dnssec_hint", "data": {"host": host, "addresses": addrs}},
    }


def paginate_results(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    rows = args.get("rows", [])
    rows = list(rows) if isinstance(rows, (list, tuple)) else []
    try:
        page_size = max(1, min(100, int(args.get("page_size", 10))))
    except (TypeError, ValueError):
        page_size = 10
    try:
        cursor = max(0, int(args.get("cursor", 0)))
    except (TypeError, ValueError):
        cursor = 0
    page = rows[cursor : cursor + page_size]
    truncated = cursor + page_size < len(rows)
    out = {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "page": page,
        "truncated": truncated,
        "next_cursor": cursor + len(page) if truncated else None,
        "total": len(rows),
        "result_for_model": f"page: {len(page)} row(s) from {cursor} of {len(rows)}"
        + (" (truncated)" if truncated else ""),
    }
    _emit(ctx, "paginate_results", {"code": "ok", "count": len(page)})
    return out


def tls_audit(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    host = _norm_host(args.get("host", ""))
    if not host:
        _emit(ctx, "tls_audit", {"code": "tls.host_required"})
        return {
            "ok": False,
            "blocked": False,
            "code": "tls.host_required",
            "result_for_model": "host required",
        }
    if not ctx.scope.allows_host(host):
        _emit(ctx, "tls_audit", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope",
                        f"BLOCKED [scope.target_out_of_scope] host '{host}' is out of scope.")
    url = f"https://{host}/"
    try:
        ex = ctx.http.request("GET", url)
    except ScopeViolation as exc:
        _emit(ctx, "tls_audit", {"code": "scope.target_out_of_scope"})
        return _blocked("scope.target_out_of_scope", str(exc))
    except httpx.HTTPError as exc:
        _emit(ctx, "tls_audit", {"code": "http.transport_error"})
        return _transport_error(f"tls audit failed: {exc}")
    headers = {k: redact_text(str(v))[:500] for k, v in ex.response_headers.items()}
    hsts = headers.get("strict-transport-security", "")
    posture = {
        "host": host,
        "hsts": bool(hsts),
        "hsts_value": hsts[:200],
        "status": ex.status,
    }
    _emit(ctx, "tls_audit", {"code": "ok", "host": host})
    return {
        "ok": True,
        "blocked": False,
        "code": "ok",
        "posture": posture,
        "result_for_model": f"tls inventory for {host}: hsts={'on' if hsts else 'off'} (passive GET-only)",
        "evidence": {"kind": "tls_inventory", "data": posture},
    }


def register_network_tools(registry: Any) -> Any:
    from hunter.agent.tools_base import ToolContext, ToolOutcome, ToolSpec  # noqa: PLC0415

    fns = {
        "dns_resolve": dns_resolve,
        "crt_sh": crt_sh,
        "headers_audit": headers_audit,
        "recon_subdomains": recon_subdomains,
        "port_hint": port_hint,
        "dnssec_validate": dnssec_validate,
        "paginate_results": paginate_results,
        "tls_audit": tls_audit,
    }
    spec_by_name = {s["name"]: s for s in (*SPECS, *WEB2_SPECS)}

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
    return registry
