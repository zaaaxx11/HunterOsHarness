"""T2 network-audit contracts — dns_resolve / crt_sh / http_request+ / headers / recon / port_hint (TDD red).

Planner B T2: audit-flavored network tools behind the fail-closed scope gate.

Production targets:
  - ``hunter.agent.tools_network`` (NEW): dns_resolve, crt_sh, headers_audit,
    recon_subdomains, port_hint handlers + specs + registration.
  - ``hunter.agent.tools._http_request`` extension: follow_redirects (manual,
    max 3 hops, per-hop check_url), max_body_chars (<=40000 + marker),
    timeout (1..30s).

DNS rules: A/AAAA via stdlib only; other types without dnspython ->
``dns.library_unavailable``; OSError -> ``dns.resolve_error`` + engine_event;
DoH fallback goes through ctx.http (scope-checked; blocked DoH host -> scope BLOCKED).
crt.sh: domain scope gate + crt.sh host allowlist gate; transport error ->
``http.transport_error``; over-limit rows truncate (truncated:true);
evidence kind ct_entry is R2-bINDABLE but never R3-sufficient alone.
port_hint: opens NO socket (assert zero http calls); returns inventory hint +
a PROPOSED shell string it does not execute.

All tests FAIL today via EXPECTED-FAIL-TDD. No real DNS / network / binaries.
"""

from __future__ import annotations


import httpx
import pytest

TDD_NET = "EXPECTED-FAIL-TDD:hunter.agent.tools_network (Planner B T2)"
TDD_HTTP = "EXPECTED-FAIL-TDD:http_request follow_redirects/max_body/timeout extension (Planner B T2)"


def _require_network():
    try:
        import hunter.agent.tools_network as net  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(
            f"{TDD_NET} — module missing; "
            "create dns_resolve/crt_sh/headers_audit/recon_subdomains/port_hint"
        )
    return net


def _ctx(scope_hosts=frozenset({"example.com"}), transport=None, events=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    scope = ScopeSet(scope_hosts, name="t2")
    http = ScopedHttpClient(scope, transport=transport or _mock([], events))
    return ToolContext(
        run_id="R-T2", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://example.com/", emit=lambda k, p: events.append((k, dict(p))),
        config={"tier": "basic"}, state={},
    ), events


def _mock(routes, events=None):
    """MockTransport router: list of (needle, status, headers, text). Records hits."""

    def handler(request: httpx.Request) -> httpx.Response:
        if events is not None:
            events.append(("http", {"url": str(request.url)}))
        for needle, status, headers, text in routes:
            if needle in str(request.url):
                return httpx.Response(status, headers=headers or {}, text=text or "")
        return httpx.Response(404, text="no route")

    return httpx.MockTransport(handler)


# -- dns_resolve ----------------------------------------------------------------

def test_t2_dns_scope_gate_exact_and_subdomain(monkeypatch):
    """Contract: in-scope exact + subdomain resolve; out-of-scope blocked with manifest hint."""
    net = _require_network()
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    ctx, _ = _ctx()
    ok = net.dns_resolve({"host": "example.com", "rtype": "A"}, ctx)
    assert ok["ok"] and "93.184.216.34" in str(ok["addresses"])
    monkeypatch.setattr(
        __import__("hunter.tools.scope", fromlist=["ScopeSet"]),
        "ScopeSet",
        __import__("hunter.tools.scope", fromlist=["ScopeSet"]).ScopeSet,
    )
    ctx2, _ = _ctx(scope_hosts=frozenset({"example.com"}))
    ctx2.scope = type(ctx2.scope)(frozenset({"example.com"}), allow_subdomains=True, name="t2-sub")
    sub = net.dns_resolve({"host": "api.example.com", "rtype": "A"}, ctx2)
    assert sub["ok"], "allow_subdomains scope must permit api.example.com"
    ctx3, _ = _ctx()
    blocked = net.dns_resolve({"host": "evil.example.net", "rtype": "A"}, ctx3)
    assert blocked.get("blocked") is True and "manifest" in blocked.get("result_for_model", "").lower()


def test_t2_dns_host_normalization_casefold_trailing_dot():
    """Contract: ``EXAMPLE.com.`` normalizes (casefold + strip trailing dot) before gating."""
    net = _require_network()
    ctx, _ = _ctx()
    outcome = net.dns_resolve({"host": "EXAMPLE.com.", "rtype": "A"}, ctx)
    assert outcome.get("blocked") is not True, (
        "trailing-dot FQDN of an allowed host must normalize, not bypass"
    )
    assert outcome["ok"] or outcome.get("code") == "dns.resolve_error"


def test_t2_dns_aaaa_stdlib_other_types_need_dnspython(monkeypatch):
    """Contract: A/AAAA work on stdlib; MX/TXT/etc without dnspython -> dns.library_unavailable."""
    net = _require_network()
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(10, 1, 6, "", ("::1", 0, 0, 0))])
    if net.HAS_DNSPYTHON:  # pragma: no cover - documents the vendored branch
        pytest.skip("dnspython present; stdlib-only branch not under test")
    ctx, _ = _ctx()
    v6 = net.dns_resolve({"host": "example.com", "rtype": "AAAA"}, ctx)
    assert v6["ok"], "AAAA must resolve via stdlib getaddrinfo"
    mx = net.dns_resolve({"host": "example.com", "rtype": "MX"}, ctx)
    assert mx.get("blocked") is True and mx.get("code") == "dns.library_unavailable"
    assert "dnspython" in mx.get("result_for_model", "").lower()


def test_t2_dns_resolve_error_path(monkeypatch):
    """Contract: stdlib OSError -> dns.resolve_error + one engine_event (never a crash)."""
    net = _require_network()
    import socket

    def boom(*a, **k):
        raise OSError("no nameserver")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    ctx, events = _ctx()
    outcome = net.dns_resolve({"host": "example.com", "rtype": "A"}, ctx)
    assert outcome["ok"] is False and outcome.get("code") == "dns.resolve_error"
    assert any(k == "engine_event" and p.get("tool") == "dns_resolve" for k, p in events)


def test_t2_dns_doh_fallback_scope_checked(monkeypatch):
    """Contract: DoH fallback rides ctx.http; blocked DoH host -> scope BLOCKED (not leak)."""
    net = _require_network()
    import socket

    def _boom(*a, **k):
        raise OSError("no nameserver")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    routes = [("dns-query", 200, {"content-type": "application/dns-json"}, '{"Answer":[{"data":"1.2.3.4"}]}')]
    ctx, _ = _ctx(scope_hosts=frozenset({"example.com", "cloudflare-dns.com"}), transport=_mock(routes))
    ok = net.dns_resolve({"host": "example.com", "rtype": "A", "doh_fallback": True}, ctx)
    assert ok["ok"], "in-scope DoH fallback must work through ctx.http"
    assert "1.2.3.4" in str(ok.get("addresses", []))
    ctx2, _ = _ctx(scope_hosts=frozenset({"example.com"}), transport=_mock(routes))  # DoH host not in scope
    blocked = net.dns_resolve({"host": "example.com", "rtype": "A", "doh_fallback": True}, ctx2)
    assert blocked.get("blocked") is True and blocked.get("code", "").startswith("scope.")


# -- crt_sh ---------------------------------------------------------------------

def test_t2_crt_sh_gates_and_transport_error():
    """Contract: domain scope gate + crt.sh allowlist gate; transport error -> http.transport_error."""
    net = _require_network()
    ctx, _ = _ctx(transport=_mock([]))  # crt.sh NOT in scope -> allowlist/scope gate fires first
    blocked = net.crt_sh({"domain": "example.com"}, ctx)
    assert blocked.get("blocked") is True, "crt.sh host must be allowlisted before any I/O"
    ctx2, _ = _ctx(scope_hosts=frozenset({"example.com", "crt.sh"}), transport=_mock([]))
    err = net.crt_sh({"domain": "example.com"}, ctx2)
    assert err.get("code") == "http.transport_error" and err["ok"] is False and err.get("blocked") is False


def test_t2_crt_sh_truncation_and_evidence_kind():
    """Contract: over-limit rows truncate (truncated:true); evidence kind ct_entry (R2, not R3)."""
    net = _require_network()
    rows = ",".join(f'{{"name_value":"h{i}.example.com"}}' for i in range(500))
    transport = _mock([("crt.sh", 200, {"content-type": "application/json"}, f"[{rows}]")])
    ctx, _ = _ctx(scope_hosts=frozenset({"example.com", "crt.sh"}), transport=transport)
    outcome = net.crt_sh({"domain": "example.com", "max_rows": 10}, ctx)
    assert outcome["ok"] and outcome.get("truncated") is True
    assert outcome["evidence"]["kind"] == "ct_entry"
    assert len(outcome["evidence"]["data"]["entries"]) <= 10


def test_t2_crt_sh_out_of_scope_domain():
    """Contract: querying a domain outside scope is BLOCKED even when crt.sh is reachable."""
    net = _require_network()
    transport = _mock([("crt.sh", 200, {}, "[]")])
    ctx, _ = _ctx(scope_hosts=frozenset({"crt.sh"}), transport=transport)
    blocked = net.crt_sh({"domain": "victim.example.net"}, ctx)
    assert blocked.get("blocked") is True


# -- http_request extended --------------------------------------------------------

def test_t2_http_follow_redirects_default_off():
    """Contract: follow_redirects defaults false — a 302 is returned raw (open-redirect probes)."""
    from hunter.agent.tools import build_registry

    spec = next(s for s in build_registry("basic").specs_for_tier("basic") if s.name == "http_request")
    assert "follow_redirects" in spec.parameters["properties"], f"{TDD_HTTP}: schema lacks follow_redirects"


def test_t2_http_manual_hops_max3_per_hop_scope():
    """Contract: follow_redirects=true walks MANUALLY, max 3 hops,
    per-hop check_url; evil hop aborts + ledgers.
    """
    from hunter.agent.tools import build_registry

    registry = build_registry("basic")
    # Part 1: evil second hop aborts fail-closed (blocked + engine_event, evil host never fetched).
    http_hits: list = []
    routes = [
        ("example.com/start", 302, {"location": "http://example.com/step1"}, "r1"),
        ("example.com/step1", 302, {"location": "http://evil.example.net/phish"}, "r2"),
    ]
    ctx, events = _ctx(scope_hosts=frozenset({"example.com"}), transport=_mock(routes, http_hits))
    out = registry.dispatch(
        "http_request",
        {"method": "GET", "url": "http://example.com/start", "follow_redirects": True},
        ctx,
    )
    assert out.blocked is True and out.code == "scope.target_out_of_scope"
    assert any(k == "engine_event" and p.get("tool") == "http_request" for k, p in events)
    assert not any("evil.example.net" in str(item) for item in http_hits), "evil hop must never be fetched"
    # Part 2: all-in-scope chain caps at max 3 follows (4 requests total, stops before 5th).
    http_hits2: list = []
    routes2 = [
        ("example.com/a", 302, {"location": "http://example.com/b"}, "r"),
        ("example.com/b", 302, {"location": "http://example.com/c"}, "r"),
        ("example.com/c", 302, {"location": "http://example.com/d"}, "r"),
        ("example.com/d", 302, {"location": "http://example.com/e"}, "r"),
        ("example.com/e", 200, {}, "final"),
    ]
    ctx2, events2 = _ctx(scope_hosts=frozenset({"example.com"}), transport=_mock(routes2, http_hits2))
    out2 = registry.dispatch(
        "http_request",
        {"method": "GET", "url": "http://example.com/a", "follow_redirects": True},
        ctx2,
    )
    assert out2.ok is True, "in-scope chain must succeed (capped, not error)"
    assert len(http_hits2) == 4, f"max 3 hops => 4 requests total, got {http_hits2}"
    assert not any("example.com/e" in str(item) for item in http_hits2), "5th hop must not be fetched"
    assert any(k == "engine_event" and p.get("hops") == 3 for k, p in events2)


def test_t2_http_max_body_and_timeout_bounds():
    """Contract: max_body_chars<=40000 truncates with marker; timeout clamped 1..30."""
    from hunter.agent.tools import build_registry

    registry = build_registry("basic")
    # Timeout bounds: 0 and 31 are BLOCKED (fail-closed), 5 passes.
    for bad in (0, 31):
        ctx, _ = _ctx(transport=_mock([("example.com", 200, {}, "hi")]))
        out = registry.dispatch(
            "http_request", {"method": "GET", "url": "http://example.com/", "timeout": bad}, ctx
        )
        assert out.blocked is True and out.code == "http.timeout_bounds"
    ctx_ok, _ = _ctx(transport=_mock([("example.com", 200, {}, "hi")]))
    ok = registry.dispatch(
        "http_request", {"method": "GET", "url": "http://example.com/", "timeout": 5}, ctx_ok
    )
    assert ok.ok is True and not (ok.blocked and ok.code == "http.timeout_bounds")
    # max_body_chars truncates with marker.
    big = "X" * 500
    ctx2, _ = _ctx(transport=_mock([("example.com", 200, {}, big)]))
    out2 = registry.dispatch(
        "http_request",
        {"method": "GET", "url": "http://example.com/", "max_body_chars": 10},
        ctx2,
    )
    assert out2.ok is True
    assert out2.evidence is not None and out2.evidence["data"]["truncated"] is True
    assert "...[body truncated at 10 chars]" in out2.evidence["data"]["response_body"]
    assert "[truncated]" in out2.result_for_model
    # Small body with default limit is not truncated.
    ctx3, _ = _ctx(transport=_mock([("example.com", 200, {}, "hi")]))
    out3 = registry.dispatch("http_request", {"method": "GET", "url": "http://example.com/"}, ctx3)
    assert out3.ok is True and out3.evidence["data"]["truncated"] is False


# -- headers_audit / recon_subdomains / port_hint ----------------------------------

def test_t2_headers_audit_contract():
    """Contract: headers_audit is passive GET-only, scope-checked, returns finding-grade header table."""
    net = _require_network()
    transport = _mock([("example.com", 200, {"server": "nginx", "x-powered-by": "PHP/7.4"}, "hi")])
    ctx, events = _ctx(transport=transport)
    outcome = net.headers_audit({"url": "http://example.com/"}, ctx)
    assert outcome["ok"] and outcome["evidence"]["kind"] == "headers_audit"
    assert any(k == "engine_event" for k, _ in events)


def test_t2_recon_subdomains_ct_only():
    """Contract: recon_subdomains is CT-only; live bruteforce unavailable -> source_unavailable."""
    net = _require_network()
    ctx, _ = _ctx()
    live = net.recon_subdomains({"domain": "example.com", "source": "bruteforce"}, ctx)
    assert live.get("code") == "source_unavailable", "only CT sources allowed; no DNS bruteforce"


def test_t2_port_hint_no_socket():
    """Contract: port_hint opens NO socket (zero http calls); returns inventory
    hint + proposed shell string.
    """
    net = _require_network()
    calls: list[str] = []

    def spy(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="must not be called")

    ctx, _ = _ctx(transport=httpx.MockTransport(spy))
    outcome = net.port_hint({"host": "example.com"}, ctx)
    assert outcome["ok"] and calls == [], "port_hint must not open any socket"
    assert "proposed_command" in outcome and outcome.get("executed") is False
    assert "nmap" in outcome["proposed_command"]
