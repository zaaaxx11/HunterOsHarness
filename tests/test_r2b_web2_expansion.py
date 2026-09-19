"""R2-B Web2 expansion: dnssec / pagination / tls / glob / archive (TDD RED).

B-gate: B5 (Web2 expansion) — R decision gate: needs_follow_up vs no_issue_found.

Prod targets (READ ONLY, do NOT edit):
- src/hunter/agent/tools_network.py: dns_resolve/crt_sh/headers_audit/recon/port_hint (pinned)
- src/hunter/agent/tools_local.py: search_files/read_file (pinned)
- src/hunter/agent/tools.py: _http_request bounds + build_registry (pinned)
- per-fn -> prod:
  dnssec_validate -> tools_network.py (NEW, stdlib-only, scope-checked)
  tls_audit -> tools_network.py (NEW, passive GET-only, scope-checked)
  paginate_results -> tools_network.py (NEW, cursor pagination helper)
  search_glob -> tools_local.py (NEW, glob opt-in, jailed, redacted)
  archive_read -> tools_local.py (NEW, advanced lock, jail, 8k bound)

All tests FAIL today via EXPECTED-FAIL-R2B until Web2 expansion lands.
Mock only: httpx.MockTransport, tmp_path jail, :memory: Ledger, no live net.
Adversarial: jail escape BLOCKED (incl. Windows backslash), ReDoS caps,
secret redact, size/time budgets (8k/32k), scope fail-closed, negatives.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

R2B = "EXPECTED-FAIL-R2B:Web2 expansion dnssec/pagination/tls/glob/archive (R2-B B5)"


def _require_network_attr(name: str):
    import hunter.agent.tools_network as net

    fn = getattr(net, name, None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_network.{name} missing (Web2 expansion)")
    return fn


def _require_local_attr(name: str):
    import hunter.agent.tools_local as loc

    fn = getattr(loc, name, None)
    if fn is None:
        pytest.fail(f"{R2B} — hunter.agent.tools_local.{name} missing (Web2 expansion)")
    return fn


def _mock(routes, events=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if events is not None:
            events.append(("http", {"url": str(request.url)}))
        for needle, status, headers, text in routes:
            if needle in str(request.url):
                return httpx.Response(status, headers=headers or {}, text=text or "")
        return httpx.Response(404, text="no route")

    return httpx.MockTransport(handler)


def _ctx(scope_hosts=frozenset({"example.com"}), transport=None, events=None, tier="basic", jail=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    scope = ScopeSet(scope_hosts, name="r2b-web2")
    http = ScopedHttpClient(scope, transport=transport or _mock([], events), min_interval=0)
    config: dict[str, Any] = {"tier": tier}
    if jail is not None:
        config["jail"] = str(jail)
    return ToolContext(
        run_id="R-WEB2", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://example.com/", emit=lambda k, p: events.append((k, dict(p))),
        config=config, state={},
    ), events


def _jail(tmp_path: Path) -> Path:
    jail = tmp_path / "jail"
    (jail / "docs").mkdir(parents=True, exist_ok=True)
    (jail / "docs" / "audit.md").write_text(
        "scope: example.com\nfinding: reflected xss in q\nsecret token=TOPSECRET-abc123\n",
        encoding="utf-8",
    )
    (jail / "docs" / "notes.txt").write_text("plain notes\nnothing here\n", encoding="utf-8")
    return jail


def test_r2b_web2_dnssec_chain_validates():
    """dnssec_validate: scope-checked, stdlib-only, one engine_event, redacted."""
    fn = _require_network_attr("dnssec_validate")
    ctx, events = _ctx()
    out = fn({"host": "example.com"}, ctx)
    assert out.get("ok") is True or out.get("code") in ("dns.resolve_error", "dnssec.bogus")
    assert sum(1 for k, p in events if k == "engine_event" and p.get("tool") == "dnssec_validate") == 1
    assert "TOPSECRET" not in json.dumps(out)


def test_r2b_web2_dnssec_bogus_needs_follow_up():
    """dnssec bogus -> needs_follow_up, NEVER ruled_out (fail-closed)."""
    fn = _require_network_attr("dnssec_validate")
    ctx, _ = _ctx()
    out = fn({"host": "example.com", "ds": "BOGUS"}, ctx)
    assert out.get("verdict") == "needs_follow_up"
    assert out.get("verdict") != "ruled_out"


def test_r2b_web2_pagination_cursor_bounded():
    """Pagination: cursor/page_token bounded <=100 rows, truncated flag, budget."""
    fn = _require_network_attr("paginate_results")
    rows = [{"n": i} for i in range(250)]
    ctx, _ = _ctx()
    out = fn({"rows": rows, "page_size": 10, "cursor": 0}, ctx)
    assert out.get("ok") is True
    assert len(out.get("page", [])) <= 100
    assert out.get("truncated") is True
    assert "next_cursor" in out


def test_r2b_web2_tls_inventory_basic():
    """tls_audit: passive inventory, scope-checked, basic tier, one engine_event."""
    fn = _require_network_attr("tls_audit")
    import hunter.agent.tools_network as net

    spec = getattr(net, "TLS_AUDIT_SPEC", {})
    assert spec.get("min_tier") == "basic", "tls inventory stays passive/basic"
    assert spec.get("danger") == "none"
    transport = _mock([("example.com", 200, {"strict-transport-security": "max-age=63072000"}, "hi")])
    ctx, events = _ctx(transport=transport)
    out = fn({"host": "example.com"}, ctx)
    assert out.get("ok") is True
    assert sum(1 for k, p in events if k == "engine_event") == 1
    # Out-of-scope host must BLOCK without I/O.
    ctx2, events2 = _ctx()
    blocked = fn({"host": "evil.example.net"}, ctx2)
    assert blocked.get("blocked") is True
    assert [e for e in events2 if e[0] == "http"] == []


def test_r2b_web2_search_glob_jailed(tmp_path: Path):
    """search_glob: glob opt-in, jail-relative, escape BLOCKED, redacted."""
    fn = _require_local_attr("search_glob")
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail=jail)
    out = fn({"glob": "docs/*.md", "pattern": "reflected xss"}, ctx)
    assert out.get("ok") is True
    assert any("audit.md" in h.get("path", "") for h in out.get("hits", []))
    assert "TOPSECRET-abc123" not in json.dumps(out)
    for evil in ("../outside.txt", "..\\outside.txt", "/etc/passwd", "**/../../etc/*"):
        blocked = fn({"glob": evil, "pattern": "secret"}, ctx)
        assert blocked.get("blocked") is True, evil


def test_r2b_web2_archive_advanced_locked(tmp_path: Path):
    """archive_read: advanced lock — basic -> tier.capability_locked."""
    fn = _require_local_attr("archive_read")
    import hunter.agent.tools_local as loc

    spec = getattr(loc, "ARCHIVE_READ_SPEC", {})
    assert spec.get("min_tier") == "advanced", "archive extraction is advanced-only"
    jail = _jail(tmp_path)
    ctx_basic, _ = _ctx(tier="basic", jail=jail)
    locked = fn({"path": "docs/audit.md", "archive": "bundle.zip"}, ctx_basic)
    assert locked.get("blocked") is True and locked.get("code") == "tier.capability_locked"
    ctx_adv, _ = _ctx(tier="advanced", jail=jail)
    out = fn({"path": "docs/audit.md", "archive": "bundle.zip"}, ctx_adv)
    assert out.get("ok") is True or out.get("code") in ("archive.not_found", "archive.bad_envelope")


def test_r2b_web2_archive_jail_escape_blocked(tmp_path: Path):
    """archive_read jail: escape paths BLOCKED, no read outside jail."""
    fn = _require_local_attr("archive_read")
    jail = _jail(tmp_path)
    (tmp_path / "outside.txt").write_text("outside secret", encoding="utf-8")
    ctx, _ = _ctx(tier="advanced", jail=jail)
    for evil in ("../outside.txt", "..\\outside.txt", "/etc/passwd", "docs/../../outside.txt"):
        blocked = fn({"path": evil, "archive": "bundle.zip"}, ctx)
        assert blocked.get("blocked") is True and "jail" in blocked.get("code", "").lower(), evil


def test_r2b_web2_no_live_net_transport_guard():
    """Meta-guard: Web2 expansion harness uses MockTransport only (no sockets)."""
    import hunter.tools.http_client as hc
    import inspect

    src = inspect.getsource(hc.ScopedHttpClient.__init__)
    assert "trust_env=False" in src or "trust_env" in src
    # Every ctx in this file rides MockTransport; prove one round-trip stays mocked.
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    from hunter.tools.scope import ScopeSet

    client = hc.ScopedHttpClient(
        ScopeSet(frozenset({"example.com"}), name="r2b"),
        transport=httpx.MockTransport(handler),
    )
    assert client.request("GET", "http://example.com/").status == 200
    assert seen == ["http://example.com/"]
    client.close()
    # TDD red pin: expansion registry must exist (fails until Web2 lands).
    _require_network_attr("tls_audit")
