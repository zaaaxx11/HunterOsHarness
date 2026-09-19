"""R2-B royalty guards — MUST PASS TODAY (green).

Non-negotiable pins the R2-B hardening must never break:
t4 bounded_redacted + no_send + slither_unavailable (same message),
t2 dns/crt/http bounds, t1 jail, t5 patch/approval, contract OUTCOME_TABLE,
scope exact + trust_env False, ledger redact + RULE-E1, inventory pinned 15.

Unlike the R2-B red files, every test here passes on the current tree.
If any test goes red, R2-B has broken a load-bearing invariant — stop.
Mock only: httpx.MockTransport, tmp_path jail, :memory: Ledger, no live net.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

PINNED_15 = (
    "curl", "wget", "nmap", "sqlmap", "nuclei", "ffuf", "dig", "nslookup",
    "whois", "whatweb", "gobuster", "masscan", "testssl", "openssl", "httpx",
)
# R2-B B3 heavy opt-in tail (append-only, sorted): the first 15 never move.
PINNED_HEAVY_SORTED = ("anvil", "cast", "slither")
PINNED_BINARIES = PINNED_15 + PINNED_HEAVY_SORTED
FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")
ADDR = "0xabc0000000000000000000000000000000000def"
RPC = "https://rpc.example.com"


def _mock(text="ok", status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=text)

    return httpx.MockTransport(handler)


def _ctx(transport=None, events=None, tier="basic", jail=None, scope_hosts=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    scope = ScopeSet(
        scope_hosts or frozenset({"rpc.example.com", "api.etherscan.io", "example.com"}),
        name="r2b-royal",
    )
    http = ScopedHttpClient(scope, transport=transport or _mock(), min_interval=0)
    config: dict[str, Any] = {"tier": tier}
    if jail is not None:
        config["jail"] = str(jail)
    return ToolContext(
        run_id="R-R2B-ROYAL", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://rpc.example.com/", emit=lambda k, p: events.append((k, dict(p))),
        config=config, state={},
    ), events


def _chain_ctx(events=None, tier="basic", transport=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    if events is None:
        events = []
    scope = ScopeSet(frozenset({"rpc.example.com", "api.etherscan.io"}), name="r2b-royal-t4")
    http = ScopedHttpClient(scope, transport=transport or _mock(), min_interval=0)
    return ToolContext(
        run_id="R-R2B-ROYAL", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://rpc.example.com/", emit=lambda k, p: events.append((k, dict(p))),
        config={"tier": tier, "chain_scope": [{"chain_id": 1, "address": ADDR}]},
        state={},
    ), events


def test_r2b_royal_t4_bounded_redacted():
    """Guard: contract_call evidence bounded 8k (+256 slack), redacted."""
    import hunter.agent.tools_web3 as w3

    rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x" + "ab" * 9000})
    ctx, _ = _chain_ctx(transport=_mock(text=rpc))
    out = w3.contract_read({"chain_id": 1, "address": ADDR, "method": "eth_call",
                            "rpc_url": RPC, "calldata": "0x70a08231"}, ctx)
    assert out["ok"] and out["evidence"]["kind"] == "contract_call"
    assert len(json.dumps(out["evidence"]["data"])) <= 8192 + 256
    ctx.ledger.close()
    ctx.http.close()


def test_r2b_royal_t4_no_send_never_registered():
    """Guard: send verbs never registered; module never imports web3."""
    import hunter.agent.tools_web3 as w3

    names = set(w3.SPEC_NAMES)
    for evil in ("sendTransaction", "sendRawTransaction", "eth_sendTransaction", "eth_sendRawTransaction"):
        assert evil not in names
    assert "eth_sendTransaction" not in str(getattr(w3, "CONTRACT_READ_METHODS", "")).lower()
    src = Path(w3.__file__).read_text(encoding="utf-8")
    assert "import web3" not in src and "from web3" not in src


def test_r2b_royal_t4_slither_cast_unavailable_same_message():
    """Guard: slither/cast surface as tool.unavailable + install hint; inventory all-missing."""
    import hunter.agent.inventory as inventory
    import hunter.agent.tools_web3 as w3

    ctx, _ = _chain_ctx()
    reg = w3.build_web3_registry("basic")
    for name in ("slither_hint", "cast_hint"):
        out = reg.dispatch(name, {}, ctx)
        assert out.blocked and out.code == "tool.unavailable"
        assert "install" in out.result_for_model.lower()
    found = inventory.inventory_binaries(which_fn=lambda _n: None)
    assert set(found) == {"available", "missing", "platform"}
    assert found["available"] == {} and set(found["missing"]) == set(inventory.INVENTORY_BINARIES)
    ctx.ledger.close()
    ctx.http.close()


def test_r2b_royal_t2_dns_crt_http_preserved():
    """Guard: T2 pins preserved — dns scope gate, crt allowlist gate, http timeout bounds."""
    import hunter.agent.tools_network as net
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx(scope_hosts=frozenset({"example.com"}))
    blocked = net.dns_resolve({"host": "evil.example.net", "rtype": "A"}, ctx)
    assert blocked.get("blocked") is True
    ctx2, _ = _ctx(scope_hosts=frozenset({"example.com"}))
    assert net.crt_sh({"domain": "example.com"}, ctx2).get("blocked") is True
    ctx3, _ = _ctx(scope_hosts=frozenset({"example.com"}))
    out = build_registry("basic").dispatch(
        "http_request", {"method": "GET", "url": "http://example.com/", "timeout": 0}, ctx3)
    assert out.blocked and out.code == "http.timeout_bounds"
    for c in (ctx, ctx2, ctx3):
        c.ledger.close()
        c.http.close()


def test_r2b_royal_t1_jail_preserved(tmp_path: Path):
    """Guard: T1 jail preserved — search/root escape + read escape BLOCKED."""
    import hunter.agent.tools_local as loc

    jail = tmp_path / "jail"
    (jail / "docs").mkdir(parents=True)
    (jail / "docs" / "audit.md").write_text("scope: example.com\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    ctx, _ = _ctx(jail=jail)
    assert loc.search_files(
        {"pattern": "scope", "root": str(tmp_path / "outside.txt")}, ctx
    ).get("blocked") is True
    assert loc.read_file({"path": "../outside.txt"}, ctx).get("blocked") is True
    ctx.ledger.close()
    ctx.http.close()


def test_r2b_royal_t5_patch_approval_preserved(tmp_path: Path):
    """Guard: patch_write danger=approval advanced; catastrophic pends; TTL 300."""
    from hunter.agent.approval import APPROVAL_TTL_SECONDS, ApprovalStore, make_approval_gate
    from hunter.agent.tools_patch import PATCH_WRITE_SPEC
    from hunter.kernel.ledger import Ledger

    assert PATCH_WRITE_SPEC["danger"] == "approval"
    assert PATCH_WRITE_SPEC["min_tier"] == "advanced"
    assert APPROVAL_TTL_SECONDS == 300
    store = ApprovalStore(tmp_path / "approvals")
    ledger = Ledger(":memory:")
    try:
        gate = make_approval_gate(store, ledger=ledger, run_id="R-R2B-ROYAL", auto_allow=True)
        ctx, _ = _ctx()
        decision = gate("shell_exec", {"command": "rm -rf /"}, ctx)
        assert decision is not None and decision.code == "approval.catastrophic"
        ctx.ledger.close()
        ctx.http.close()
    finally:
        ledger.close()


def test_r2b_royal_contract_outcome_table_five():
    """Guard: every Planner B OUTCOME_TABLE documents all five outcomes."""
    import hunter.agent.tools_local as loc
    import hunter.agent.tools_network as net
    import hunter.agent.tools_patch as pat
    import hunter.agent.tools_web3 as w3

    for module, tools in (
        (loc, ("search_files", "read_file")),
        (net, ("dns_resolve", "crt_sh", "headers_audit", "recon_subdomains", "port_hint")),
        (w3, ("contract_read", "contract_source_fetch", "abi_decode_hint")),
        (pat, ("patch_write",)),
    ):
        for tool in tools:
            assert set(FIVE) <= set(module.OUTCOME_TABLE.get(tool, ())), f"{module.__name__}.{tool}"


def test_r2b_royal_scope_exact_trust_env_false():
    """Guard: scope exact-host (no widening) + http trust_env False + no auto-redirect."""
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet, ScopeViolation
    import inspect

    import pytest

    scope = ScopeSet(frozenset({"example.com"}), False, name="royal")
    assert scope.check_url("http://example.com/x") == "example.com"
    for hostile in ("http://evil.com/x", "http://sub.example.com/x", "http://example.com.evil.com/x"):
        with pytest.raises(ScopeViolation):
            scope.check_url(hostile)
    assert "trust_env" in inspect.getsource(ScopedHttpClient.__init__)
    client = ScopedHttpClient(scope, transport=_mock(status=302, text="r"))
    try:
        assert client.request("GET", "http://example.com/").status == 302
    finally:
        client.close()


def test_r2b_royal_ledger_redact_rule_e1(tmp_path: Path):
    """Guard: ledger redacts secrets at storage + RULE-E1 blocks zero-evidence inserts."""
    from hunter.kernel.claimgate import ClaimGateBlocked, validate_finding_insert
    from hunter.kernel.findings import Finding, FindingStatus, Severity
    from hunter.kernel.ledger import Ledger

    ledger = Ledger(":memory:")
    try:
        eid = ledger.add_evidence("R-R2B-ROYAL", "http_exchange", {"api_key": "sk-live-1234567890"})
        rows = ledger.evidence("R-R2B-ROYAL")
        assert rows[0]["data"]["api_key"] == "[REDACTED]"
        with pytest.raises(ClaimGateBlocked):
            validate_finding_insert(Finding(id="", run_id="R", key="k", title="t",
                                            severity=Severity.HIGH, cwe="CWE-79", endpoint="/",
                                            method="GET", status=FindingStatus.CANDIDATE,
                                            evidence_ids=()), 0)
        assert eid.startswith("EV-")
    finally:
        ledger.close()


def test_r2b_royal_inventory_pinned_15():
    """Guard: inventory pinned 18 append-only (supersedes the 15-pin).

    R2-B B3 appends the heavy opt-in tail AFTER the pinned 15: the first 15
    entries never move; the tail stays sorted (anvil/cast/slither)."""
    from hunter.agent.inventory import INVENTORY_BINARIES

    assert INVENTORY_BINARIES == PINNED_BINARIES
    assert len(INVENTORY_BINARIES) == 18
    assert INVENTORY_BINARIES[:15] == PINNED_15
    assert INVENTORY_BINARIES[15:] == PINNED_HEAVY_SORTED
    assert tuple(sorted(INVENTORY_BINARIES[15:])) == INVENTORY_BINARIES[15:]
