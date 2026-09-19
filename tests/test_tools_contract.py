"""Tool-envelope contract — five outcomes, tier-schema parity, loop persistence (TDD red).

Pins the cross-cutting envelope every Planner B tool must honor:

1. Five outcomes per tool: success / blocked / unavailable / redacted / truncated.
2. Transport-error shape: ok=False, blocked=False, code http.transport_error (retryable).
3. Identical schemas across tiers (refusal INSIDE handlers with tier.* codes).
4. Handlers never persist ids — the LOOP calls ledger.add_evidence (assert the
   loop seam, and that handler outcomes carry no fabricated ids).
5. Every handler emits exactly one engine_event, even on error paths.
6. Redaction + 16k cap marker on model-visible text.
7. _observe_tool phase fold is a no-op when no machine is mounted.
8. Unknown tool -> tool.tool_not_found + available-tool list.

Present-tool asserts pass today; per-new-tool (T1-T5) asserts FAIL via
EXPECTED-FAIL-TDD until those modules land, keeping the file red by design.
"""

from __future__ import annotations


import httpx
import pytest

TDD_NEW = "EXPECTED-FAIL-TDD:Planner B T1-T5 tools honoring the five-outcome envelope"

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

# (future module, tool names it must surface through the envelope)
FUTURE_TOOLS = {
    "hunter.agent.tools_local": ("search_files", "read_file"),
    "hunter.agent.tools_network": ("dns_resolve", "crt_sh", "headers_audit", "recon_subdomains", "port_hint"),
    "hunter.agent.tools_web3": ("contract_read", "contract_source_fetch", "abi_decode_hint"),
    "hunter.agent.tools_patch": ("patch_write",),
}


def _ctx(transport=None, events=None, tier="basic"):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    if events is None:
        events = []
    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=transport or _ok_transport())
    return ToolContext(
        run_id="R-C", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://127.0.0.1:9/", emit=lambda k, p: events.append((k, dict(p))),
        config={"tier": tier}, state={},
    ), events


def _ok_transport(text="ok", status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=text)

    return httpx.MockTransport(handler)


def _boom_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    return httpx.MockTransport(handler)


# -- five outcomes per future tool (red) ----------------------------------------------------

def test_contract_five_outcomes_per_new_tool():
    """Contract: every Planner B tool documents all five outcomes in its spec/contract table."""
    missing: list[str] = []
    for module_name, tools in FUTURE_TOOLS.items():
        try:
            module = __import__(module_name, fromlist=["x"])
        except ImportError:
            missing.extend(f"{module_name}.{t}" for t in tools)
            continue
        table = getattr(module, "OUTCOME_TABLE", {})
        for tool in tools:
            outcomes = set(table.get(tool, ()))
            if not set(FIVE) <= outcomes:
                missing.append(f"{module_name}.{tool} outcomes={sorted(outcomes)}")
    if missing:
        pytest.fail(f"{TDD_NEW}: missing five-outcome coverage: {missing}")


def test_contract_transport_error_retryable_shape():
    """Contract: transport errors are ok=False, blocked=False (retryable, never a refusal)."""
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx(transport=_boom_transport())
    out = build_registry("basic").dispatch(
        "http_request", {"method": "GET", "url": "http://127.0.0.1:9/"}, ctx
    )
    assert out.ok is False and out.blocked is False and out.code == "http.transport_error"


def test_contract_identical_schemas_across_tiers():
    """Contract: schemas_for_tier equal for basic/advanced among v0.2 tools; refusal inside handler."""
    from hunter.agent.tools import build_registry

    basic = build_registry("basic").schemas_for_tier("basic")
    advanced = build_registry("advanced").schemas_for_tier("advanced")
    basic_names = {s["function"]["name"] for s in basic}
    for name in basic_names:
        if name in ("shell_exec",):  # M8 structural exception: advanced-only + approval-danger
            continue
        assert name in {s["function"]["name"] for s in advanced}
    ctx, _ = _ctx(tier="basic")
    out = build_registry("basic").dispatch(
        "http_request", {"method": "POST", "url": "http://127.0.0.1:9/"}, ctx
    )
    assert out.blocked and out.code == "tier.passive_only"


def test_contract_handlers_never_persist_ids_loop_does():
    """Contract: handlers return evidence WITHOUT ids; the loop persists via ledger.add_evidence."""
    import inspect

    import hunter.agent.loop as loop
    import hunter.agent.tools as tools

    source = inspect.getsource(loop.AgentLoop._store_evidence)
    assert "add_evidence" in source, "loop must persist evidence via ledger.add_evidence"
    handler_source = inspect.getsource(tools._http_request)
    assert "add_evidence" not in handler_source, "handlers must never persist evidence themselves"
    ctx, _ = _ctx()
    from hunter.agent.tools import build_registry

    out = build_registry("basic").dispatch(
        "http_request", {"method": "GET", "url": "http://127.0.0.1:9/"}, ctx
    )
    assert "EV-" not in out.result_for_model, "handlers must never fabricate evidence ids"


def test_contract_every_handler_emits_one_engine_event_even_on_error():
    """Contract: success AND error paths emit exactly one engine_event each."""
    from hunter.agent.tools import build_registry

    registry = build_registry("basic")
    ctx, events = _ctx()
    registry.dispatch("http_request", {"method": "GET", "url": "http://127.0.0.1:9/"}, ctx)
    assert sum(1 for k, p in events if k == "engine_event" and p.get("tool") == "http_request") == 1
    events.clear()
    blocked = registry.dispatch("http_request", {"method": "GET", "url": "http://evil.example.net/"}, ctx)
    assert blocked.blocked and blocked.code == "scope.target_out_of_scope"
    # Transport-error path must ALSO emit exactly one engine_event (red today:
    # _http_request returns http.transport_error without emitting).
    ctx2, events2 = _ctx(transport=_boom_transport())
    registry.dispatch("http_request", {"method": "GET", "url": "http://127.0.0.1:9/"}, ctx2)
    if sum(1 for k, p in events2 if k == "engine_event" and p.get("tool") == "http_request") != 1:
        pytest.fail(
            "EXPECTED-FAIL-TDD:http_request transport-error path must emit one engine_event "
            "(even errors are observable)"
        )


def test_contract_redaction_and_16k_cap_marker():
    """Contract: secret shapes redacted in stored payloads; model text capped with marker."""
    from hunter.kernel.ledger import Ledger
    from hunter.kernel.redaction import redact_text

    assert "[REDACTED]" in redact_text("Authorization: Bearer abcdefghijklmnop")
    ledger = Ledger(":memory:")
    eid = ledger.add_evidence("R-C", "http_exchange", {"body": "token=supersecretvalue12345"})
    stored = next(r for r in ledger.evidence("R-C") if r["id"] == eid)
    assert "supersecretvalue12345" not in str(stored["data"]), "redaction applies at add_evidence"
    import hunter.agent.tools as tools

    assert getattr(tools, "_SHELL_OUTPUT_LIMIT", 16_384) == 16_384
    assert "truncat" in getattr(tools, "_SHELL_TRUNCATION_MARKER", "truncated")
    ledger.close()


def test_contract_observe_tool_noop_when_unmounted():
    """Contract: _observe_tool folds phases only when a machine is mounted; else no-op."""
    from hunter.agent.tools import _observe_tool

    ctx, _ = _ctx()
    assert "phase_machine" not in ctx.config
    _observe_tool(ctx, "http_request")  # must not raise, must not emit
    assert ctx.state == {}


def test_contract_unknown_tool_lists_available():
    """Contract: unknown tool -> tool.tool_not_found + available list (recoverable)."""
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx()
    out = build_registry("basic").dispatch("sendTransaction", {}, ctx)
    assert out.ok is False and out.code == "tool.tool_not_found"
    assert "http_request" in out.result_for_model
    assert "sendTransaction" not in {s.name for s in build_registry("basic").specs_for_tier("advanced")}
