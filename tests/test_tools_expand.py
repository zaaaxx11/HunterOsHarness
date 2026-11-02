"""``expand_finding`` regression suite — scope safety and degradation paths.

This module is the recursive attack-surface expansion tool (see
``hunter.agent.tools_expand``). Two things in it are load-bearing and must not
rot silently:

* **Scope is enforced on every candidate, in both modes.** A follow-up target
  that leaves the approved scope is dropped *before* it reaches the model, and
  a planner that hallucinates an out-of-scope host cannot smuggle it back in.
  The expansion step must never become a scope-bypass primitive.
* **Every optional path degrades, never raises.** No provider, a provider that
  explodes, an unparseable reply — all collapse to a safe value. A slow or
  broken planner must never make an agent turn unusable.

The ledger is a real in-memory :class:`Ledger` (the fake is only the planner),
so the "finding must be anchored to real evidence" gate is exercised as
written. No network, no sleeps, no model calls.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from hunter.agent.tools_base import ToolContext, ToolRegistry
from hunter.agent.tools_expand import (
    _MAX_TARGETS,
    derive_targets,
    expand_finding,
    register_expand_tools,
    wonder_targets,
)
from hunter.kernel.findings import Finding
from hunter.kernel.ledger import Ledger
from hunter.tools.scope import ScopeSet, localhost_scope

RUN = "R-EXPAND"
IN_SCOPE_ORIGIN = "https://example.test"
OUTSIDE_HOST = "evil.attacker.test"


# -- fixtures -------------------------------------------------------------------


class _FakeProvider:
    """A planner stand-in: returns a canned reply (or raises) for ``complete``."""

    def __init__(self, *, reply: Any = "[]", raises: Exception | None = None) -> None:
        self.reply = reply
        self.raises = raises
        self.calls: list[tuple[str, Any, Any]] = []

    def complete(self, task: str, messages: Any, budget: Any = None) -> Any:
        self.calls.append((task, messages, budget))
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(text=self.reply)


class _RaisingScope:
    """A scope whose check raises (not returns False) — must be read as refusal."""

    allowed_hosts = frozenset({"example.test"})

    def check_url(self, url: str, *, base_url: str = "") -> str:
        raise RuntimeError("scope backend unavailable")


def _scope(*hosts: str) -> ScopeSet:
    return ScopeSet(allowed_hosts=frozenset(hosts), name="expand-test")


def _ctx(
    scope: Any,
    *,
    target_url: str = IN_SCOPE_ORIGIN + "/",
    config: dict[str, Any] | None = None,
) -> ToolContext:
    ledger = Ledger(":memory:")
    ledger.create_run(RUN, target_url, "deterministic", "test")
    return ToolContext(
        run_id=RUN,
        ledger=ledger,
        http=None,  # type: ignore[arg-type] - expand_finding never makes a request
        scope=scope,
        target_url=target_url,
        emit=lambda kind, payload: None,
        config=dict(config or {}),
        state={},
    )


@pytest.fixture()
def ctx() -> Any:
    context = _ctx(_scope("example.test"))
    try:
        yield context
    finally:
        context.ledger.close()


@pytest.fixture()
def finding(ctx: ToolContext) -> Finding:
    evidence = ctx.ledger.add_evidence(
        RUN, "http_exchange", {"method": "GET", "url": IN_SCOPE_ORIGIN + "/v1/users/42"}
    )
    return ctx.ledger.create_finding(
        Finding(
            id="",
            run_id=RUN,
            key="idor|GET|/v1/users/42|id",
            title="IDOR on user object",
            severity="medium",  # type: ignore[arg-type] - Severity coerces str
            cwe="CWE-639",
            endpoint="/v1/users/42",
            evidence_ids=(evidence,),
        )
    )


# -- derive_targets: deterministic expansion ------------------------------------


def test_derive_targets_returns_endpoint_and_path_parent(ctx: ToolContext) -> None:
    """A deep path yields the endpoint itself plus its aggregating parent."""
    targets = derive_targets(ctx, "/v1/users/42/orders?status=open")

    assert targets[0] == IN_SCOPE_ORIGIN + "/v1/users/42/orders?status=open"
    assert IN_SCOPE_ORIGIN + "/v1/users/42/orders" in targets
    assert IN_SCOPE_ORIGIN + "/v1/users/42" in targets
    # Nothing above the immediate parent is invented.
    assert IN_SCOPE_ORIGIN + "/v1" not in targets
    assert IN_SCOPE_ORIGIN + "/" not in targets


def test_derive_targets_adds_query_variants_without_query(ctx: ToolContext) -> None:
    targets = derive_targets(ctx, "/v1/users/42")
    base = IN_SCOPE_ORIGIN + "/v1/users/42"

    assert base in targets
    assert [t for t in targets if t.startswith(base + "?")]  # pagination/id/debug variants
    assert base + "?page=2" in targets
    # The parent for a shallow path is still an anchor.
    assert IN_SCOPE_ORIGIN + "/v1/users" in targets
    assert len(targets) <= _MAX_TARGETS


def test_derive_targets_collapses_to_bare_path_when_query_present(ctx: ToolContext) -> None:
    targets = derive_targets(ctx, "/v1/users/42/orders?status=open")
    bare = IN_SCOPE_ORIGIN + "/v1/users/42/orders"

    assert bare in targets
    # No speculative query variants once the caller already supplied one: the
    # only query-bearing target is the caller's own endpoint.
    seeded = IN_SCOPE_ORIGIN + "/v1/users/42/orders?status=open"
    assert [t for t in targets if t.startswith(bare + "?")] == [seeded]


def test_derive_targets_drops_out_of_scope_endpoint(ctx: ToolContext) -> None:
    assert derive_targets(ctx, f"https://{OUTSIDE_HOST}/admin") == []


def test_derive_targets_empty_for_non_url_target(ctx: ToolContext) -> None:
    """Repo / local-dir hunts have no URL origin: expansion is a no-op.

    Pinned as intended behaviour — there is nothing for a URL-based follow-up
    to hang off, and inventing an origin would be a scope guess.
    """
    repo_ctx = _ctx(_scope(), target_url="/home/ubuntu/locals/hunted-repo")
    try:
        assert derive_targets(repo_ctx, "/v1/users/42") == []
        assert derive_targets(repo_ctx, "v1/users/42") == []
    finally:
        repo_ctx.ledger.close()


def test_derive_targets_treats_raising_scope_as_refusal(ctx: ToolContext) -> None:
    """Fail closed: a scope check that raises is a refusal, not a pass."""
    hostile = _ctx(_RaisingScope())
    try:
        assert derive_targets(hostile, "/v1/users/42") == []
    finally:
        hostile.ledger.close()


def test_derive_targets_respects_limit(ctx: ToolContext) -> None:
    assert len(derive_targets(ctx, "/a/b/c/d", limit=2)) == 2


# -- wonder_targets: opt-in planner assist --------------------------------------


def test_wonder_targets_without_provider_is_empty(ctx: ToolContext) -> None:
    assert ctx.config.get("provider") is None
    assert wonder_targets(ctx, "/v1/users/42", "IDOR on user object") == []


def test_wonder_targets_filters_out_of_scope_planner_candidates(ctx: ToolContext) -> None:
    """A hostile planner cannot smuggle an out-of-scope host through expand."""
    provider = _FakeProvider(
        reply=(
            "Sure:\n"
            "```json\n"
            '["/v1/users/42/orders", '
            f'"https://{OUTSIDE_HOST}/steal-cookies", '
            '"/v1/admin/users"]\n'
            "```"
        )
    )
    planning = _ctx(_scope("example.test"), config={"provider": provider})

    try:
        targets = wonder_targets(planning, "/v1/users/42", "IDOR on user object")
    finally:
        planning.ledger.close()

    assert targets == [
        IN_SCOPE_ORIGIN + "/v1/users/42/orders",
        IN_SCOPE_ORIGIN + "/v1/admin/users",
    ]
    assert not any(OUTSIDE_HOST in t for t in targets)
    assert provider.calls  # the planner really was consulted
    assert provider.calls[0][0] == "utility"


def test_wonder_targets_degrades_when_provider_raises(ctx: ToolContext) -> None:
    provider = _FakeProvider(raises=RuntimeError("planner rate limited"))
    planning = _ctx(_scope("example.test"), config={"provider": provider})
    try:
        assert wonder_targets(planning, "/v1/users/42", "IDOR") == []
    finally:
        planning.ledger.close()


@pytest.mark.parametrize("reply", ["no urls here", "[not json", "{}", ""])
def test_wonder_targets_degrades_on_unparseable_reply(ctx: ToolContext, reply: str) -> None:
    planning = _ctx(_scope("example.test"), config={"provider": _FakeProvider(reply=reply)})
    try:
        assert wonder_targets(planning, "/v1/users/42", "IDOR") == []
    finally:
        planning.ledger.close()


# -- expand_finding: the tool surface -------------------------------------------


def test_expand_finding_blocks_unknown_finding_id(ctx: ToolContext) -> None:
    outcome = expand_finding({"finding_id": "F-9999"}, ctx)

    assert outcome.result_for_model.startswith("BLOCKED:")
    assert "F-9999" in outcome.result_for_model
    assert "expansions" not in ctx.state  # a refusal leaves no trace


def test_expand_finding_blocks_when_no_anchor_given(ctx: ToolContext) -> None:
    outcome = expand_finding({}, ctx)

    assert outcome.result_for_model.startswith("BLOCKED:")
    assert "endpoint" in outcome.result_for_model


def test_expand_finding_accepts_explicit_endpoint(ctx: ToolContext) -> None:
    outcome = expand_finding({"endpoint": "/v1/users/42/orders"}, ctx)

    assert not outcome.result_for_model.startswith("BLOCKED:")
    assert "/v1/users/42/orders" in outcome.result_for_model
    assert IN_SCOPE_ORIGIN + "/v1/users/42" in outcome.result_for_model


def test_expand_finding_resolves_finding_and_records_expansion(
    ctx: ToolContext, finding: Finding
) -> None:
    outcome = expand_finding({"finding_id": finding.id}, ctx)

    text = outcome.result_for_model
    assert not text.startswith("BLOCKED:")
    assert finding.endpoint in text

    expansions = ctx.state["expansions"]
    assert len(expansions) == 1
    record = expansions[0]
    assert record["finding_id"] == finding.id
    assert record["endpoint"] == finding.endpoint
    assert record["assist"] is False
    assert record["targets"]
    assert all(t.startswith(IN_SCOPE_ORIGIN + "/") for t in record["targets"])


def test_expand_finding_records_expansion_for_explicit_endpoint(ctx: ToolContext) -> None:
    expand_finding({"endpoint": "/v1/users/42"}, ctx)

    assert ctx.state["expansions"][0]["finding_id"] is None
    assert ctx.state["expansions"][0]["endpoint"] == "/v1/users/42"


def test_expand_finding_reports_no_targets_for_out_of_scope_endpoint(ctx: ToolContext) -> None:
    outcome = expand_finding({"endpoint": f"https://{OUTSIDE_HOST}/admin"}, ctx)

    assert outcome.result_for_model.startswith("no in-scope follow-up targets")
    assert "expansions" not in ctx.state


def test_expand_finding_assist_survives_broken_planner(
    ctx: ToolContext, finding: Finding
) -> None:
    """assist=true with an exploding planner still returns the deterministic set."""
    ctx.config["provider"] = _FakeProvider(raises=RuntimeError("planner down"))

    outcome = expand_finding({"finding_id": finding.id, "assist": True}, ctx)

    assert not outcome.result_for_model.startswith("BLOCKED:")
    assert "llm-assisted: 0" in outcome.result_for_model
    assert ctx.state["expansions"][0]["assist"] is True
    assert ctx.state["expansions"][0]["targets"]


def test_expand_finding_never_returns_out_of_scope_target_from_assist(
    ctx: ToolContext, finding: Finding
) -> None:
    ctx.config["provider"] = _FakeProvider(
        reply=f'["https://{OUTSIDE_HOST}/admin", "https://{OUTSIDE_HOST}/api"]'
    )

    outcome = expand_finding({"finding_id": finding.id, "assist": True}, ctx)

    text = outcome.result_for_model
    assert not text.startswith("BLOCKED:")
    assert OUTSIDE_HOST not in text
    assert all(
        OUTSIDE_HOST not in target for target in ctx.state["expansions"][0]["targets"]
    )


# -- registration ---------------------------------------------------------------


def test_register_expand_tools_registers_a_safe_tool() -> None:
    registry = ToolRegistry()
    register_expand_tools(registry)

    spec = registry.get("expand_finding")
    assert spec is not None
    assert spec.effective_danger == "none"
    assert spec.parameters["required"] == []
    assert {"finding_id", "endpoint", "assist", "limit"} <= set(spec.parameters["properties"])


def test_expand_tool_is_wired_into_build_registry() -> None:
    """The loader loop in build_registry must keep registering this surface."""
    from hunter.agent.tools import build_registry

    registry = build_registry()
    assert registry.get("expand_finding") is not None


def test_expand_finding_dispatch_blocks_out_of_scope_via_registry(ctx: ToolContext) -> None:
    from hunter.agent.tools import build_registry

    registry = build_registry()
    outcome = registry.dispatch("expand_finding", {"endpoint": f"https://{OUTSIDE_HOST}/x"}, ctx)

    # No target is derived or recorded; the message only echoes the caller's
    # own input back at it, never a resolvable out-of-scope target.
    assert outcome.result_for_model.startswith("no in-scope follow-up targets")
    assert ctx.state.get("expansions") is None


def test_localhost_scope_still_expands_loopback() -> None:
    """Demo surface: loopback is implicitly in scope, so expansion works there."""
    demo = _ctx(localhost_scope(), target_url="http://127.0.0.1:8000/")
    try:
        targets = derive_targets(demo, "/api/v1/items?page=1")
    finally:
        demo.ledger.close()
    assert targets
    assert all(t.startswith("http://127.0.0.1:8000/") for t in targets)
