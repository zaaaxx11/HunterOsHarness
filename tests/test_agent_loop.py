"""AgentLoop tests — scripted FakeProvider, real Ledger, real scope gate.

The FakeProvider is deterministic: a script of TurnResults (or callables
receiving the live message history, so scripted finding requests can cite
the REAL evidence ids the loop appended to tool messages). No network, no
litellm — except the http_request test, which talks to the local
PracticeVault to exercise the full evidence path.
"""

import re
from typing import Any
from urllib.parse import urlencode

import pytest

from hunter.agent.loop import AgentLoop
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.findings import FindingStatus
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ClassifiedError, RunBudget, ToolCall, TurnResult
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
CANARY = "hun<x>ter<b>q9"


# -- FakeProvider ------------------------------------------------------------------


class FakeProvider:
    """Scripted ChatProvider: entries are TurnResults or callables
    f(messages, tools) -> TurnResult (used when the script must react to
    evidence ids the loop attached)."""

    name = "fake"

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append(
            {
                "tier": tier,
                "tools": tools,
                "messages": [dict(m) for m in messages],
                "stream_cb": stream_cb,
                "budget": budget,
            }
        )
        index = len(self.calls) - 1
        if index >= len(self.script):
            raise AssertionError(f"FakeProvider script exhausted after {len(self.script)} turns")
        step = self.script[index]
        if callable(step):
            return step(messages=messages, tools=tools)
        return step

    def classify(self, exc: BaseException) -> ClassifiedError:
        return ClassifiedError(reason="unknown")


def turn(
    *calls: ToolCall, text: str = "", cost: float = 0.01, tokens_in: int = 10, tokens_out: int = 5
) -> TurnResult:
    return TurnResult(
        text=text,
        tool_calls=tuple(calls),
        finish_reason="tool_calls" if calls else "stop",
        input_tokens=tokens_in,
        output_tokens=tokens_out,
        cost_usd=cost,
        model="fake-model",
        provider="fake",
    )


def evidence_ids_in(messages: list[dict[str, Any]], marker: str = "") -> list[str]:
    ids: list[str] = []
    for message in messages:
        if message.get("role") != "tool":
            continue
        content = str(message.get("content", ""))
        if marker and marker not in content:
            continue
        ids.extend(re.findall(r"evidence_id: (EV-\d+)", content))
    return ids


def tool_call(name: str, **args: Any) -> ToolCall:
    return ToolCall(id=f"c-{name}-{len(args)}-{abs(hash(name)) % 1000}", name=name, arguments=dict(args))


def tool_messages_of(loop: AgentLoop) -> list[dict[str, Any]]:
    return [
        m for m in loop.provider.calls[-1]["messages"]  # type: ignore[attr-defined]
        if m.get("role") == "tool"
    ]


# -- fixtures -------------------------------------------------------------------


@pytest.fixture()
def no_proxy(monkeypatch):
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


@pytest.fixture()
def vault(no_proxy):
    handle, _port = start_server()
    try:
        yield handle
    finally:
        handle.shutdown()


@pytest.fixture()
def env(vault, tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    events: list[tuple[str, dict]] = []
    http = ScopedHttpClient(scope)
    ctx = ToolContext(
        run_id="R-LOOP-0001",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url=vault.url,
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"tier": "basic"},
    )
    try:
        yield LoopEnv(ctx=ctx, ledger=ledger, events=events, vault=vault)
    finally:
        http.close()
        ledger.close()


class LoopEnv:
    def __init__(self, ctx, ledger, events, vault):
        self.ctx = ctx
        self.ledger = ledger
        self.events = events
        self.vault = vault

    def run(self, script, goal="Audit the target.", *, _provider=None, **kwargs) -> Any:
        """One loop, one run — assertions can inspect the loop's call log."""
        provider = _provider if _provider is not None else FakeProvider(script)
        loop = AgentLoop(provider, build_registry("basic"), tier="basic", **kwargs)
        result = loop.run(self.ctx, goal)
        return result, loop


# -- core mechanics -----------------------------------------------------------------


def test_system_prompt_and_goal_shape_first_provider_call(env):
    def inspect(messages, tools):
        assert messages[0]["role"] == "system"
        assert "Evidence or Nothing" in messages[0]["content"]
        assert env.ctx.target_url in messages[0]["content"]
        assert "do NOT expand scope" in messages[0]["content"]
        assert messages[1] == {"role": "user", "content": "Audit the target."}
        names = {entry["function"]["name"] for entry in tools}
        assert "create_finding_request" in names and "finish_scan" in names
        return turn(tool_call("respond_to_user", message="briefing acknowledged"))

    result, loop = env.run([inspect])
    assert loop.provider.calls[0]["tier"] == "planner"  # provider model-tier, NOT the agent tier
    assert loop.provider.calls[0]["tools"]  # schemas were offered
    assert result.stats["turns"] == 1
    assert result.yield_message == "briefing acknowledged"


def test_tool_call_stores_evidence_and_rewrites_ids(env):
    script = [
        turn(tool_call("http_request", method="GET", url=f"{env.ctx.target_url}/", purpose="baseline")),
        turn(tool_call("respond_to_user", message="baseline fetched, continuing")),
    ]
    result, loop = env.run(script)
    assert result.yield_message == "baseline fetched, continuing"
    assert result.finished is False
    rows = env.ledger.evidence(env.ctx.run_id)
    assert [row["id"] for row in rows] == ["EV-0001"]
    assert rows[0]["kind"] == "http_exchange"
    assert rows[0]["data"]["purpose"] == "baseline"
    # the loop appended the id to the tool message the model reads
    tool_messages = tool_messages_of(loop)
    assert "evidence_id: EV-0001" in tool_messages[-1]["content"]
    # the ledger got the attribution event too
    assert any(
        kind == "evidence_stored" and payload.get("tool") == "http_request" for kind, payload in env.events
    )


def test_finding_request_creates_ledger_finding(env):
    probe = turn(
        tool_call(
            "http_request",
            method="GET",
            url=f"{env.ctx.target_url}/search?{urlencode({'q': CANARY})}",
            purpose="xss canary",
        )
    )

    def request_finding(messages, tools):
        ids = evidence_ids_in(messages)
        assert ids, "loop did not append evidence ids before the finding request"
        return turn(
            tool_call(
                "create_finding_request",
                check_id="reflected-xss",
                title="Reflected XSS in search parameter",
                severity="high",
                cwe="CWE-79",
                endpoint="/search",
                method="GET",
                param="q",
                payload_used=CANARY,
                description="Canary reflected unescaped.",
                impact="Script execution in browsers.",
                severity_justification="No escaping, no CSP.",
                counterevidence="Baseline does not reflect.",
                confidence="high",
                evidence_ids=ids,
            )
        )

    finish = turn(tool_call("finish_scan"))
    result, _loop = env.run([probe, request_finding, finish])
    assert result.finished is True
    assert "findings: 1" in result.summary  # finish_scan's summary is the last tool result
    findings = env.ledger.findings(env.ctx.run_id)
    assert [f.id for f in findings] == ["F-0001"]
    assert findings[0].status is FindingStatus.CANDIDATE
    assert findings[0].evidence_ids == ("EV-0001",)
    assert findings[0].key == "reflected-xss|GET|/search|q"
    assert result.stats["evidence_stored"] == 1
    assert result.stats["tool_calls"] == 3


def test_plain_text_nudges_three_times_then_stalled(env):
    script = [turn(text="I think it might be vulnerable, let me explain...") for _ in range(4)]
    result, loop = env.run(script)
    assert result.finished is True and result.stalled is True
    assert result.summary == "stalled: no lifecycle tool called"
    nudges = [
        m["content"]
        for m in loop.provider.calls[-1]["messages"]
        if m.get("role") == "user" and "Recovery attempt" in str(m.get("content", ""))
    ]
    assert nudges == [
        "Plain text never ends an audit turn. Call exactly one tool. Recovery attempt 1/3.",
        "Plain text never ends an audit turn. Call exactly one tool. Recovery attempt 2/3.",
        "Plain text never ends an audit turn. Call exactly one tool. Recovery attempt 3/3.",
    ]
    assert result.stats["turns"] == 4


def test_lifecycle_yield_returns_control(env):
    script = [turn(tool_call("respond_to_user", message="Need credentials to test /admin."))]
    result, _loop = env.run(script)
    assert result.yield_message == "Need credentials to test /admin."
    assert result.finished is False
    assert result.stalled is False
    assert result.stats["turns"] == 1


def test_finish_scan_finishes_with_summary(env):
    env.ctx.state.setdefault("coverage", []).append(
        {"surface": "/", "risk_area": "headers", "outcome": "reported", "note": "", "evidence_ids": []}
    )
    result, _loop = env.run([turn(tool_call("finish_scan"))])
    assert result.finished is True
    assert result.stalled is False
    assert "findings: 0" in result.summary
    assert "No coverage was recorded" not in result.summary


def test_interrupt_check_fires_before_any_provider_call(env):
    result, _loop = env.run([turn()], interrupt_check=lambda: True)
    assert result.interrupted is True
    assert result.finished is False
    assert any(
        kind == "error" and payload.get("reason") == "interrupted" for kind, payload in env.events
    )


def test_interrupt_check_fires_mid_loop(env):
    counter = {"n": 0}

    def interrupt_after_four_checks() -> bool:
        counter["n"] += 1
        return counter["n"] > 4  # checks: pc1, dispatch1, pc2, dispatch2 -> stop before pc3

    script = [
        turn(tool_call("think", thought="1")),
        turn(tool_call("think", thought="2")),
        turn(tool_call("think", thought="3")),
        turn(tool_call("finish_scan")),
    ]
    result, _loop = env.run(script, interrupt_check=interrupt_after_four_checks)
    assert result.interrupted is True
    assert result.finished is False
    assert result.stats["turns"] == 2  # two full turns complete; the third never starts


def test_budget_exhaustion_stops_loop(env):
    budget = RunBudget(max_iterations=2)
    script = [turn(tool_call("think", thought=f"step {i}")) for i in range(5)]
    result, _loop = env.run(script, budget=budget)
    assert result.finished is True
    assert "budget exhausted" in result.summary
    assert "iterations 2/2" in result.summary
    assert result.stats["turns"] == 2
    assert budget.iterations_used == 2


def test_governed_budget_delegates_exhaustion_and_cost(env):
    """A concrete budget (B5's hunter.llm.budget.RunBudget semantics, mimicked
    here without importing that module) governs itself: the loop trusts its
    exhausted() and NEVER touches its spend — the provider contract has the
    router call add_cost()."""
    from hunter.llm.base import RunBudget as RunBudgetContract

    class GovernedBudget(RunBudgetContract):
        def add_cost(self, usd: float) -> None:
            self.spent_usd = max(0.0, self.spent_usd + float(usd))

        def exhausted(self) -> str | None:
            if self.max_iterations > 0 and self.iterations_used >= self.max_iterations:
                return f"iteration budget exhausted: {self.iterations_used} of {self.max_iterations}"
            return None

    budget = GovernedBudget(max_iterations=2)
    script = [turn(tool_call("think", thought=str(i)), cost=0.5) for i in range(5)]
    result, _loop = env.run(script, budget=budget)
    assert result.finished is True
    assert "iteration budget exhausted" in result.summary
    assert result.stats["turns"] == 2
    assert budget.spent_usd == 0.0  # loop must not double-count provider-side accounting
    assert budget.iterations_used == 2


def test_provider_budget_exhaustion_error_ends_run_cleanly(env):
    """When a governed provider raises the budget error (router behavior), the
    loop converts it into a normal finished result, not a crashed run."""
    from hunter.errors import HunterError

    class BudgetRaisingProvider(FakeProvider):
        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            self.calls.append({"tier": tier})
            raise HunterError(
                code="budget.exhausted",
                layer="usage",
                message="iteration budget exhausted: 3 of 3",
            )

    result, _loop = env.run([], _provider=BudgetRaisingProvider([]))
    assert result.finished is True
    assert result.stalled is False
    assert "budget exhausted" in result.summary
    assert result.stats["turns"] == 0


def test_cost_and_token_accumulation_per_turn(env):
    script = [
        turn(tool_call("think", thought="a"), cost=0.25, tokens_in=100, tokens_out=50),
        turn(tool_call("think", thought="b"), cost=0.25, tokens_in=200, tokens_out=60),
        turn(tool_call("finish_scan")),
    ]
    result, _loop = env.run(script)
    assert result.stats["turns"] == 3
    assert result.stats["cost_usd"] == pytest.approx(0.51)  # 0.25 + 0.25 + 0.01 (finish turn)
    assert result.stats["tokens_in"] == 310
    assert result.stats["tokens_out"] == 115
    turn_events = [
        payload for kind, payload in env.events
        if kind == "engine_event" and payload.get("stage") == "agent_turn"
    ]
    assert len(turn_events) == 3
    assert turn_events[0]["tool_calls"] == 1 and turn_events[0]["cost_usd"] == 0.25


def test_malformed_arguments_become_format_error_tool_message(env):
    bad_call = ToolCall(id="c-bad", name="note_add", arguments="{not json")
    script = [
        turn(bad_call),
        turn(tool_call("respond_to_user", message="recovered")),
    ]
    result, loop = env.run(script)
    assert result.yield_message == "recovered"  # the loop survived and continued
    tool_messages = tool_messages_of(loop)
    assert tool_messages[0]["tool_call_id"] == "c-bad"
    assert tool_messages[0]["content"].startswith("[format_error]")
    assert "JSON" in tool_messages[0]["content"]


def test_unknown_tool_name_fed_back_verbatim(env):
    script = [
        turn(tool_call("exfiltrate_ledger")),
        turn(tool_call("respond_to_user", message="sorry, wrong tool")),
    ]
    result, loop = env.run(script)
    assert result.yield_message == "sorry, wrong tool"
    tool_messages = tool_messages_of(loop)
    assert tool_messages[0]["content"].startswith("unknown tool 'exfiltrate_ledger'")


def test_blocked_outcome_included_verbatim(env):
    """A basic-tier model attempting DELETE reads its refusal, self-corrects."""
    script = [
        turn(tool_call("http_request", method="DELETE", url=f"{env.ctx.target_url}/")),
        turn(tool_call("respond_to_user", message="understood, staying passive")),
    ]
    result, loop = env.run(script)
    assert result.yield_message == "understood, staying passive"
    tool_messages = tool_messages_of(loop)
    assert "tier.passive_only" in tool_messages[0]["content"]
    assert env.ledger.evidence(env.ctx.run_id) == []  # refused request left nothing behind


def test_provider_error_surface_loops_back_as_user_message(env):
    error_turn = TurnResult(text="", error_surface={"code": "rate_limit", "message": "slow down"})
    script = [error_turn, turn(tool_call("finish_scan"))]
    result, loop = env.run(script)
    assert result.finished is True
    last = loop.provider.calls[-1]["messages"][-1]
    assert last["role"] == "user"
    assert "provider error rate_limit" in last["content"]


def test_stream_cb_passed_through_to_provider(env):
    seen = []
    loop = AgentLoop(FakeProvider([turn(tool_call("finish_scan"))]), build_registry("basic"), tier="basic")
    loop.run(env.ctx, "Audit the target.", stream_cb=seen.append)
    assert loop.provider.calls[0]["stream_cb"] == seen.append  # bound-method equality


def test_agent_loop_rejects_unknown_tier(env):
    with pytest.raises(ValueError, match="unknown tier"):
        AgentLoop(FakeProvider([]), build_registry("basic"), tier="elite")


# -- phase machine via config (v0.3, additive) -----------------------------------------


def test_phase_machine_mounted_via_config_drives_transitions(env):
    """The pipeline mounts PhaseState in ctx.config["phase_machine"]; agent
    tool calls fold into canonical transitions; finish_scan shows the line."""
    from hunter.phases import PhaseState

    ledger, run = env.ledger, env.ctx.run_id
    ledger.create_run(run, env.ctx.target_url, "llm", "localhost-only")
    ledger.append(
        run,
        "run_started",
        {"target": env.ctx.target_url, "engine": "llm", "scope": env.ctx.scope.summary()},
    )
    machine = PhaseState(ledger, run)
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    env.ctx.config = {**env.ctx.config, "phase_machine": machine}

    script = [
        turn(tool_call("coverage_record", surface="/", risk_area="headers", outcome="reported")),
        turn(tool_call("finish_scan")),
    ]
    result, _loop = env.run(script)
    assert result.finished is True
    assert machine.current == "hunting"
    events = ledger.events(run)
    assert any(e.kind_value() == "classification_recorded" for e in events)
    assert any(
        e.kind_value() == "phase_started" and e.payload.get("phase") == "hunting" for e in events
    )
    assert "hunting" in result.summary  # finish_scan's phase line
