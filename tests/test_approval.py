"""M8 approval-store and generic approval-gate contract (test-first).

All offline: tmp_path store, real Ledger, and a test-only
``danger="approval"`` tool so no subprocess ever runs. M9 shell-specific
classification, readonly hunter-mode auto-allow, and catastrophic explicit
approval are covered in ``test_approval_m9.py`` and ``test_shell_tool.py``.
The generic gate below remains fail-closed, fingerprinted, TTL-bound, and
single-use.
"""


from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from hunter.agent.approval import (
    APPROVAL_TTL_SECONDS,
    ApprovalStore,
    effective_status,
    make_approval_gate,
)
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext, ToolOutcome, ToolSpec
from hunter.kernel.events import canonical_json, sha256_hex
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ClassifiedError, ToolCall
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

REQUEST_ID_RE = re.compile(r"A-[0-9a-f]{8}")
PINNED_FILE_KEYS = {
    "request_id",
    "tool",
    "fingerprint",
    "summary",
    "args",
    "status",
    "surface",
    "created_ts",
    "expires_ts",
    "decided_ts",
    "used_ts",
}


class _Env:
    """One run's ToolContext + Ledger + captured emit events."""

    def __init__(
        self, tmp_path: Path, *, tier: str = "advanced", config: dict[str, Any] | None = None
    ) -> None:
        self.run_id = "R-APPROVAL"
        self.ledger = Ledger(tmp_path / "ledger.db")
        self.ledger.create_run(self.run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
        self.scope = localhost_scope()
        self.http = ScopedHttpClient(self.scope, min_interval=0)
        self.events: list[tuple[str, dict[str, Any]]] = []

        def emit(kind: str, payload: dict[str, Any]) -> None:
            self.events.append((kind, dict(payload)))
            self.ledger.append(self.run_id, kind, dict(payload))

        self.ctx = ToolContext(
            run_id=self.run_id,
            ledger=self.ledger,
            http=self.http,
            scope=self.scope,
            target_url="http://127.0.0.1/",
            emit=emit,
            config={"tier": tier, **(config or {})},
        )
        self.store = ApprovalStore(Path(tmp_path) / "approvals")

    def ledger_events(self) -> list[dict[str, Any]]:
        return [event.payload for event in self.ledger.events(self.run_id)]

    def close(self) -> None:
        self.http.close()
        self.ledger.close()


@pytest.fixture()
def env(tmp_path):
    opened = _Env(tmp_path)
    try:
        yield opened
    finally:
        opened.close()


def _gated_registry(ran: list[dict[str, Any]]):
    """The real registry plus one test-only approval-danger tool."""
    registry = build_registry("advanced")

    def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
        ran.append(dict(args))
        return ToolOutcome(result_for_model="gated tool ran")

    registry.register(
        ToolSpec(
            name="gated_probe",
            description="test-only approval-gated tool (no side effects)",
            parameters={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            handler=handler,
            min_tier="advanced",
            danger="approval",
        )
    )
    return registry


# -- store: file format, TTL, single-use, corruption -----------------------------


def test_approval_store_roundtrip_and_file_format(tmp_path):
    store = ApprovalStore(Path(tmp_path) / "state" / "approvals")
    request = store.create("shell_exec", {"command": "nmap -sV"}, surface="telegram:12345")
    assert request.request_id.startswith("A-") and len(request.request_id) == 2 + 8
    assert request.tool == "shell_exec"
    assert request.status == "pending"
    assert request.decided_ts is None and request.used_ts is None
    assert request.surface == "telegram:12345"
    assert request.expires_ts - request.created_ts == pytest.approx(float(APPROVAL_TTL_SECONDS))
    assert APPROVAL_TTL_SECONDS == 300
    expected_fingerprint = sha256_hex(
        canonical_json({"tool": "shell_exec", "args": {"command": "nmap -sV"}})
    )
    assert request.fingerprint == expected_fingerprint
    # one-line, redacted, bounded summary
    assert len(request.summary) <= 200
    assert "\n" not in request.summary and "nmap" in request.summary

    path = Path(store.root) / f"{request.request_id}.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == PINNED_FILE_KEYS
    assert data["status"] == "pending"
    assert data["decided_ts"] is None and data["used_ts"] is None
    assert data["fingerprint"] == request.fingerprint


def test_approval_get_missing_corrupt_returns_none(tmp_path):
    store = ApprovalStore(Path(tmp_path) / "approvals")
    assert store.get("A-00000000") is None  # unknown id (forgery)
    assert store.get(None) is None
    (Path(store.root) / "A-garbage1.json").write_text("{not json", encoding="utf-8")
    assert store.get("A-garbage1") is None  # corrupt file never raises


def test_approval_decide_approve_deny_and_double_decide_refused(tmp_path):
    store = ApprovalStore(Path(tmp_path) / "approvals")
    first = store.create("shell_exec", {"command": "id"})
    second = store.create("shell_exec", {"command": "whoami"})
    approved = store.decide(first.request_id, "approved")
    assert approved is not None and approved.status == "approved" and approved.decided_ts is not None
    denied = store.decide(second.request_id, "denied")
    assert denied is not None and denied.status == "denied"
    # already decided -> None; unknown id -> None
    assert store.decide(first.request_id, "denied") is None
    assert store.decide("A-00000000", "approved") is None


def test_approval_ttl_expiry_refuses_decide(tmp_path):
    store = ApprovalStore(Path(tmp_path) / "approvals")
    request = store.create("shell_exec", {"command": "nmap -sV"}, ttl_seconds=0)
    assert effective_status(request) == "expired"
    assert effective_status(request, now=request.expires_ts + 1) == "expired"
    assert effective_status(request, now=request.created_ts - 1) == "pending"
    # expiry is COMPUTED, never stored: the file still says pending
    data = json.loads((Path(store.root) / f"{request.request_id}.json").read_text(encoding="utf-8"))
    assert data["status"] == "pending"
    assert store.decide(request.request_id, "approved") is None


# -- the dispatch gate ------------------------------------------------------------


def test_gate_without_gate_config_fails_closed(env):
    ran: list[dict[str, Any]] = []
    registry = _gated_registry(ran)
    outcome = registry.dispatch("gated_probe", {}, env.ctx)
    assert outcome.ok is False and outcome.blocked is True
    assert outcome.code == "approval.unavailable"
    assert "requires an approval gate" in outcome.result_for_model
    assert ran == []  # handler never ran


def test_gate_creates_pending_request_and_blocks_with_id(env):
    ran: list[dict[str, Any]] = []
    registry = _gated_registry(ran)
    gate = make_approval_gate(env.store, ledger=env.ledger, run_id=env.run_id, surface="repl")
    env.ctx.config["approval_gate"] = gate
    outcome = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    assert outcome.ok is False and outcome.blocked is True
    assert outcome.code == "approval.required"
    match = REQUEST_ID_RE.search(outcome.result_for_model)
    assert match is not None  # the blocked text carries the request id
    request_id = match.group(0)
    assert "/approve" in outcome.result_for_model
    assert "do not retry before approval" in outcome.result_for_model
    assert ran == []  # nothing ran while pending
    files = list(Path(env.store.root).glob("*.json"))
    assert len(files) == 1  # exactly one request file
    stored = env.store.get(request_id)
    assert stored is not None and stored.status == "pending"
    assert any(
        payload.get("approval") == f"requested:{request_id}" and payload.get("fingerprint")
        for payload in env.ledger_events()
    )


def test_gate_resume_after_approve_is_single_use(env):
    ran: list[dict[str, Any]] = []
    registry = _gated_registry(ran)
    gate = make_approval_gate(env.store, ledger=env.ledger, run_id=env.run_id, surface="repl")
    env.ctx.config["approval_gate"] = gate

    first = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    assert first.code == "approval.required"
    request_id = REQUEST_ID_RE.search(first.result_for_model).group(0)  # type: ignore[union-attr]
    assert env.store.decide(request_id, "approved") is not None

    second = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    assert second.ok is True and second.code == ""  # the gate let it through
    assert len(ran) == 1  # handler ran exactly once
    assert env.store.get(request_id).used_ts is not None  # consumed (single-use)
    assert any(
        payload.get("approval") == f"consumed:{request_id}" for payload in env.ledger_events()
    )

    third = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    assert third.code == "approval.required"  # the spent approval is not reusable
    new_id = REQUEST_ID_RE.search(third.result_for_model).group(0)  # type: ignore[union-attr]
    assert new_id != request_id  # a NEW pending request was created


def test_gate_auto_allow_emits_ledger_event_without_file(env):
    ran: list[dict[str, Any]] = []
    registry = _gated_registry(ran)
    gate = make_approval_gate(
        env.store, ledger=env.ledger, run_id=env.run_id, auto_allow=True, surface="repl"
    )
    env.ctx.config["approval_gate"] = gate
    outcome = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    assert outcome.ok is True
    assert ran == [{"selector": "#x"}]  # handler ran
    assert list(Path(env.store.root).glob("*.json")) == []  # no approval file
    events = env.ledger_events()
    assert any(
        payload.get("approval") == "auto_allowed"
        and payload.get("tool") == "gated_probe"
        and payload.get("fingerprint")
        for payload in events
    )


def test_gate_confirm_fn_denial_persists(env):
    ran: list[dict[str, Any]] = []
    registry = _gated_registry(ran)
    gate = make_approval_gate(
        env.store,
        ledger=env.ledger,
        run_id=env.run_id,
        confirm_fn=lambda request: False,
        surface="repl",
    )
    env.ctx.config["approval_gate"] = gate
    first = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    assert first.ok is False and first.blocked is True
    assert first.code == "approval.denied"
    request_id = REQUEST_ID_RE.search(first.result_for_model).group(0)  # type: ignore[union-attr]
    stored = env.store.get(request_id)
    assert stored is not None and stored.status == "denied" and stored.decided_ts is not None
    assert ran == []

    second = registry.dispatch("gated_probe", {"selector": "#x"}, env.ctx)
    # the denial is recorded, but a new dispatch still needs a NEW decision
    assert second.code == "approval.required"
    new_id = REQUEST_ID_RE.search(second.result_for_model).group(0)  # type: ignore[union-attr]
    assert new_id != request_id


def test_chat_approve_and_deny_commands_nudge_agent(tmp_path):
    from hunter.chat.repl import ChatEngine
    from hunter.chat.sessions import ChatStore
    from hunter.llm.base import TurnResult as Turn
    from hunter.llm.config import default_config

    class YieldProvider:
        name = "fake-yield"

        def __init__(self) -> None:
            self.calls: list[list[dict[str, Any]]] = []

        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            self.calls.append([dict(m) for m in messages])
            return Turn(
                text="",
                tool_calls=(ToolCall(id="1", name="respond_to_user", arguments={"message": "yield"}),),
                cost_usd=0.01,
            )

        def classify(self, _exc: BaseException) -> ClassifiedError:
            return ClassifiedError(reason="unknown")

    chat_store = ChatStore(tmp_path / "chat.db")
    provider = YieldProvider()
    config = default_config()
    # The approval-gated toolset is advanced-tier by design (F1) and the M3
    # invariant keeps the audit ctx at the CONFIGURED tier — opt in here so
    # this test exercises the approval flow, not tier.capability_locked.
    config.agent.tier = "advanced"
    engine = ChatEngine(
        store=chat_store,
        config=config,
        provider=provider,
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
        confirm_fn=lambda _prompt: True,
    )
    approval_store = ApprovalStore(Path(tmp_path) / "approvals")
    try:
        engine._audit_open(
            {
                "target": "http://127.0.0.1:8941/",
                "engine_name": "agent-chat",
                "scope": {"name": "localhost-only", "hosts": []},
            }
        )
        assert engine._audit is not None
        # a blocked dispatch leaves one pending request behind
        ran: list[dict[str, Any]] = []
        registry = _gated_registry(ran)
        gate = make_approval_gate(
            approval_store, ledger=engine._audit["ledger"], run_id=engine._audit["run_id"], surface="repl"
        )
        engine._audit["ctx"].config["approval_gate"] = gate
        blocked = registry.dispatch("gated_probe", {}, engine._audit["ctx"])
        assert blocked.code == "approval.required"
        request_id = REQUEST_ID_RE.search(blocked.result_for_model).group(0)  # type: ignore[union-attr]

        out = engine.handle_text(f"/approve {request_id}")
        assert "granted" in out.text
        assert out.data.get("approval_granted") == request_id
        # the approval nudge reached the audit agent as a user turn
        assert provider.calls and any(
            m.get("role") == "user" and f"Approval {request_id} granted" in str(m.get("content", ""))
            for m in provider.calls[-1]
        )

        other = approval_store.create("shell_exec", {"command": "whoami"}, surface="repl")
        out = engine.handle_text(f"/deny {other.request_id}")
        assert "denied" in out.text
        assert out.data.get("approval_denied") == other.request_id
        stored = approval_store.get(other.request_id)
        assert stored is not None and stored.status == "denied"
    finally:
        engine.close()
        chat_store.close()
