"""M9-A approval-gate red tests.

These tests exercise the shell-specific class matrix while retaining the M8
file-backed approval, fingerprint, and single-use behavior. No subprocess is
allowed to run except a patched sentinel on the explicitly approved retry.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from hunter.agent.approval import ApprovalStore, make_approval_gate
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

REQUEST_ID_RE = re.compile(r"A-[0-9a-f]{8}")


class ShellEnv:
    def __init__(self, tmp_path: Path, *, auto_allow: bool = False) -> None:
        self.run_id = "R-M9-APPROVAL"
        self.ledger = Ledger(tmp_path / "ledger.db")
        self.ledger.create_run(self.run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
        self.http = ScopedHttpClient(localhost_scope(), min_interval=0)
        self.store = ApprovalStore(tmp_path / "approvals")
        self.ctx = ToolContext(
            run_id=self.run_id,
            ledger=self.ledger,
            http=self.http,
            scope=localhost_scope(),
            target_url="http://127.0.0.1/",
            emit=lambda kind, payload: self.ledger.append(self.run_id, kind, dict(payload)),
            config={"tier": "advanced", "state_dir": str(tmp_path)},
        )
        self.ctx.config["approval_gate"] = make_approval_gate(
            self.store,
            ledger=self.ledger,
            run_id=self.run_id,
            auto_allow=auto_allow,
            surface="repl",
        )

    def events(self) -> list[dict[str, Any]]:
        return [row.payload for row in self.ledger.events(self.run_id)]

    def close(self) -> None:
        self.http.close()
        self.ledger.close()


@pytest.fixture()
def env(tmp_path):
    opened = ShellEnv(tmp_path)
    try:
        yield opened
    finally:
        opened.close()


def _request_id(text: str) -> str:
    match = REQUEST_ID_RE.search(text)
    assert match is not None, text
    return match.group(0)


def test_hunter_auto_allow_is_readonly_only(env, monkeypatch):
    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *args, **kwargs: _completed())
    env.ctx.config["approval_gate"] = make_approval_gate(
        env.store, ledger=env.ledger, run_id=env.run_id, auto_allow=True, surface="repl"
    )
    registry = build_registry("advanced")

    readonly = registry.dispatch("shell_exec", {"command": "pwd"}, env.ctx)
    mutating = registry.dispatch("shell_exec", {"command": "touch marker"}, env.ctx)
    catastrophic = registry.dispatch("shell_exec", {"command": "rm -rf /"}, env.ctx)

    assert readonly.ok is True
    assert mutating.code == "approval.required"
    assert catastrophic.code == "approval.catastrophic"
    assert len(list(env.store.root.glob("*.json"))) == 2
    assert any(event.get("approval") == "auto_allowed" for event in env.events())


def test_mutating_command_requires_approval_in_hunter_mode(env, monkeypatch):
    calls: list[tuple[Any, ...]] = []

    def sentinel(*args, **kwargs):
        calls.append(args)
        raise AssertionError("mutating shell command reached subprocess before approval")

    monkeypatch.setattr("hunter.agent.tools.subprocess.run", sentinel)
    env.ctx.config["approval_gate"] = make_approval_gate(
        env.store, ledger=env.ledger, run_id=env.run_id, auto_allow=True, surface="repl"
    )
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": "touch marker"}, env.ctx
    )

    assert outcome.ok is False and outcome.blocked is True
    assert outcome.code == "approval.required"
    assert "/approve" in outcome.result_for_model
    assert calls == []


def test_catastrophic_returns_special_code_and_ledger_marker(env, monkeypatch):
    def sentinel(*args, **kwargs):
        raise AssertionError("catastrophic command reached subprocess while pending")

    monkeypatch.setattr("hunter.agent.tools.subprocess.run", sentinel)
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": "rm -rf /"}, env.ctx
    )

    assert outcome.ok is False and outcome.blocked is True
    assert outcome.code == "approval.catastrophic"
    request_id = _request_id(outcome.result_for_model)
    assert "/approve" in outcome.result_for_model
    assert len(list(env.store.root.glob("*.json"))) == 1
    events = env.events()
    marker = next(event for event in events if event.get("approval", "").startswith("catastrophic:"))
    assert set(marker) == {"tool", "command_class", "approval", "fingerprint", "reason"}
    assert marker["tool"] == "shell_exec"
    assert marker["command_class"] == "catastrophic"
    assert marker["approval"] == f"catastrophic:{request_id}"
    assert marker["reason"] == "recursive force delete"


def test_catastrophic_approval_is_explicit_and_single_use(env, monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return _completed()

    monkeypatch.setattr("hunter.agent.tools.subprocess.run", fake_run)
    registry = build_registry("advanced")
    args = {"command": "rm -rf /"}
    first = registry.dispatch("shell_exec", args, env.ctx)
    request_id = _request_id(first.result_for_model)
    assert first.code == "approval.catastrophic"
    assert env.store.decide(request_id, "approved") is not None

    second = registry.dispatch("shell_exec", args, env.ctx)
    assert second.ok is True
    assert len(calls) == 1
    assert env.store.get(request_id).used_ts is not None

    third = registry.dispatch("shell_exec", args, env.ctx)
    assert third.code == "approval.catastrophic"
    assert _request_id(third.result_for_model) != request_id
    assert len(calls) == 1


def test_catastrophic_never_calls_confirm_or_auto_allow(env, monkeypatch):
    confirmations: list[str] = []

    def confirm(request):
        confirmations.append(request.request_id)
        return True

    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *a, **k: _completed())
    env.ctx.config["approval_gate"] = make_approval_gate(
        env.store,
        ledger=env.ledger,
        run_id=env.run_id,
        auto_allow=True,
        confirm_fn=confirm,
        surface="repl",
    )
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": "format C:"}, env.ctx
    )

    assert outcome.code == "approval.catastrophic"
    assert confirmations == []
    assert len(list(env.store.root.glob("*.json"))) == 1


def test_approval_gate_without_gate_fails_closed_for_shell():
    from hunter.agent.tools_base import ToolContext

    ledger = Ledger(":memory:")
    http = ScopedHttpClient(localhost_scope(), min_interval=0)
    try:
        ctx = ToolContext(
            run_id="R-NO-GATE",
            ledger=ledger,
            http=http,
            scope=localhost_scope(),
            target_url="http://127.0.0.1/",
            emit=lambda *_args: None,
            config={"tier": "advanced"},
        )
        outcome = build_registry("advanced").dispatch("shell_exec", {"command": "pwd"}, ctx)
    finally:
        http.close()
        ledger.close()
    assert outcome.code == "approval.unavailable"
    assert outcome.blocked is True


def test_shell_approval_events_include_class_and_fingerprint(env, monkeypatch):
    monkeypatch.setattr("hunter.agent.tools.subprocess.run", lambda *a, **k: _completed())
    env.ctx.config["approval_gate"] = make_approval_gate(
        env.store, ledger=env.ledger, run_id=env.run_id, auto_allow=True, surface="repl"
    )
    registry = build_registry("advanced")
    readonly = registry.dispatch("shell_exec", {"command": "echo ok"}, env.ctx)
    pending = registry.dispatch("shell_exec", {"command": "touch marker"}, env.ctx)
    assert readonly.ok is True and pending.code == "approval.required"
    gate_events = [event for event in env.events() if event.get("tool") == "shell_exec"]
    assert any(event.get("command_class") == "readonly" for event in gate_events)
    requested = next(event for event in gate_events if event.get("approval", "").startswith("requested:"))
    assert requested["command_class"] == "mutating"
    assert re.fullmatch(r"[0-9a-f]{64}", requested["fingerprint"])


def test_shell_spec_no_longer_hard_denies_catastrophic_commands(env):
    spec = build_registry("advanced").get("shell_exec")
    assert spec is not None
    assert spec.danger == "approval"
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": "format C:"}, env.ctx
    )
    assert outcome.code == "approval.catastrophic"
    assert "never run" not in outcome.result_for_model.lower()


def _completed() -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n", stderr="")
