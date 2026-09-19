"""M8 F1 — ``shell_exec`` agent tool (test-first).

Real subprocesses of the venv python ONLY (never a shell): commands are built
as ``"<python.exe>" -c "<code>"`` with forward-slash quoting so
``shlex.split`` stays correct on Windows paths containing spaces. Everything
else (denylist, cwd jail, env minimization, output caps/redaction, timeout,
ledger events) is asserted against the pinned F1 contract.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from hunter.agent.approval import ApprovalStore, make_approval_gate
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

PY = sys.executable.replace("\\", "/")


def py_command(code: str) -> str:
    return f'"{PY}" -c "{code}"'


class ShellEnv:
    def __init__(self, tmp_path, *, auto_allow: bool = True) -> None:
        self.run_id = "R-SHELL"
        self.ledger = Ledger(tmp_path / "ledger.db")
        self.ledger.create_run(self.run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
        self.scope = localhost_scope()
        self.http = ScopedHttpClient(self.scope, min_interval=0)
        self.events: list[tuple[str, dict[str, Any]]] = []

        def emit(kind: str, payload: dict[str, Any]) -> None:
            self.events.append((kind, dict(payload)))
            self.ledger.append(self.run_id, kind, dict(payload))

        config: dict[str, Any] = {"tier": "advanced", "state_dir": str(tmp_path)}
        self.store = ApprovalStore(tmp_path / "approvals")
        if auto_allow:
            config["approval_gate"] = make_approval_gate(
                self.store,
                ledger=self.ledger,
                run_id=self.run_id,
                auto_allow=True,
                confirm_fn=lambda _request: True,
                surface="repl",
            )
        self.ctx = ToolContext(
            run_id=self.run_id,
            ledger=self.ledger,
            http=self.http,
            scope=self.scope,
            target_url="http://127.0.0.1/",
            emit=emit,
            config=config,
        )

    def shell_events(self) -> list[dict[str, Any]]:
        return [payload for _kind, payload in self.events if payload.get("tool") == "shell_exec"]

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


def test_shell_exec_gated_advanced_and_approval_danger(tmp_path):
    advanced = build_registry("advanced")
    spec = advanced.get("shell_exec")
    assert spec is not None
    assert spec.min_tier == "advanced"
    assert spec.danger == "approval"
    basic_names = {entry["function"]["name"] for entry in build_registry("basic").schemas_for_tier("basic")}
    assert "shell_exec" not in basic_names  # structurally absent below advanced
    parameters = spec.parameters
    assert parameters["additionalProperties"] is False
    assert parameters["required"] == ["command"]
    assert parameters["properties"]["command"] == {"type": "string", "minLength": 1, "maxLength": 4000}
    assert parameters["properties"]["timeout_seconds"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 600,
    }
    assert parameters["properties"]["cwd"] == {"type": "string"}

    # direct dispatch below the tier is refused before any gate/handler work
    ledger = Ledger(tmp_path / "basic.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)
    try:
        basic_ctx = ToolContext(
            run_id="R-SHELL-BASIC",
            ledger=ledger,
            http=http,
            scope=scope,
            target_url="http://127.0.0.1/",
            emit=lambda kind, payload: None,
            config={"tier": "basic", "state_dir": str(tmp_path)},
        )
        outcome = build_registry("basic").dispatch("shell_exec", {"command": "echo hi"}, basic_ctx)
        assert outcome.ok is False and outcome.blocked is True
        assert outcome.code == "tier.capability_locked"
    finally:
        http.close()
        ledger.close()


def test_shell_exec_executes_and_caps_output_16k(env):
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": py_command("print('A' * 20000)")}, env.ctx
    )
    assert outcome.ok is True, outcome.result_for_model
    assert "[stdout]" in outcome.result_for_model
    assert "...[output truncated at 16384 chars]" in outcome.result_for_model
    assert len(outcome.result_for_model) <= 16384 + 1200  # bounded model text


def test_shell_exec_redacts_secrets_in_output(env):
    outcome = build_registry("advanced").dispatch(
        "shell_exec",
        {"command": py_command("print('authorization: Bearer supersecrettoken99')")},
        env.ctx,
    )
    assert outcome.ok is True, outcome.result_for_model
    assert "supersecrettoken99" not in outcome.result_for_model
    assert "[REDACTED]" in outcome.result_for_model


def test_shell_exec_timeout_enforced_default_120_max_600(env):
    registry = build_registry("advanced")
    outcome = registry.dispatch(
        "shell_exec",
        {"command": py_command("import time; time.sleep(5)"), "timeout_seconds": 1},
        env.ctx,
    )
    assert outcome.ok is False
    assert "[timed out after 1s]" in outcome.result_for_model
    for bad in (0, 601):
        blocked = registry.dispatch(
            "shell_exec",
            {"command": py_command("print('unused')"), "timeout_seconds": bad},
            env.ctx,
        )
        assert blocked.ok is False and blocked.blocked is True
        assert blocked.code == "shell.timeout_bounds"


def test_shell_exec_cwd_defaults_to_state_dir_and_refuses_escape(env):
    registry = build_registry("advanced")
    state_dir = str(env.ctx.config["state_dir"])
    outcome = registry.dispatch(
        "shell_exec", {"command": py_command("import os; print(os.getcwd())")}, env.ctx
    )
    assert outcome.ok is True, outcome.result_for_model
    # default cwd IS the state dir (its unique tmp basename shows in getcwd)
    basename = state_dir.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    assert basename in outcome.result_for_model
    for bad_cwd in ("..", f"{state_dir}/..", f"{state_dir}/../elsewhere"):
        blocked = registry.dispatch(
            "shell_exec", {"command": py_command("print('unused')"), "cwd": bad_cwd}, env.ctx
        )
        assert blocked.ok is False and blocked.blocked is True, bad_cwd
        assert blocked.code == "shell.cwd_outside_state", bad_cwd


def test_shell_exec_denylist_refused_even_in_hunter_mode(env, monkeypatch):
    import subprocess as subprocess_module

    def _no_subprocess(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a pending catastrophic command must not reach a subprocess")

    monkeypatch.setattr(subprocess_module, "run", _no_subprocess)
    registry = build_registry("advanced")
    for index, command in enumerate(("format C:", "rm -rf /"), start=1):
        outcome = registry.dispatch("shell_exec", {"command": command}, env.ctx)
        assert outcome.ok is False and outcome.blocked is True
        assert outcome.code == "approval.catastrophic"
        assert "/approve" in outcome.result_for_model
        assert len(list(env.store.root.glob("*.json"))) == index


def test_shell_exec_denylist_quoting_and_escapes_refused(env):
    registry = build_registry("advanced")
    variants = [
        '"for""mat" c:',  # quote-sandwiched token — normalization removes quotes
        'r"m" -rf /',  # split token reassembles after quote removal
        "^format c:",  # caret-escape prefix
        "c:\\windows\\system32\\format.com c:",  # backslash path still matches
    ]
    for command in variants:
        outcome = registry.dispatch("shell_exec", {"command": command}, env.ctx)
        assert outcome.ok is False and outcome.blocked is True, command
        assert outcome.code == "approval.catastrophic", command
        assert "/approve" in outcome.result_for_model, command


def test_shell_exec_env_is_minimal_no_canary_leak(env, monkeypatch):
    monkeypatch.setenv("HUNTER_CANARY", "canary-value-xyz")
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": py_command("import os; print(os.environ)")}, env.ctx
    )
    assert outcome.ok is True, outcome.result_for_model
    assert "HUNTER_CANARY" not in outcome.result_for_model
    assert "canary-value-xyz" not in outcome.result_for_model
    assert "HUNTER_SANDBOX" in outcome.result_for_model


def test_shell_exec_ledger_event_per_run(env):
    registry = build_registry("advanced")
    allowed = registry.dispatch(
        "shell_exec", {"command": py_command("print('benign')")}, env.ctx
    )
    assert allowed.ok is True, allowed.result_for_model
    denied = registry.dispatch(
        "shell_exec", {"command": py_command("print('unused')"), "cwd": ".."}, env.ctx
    )
    assert denied.ok is False and denied.code == "shell.cwd_outside_state"
    events = env.shell_events()
    assert len(events) == 2  # one ledger engine_event per run, allowed or denied
    for payload in events:
        assert payload.get("tool") == "shell_exec"
        assert "exit_code" in payload
        assert "timed_out" in payload
        assert "duration_ms" in payload
        assert "cwd" in payload
        assert "approval_id" in payload
        assert "command" in payload  # redacted command echo, bounded
    assert events[0]["exit_code"] == 0
    assert events[1]["exit_code"] is None
