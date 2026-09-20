"""M9-B CLI engine grammar tests.

CliRunner exercises the command boundary only. Daemon start/status seams are
patched so a test can never spawn, poll, or kill a process.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from hunter.cli.main import app

runner = CliRunner()


def _patch(monkeypatch, name: str, fn) -> None:
    monkeypatch.setattr(f"hunter.daemon.{name}", fn, raising=False)
    monkeypatch.setattr(f"hunter.cli.daemon.{name}", fn, raising=False)


def _status(running: bool = False) -> dict[str, Any]:
    return {
        "running": running,
        "pid": 4321 if running else None,
        "uptime_seconds": 1.0 if running else None,
        "heartbeat_age_seconds": 0.1 if running else None,
        "stale": False,
        "queue_pending": 0,
        "queue_claimed": 0,
        "transports": [],
        "last_run": None,
    }


@pytest.fixture(autouse=True)
def cli_hygiene(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    from hunter.cli import update_core

    update_core.reset()
    yield
    update_core.reset()


def test_hunt_start_without_target_boots_engine_exactly(monkeypatch, tmp_path):
    captured: dict[str, Any] = {}

    def fake_start(state_dir, **kwargs):
        captured["state_dir"] = Path(state_dir)
        captured.update(kwargs)
        return 0

    _patch(monkeypatch, "start_daemon", fake_start)
    monkeypatch.setattr("hunter.cli.daemon._resolve_engine", lambda explicit: ("deterministic", 0))
    result = runner.invoke(app, ["hunt", "start", "--state", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("engine started")
    assert "tip:" in result.stdout.lower() and "hunt start" in result.stdout
    assert captured == {
        "state_dir": tmp_path,
        "target": None,
        "scope": None,
        "engine": "deterministic",
        "min_wall_seconds": 0.0,
        "max_wall_seconds": 0.0,
        "max_cost_usd": 0.0,
        "force": False,
    }


def test_hunt_start_optional_target_enqueues_time_and_budget(monkeypatch, tmp_path):
    captured: dict[str, Any] = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    _patch(monkeypatch, "start_daemon", fake_start)
    monkeypatch.setattr("hunter.cli.daemon._resolve_engine", lambda explicit: ("deterministic", 0))
    result = runner.invoke(
        app,
        [
            "hunt",
            "start",
            "--target",
            "http://127.0.0.1:8941/",
            "--time",
            "90s",
            "--budget",
            "0",
            "--state",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["target"] == "http://127.0.0.1:8941/"
    assert captured["max_wall_seconds"] == pytest.approx(90.0)
    assert captured["max_cost_usd"] == 0.0
    assert "engine started" in result.stdout


@pytest.mark.parametrize("budget", ["-1", "nan", "inf", "garbage"])
def test_hunt_start_rejects_invalid_budget_without_queue(monkeypatch, tmp_path, budget):
    calls: list[Any] = []
    _patch(monkeypatch, "start_daemon", lambda *args, **kwargs: calls.append((args, kwargs)) or 0)
    result = runner.invoke(
        app,
        [
            "hunt",
            "start",
            "--target",
            "http://127.0.0.1:8941/",
            "--time",
            "1m",
            "--budget",
            budget,
            "--state",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 8
    assert "config" in result.output.lower() or "budget" in result.output.lower()
    assert calls == []


def test_hunt_start_when_running_is_idempotent(monkeypatch, tmp_path):
    starts: list[Any] = []
    _patch(monkeypatch, "daemon_running", lambda state: (True, "running"))
    _patch(monkeypatch, "start_daemon", lambda *a, **k: starts.append((a, k)) or 3)
    result = runner.invoke(app, ["hunt", "start", "--state", str(tmp_path)])

    assert result.exit_code == 0
    assert result.stdout.strip() == "engine already on — 24/7 engine is on"
    assert starts == []


def test_hunt_start_off_localhost_auto_authorizes_exit_zero(monkeypatch, tmp_path):
    """Off-localhost `hunt start` auto-authorizes the minimal scope (recorded
    under agent.approved_scopes) — exit 0. Only agent.scope_confirm=true
    restores the old refuse-without---yes behavior (exit 3)."""
    captured: dict[str, Any] = {}
    _patch(monkeypatch, "start_daemon", lambda state_dir, **kwargs: captured.update(kwargs) or 0)
    result = runner.invoke(
        app,
        [
            "hunt",
            "start",
            "--target",
            "https://evil.example",
            "--state",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["scope"] is not None
    assert captured["scope"].summary()["hosts"] == ["evil.example"]


def test_hunt_start_scope_confirm_true_restores_exit_three(monkeypatch, tmp_path):
    calls: list[Any] = []
    _patch(monkeypatch, "start_daemon", lambda *a, **k: calls.append((a, k)) or 0)
    (tmp_path / "config.yaml").write_text("agent:\n  scope_confirm: true\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "hunt",
            "start",
            "--target",
            "https://evil.example",
            "--state",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 3
    assert "localhost" in result.output
    assert calls == []


def test_hunt_command_help_exposes_optional_start_target_and_queue_options():
    result = runner.invoke(app, ["hunt", "--help"])

    assert result.exit_code == 0, result.output
    # Renderer-proof: strip ANSI and collapse all whitespace so wrapped
    # option names ('--\ntarget' on narrow terminals / newer rich) still match.
    clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    compact = re.sub(r"\s+", "", clean)
    for option in ("--target", "--time", "--budget", "--min-time", "--state"):
        assert option in compact, result.output


def test_hunt_start_help_mentions_target_free_engine():
    result = runner.invoke(app, ["hunt", "start", "--help"])

    assert result.exit_code == 0, result.output
    assert "target" in result.output.lower()
    assert "24/7" in result.output or "engine" in result.output.lower()


def test_hunt_aliases_start_and_status_are_available(monkeypatch, tmp_path):
    calls: list[str] = []

    def fake_status(state):
        calls.append(str(state))
        return _status()

    _patch(monkeypatch, "daemon_status", fake_status)
    start = runner.invoke(app, ["start", "--state", str(tmp_path)])
    status = runner.invoke(app, ["status", "--state", str(tmp_path)])

    assert start.exit_code in {0, 3}
    assert status.exit_code == 0, status.output
    assert calls == [str(tmp_path)]


def test_hunt_status_json_remains_unstyled(monkeypatch, tmp_path):
    _patch(monkeypatch, "daemon_status", lambda state: _status())
    result = runner.invoke(app, ["hunt", "status", "--state", str(tmp_path), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["running"] is False
    assert "\x1b[" not in result.stdout
