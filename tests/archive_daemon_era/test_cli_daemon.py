"""M8 F2 — the ``hunter daemon`` / ``hunt <verb>`` CLI surface (test-first).

Typer CliRunner against the real app; daemon internals are seamed via
``hunter.daemon.*`` (and ``hunter.cli.daemon.*`` once importable) so no
process is ever spawned, polled, or killed. The status/logs tests run the
real read-only code paths against tmp state.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from hunter.cli.main import app

runner = CliRunner()

STATUS_JSON_KEYS = (
    "running",
    "pid",
    "uptime_seconds",
    "heartbeat_age_seconds",
    "stale",
    "queue_pending",
    "queue_claimed",
    "transports",
    "last_run",
)


@pytest.fixture(autouse=True)
def _cli_hygiene(monkeypatch, tmp_path):
    """No real HOME/config/state; the background update check can never fire."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    from hunter.cli import update_core

    update_core.reset()
    yield
    update_core.reset()


def _patch_daemon_fn(monkeypatch, name: str, fn: Any) -> None:
    """Seam a daemon function at both import sites (source + cli module)."""
    monkeypatch.setattr(f"hunter.daemon.{name}", fn)
    try:
        import hunter.cli.daemon as cli_daemon
    except ImportError:
        return
    if hasattr(cli_daemon, name):
        monkeypatch.setattr(cli_daemon, name, fn)


def _fake_status() -> dict[str, Any]:
    return {
        "running": False,
        "pid": None,
        "uptime_seconds": None,
        "heartbeat_age_seconds": None,
        "stale": False,
        "queue_pending": 0,
        "queue_claimed": 0,
        "transports": [],
        "last_run": None,
    }


def test_daemon_start_target_is_optional_but_scope_gate_remains(monkeypatch, tmp_path):
    """M11 M7 (§14 item 5): non-localhost start without --scope AUTO-authorizes
    the minimal scope, exits 0, and records `agent.approved_scopes`;
    `agent.scope_confirm: true` restores today's refuse-with-exit-3."""
    captured: dict[str, Any] = {}

    def fake_start(state_dir, **kwargs):
        captured["state_dir"] = str(state_dir)
        captured.update(kwargs)
        return 0

    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)
    monkeypatch.setattr("hunter.cli.daemon._resolve_engine", lambda explicit: ("deterministic", 0))
    result = runner.invoke(app, ["daemon", "start", "--state", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["target"] is None
    assert captured["max_wall_seconds"] == 0.0
    assert captured["max_cost_usd"] == 0.0

    # non-localhost without --scope: auto-authorized minimal scope + audit trail
    config_path = tmp_path / "config.yaml"
    config_path.write_text("agent:\n  tier: basic\n", encoding="utf-8")
    monkeypatch.setenv("HUNTEROS_CONFIG", str(config_path))
    result = runner.invoke(
        app,
        ["daemon", "start", "--state", str(tmp_path), "--target", "https://example.com"],
    )
    assert result.exit_code == 0, result.output
    scope = captured.get("scope")
    assert scope is not None and scope.allowed_hosts == frozenset({"example.com"})
    import yaml

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    scopes = raw["agent"]["approved_scopes"]
    assert scopes[0]["host"] == "example.com"
    assert scopes[0]["source"] == "hunt-start"

    # The opt-back-in switch restores the refusal, verbatim.
    config_path.write_text("agent:\n  scope_confirm: true\n", encoding="utf-8")
    refused = runner.invoke(
        app,
        ["daemon", "start", "--state", str(tmp_path), "--target", "https://example.com"],
    )
    assert refused.exit_code == 3, refused.output
    assert "BLOCKED" in refused.output


def test_hunt_verbs_delegate_to_daemon(monkeypatch, tmp_path):
    calls: list[tuple[str, str]] = []

    def fake_stop(state_dir, **_kwargs):
        calls.append(("stop", str(state_dir)))
        return 0

    def fake_status(state_dir):
        calls.append(("status", str(state_dir)))
        return _fake_status()

    def forbidden_normalize(_raw):
        raise AssertionError("daemon verbs must never reach normalize_hunt_target")

    _patch_daemon_fn(monkeypatch, "stop_daemon", fake_stop)
    _patch_daemon_fn(monkeypatch, "daemon_status", fake_status)
    monkeypatch.setattr("hunter.hunt.normalize_hunt_target", forbidden_normalize)

    result = runner.invoke(app, ["hunt", "stop", "--state", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert ("stop", str(tmp_path)) in calls

    result = runner.invoke(app, ["hunt", "status", "--state", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert any(kind == "status" for kind, _state in calls)

    # `hunt logs` tails the same daemon.log (real read-only path)
    log = tmp_path / "daemon" / "daemon.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("\n".join(f"line-{i}" for i in range(6)) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["hunt", "logs", "--lines", "2", "--state", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "line-5" in result.output and "line-0" not in result.output


def test_hunt_start_parses_time_and_min_time(monkeypatch, tmp_path):
    captured: dict[str, Any] = {}

    def fake_start(state_dir, **kwargs):
        captured["state_dir"] = str(state_dir)
        captured.update(kwargs)
        return 0

    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)
    result = runner.invoke(
        app,
        [
            "hunt", "start",
            "--target", "http://127.0.0.1:9/",
            "--time", "2h",
            "--min-time", "1h30m",
            "--yes",
            "--state", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["max_wall_seconds"] == pytest.approx(7200.0)
    assert captured["min_wall_seconds"] == pytest.approx(5400.0)
    assert captured["target"] == "http://127.0.0.1:9/"


def test_top_level_start_stop_status_aliases(monkeypatch, tmp_path):
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("start", "stop", "status"):
        assert name in result.output

    calls: list[str] = []

    def fake_status(state_dir):
        calls.append(str(state_dir))
        return _fake_status()

    _patch_daemon_fn(monkeypatch, "daemon_status", fake_status)
    result = runner.invoke(app, ["status", "--state", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert calls == [str(tmp_path)]


def test_status_json_contract(monkeypatch, tmp_path):
    # the real read-only status path against an empty tmp state
    result = runner.invoke(app, ["daemon", "status", "--state", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.index("{"):])
    for key in STATUS_JSON_KEYS:
        assert key in payload
    assert payload["running"] is False
    assert payload["pid"] is None
    assert payload["stale"] is False
    assert payload["queue_pending"] == 0 and payload["queue_claimed"] == 0
    assert payload["transports"] == []
    assert payload["last_run"] is None


def test_daemon_logs_tails_log_file(monkeypatch, tmp_path):
    log = tmp_path / "daemon" / "daemon.log"
    log.parent.mkdir(parents=True)
    log.write_text("\n".join(f"line-{i:02d}" for i in range(10)) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["daemon", "logs", "--state", str(tmp_path), "--lines", "5"])
    assert result.exit_code == 0, result.output
    for i in range(5, 10):
        assert f"line-{i:02d}" in result.output
    for i in range(0, 5):
        assert f"line-{i:02d}" not in result.output
