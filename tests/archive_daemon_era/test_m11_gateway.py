"""M11 M5 — gateway verbs, drain-first restart, top-level aliases (§9).

Spec: docs/plans/m11-ux.md §2.2 Q4, §9. Daemon internals are seamed
via the ``_patch_daemon_fn`` pattern (both ``hunter.daemon`` and
``hunter.cli.daemon`` import sites) — no process is ever spawned, polled, or
killed; the real read-only status/log paths run against tmp state. New M5
symbols (``drain_daemon``, ``_should_claim``, ``_consume_restart_marker``,
the gateway stop/restart/status/logs verbs, top-level restart/logs) are
monkeypatched or invoked through the CLI so pre-M5 runs fail on BEHAVIOR.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from typer.testing import CliRunner

from hunter.cli.main import app

runner = CliRunner()

DRAIN_TIMEOUT_NOTE = (
    "drain timed out after {n}s — stopped after cutting the in-flight run short"
)
NOT_RUNNING_LINE = "engine was not running — starting it"
GATEWAY_HINT = "💡 start the 24/7 engine instead: hunter start"
RUNNING_HINT = "💡 logs: hunter logs --follow · stop: hunter stop · restart: hunter restart"
STOPPED_HINT = "💡 start it: hunter start (foreground transports: hunter gateway start)"
MARKER_LOG_LINE = "restart: previous process (pid {pid}) drained; downtime"


def _patch_daemon_fn(monkeypatch, name: str, fn: Any) -> None:
    """Seam a daemon function at both import sites (source + cli module)."""
    monkeypatch.setattr(f"hunter.daemon.{name}", fn)
    try:
        import hunter.cli.daemon as cli_daemon
    except ImportError:
        return
    if hasattr(cli_daemon, name):
        monkeypatch.setattr(cli_daemon, name, fn)


def _fake_status(**overrides) -> dict[str, Any]:
    status = {
        "running": False,
        "pid": None,
        "uptime_seconds": None,
        "heartbeat_age_seconds": None,
        "stale": False,
        "paused": False,
        "queue_pending": 0,
        "queue_claimed": 0,
        "transports": [],
        "last_run": None,
        "config_path": "",
    }
    status.update(overrides)
    return status


@pytest.fixture(autouse=True)
def _quiet_update(monkeypatch):
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    from hunter.cli import update_core

    update_core.reset()
    yield
    update_core.reset()


# -- 1 --------------------------------------------------------------------------


def test_gateway_stop_restart_status_logs_delegate(monkeypatch, tmp_path):
    """gateway stop/restart/status/logs delegate to the daemon _cmd_* verbs and
    propagate their exit codes."""
    calls: list[str] = []

    def fake_stop(**kwargs):
        calls.append("stop")
        return 0

    def fake_restart(**kwargs):
        calls.append("restart")
        return 0

    def fake_status(**kwargs):
        calls.append("status")
        return 0

    def fake_logs(**kwargs):
        calls.append("logs")
        return 4  # a distinctive code proves propagation

    monkeypatch.setattr("hunter.cli.daemon._cmd_stop", fake_stop)
    monkeypatch.setattr("hunter.cli.daemon._cmd_restart", fake_restart)
    monkeypatch.setattr("hunter.cli.daemon._cmd_status", fake_status)
    monkeypatch.setattr("hunter.cli.daemon._cmd_logs", fake_logs)

    assert runner.invoke(app, ["gateway", "stop", "--state", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["gateway", "restart", "--state", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["gateway", "status", "--state", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["gateway", "logs", "--state", str(tmp_path)]).exit_code == 4
    assert calls == ["stop", "restart", "status", "logs"]


# -- 2 --------------------------------------------------------------------------


def test_restart_drains_running_daemon(monkeypatch, tmp_path):
    """Running daemon: the restart marker is written BEFORE the drain, the
    start comes after, and the default drain timeout 60.0 is threaded."""
    state = tmp_path / "state"
    events: list[str] = []
    seen_timeouts: list[float] = []
    marker_during_drain: list[bool] = []

    def fake_drain(state_dir, *, timeout=60.0):
        seen_timeouts.append(timeout)
        marker_during_drain.append((state_dir / "daemon" / "restart.json").exists())
        events.append("drain")
        return 0

    def fake_start(**kwargs):
        events.append("start")
        return 0

    _patch_daemon_fn(monkeypatch, "daemon_status", lambda state_dir: _fake_status(running=True, pid=4242))
    _patch_daemon_fn(monkeypatch, "drain_daemon", fake_drain)
    monkeypatch.setattr("hunter.cli.daemon._cmd_start", fake_start)

    result = runner.invoke(app, ["restart", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert events == ["drain", "start"]
    assert marker_during_drain == [True]  # the marker existed BEFORE the drain
    assert seen_timeouts == [60.0]  # the default drain timeout


# -- 3 (adversarial: drain timeout, hung daemon) ----------------------------------


def test_restart_drain_timeout_escalates_to_force_stop(monkeypatch, tmp_path):
    state = tmp_path / "state"
    force_stops: list[bool] = []

    def fake_drain(state_dir, *, timeout=60.0):
        return 1  # the daemon never exited

    def fake_stop(state_dir, *, timeout=15.0, force=False):
        force_stops.append(force)
        return 0

    def fake_start(**kwargs):
        return 0

    _patch_daemon_fn(monkeypatch, "daemon_status", lambda state_dir: _fake_status(running=True, pid=4242))
    _patch_daemon_fn(monkeypatch, "drain_daemon", fake_drain)
    _patch_daemon_fn(monkeypatch, "stop_daemon", fake_stop)
    monkeypatch.setattr("hunter.cli.daemon._cmd_start", fake_start)

    result = runner.invoke(app, ["restart", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert force_stops == [True]  # escalated with force
    assert DRAIN_TIMEOUT_NOTE.format(n="60.0") in result.output or (
        "drain timed out after" in result.output
    )


# -- 4 (Q4: restart when nothing runs) --------------------------------------------


def test_restart_when_not_running_autostarts(monkeypatch, tmp_path):
    state = tmp_path / "state"
    drains: list = []
    starts: list = []

    def forbidden_drain(state_dir, *, timeout=60.0):
        drains.append(state_dir)
        return 0

    def fake_start(**kwargs):
        starts.append(kwargs)
        return 0

    _patch_daemon_fn(monkeypatch, "daemon_status", lambda state_dir: _fake_status())
    _patch_daemon_fn(monkeypatch, "drain_daemon", forbidden_drain)
    monkeypatch.setattr("hunter.cli.daemon._cmd_start", fake_start)

    result = runner.invoke(app, ["restart", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert drains == []  # no drain attempted against a dead daemon
    assert starts, "restart must proceed straight to start"
    assert NOT_RUNNING_LINE in result.output


# -- 5 --------------------------------------------------------------------------


def test_drain_timeout_from_flag_and_env(monkeypatch, tmp_path):
    state = tmp_path / "state"
    seen: list[float] = []

    def fake_status(state_dir):
        return _fake_status(running=True, pid=4242)

    def fake_drain(state_dir, *, timeout=60.0):
        seen.append(timeout)
        return 0

    def fake_start(**kwargs):
        return 0

    _patch_daemon_fn(monkeypatch, "daemon_status", fake_status)
    _patch_daemon_fn(monkeypatch, "drain_daemon", fake_drain)
    monkeypatch.setattr("hunter.cli.daemon._cmd_start", fake_start)

    result = runner.invoke(app, ["restart", "--state", str(state), "--drain-timeout", "5"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert seen == [5.0]  # the flag wins

    monkeypatch.setenv("HUNTEROS_DRAIN_TIMEOUT", "90s")
    result2 = runner.invoke(app, ["restart", "--state", str(state)])
    assert result2.exit_code == 0, (result2.output, result2.exception)
    assert seen[-1] == pytest.approx(90.0)  # the env var parses via parse_duration

    monkeypatch.setenv("HUNTEROS_DRAIN_TIMEOUT", "garbage")
    result3 = runner.invoke(app, ["restart", "--state", str(state)])
    assert result3.exit_code == 8, (result3.output, result3.exception)
    assert "[Nh][Nm][Ns]" in result3.output  # the duration grammar hint


# -- 6 --------------------------------------------------------------------------


def test_drain_daemon_writes_flag_and_waits(monkeypatch, tmp_path):
    """Real drain_daemon: flag appears during the wait; 0 on exit, 1 on timeout."""
    from hunter.daemon import drain_daemon, pid_path, write_json_atomic

    state = tmp_path / "state-a"
    write_json_atomic(pid_path(state), {"pid": 4242})
    alive_sequence = iter([True, True, False])
    observed_flags: list[bool] = []

    def fake_alive(pid: int) -> bool:
        observed_flags.append((state / "daemon" / "drain.flag").exists())
        return next(alive_sequence)

    monkeypatch.setattr("hunter.daemon.pid_alive", fake_alive)
    assert drain_daemon(state, timeout=10.0) == 0
    assert (state / "daemon" / "drain.flag").exists()  # the flag stays written
    assert observed_flags and observed_flags[0] is True  # flag existed during wait

    # Timeout path: the pid never dies.
    state_b = tmp_path / "state-b"
    write_json_atomic(pid_path(state_b), {"pid": 5151})
    monkeypatch.setattr("hunter.daemon.pid_alive", lambda pid: True)
    assert drain_daemon(state_b, timeout=0.2) == 1


# -- 7 --------------------------------------------------------------------------


def test_daemon_serve_skips_claims_while_draining(tmp_path):
    """The extracted claim predicate: flags gate claims; in-flight does not."""
    from hunter.daemon import _should_claim

    state = tmp_path / "state"
    (state / "daemon").mkdir(parents=True)
    assert _should_claim(state) is True

    (state / "daemon" / "drain.flag").write_text("", encoding="utf-8")
    assert _should_claim(state) is False  # draining
    (state / "daemon" / "drain.flag").unlink()

    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")
    assert _should_claim(state) is False  # paused
    (state / "daemon" / "pause.flag").unlink()

    # In-flight (claimed) presence does not flip the claim gate itself.
    claimed = state / "daemon" / "claimed"
    claimed.mkdir()
    (claimed / "task.json").write_text("{}", encoding="utf-8")
    assert _should_claim(state) is True


# -- 8 --------------------------------------------------------------------------


def test_restart_marker_consumed_on_boot(monkeypatch, tmp_path):
    from hunter.daemon import _consume_restart_marker, restart_marker_path

    state = tmp_path / "state"
    (state / "daemon").mkdir(parents=True)
    log = state / "daemon" / "daemon.log"
    marker = restart_marker_path(state)
    marker.write_text(json.dumps({"ts": time.time() - 12.0, "pid": 1234}), encoding="utf-8")

    _consume_restart_marker(state, log)
    text = log.read_text(encoding="utf-8")
    assert "drained" in text
    assert MARKER_LOG_LINE.format(pid=1234) in text
    assert not marker.exists()  # consumed

    # A malformed marker is deleted silently (never crashes the boot).
    marker.write_text("{not json", encoding="utf-8")
    _consume_restart_marker(state, log)
    assert not marker.exists()


# -- 9 --------------------------------------------------------------------------


def test_status_shows_config_path_and_hints(monkeypatch, tmp_path):
    """Human status gains the config line + hint lines; --json gains
    `paused` and `config_path`."""
    running = _fake_status(running=True, pid=4242, uptime_seconds=90.0,
                           heartbeat_age_seconds=3.0, paused=True, config_path="")
    _patch_daemon_fn(monkeypatch, "daemon_status", lambda state_dir: running)
    result = runner.invoke(app, ["status", "--state", str(tmp_path)])
    assert result.exit_code == 0, (result.output, result.exception)
    text = result.output
    assert "running" in text and "pid 4242" in text
    assert "config:" in text and "(none)" in text
    assert "⏸️ paused" in text
    assert RUNNING_HINT in text

    stopped = _fake_status()
    _patch_daemon_fn(monkeypatch, "daemon_status", lambda state_dir: stopped)
    result2 = runner.invoke(app, ["status", "--state", str(tmp_path)])
    assert STOPPED_HINT in result2.output

    # The real read-only JSON status carries the additive keys.
    result3 = runner.invoke(app, ["status", "--state", str(tmp_path / "fresh"), "--json"])
    assert result3.exit_code == 0, (result3.output, result3.exception)
    payload = json.loads(result3.output[result3.output.index("{"):])
    assert "paused" in payload and "config_path" in payload


# -- 10 -------------------------------------------------------------------------


def test_top_level_restart_and_logs_aliases(monkeypatch, tmp_path):
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("restart", "logs"):
        assert name in result.output

    calls: list[str] = []

    def fake_restart(**kwargs):
        calls.append("restart")
        return 0

    def fake_logs(**kwargs):
        calls.append("logs")
        return 0

    monkeypatch.setattr("hunter.cli.daemon._cmd_restart", fake_restart)
    monkeypatch.setattr("hunter.cli.daemon._cmd_logs", fake_logs)

    assert runner.invoke(app, ["restart", "--state", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["logs", "--lines", "3", "--state", str(tmp_path)]).exit_code == 0
    assert calls == ["restart", "logs"]


# -- 11 -------------------------------------------------------------------------


def test_gateway_start_foreground_unchanged_hint(monkeypatch, tmp_path):
    """No transports -> exit 8 + the engine hint; transports -> the foreground
    run is entered and Ctrl+C stops cleanly."""
    result = runner.invoke(app, ["gateway", "start", "--state", str(tmp_path)])
    assert result.exit_code == 8, (result.output, result.exception)
    assert GATEWAY_HINT in result.output

    import hunter.gateway.app as gateway_app_module

    class FakeGatewayApp:
        def __init__(self, cfg, transports, state_dir=None):
            self.cfg = cfg
            self.transports = transports
            self.state_dir = state_dir

        def run(self):
            raise KeyboardInterrupt  # the operator pressed Ctrl+C

    monkeypatch.setattr(gateway_app_module, "GatewayApp", FakeGatewayApp)
    monkeypatch.setattr(
        gateway_app_module, "transports_from_env",
        lambda: [object()],  # one configured transport
    )
    result2 = runner.invoke(app, ["gateway", "start", "--state", str(tmp_path)])
    assert result2.exit_code == 0, (result2.output, result2.exception)
    assert "gateway stopped." in result2.output


# -- 12 (adversarial: stale pid.json + restart) -----------------------------------


def test_stale_pid_restart_path(monkeypatch, tmp_path):
    state = tmp_path / "state"
    events: list[str] = []
    drains: list = []

    def fake_status(state_dir):
        return _fake_status(running=False, stale=True, pid=4242)

    def fake_stop(state_dir, *, timeout=15.0, force=False):
        events.append(f"stop force={force}")
        return 0

    def fake_drain(state_dir, *, timeout=60.0):
        drains.append(state_dir)
        return 0

    def fake_start(**kwargs):
        events.append("start")
        return 0

    _patch_daemon_fn(monkeypatch, "daemon_status", fake_status)
    _patch_daemon_fn(monkeypatch, "stop_daemon", fake_stop)
    _patch_daemon_fn(monkeypatch, "drain_daemon", fake_drain)
    monkeypatch.setattr("hunter.cli.daemon._cmd_start", fake_start)

    result = runner.invoke(app, ["restart", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert events == ["stop force=True", "start"]  # the existing stale contract
    assert drains == []  # no drain against a dead pid
