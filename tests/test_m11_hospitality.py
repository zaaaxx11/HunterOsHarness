"""M11 M8 — hospitality sweep: exit hints, --version, pause/resume, PATH (§12).

Spec: docs/plans/m11-ux.md §2.2 Q7, §12. The hospitality module and
its pinned strings land in M1 (Q12); the WIRING (exit_hint table, backstop,
--version, pause/resume ESTOP, installer PATH) is M8 and stays red until
then. New symbols are imported inside test bodies; the daemon is faked via
monkeypatched ``daemon_running``/``daemon_status`` — zero network, zero
processes.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from typer.testing import CliRunner

from hunter.cli.main import app

runner = CliRunner()

PAUSED_MESSAGE = (
    "⏸️ Hunter is paused. New work is on hold; run `hunter resume` to pick things back up."
)
RESUME_MESSAGE = "✅ Resumed — {pending} task(s) waiting in the queue."
ENGINE_OFF_NOTE = "engine was off — pause flag cleared"
WELCOME_FOOTER_LINE = "home: ~/.hunter · config: hunter config show · doctor: hunter doctor"


def _patch_daemon_fn(monkeypatch, name, fn):
    monkeypatch.setattr(f"hunter.daemon.{name}", fn)
    for module_name in ("hunter.cli.daemon", "hunter.cli.estop"):
        try:
            module = __import__(module_name, fromlist=["x"])
        except ImportError:
            continue
        if hasattr(module, name):
            monkeypatch.setattr(module, name, fn)


def _state(tmp_path: Path) -> Path:
    return tmp_path / "state"


# -- 1 --------------------------------------------------------------------------


def test_exit_hint_table_covers_config_auth_ledger_error_only():
    """Blocked layers and unmapped codes -> None; mapped codes -> the pinned
    `💡 Try:` lines."""
    from hunter.hospitality import exit_hint

    assert exit_hint(8) == "💡 Try: hunter config check"
    assert exit_hint(4) == "💡 Try: hunter config key list — then hunter config key set <VAR>"
    assert exit_hint(7) == "💡 Try: hunter verify"
    assert (
        exit_hint(5)
        == "💡 Try: retry later — or add a fallback: hunter config provider add"
    )
    assert exit_hint(1) == "💡 Try: hunter doctor"
    # Blocked lines never suggest widening; usage/interrupt speak for themselves.
    assert exit_hint(3) is None  # scope denied
    assert exit_hint(6) is None  # claim gate
    assert exit_hint(2) is None  # usage
    assert exit_hint(130) is None  # interrupt
    assert exit_hint(8, blocked=True) is None  # blocked beats the table
    assert exit_hint(99) is None  # codes without a map


# -- 2 --------------------------------------------------------------------------


def test_backstop_appends_hint_for_hintless_config_error(capsys):
    """A hintless HunterError through the backstop gains the 💡 trailer;
    hint-bearing errors are byte-identical to today (Q7)."""
    from hunter.cli.handle import handle_cli_error
    from hunter.errors import HunterError

    hintless = HunterError(
        code="config.broken", layer="config", message="something is off", hint=""
    )
    handle_cli_error(hintless, verbose=False)
    err = capsys.readouterr().err
    assert "something is off" in err
    assert err.rstrip().endswith("💡 Try: hunter config check")

    hinted = HunterError(
        code="config.broken", layer="config", message="something is off",
        hint="do the specific fix",
    )
    handle_cli_error(hinted, verbose=False)
    err2 = capsys.readouterr().err
    assert "do the specific fix" in err2
    assert "💡 Try:" not in err2  # no extra trailer when the error has its own hint


# -- 3 (adversarial: --version must be side-effect free) ---------------------------


def test_version_flag_prints_and_exits_zero_before_migration():
    """`hunter --version` prints and exits BEFORE keys/env/migration: a
    legacy-only home stays untouched and no migration notice prints."""
    home = Path(os.environ["USERPROFILE"])
    (home / ".hunteros").mkdir(parents=True, exist_ok=True)
    (home / ".hunteros" / "config.yaml").write_text("agent:\n  tier: basic\n", encoding="utf-8")

    from hunter.cli.main import _version

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert result.output.strip() == f"hunter {_version()}"
    assert "migrated" not in result.output
    assert not (home / ".hunter").exists()  # NO migration side effect


# -- 4 --------------------------------------------------------------------------


def test_pause_when_running_writes_flag_and_pinned_copy(tmp_path, monkeypatch):
    state = _state(tmp_path)
    _patch_daemon_fn(monkeypatch, "daemon_running", lambda state_dir: (True, "4242"))

    result = runner.invoke(app, ["pause", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert (state / "daemon" / "pause.flag").exists()
    assert PAUSED_MESSAGE in result.output


# -- 5 --------------------------------------------------------------------------


def test_pause_when_not_running_refuses_exit_1(tmp_path, monkeypatch):
    state = _state(tmp_path)
    _patch_daemon_fn(monkeypatch, "daemon_running", lambda state_dir: (False, ""))

    result = runner.invoke(app, ["pause", "--state", str(state)])
    assert result.exit_code == 1, (result.output, result.exception)
    assert "engine is off — nothing to pause" in result.output
    assert not (state / "daemon" / "pause.flag").exists()


# -- 6 --------------------------------------------------------------------------


def test_resume_removes_flag_and_reports_queue(tmp_path, monkeypatch):
    from hunter.daemon import enqueue_task

    state = _state(tmp_path)
    (state / "daemon").mkdir(parents=True)
    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")
    for _ in range(3):  # the live queue really holds three tasks
        enqueue_task(
            state,
            {"target": "http://127.0.0.1:9/", "scope": {"hosts": ["127.0.0.1"]},
             "engine": "deterministic", "min_wall_seconds": 0.0,
             "max_wall_seconds": 60.0, "max_cost_usd": 0.0},
        )

    _patch_daemon_fn(monkeypatch, "daemon_running", lambda state_dir: (True, "4242"))
    result = runner.invoke(app, ["resume", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert RESUME_MESSAGE.format(pending=3) in result.output
    assert not (state / "daemon" / "pause.flag").exists()  # the flag is gone


# -- 7 --------------------------------------------------------------------------


def test_resume_when_off_clears_stale_flag_with_note(tmp_path, monkeypatch):
    state = _state(tmp_path)
    (state / "daemon").mkdir(parents=True)
    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")

    _patch_daemon_fn(monkeypatch, "daemon_running", lambda state_dir: (False, ""))
    result = runner.invoke(app, ["resume", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert ENGINE_OFF_NOTE in result.output
    assert not (state / "daemon" / "pause.flag").exists()  # a later boot is not paused


# -- 8 --------------------------------------------------------------------------


def test_daemon_serve_holds_claims_while_paused(tmp_path):
    """The daemon-side wiring end to end: the claim predicate refuses while a
    pause.flag exists, and _daemon_serve consults it (static + behavior)."""
    from hunter.daemon import _should_claim

    state = _state(tmp_path)
    (state / "daemon").mkdir(parents=True)
    assert _should_claim(state) is True
    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")
    assert _should_claim(state) is False

    source = Path(__file__).parents[1] / "src" / "hunter" / "daemon.py"
    src = source.read_text(encoding="utf-8")
    assert "_should_claim(" in src  # the serve loop consults the predicate
    assert "pause.flag" in src


# -- 9 (adversarial: pause must NEVER kill in-flight work) -------------------------


def test_paused_does_not_kill_in_flight(tmp_path, monkeypatch):
    """A claimed task completes even though pause.flag appears mid-run:
    hunt_worker runs it to the done-*.json file (RunBudget/stop.flag untouched)."""
    import hunter.daemon as daemon_module
    from hunter.daemon import enqueue_task, hunt_worker, stop_flag_path

    state = _state(tmp_path)
    enqueue_task(
        state,
        {"target": "http://127.0.0.1:9/", "scope": {"hosts": ["127.0.0.1"], "name": "local"},
         "engine": "deterministic", "min_wall_seconds": 0.0,
         "max_wall_seconds": 60.0, "max_cost_usd": 0.0},
    )
    ran: list = []

    class _Outcome:
        run_id = "R-m11-inflight"
        status = "completed"
        findings = 0
        exit_code = 0

    def fake_run_hunt(target, **kwargs):
        ran.append(target)
        (state / "daemon" / "pause.flag").parent.mkdir(parents=True, exist_ok=True)
        (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")  # paused MID-RUN
        return _Outcome()

    monkeypatch.setattr(daemon_module, "run_hunt", fake_run_hunt)
    heartbeat: dict = {"active_task": None}

    asyncio.run(hunt_worker(str(state), stop_path=stop_flag_path(state), heartbeat=heartbeat))
    assert ran == ["http://127.0.0.1:9/"]  # the in-flight run COMPLETED
    done_files = list((state / "daemon" / "queue").glob("done-*.json"))
    assert done_files, "the claimed task must land its done file despite the pause"


# -- 10 -------------------------------------------------------------------------


def test_status_and_heartbeat_report_paused(tmp_path, monkeypatch):
    """daemon_status carries `paused` (pause.flag presence) and the human
    status renders `⏸️ paused`."""
    from hunter.daemon import daemon_status

    state = _state(tmp_path)
    (state / "daemon").mkdir(parents=True)
    assert daemon_status(state)["paused"] is False
    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")
    assert daemon_status(state)["paused"] is True

    import hunter.cli.daemon as cli_daemon

    status = daemon_status(state)
    monkeypatch.setattr(cli_daemon, "daemon_status", lambda state_dir: status)
    result = runner.invoke(app, ["status", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "⏸️ paused" in result.output


# -- 11 -------------------------------------------------------------------------


def test_welcome_footer_mentions_home_and_where():
    from hunter._data.branding import welcome_lines

    lines = welcome_lines("9.9.9")
    body = "\n".join(lines)
    assert WELCOME_FOOTER_LINE in body  # the additive footer line


# -- 12 (static installer pin) -----------------------------------------------------


def test_install_ps1_path_prefers_venv_scripts():
    repo = Path(__file__).parents[1]
    ps1 = (repo / "install.ps1").read_text(encoding="utf-8")
    assert ps1.count("# >>> hunteros PATH >>>") == 1
    assert ps1.count("# <<< hunteros PATH <<<") == 1
    block_start = ps1.index("# >>> hunteros PATH >>>")
    block_end = ps1.index("# <<< hunteros PATH <<<")
    block = ps1[block_start:block_end]
    assert "venv\\Scripts" in block and ".hunteros\\bin" in block
    assert block.index("venv\\Scripts") < block.index(".hunteros\\bin")  # venv WINS
    # The .cmd shims are still written (back-compat).
    assert "hunter.cmd" in ps1 and "hunt.cmd" in ps1


# -- 13 -------------------------------------------------------------------------


def test_wizard_interrupt_never_escalates_to_batch_job(tmp_path):
    """KeyboardInterrupt inside the DEFAULT ask during run_init_wizard becomes
    the M2 cancelled copy + exit 130 — the raw exception never escapes."""
    import io

    from rich.console import Console

    from hunter.cli.init_wizard import run_init_wizard

    class _InterruptingConsole(Console):
        def input(self, *args, **kwargs) -> str:
            raise KeyboardInterrupt  # the operator pressed Ctrl+C at the prompt

    out, err = io.StringIO(), io.StringIO()
    code = run_init_wizard(
        path=tmp_path / "config.yaml",
        console=_InterruptingConsole(file=out, width=200, legacy_windows=False),
        err_console=Console(file=err, width=200, legacy_windows=False),
        checks_fn=lambda: [],
        environ={},
        home=tmp_path,
    )
    assert code == 130
    assert "cancelled" in out.getvalue() + err.getvalue()
    assert not (tmp_path / "config.yaml").exists()
