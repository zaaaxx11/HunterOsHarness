"""`hunter update` command flows (M4) — confirm gates, plans, migration notes.

Written first (TDD) against docs/plans/v0.4/M4-update-command.md §5/§10/§12.
``run_update`` is exercised directly with string consoles (width 200 — repo
convention) so the normative copy is asserted unwrapped; CliRunner-level
tests pass ``env={"COLUMNS": "200"}`` because rich would otherwise soft-wrap
the ~94-char manual one-liner at the 80-column non-tty default. Zero
execution: ``detect_install_method`` / ``check_for_newer_version`` /
``default_runner`` / ``default_fetch_script`` / ``_stdin_isatty`` are
monkeypatched on the module (seams resolve via module attributes at call
time); the explicit ``ask=`` / ``is_windows=`` keyword seams pin the confirm
prompt and the POSIX installer branch deterministically on every OS.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
import yaml
from rich.console import Console
from typer.testing import CliRunner

import hunter.cli.main as cli_main

runner = CliRunner()

RAW_INSTALL_SH = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh"
_MANUAL_URL_SH = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh"
_MANUAL_URL_PS1 = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1"
MANUAL_POSIX = f"curl -fsSL {_MANUAL_URL_SH} | bash"  # §5.1 normative copy
MANUAL_WINDOWS = f"irm {_MANUAL_URL_PS1} | iex"
MANUAL = MANUAL_WINDOWS if os.name == "nt" else MANUAL_POSIX  # the running platform's line

SCRIPT_TEXT = "#!/usr/bin/env bash\nset -e\necho updated\n"
COLUMNS = {"COLUMNS": "200"}


def _string_console():
    out = io.StringIO()
    err = io.StringIO()
    console = Console(file=out, width=200, legacy_windows=False)
    err_console = Console(file=err, width=200, legacy_windows=False)
    return console, err_console, out, err


def _text(out, err) -> str:
    return out.getvalue() + err.getvalue()


def _check_result(**overrides):
    from hunter.cli import update_core

    fields = {
        "latest": "0.4.0",
        "current": "0.3.1",
        "source": "github",
        "update_available": True,
        "error": "",
    }
    fields.update(overrides)
    return update_core.CheckResult(**fields)


def _cli_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)


class _EofConsole(Console):
    """A console whose input() is already at EOF: drives the default-ask EOF path."""

    def input(self, *args, **kwargs) -> str:
        raise EOFError


@pytest.fixture(autouse=True)
def _m4_update_hygiene(monkeypatch):
    """Belt (§8.6): opt-out env set, CI vars scrubbed, update_core state reset
    around every test so stale notices never leak between tests (§11 #18)."""
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    for var in (
        "HUNTEROS_ONBOARD_DECLINED",
        "HUNTEROS_KEYS_FILE",
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "BUILDKITE",
        "CIRCLECI",
    ):
        monkeypatch.delenv(var, raising=False)
    try:
        from hunter.cli import update_core
    except ImportError:  # red state — the module is the thing under test
        yield
        return
    update_core.reset()
    yield
    update_core.reset()


def _recorder(ran):
    """A runner seam that records the argv it was handed (never executes)."""

    def runner_fn(argv):
        ran.append(list(argv))
        return 0

    return runner_fn


# ------------------------------------------------------------- command flows --


def test_update_dev_method_advice_only(monkeypatch, tmp_path):
    """C1: a dev/checkout install gets advice only — nothing is ever executed."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "dev")
    ran: list[list[str]] = []
    monkeypatch.setattr(update_core, "default_runner", _recorder(ran))

    result = runner.invoke(cli_main.app, ["update"], env=COLUMNS)
    assert result.exit_code == 0, (result.output, result.exception)
    assert "git pull && pip install -e ." in result.output
    assert ran == []  # the runner seam was never called


def test_update_check_failure_prints_manual_one_liner(monkeypatch, tmp_path):
    """C2: an unreachable version check prints the manual one-liner, exit 1."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "pip")

    def failed_check(**kwargs):
        return _check_result(latest="", source="", update_available=False, error="unreachable")

    monkeypatch.setattr(update_core, "check_for_newer_version", failed_check)
    ran: list[list[str]] = []
    monkeypatch.setattr(update_core, "default_runner", _recorder(ran))

    result = runner.invoke(cli_main.app, ["update"], env=COLUMNS)
    assert result.exit_code == 1, (result.output, result.exception)
    assert "could not check" in result.output
    assert MANUAL in result.output  # the platform one-liner (§5.1 normative copy)
    assert ran == []


def test_update_up_to_date_exits_zero(monkeypatch, tmp_path):
    """C3: latest <= current (incl. a locally newer build) -> up to date, exit 0."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "pip")

    def not_newer(**kwargs):
        return _check_result(latest="0.3.1", update_available=False)

    monkeypatch.setattr(update_core, "check_for_newer_version", not_newer)
    ran: list[list[str]] = []
    monkeypatch.setattr(update_core, "default_runner", _recorder(ran))

    result = runner.invoke(cli_main.app, ["update"], env=COLUMNS)
    assert result.exit_code == 0, (result.output, result.exception)
    assert "up to date" in result.output
    assert ran == []


def test_update_non_tty_without_yes_aborts_with_advice(monkeypatch, tmp_path):
    """C4: a dead stdin never blocks — declined line + one-liner, exit 0 (§11 #11)."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "pip")

    def available(**kwargs):
        return _check_result()

    monkeypatch.setattr(update_core, "check_for_newer_version", available)
    monkeypatch.setattr(update_core, "_stdin_isatty", lambda: False)
    ran: list[list[str]] = []
    monkeypatch.setattr(update_core, "default_runner", _recorder(ran))

    result = runner.invoke(cli_main.app, ["update"], env=COLUMNS)
    assert result.exit_code == 0, (result.output, result.exception)
    assert "update declined" in result.output
    assert MANUAL in result.output
    assert ran == []


def test_update_yes_pipx_runs_plan_and_prints_reminder(monkeypatch, tmp_path):
    """C5: --yes + pipx -> exactly the plan argv runs; success + reminder copy."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "pipx")

    def available(**kwargs):
        return _check_result()

    monkeypatch.setattr(update_core, "check_for_newer_version", available)
    ran: list[list[str]] = []
    monkeypatch.setattr(update_core, "default_runner", _recorder(ran))

    result = runner.invoke(cli_main.app, ["update", "--yes"], env=COLUMNS)
    assert result.exit_code == 0, (result.output, result.exception)
    assert ran == [["pipx", "upgrade", "hunteros-harness"]]
    assert "updated: hunter 0.3.1 → 0.4.0" in result.output
    assert "config migrations run on next command" in result.output


def test_update_confirm_y_runs_n_declines(monkeypatch, tmp_path):
    """C6: tty confirm — 'y' runs the plan; 'n' and the EOF default decline with
    advice and exit 0 (never blocks on a dead stdin, never installs unasked)."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "pip")

    def available(**kwargs):
        return _check_result()

    monkeypatch.setattr(update_core, "check_for_newer_version", available)
    monkeypatch.setattr(update_core, "_stdin_isatty", lambda: True)
    ran: list[list[str]] = []
    monkeypatch.setattr(update_core, "default_runner", _recorder(ran))

    prompts: list[str] = []

    def ask_yes(prompt, default=""):
        prompts.append(prompt)
        return "y"

    console, err_console, out, err = _string_console()
    code = update_core.run_update(
        console=console, err_console=err_console, yes=False, ask=ask_yes, is_windows=False
    )
    assert code == 0
    assert prompts == ["update hunter 0.3.1 → 0.4.0 now?"]  # §5.1 normative prompt
    assert len(ran) == 1
    assert "updated: hunter 0.3.1 → 0.4.0" in out.getvalue()

    def ask_no(prompt, default=""):
        prompts.append(prompt)
        return "n"

    console, err_console, out, err = _string_console()
    code = update_core.run_update(
        console=console, err_console=err_console, yes=False, ask=ask_no, is_windows=False
    )
    assert code == 0
    assert len(ran) == 1  # unchanged — the decline never executes anything
    assert "update declined" in _text(out, err)
    assert MANUAL_POSIX in _text(out, err)

    # The default ask maps EOFError -> "n" (§5.1) — driven via a dead console.
    console, err_console, out, err = _string_console()
    code = update_core.run_update(
        console=_EofConsole(file=out, width=200, legacy_windows=False),
        err_console=err_console,
        yes=False,
        is_windows=False,
    )
    assert code == 0
    assert len(ran) == 1
    assert "update declined" in _text(out, err)


def test_update_installer_posix_downloads_temp_and_cleans_up(monkeypatch, tmp_path):
    """C7: the installer plan fetches the raw script into a real temp file, runs
    `bash <temp> --skip-setup`, and removes the file afterwards (POSIX branch)."""
    from hunter.cli import update_core

    assert update_core.RAW_INSTALL_SH == RAW_INSTALL_SH
    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "installer")

    def available(**kwargs):
        return _check_result()

    monkeypatch.setattr(update_core, "check_for_newer_version", available)

    fetched: list[str] = []

    def fake_fetch(url):
        fetched.append(url)
        return SCRIPT_TEXT

    monkeypatch.setattr(update_core, "default_fetch_script", fake_fetch)

    ran: list[dict] = []

    def recorder(argv):
        argv = list(argv)
        script = Path(argv[1])
        ran.append(
            {
                "argv": argv,
                "existed": script.exists(),
                "content": script.read_text(encoding="utf-8") if script.exists() else "",
            }
        )
        return 0

    monkeypatch.setattr(update_core, "default_runner", recorder)

    console, err_console, out, err = _string_console()
    code = update_core.run_update(
        console=console, err_console=err_console, yes=True, is_windows=False
    )
    assert code == 0
    assert fetched == [RAW_INSTALL_SH]
    record = ran[0]
    assert record["argv"][0] == "bash"
    assert record["argv"][2] == "--skip-setup"
    assert record["argv"][1].endswith(".sh")
    assert record["existed"] is True  # the temp file existed at call time...
    assert record["content"] == SCRIPT_TEXT  # ...with the fetched bytes in it
    assert not Path(record["argv"][1]).exists()  # ...and is gone afterwards
    assert "updated: hunter 0.3.1 → 0.4.0" in _text(out, err)


def test_update_installer_failure_prints_manual_one_liner(monkeypatch, tmp_path):
    """C8: a failing (or OSError-raising) installer run maps to exit 1 plus the
    manual one-liner — the user is never stranded (§11 #10/#16)."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "installer")

    def available(**kwargs):
        return _check_result()

    monkeypatch.setattr(update_core, "check_for_newer_version", available)
    monkeypatch.setattr(update_core, "default_fetch_script", lambda url: SCRIPT_TEXT)

    def failing_runner(argv):
        return 1

    monkeypatch.setattr(update_core, "default_runner", failing_runner)
    console, err_console, out, err = _string_console()
    code = update_core.run_update(
        console=console, err_console=err_console, yes=True, is_windows=False
    )
    assert code == 1
    assert "update failed" in _text(out, err)
    assert MANUAL_POSIX in _text(out, err)

    def oserror_runner(argv):
        raise OSError("bash: command not found")

    monkeypatch.setattr(update_core, "default_runner", oserror_runner)
    console, err_console, out, err = _string_console()
    code = update_core.run_update(
        console=console, err_console=err_console, yes=True, is_windows=False
    )
    assert code == 1  # OSError -> 127 -> the same failure exit (§5.3)
    assert "update failed" in _text(out, err)
    assert MANUAL_POSIX in _text(out, err)


def test_update_success_prints_migration_notes(monkeypatch, tmp_path):
    """C9: a successful install prints the reminder plus schema-diff notes read
    from the RAW config; no config file -> reminder only (§6, read-only)."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "pipx")

    def available(**kwargs):
        return _check_result()

    monkeypatch.setattr(update_core, "check_for_newer_version", available)
    monkeypatch.setattr(update_core, "default_runner", _recorder([]))

    schema = update_core.example_schema()
    raw = {key: {} for key in schema}  # every schema section present, empty
    raw["legacy_thing"] = 1  # one key the example schema does not know
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = runner.invoke(cli_main.app, ["update", "--yes"], env=COLUMNS)
    assert result.exit_code == 0, (result.output, result.exception)
    assert "note: config migrations run on next command" in result.output
    note_line = "note: config key 'legacy_thing' is not in the current schema — run 'hunter config example'"
    assert note_line in result.output

    # No config anywhere -> no schema notes; the reminder line is still present.
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    monkeypatch.setenv("HOME", str(fresh))
    monkeypatch.setenv("USERPROFILE", str(fresh))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(fresh / "config.yaml"))
    result = runner.invoke(cli_main.app, ["update", "--yes"], env=COLUMNS)
    assert result.exit_code == 0, (result.output, result.exception)
    assert "note: config migrations run on next command" in result.output
    assert "note: config key" not in result.output
    assert "optional config section" not in result.output


# ---------------------------------------------------------------- docs --


def test_docs_updating_sections():
    """D1: README/QUICKSTART gain an Updating section + the opt-out var;
    FIRST-RUN documents the cache file."""
    root = Path(__file__).resolve().parents[1]
    for name in ("README.md", "QUICKSTART.md"):
        text = (root / name).read_text(encoding="utf-8")
        headings = [line.strip() for line in text.splitlines() if line.lstrip().startswith("#")]
        assert any("Updating" in heading for heading in headings), name
        assert "hunter update" in text, name
        assert "HUNTEROS_NO_UPDATE_CHECK" in text, name
    first_run = (root / "docs" / "FIRST-RUN.md").read_text(encoding="utf-8")
    assert "update-check.json" in first_run
