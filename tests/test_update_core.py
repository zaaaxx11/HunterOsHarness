"""M4 update core — version check, background notify, install plans, migrations.

Written first (TDD) against docs/plans/v0.4/M4-update-command.md §10/§12.
``hunter.cli.update_core`` is new, so it is imported inside the test bodies —
a missing implementation fails the test, never the collection (M1/M2
precedent). Zero network: every HTTP touch goes through
``client_factory`` = ``httpx.MockTransport``; spawn tests pass ``environ={}``
explicitly to bypass the ``PYTEST_CURRENT_TEST`` refusal gate (§4.1) and
inject ``check_fn`` fakes.

Contracts pinned here (all doc-derived):
- ``_auto_check_allowed(environ)`` is the U9 skip-gate observable (the §4.1
  gate, factored out so the table is mechanically checkable).
- ``_newer(a, b)`` is the pure strict-comparison helper (§3.2).
- ``run_update`` accepts ``ask=`` / ``is_windows=`` keyword seams (§5.1
  "**seams ... or pass explicit callables"); ``is_windows`` drives
  build_install_plan, execute_plan AND the manual one-liner so the POSIX
  flow (C7/C8) is deterministic on Windows CI too.
- CliRunner: click 8.5 always separates streams (``mix_stderr`` is gone), so
  N6 asserts on ``result.stdout`` / ``result.stderr`` directly.
"""

from __future__ import annotations

import copy
import json
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import yaml
from typer.testing import CliRunner

import hunter.cli.main as cli_main
from hunter.llm.config import config_example_yaml

runner = CliRunner()

# Normative endpoint constants (§3.1) — module constants must match these.
GITHUB_RELEASES_URL = "https://api.github.com/repos/zaaaxx11/HunterOsHarness/releases/latest"
PYPI_JSON_URL = "https://pypi.org/pypi/hunteros-harness/json"
RAW_INSTALL_SH = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh"
RAW_INSTALL_PS1 = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1"

# Normative notice copy (§4.2) — one line, arrow-bearing, em-dash-free.
NOTICE = "A new version of hunter is available: 0.3.1 → 0.4.0. Run: hunter update"

T0 = 1_700_000_000.0
STALE = T0 + 25 * 3600.0  # 25h later — past the 24h TTL


def _mock_client(handler):
    def client_factory():
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=5)

    return client_factory


def _cache_path(home: Path) -> Path:
    return Path(home) / ".hunteros" / "update-check.json"


def _github_ok(seen, tag: str = "v0.4.0"):
    """GitHub answers 200 with the tag; any other URL (PyPI) answers 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "api.github.com" in str(request.url):
            return httpx.Response(200, json={"tag_name": tag})
        return httpx.Response(404, json={})

    return handler


def _cli_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)


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


# ------------------------------------------------------------------ check core --


def test_github_release_happy_path_writes_cache(tmp_path):
    """U1: exact GitHub URL + Accept header, v stripped, cache written."""
    from hunter.cli import update_core

    assert update_core.GITHUB_RELEASES_URL == GITHUB_RELEASES_URL
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "api.github.com" in str(request.url):
            return httpx.Response(200, json={"tag_name": "v0.4.0"})
        return httpx.Response(404, json={})

    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(handler),
    )
    assert len(seen) == 1
    assert str(seen[0].url) == GITHUB_RELEASES_URL
    assert seen[0].headers.get("accept") == "application/vnd.github+json"
    assert result.latest == "0.4.0"
    assert result.current == "0.3.1"
    assert result.source == "github"
    assert result.update_available is True
    assert result.error == ""
    assert _cache_path(tmp_path).exists()


def test_github_403_falls_back_to_pypi(tmp_path):
    """U2: a 403 rate limit on GitHub silently falls back to the PyPI JSON API."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "api.github.com" in str(request.url):
            return httpx.Response(403, json={"message": "API rate limit exceeded"})
        return httpx.Response(200, json={"info": {"version": "0.4.0"}})

    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(handler),
    )
    assert [str(r.url) for r in seen] == [GITHUB_RELEASES_URL, PYPI_JSON_URL]
    assert result.source == "pypi"
    assert result.latest == "0.4.0"
    assert result.update_available is True
    assert _cache_path(tmp_path).exists()


def test_total_failure_is_silent_noop_without_cache(tmp_path):
    """U3: GitHub 403 + PyPI 500 (and transport errors) -> silent no-op, no cache."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "api.github.com" in str(request.url):
            return httpx.Response(403, json={"message": "API rate limit exceeded"})
        return httpx.Response(500, json={})

    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(handler),
    )
    assert result.latest == ""
    assert result.current == "0.3.1"
    assert result.update_available is False
    assert result.error == "unreachable"  # §3.3 step 4 normative reason
    assert not _cache_path(tmp_path).exists()

    def broken(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        raise httpx.ConnectError("connection refused")

    offline = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(broken),
    )
    assert offline.latest == ""
    assert offline.error == "unreachable"
    assert not _cache_path(tmp_path).exists()


def test_malformed_payloads_fall_through_to_error(tmp_path):
    """U4: unparseable tag/version strings fall through to PyPI, then error."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "api.github.com" in str(request.url):
            return httpx.Response(200, json={"tag_name": "banana"})
        return httpx.Response(200, json={"info": {"version": "not-semver"}})

    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(handler),
    )
    assert PYPI_JSON_URL in [str(r.url) for r in seen]  # PyPI was consulted
    assert result.latest == ""
    assert result.update_available is False
    assert result.error == "unreachable"
    assert not _cache_path(tmp_path).exists()  # failed checks never write (§3.3 #5)


def test_fresh_cache_serves_without_network(tmp_path):
    """U5: the 24h cache is written with typed keys, then served with zero
    network; update_available is recomputed against the running version."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []
    first = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert first.source == "github"
    assert first.update_available is True

    data = json.loads(_cache_path(tmp_path).read_text(encoding="utf-8"))
    assert set(data) == {"checked_at", "latest", "current", "source"}
    assert isinstance(data["checked_at"], (int, float))
    assert data["checked_at"] == T0
    assert data["latest"] == "0.4.0"
    assert data["current"] == "0.3.1"
    assert data["source"] == "github"

    def refusing(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network must not be touched while the cache is fresh")

    second = update_core.check_for_newer_version(
        current_version="0.4.0",  # the running version moved on since the write
        home=tmp_path,
        now_fn=lambda: T0 + 3600.0,
        client_factory=_mock_client(refusing),
    )
    assert second.source == "cache"
    assert second.latest == "0.4.0"
    assert second.current == "0.4.0"
    assert second.update_available is False  # recomputed, never trusted from the file


def test_stale_cache_and_force_refetch(tmp_path):
    """U6: +25h staleness refetches and rewrites; force=True refetches a FRESH cache."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []
    first = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert first.source == "github"
    assert len(seen) == 1

    second = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: STALE,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert second.source == "github"  # stale -> the network handler WAS called
    assert len(seen) == 2
    data = json.loads(_cache_path(tmp_path).read_text(encoding="utf-8"))
    assert data["checked_at"] == STALE  # rewritten with the new timestamp

    seen.clear()
    forced = update_core.check_for_newer_version(
        force=True,
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: STALE + 10.0,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert forced.source == "github"  # force bypasses the freshness window
    assert len(seen) == 1
    data = json.loads(_cache_path(tmp_path).read_text(encoding="utf-8"))
    assert data["checked_at"] == STALE + 10.0


def test_corrupt_cache_ignored_and_rewritten(tmp_path):
    """U7: garbage cache bytes are ignored (no exception), then rewritten parseable."""
    from hunter.cli import update_core

    cache_path = _cache_path(tmp_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(b"\x00{definitely not json")

    seen: list[httpx.Request] = []
    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert len(seen) == 1  # the network path proceeded
    assert result.source == "github"
    assert result.latest == "0.4.0"
    data = json.loads(cache_path.read_text(encoding="utf-8"))
    assert data["latest"] == "0.4.0"
    assert isinstance(data["checked_at"], (int, float))


def test_downgrade_not_reported_but_cached(tmp_path):
    """U8: a locally newer build is "up to date"; the cache is still written."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []
    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(_github_ok(seen, tag="v0.3.0")),
    )
    assert result.latest == "0.3.0"
    assert result.update_available is False
    data = json.loads(_cache_path(tmp_path).read_text(encoding="utf-8"))
    assert data["latest"] == "0.3.0"


def test_skip_gates_ci_optout_and_pytest():
    """U9: the spawn-gate observable — 6 CI vars, opt-out, and the pytest refusal."""
    from hunter.cli import update_core

    assert update_core.OPT_OUT_ENV == "HUNTEROS_NO_UPDATE_CHECK"
    cases = [
        ({}, True),
        ({"CI": "true"}, False),
        ({"GITHUB_ACTIONS": "1"}, False),
        ({"GITLAB_CI": "1"}, False),
        ({"JENKINS_URL": "https://jenkins.example.com"}, False),
        ({"BUILDKITE": "true"}, False),
        ({"CIRCLECI": "true"}, False),
        ({"CI": "0"}, True),  # a falsy CI value does not gate (§4.1 _truthy)
        ({update_core.OPT_OUT_ENV: "1"}, False),
        ({update_core.OPT_OUT_ENV: "0"}, True),  # =0 explicitly allows checks
        ({update_core.OPT_OUT_ENV: "false"}, True),
        ({update_core.OPT_OUT_ENV: "no"}, True),
        ({"PYTEST_CURRENT_TEST": "tests/test_update_core.py::test_x"}, False),
    ]
    for environ, expected in cases:
        assert update_core._auto_check_allowed(environ) is expected, environ

    # The hard gate: with the real environment (pytest sets PYTEST_CURRENT_TEST)
    # nothing is ever spawned, conftest belt or not (§8.6).
    assert update_core.start_background_check() is False


def test_force_bypasses_freshness_and_gates(tmp_path):
    """U10: force=True ignores the freshness window AND the politeness gates —
    an explicit `hunter update` must work on CI and with the opt-out set."""
    from hunter.cli import update_core

    seen: list[httpx.Request] = []
    first = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert first.source == "github"  # fresh cache written at T0

    result = update_core.check_for_newer_version(
        force=True,
        environ={"CI": "true", "GITHUB_ACTIONS": "true", update_core.OPT_OUT_ENV: "1"},
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: T0 + 10.0,
        client_factory=_mock_client(_github_ok(seen)),
    )
    assert len(seen) == 2  # the mock handler recorded the request
    assert result.source == "github"
    assert result.update_available is True


def test_parse_version_and_newer_table():
    """U11: dot-separated integers only; strict >, zero-padded (§3.2)."""
    from hunter.cli import update_core

    assert update_core.parse_version("v0.4.0") == (0, 4, 0)
    assert update_core.parse_version("V0.4.0") == (0, 4, 0)  # one leading v/V
    assert update_core.parse_version("  0.4.0  ") == (0, 4, 0)  # whitespace stripped
    assert update_core.parse_version("0.4") == (0, 4)
    assert update_core.parse_version("0.4.0-beta1") is None  # pre-releases malformed
    assert update_core.parse_version("banana") is None
    assert update_core.parse_version("0.4.x") is None
    assert update_core.parse_version("0..4") is None
    assert update_core.parse_version("") is None

    assert update_core._newer((0, 4), (0, 4, 0)) is False  # equal after padding
    assert update_core._newer((0, 10, 0), (0, 9, 0)) is True
    assert update_core._newer((0, 4, 0), (0, 4, 0)) is False  # strict: equal is not newer
    assert update_core._newer((0, 4, 0), (0, 3, 1)) is True
    assert update_core._newer((0, 3, 1), (0, 4, 0)) is False


# ------------------------------------------------------------- background notify --


def test_spawn_store_pop_once_notice_format():
    """N1: one spawn stores the result; the notice pops exactly once, verbatim."""
    from hunter.cli import update_core

    spawned = update_core.start_background_check(
        environ={},
        wait=True,
        check_fn=lambda: update_core.CheckResult(
            latest="0.4.0", current="0.3.1", source="github", update_available=True
        ),
    )
    assert spawned is True
    assert update_core.pop_pending_notice() == NOTICE
    assert update_core.pop_pending_notice() is None


def test_pop_suppressed_before_completion_no_update_or_quiet():
    """N2: pop is None before completion, for a no-update result, and when the
    spawn used suppress_notice=True (§4.2)."""
    from hunter.cli import update_core

    release = threading.Event()

    def slow_check():
        assert release.wait(5), "test harness hung"
        return update_core.CheckResult(
            latest="0.4.0", current="0.3.1", source="github", update_available=True
        )

    assert update_core.start_background_check(environ={}, check_fn=slow_check) is True
    assert update_core.pop_pending_notice() is None  # check has not completed yet
    release.set()
    deadline = time.monotonic() + 5
    notice = None
    while time.monotonic() < deadline:  # drain so the thread never leaks state
        notice = update_core.pop_pending_notice()
        if notice is not None:
            break
        time.sleep(0.01)
    assert notice == NOTICE

    assert (
        update_core.start_background_check(
            environ={},
            wait=True,
            check_fn=lambda: update_core.CheckResult(current="0.3.1", source="github"),
        )
        is True
    )
    assert update_core.pop_pending_notice() is None  # completed, but no update

    assert (
        update_core.start_background_check(
            environ={},
            wait=True,
            suppress_notice=True,
            check_fn=lambda: update_core.CheckResult(
                latest="0.4.0", current="0.3.1", source="github", update_available=True
            ),
        )
        is True
    )
    assert update_core.pop_pending_notice() is None  # quiet surface never pops


def test_check_exception_swallowed_and_reset_clears():
    """N3: a raising check_fn never escapes the thread; reset() clears state."""
    from hunter.cli import update_core

    def boom():
        raise RuntimeError("background check exploded")

    assert update_core.start_background_check(environ={}, wait=True, check_fn=boom) is True
    assert update_core.pop_pending_notice() is None
    update_core.reset()
    assert update_core.pop_pending_notice() is None


def test_root_callback_spawns_version_not_update(monkeypatch, tmp_path):
    """N4: the root callback spawns the check for `version` but never for
    `update` (§4.3) — the seam resolves via the module attribute at call time."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    calls: list[dict] = []

    def recorder(**kwargs):
        calls.append(kwargs)
        return False

    monkeypatch.setattr(update_core, "start_background_check", recorder)

    result = runner.invoke(cli_main.app, ["version"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == [{"suppress_notice": False}]

    calls.clear()
    monkeypatch.setattr(update_core, "detect_install_method", lambda: "dev")
    result = runner.invoke(cli_main.app, ["update"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == []


def test_chat_spawn_is_suppressed(monkeypatch, tmp_path):
    """N5: quiet surfaces spawn with suppress_notice=True (§4.4) — the thread
    still refreshes the cache, the notice simply never prints in-process."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    calls: list[dict] = []

    def recorder(**kwargs):
        calls.append(kwargs)
        return False

    monkeypatch.setattr(update_core, "start_background_check", recorder)

    import hunter.chat.repl as chat_repl
    import hunter.cli.init_wizard as init_wizard

    repl_calls: list[dict] = []
    monkeypatch.setattr(init_wizard, "offer_onboarding", lambda **kwargs: False)
    monkeypatch.setattr(chat_repl, "run_repl", lambda **kwargs: repl_calls.append(kwargs))

    result = runner.invoke(cli_main.app, ["chat"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == [{"suppress_notice": True}]
    assert repl_calls == [{"session_id": None, "state_dir": None}]


def test_doctor_json_stdout_clean_notice_on_stderr(monkeypatch, tmp_path):
    """N6: with a forced update-available spawn, `hunter doctor --json` keeps
    stdout machine-parseable; the notice appears on stderr only (§4.4)."""
    from hunter.cli import update_core

    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HUNTEROS_CHAT_DB", str(tmp_path / "chat.db"))

    real_spawn = update_core.start_background_check

    def forced_spawn(*, suppress_notice=False, **kwargs):
        return real_spawn(
            environ={},
            wait=True,
            suppress_notice=suppress_notice,
            check_fn=lambda: update_core.CheckResult(
                latest="0.4.0", current="0.3.1", source="github", update_available=True
            ),
        )

    monkeypatch.setattr(update_core, "start_background_check", forced_spawn)

    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 0, (result.stdout, result.stderr, result.exception)
    payload = json.loads(result.stdout)  # stdout parses as pure JSON
    assert payload["ok"] is True
    assert "A new version of hunter" not in result.stdout
    assert NOTICE in result.stderr


# ---------------------------------------------------------- install method + plans --


def test_classify_install_table(tmp_path):
    """M1: the ordered pure table — venv containment beats direct_url (§5.2)."""
    from hunter.cli import update_core

    home = tmp_path
    venv = home / ".hunteros" / "venv"
    direct = {"url": "file:///repo", "dir_info": {"editable": True}}
    assert (
        update_core.classify_install(sys_prefix=venv, home=home, direct_url=direct, is_windows=False)
        == "installer"
    )
    assert (
        update_core.classify_install(sys_prefix=venv, home=home, direct_url=None, is_windows=True)
        == "installer"
    )
    assert (
        update_core.classify_install(
            sys_prefix=home / "scratch", home=home, direct_url=direct, is_windows=False
        )
        == "dev"
    )
    assert (
        update_core.classify_install(
            sys_prefix=home / ".local" / "pipx" / "venvs" / "hunteros-harness",
            home=home,
            direct_url=None,
            is_windows=False,
        )
        == "pipx"
    )
    assert (
        update_core.classify_install(
            sys_prefix=home / "somewhere", home=home, direct_url=None, is_windows=False
        )
        == "pip"
    )


def test_detect_install_method_returns_known_member():
    """M2: real metadata in the test venv — one of the four, never raises (§5.2)."""
    from hunter.cli import update_core

    assert update_core.detect_install_method() in {"dev", "installer", "pipx", "pip"}


def test_build_install_plan_table(monkeypatch):
    """M3: the argv/fetch_url table (§5.3); unknown methods degrade to the pip plan."""
    from hunter.cli import update_core

    installer = update_core.build_install_plan("installer", is_windows=False)
    assert installer.method == "installer"
    assert installer.argv == ("bash", "{script}", "--skip-setup")
    assert installer.fetch_url == RAW_INSTALL_SH

    # Hermetic: the src prefers a real pwsh 7 when present (shutil.which), so
    # pin the fallback with which() stubbed out, then pin the preference.
    monkeypatch.setattr(update_core.shutil, "which", lambda *a, **k: None)
    win = update_core.build_install_plan("installer", is_windows=True)
    assert win.argv == (
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "{script}", "-SkipSetup",
    )
    assert win.fetch_url == RAW_INSTALL_PS1
    monkeypatch.setattr(
        update_core.shutil, "which", lambda name, *a, **k: "/usr/bin/pwsh" if name == "pwsh" else None
    )
    win7 = update_core.build_install_plan("installer", is_windows=True)
    assert win7.argv[0] == "/usr/bin/pwsh"
    assert win7.argv[1:] == win.argv[1:]

    pipx = update_core.build_install_plan("pipx", is_windows=False)
    assert pipx.argv == ("pipx", "upgrade", "hunteros-harness")
    assert pipx.fetch_url == ""

    pip = update_core.build_install_plan("pip", is_windows=False)
    assert pip.argv == (sys.executable, "-m", "pip", "install", "--upgrade", "hunteros-harness")
    assert pip.fetch_url == ""

    unknown = update_core.build_install_plan("docker", is_windows=False)
    assert unknown.argv == pip.argv


# ------------------------------------------------------------ migration stub --


def test_migration_notes_shapes():
    """G1: the §6 note shapes on a synthetic schema, plus exact-match -> []."""
    from hunter.cli import update_core

    schema = {
        "model_tiers": {"orchestrator": {"provider": "anthropic", "model": "m"}},
        "budget": {"max_cost_usd": 5},
        "agent": {"tier": "basic"},
    }
    matching = {
        "model_tiers": {"orchestrator": {"provider": "anthropic", "model": "m"}},
        "budget": {"max_cost_usd": 1},
        "agent": {"tier": "orchestrator"},
    }

    unknown_top = {**matching, "legacy_hooks": 1}
    assert update_core.migration_notes(unknown_top, schema) == [
        "config key 'legacy_hooks' is not in the current schema — run 'hunter config example'"
    ]

    unknown_sub = copy.deepcopy(matching)
    unknown_sub["model_tiers"]["orchestrator"]["bogus_extra"] = 1
    assert update_core.migration_notes(unknown_sub, schema) == [
        "config key 'model_tiers.bogus_extra' is not in the current schema — run 'hunter config example'"
    ]

    missing_section = {key: value for key, value in matching.items() if key != "budget"}
    assert update_core.migration_notes(missing_section, schema) == [
        "optional config section 'budget' is available — see 'hunter config example'"
    ]

    assert update_core.migration_notes(copy.deepcopy(schema), schema) == []


def test_example_schema_and_migration_notes_never_raise_capped():
    """G2: example_schema() mirrors config_example_yaml(); garbage in -> [];
    pathological inputs never raise and cap at 5 notes (§6)."""
    from hunter.cli import update_core

    schema = update_core.example_schema()
    assert isinstance(schema, dict) and schema
    assert schema == yaml.safe_load(config_example_yaml())

    for garbage in (None, "garbage", 42, [], [{"x": 1}]):
        assert update_core.migration_notes(garbage, schema) == []
    assert update_core.migration_notes({"a": 1}, "not-a-schema") == []

    flood_top = {f"zz_unknown_{i}": 1 for i in range(8)}
    assert len(update_core.migration_notes(flood_top, schema)) == 5

    flood_sub = {"model_tiers": {f"tier_{i}": {"provider": "p"} for i in range(8)}}
    notes = update_core.migration_notes(flood_sub, schema)
    assert len(notes) == 5
    assert all("not in the current schema" in note for note in notes)
