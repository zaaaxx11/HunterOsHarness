"""`hunter init` v2 onboarding wizard + auto-trigger (M1).

Tests are written against the M1 design doc (§3/§5) and are RED until the
builder ships ``run_onboarding``, ``OnboardingAnswers``, ``onboarding_updates``,
``offer_onboarding`` and the CLI wiring — the new symbols are imported inside
the tests so a missing implementation fails the test, not the collection.
Conventions copied from tests/test_cli_init.py: string consoles,
``$HUNTEROS_CONFIG`` sandbox + ``HOME``/``USERPROFILE`` -> tmp_path,
needle-matching scripted ``ask`` (most-specific needle first), injected
``ping_fn``/``probe_fn``/``list_models_fn``/``checks_fn`` — zero network,
zero machine-HOME writes.
"""

from __future__ import annotations

import io
import os

import pytest
from rich.console import Console
from typer.testing import CliRunner

from hunter.cli.doctor_core import Check
from hunter.cli.main import app
from hunter.llm.base import TIERS
from hunter.llm.config import load_config
from hunter.llm.ping import PingResult
from hunter.llm.providers import known_provider

runner = CliRunner()
SENTINEL = "sk-sentinel-m1-never-echo-9137"
DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."
DECLINED_FLAG = "HUNTEROS_ONBOARD_DECLINED"
CUSTOM_BASE_URL = "https://llm.corp.example.com/v1"


def _string_console():
    out = io.StringIO()
    err = io.StringIO()
    console = Console(file=out, width=200, legacy_windows=False)
    err_console = Console(file=err, width=200, legacy_windows=False)
    return console, err_console, out


def _wizard_text(out, err_console) -> str:
    return out.getvalue() + err_console.file.getvalue()


def _scripted_ask(script):
    """Needle-matching ask: most-specific needle first (v1 convention).

    A scripted empty reply means "take the default" — mirrors the default
    ask's blank-falls-back-to-default contract the wizard relies on.
    """

    def ask(prompt: str, default: str = "") -> str:
        for needle, reply in script:
            if needle in prompt:
                return reply or default
        return default

    return ask


def _ok_ping(*_args, **_kwargs):
    return PingResult(ok=True, latency_ms=7, message="OK (7 ms)")


def _boom_ping(*_args, **_kwargs):
    raise RuntimeError("no network in tests")


def _fake_checks() -> list:
    return [
        Check("python", "ok", "3.13.7 on Windows"),
        Check("state-dir", "ok", "sandbox — 0 run(s)"),
    ]


def _cli_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.delenv(DECLINED_FLAG, raising=False)
    monkeypatch.delenv("HUNTEROS_KEYS_FILE", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _m1_env_hygiene(monkeypatch):
    """No machine env leaks between tests (design doc §13 hygiene rules)."""
    for var in (
        DECLINED_FLAG, "HUNTEROS_KEYS_FILE",
        "GROQ_API_KEY", "OPENAI_API_KEY", "CUSTOM_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


class _EofConsole(Console):
    """A console whose input() is already at EOF: drives the EOF-default path."""

    def input(self, *args, **kwargs) -> str:
        raise EOFError


def _recording_ask():
    """An ask double that records every prompt (used for suppression tests)."""
    prompts: list[str] = []

    def ask(prompt: str, default: str = "") -> str:
        prompts.append(prompt)
        return default

    return ask, prompts


# ----------------------------------------------------------------- wizard v2 --


def test_onboarding_auto_mode_writes_all_four_tiers(tmp_path):
    """A1: auto mode + env-var key + table-default model -> loadable config."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    text = _wizard_text(out, err_console)
    assert "using $GROQ_API_KEY from the environment" in text
    assert "step 6/7 tools:" in text
    cfg = load_config(target, env={}, home=tmp_path)
    table = known_provider("groq")
    for tier in TIERS:
        assert cfg.model_tiers[tier].provider == "groq"
        assert cfg.model_tiers[tier].model == table.default_model
    assert cfg.agent.tier == "basic"
    assert cfg.agent.browser is False


def test_onboarding_pasted_key_goes_to_keys_env_not_config(tmp_path):
    """A2: the pasted key lands in keys.env; config.yaml carries key_env only."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq"), ("key", "1")]),
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={},
        home=tmp_path,
    )
    assert code == 0
    assert "api_key" not in target.read_text(encoding="utf-8")
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["groq"].key_env == "GROQ_API_KEY"
    keys_text = (tmp_path / ".hunteros" / "keys.env").read_text(encoding="utf-8")
    assert f'GROQ_API_KEY="{SENTINEL}"' in keys_text
    assert SENTINEL not in _wizard_text(out, err_console)


def test_onboarding_advanced_mode_per_role_models(tmp_path):
    """A3: advanced mode assigns models per role; blanks inherit orchestrator/cheap."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("orchestrator model", "m-orch"),
                ("hunter model", ""),  # blank -> the orchestrator answer
                ("verifier model", ""),  # blank -> the cheap model
                ("utility model", ""),  # blank -> the cheap model
                ("provider", "groq"),
                ("mode", "advanced"),
            ]
        ),
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    cfg = load_config(target, env={}, home=tmp_path)
    cheap = known_provider("groq").cheap_model
    assert cfg.model_tiers["orchestrator"].model == "m-orch"
    assert cfg.model_tiers["hunter"].model == "m-orch"
    assert cfg.model_tiers["verifier"].model == cheap
    assert cfg.model_tiers["utility"].model == cheap


def test_onboarding_custom_endpoint_probe_stores_chat_and_responses(tmp_path):
    """A4: the custom-provider probe result is stored in providers.<n>.endpoint."""
    from hunter.cli.init_wizard import run_onboarding

    for endpoint in ("chat", "responses"):
        console, err_console, out = _string_console()
        target = tmp_path / f"probe-{endpoint}.yaml"
        seen: list[tuple] = []

        def probe(*args, _endpoint=endpoint, _seen=seen, **_kwargs):
            _seen.append(args)
            return _endpoint

        code = run_onboarding(
            path=target,
            console=console,
            err_console=err_console,
            ask=_scripted_ask(
                [
                    ("base URL", CUSTOM_BASE_URL),
                    ("provider", "custom"),
                    ("model", "1"),
                ]
            ),
            probe_fn=probe,
            list_models_fn=lambda *_args, **_kwargs: ["corp-alpha", "corp-beta"],
            ping_fn=_ok_ping,
            checks_fn=_fake_checks,
            environ={"CUSTOM_API_KEY": "sk-custom-123"},
            home=tmp_path,
        )
        assert code == 0
        cfg = load_config(target, env={}, home=tmp_path)
        assert cfg.providers["custom"].endpoint == endpoint
        assert seen[0][0] == CUSTOM_BASE_URL  # probed with the user-supplied URL...
        assert seen[0][1] == "sk-custom-123"  # ...and the captured key value


def test_onboarding_endpoint_probe_failure_is_note_and_stores_nothing(tmp_path):
    """A5: a failed (empty or raised) probe is a note; endpoint stays empty."""
    from hunter.cli.init_wizard import run_onboarding

    def broken_probe(*_args, **_kwargs):
        raise RuntimeError("probe endpoint down")

    for index, probe in enumerate((lambda *_args, **_kwargs: "", broken_probe)):
        console, err_console, out = _string_console()
        target = tmp_path / f"fail-{index}.yaml"
        code = run_onboarding(
            path=target,
            console=console,
            err_console=err_console,
            ask=_scripted_ask(
                [
                    ("base URL", CUSTOM_BASE_URL),
                    ("provider", "custom"),
                    ("model", "1"),
                ]
            ),
            probe_fn=probe,
            list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
            ping_fn=_ok_ping,
            checks_fn=_fake_checks,
            environ={"CUSTOM_API_KEY": "sk-custom-123"},
            home=tmp_path,
        )
        assert code == 0
        assert "endpoint probe failed" in _wizard_text(out, err_console)
        cfg = load_config(target, env={}, home=tmp_path)
        assert cfg.providers["custom"].endpoint == ""


def test_onboarding_model_autolist_menu_used_for_custom(tmp_path):
    """A6: the numbered model menu prints for custom and the pick fills tiers."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("provider", "custom"),
                ("model", "2"),
            ]
        ),
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha", "corp-beta", "corp-gamma"],
        probe_fn=lambda *_args, **_kwargs: "chat",
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0
    text = _wizard_text(out, err_console)
    assert "available models" in text
    assert "1. corp-alpha" in text
    assert "2. corp-beta" in text
    cfg = load_config(target, env={}, home=tmp_path)
    for tier in TIERS:
        assert cfg.model_tiers[tier].model == "corp-beta"


def test_onboarding_model_autolist_failure_falls_back_to_manual(tmp_path):
    """A7: an empty model list is a note; the manual id lands in orchestrator."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("provider", "custom"),
                ("model id", "manual-corp-model"),
            ]
        ),
        list_models_fn=lambda *_args, **_kwargs: [],
        probe_fn=lambda *_args, **_kwargs: "chat",
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0
    assert "model list failed" in _wizard_text(out, err_console)
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.model_tiers["orchestrator"].model == "manual-corp-model"


def test_onboarding_browser_true_writes_flag_and_note(tmp_path):
    """A8: 'y' writes agent.browser true + the interim note; default stays off."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    yes_target = tmp_path / "yes.yaml"
    code = run_onboarding(
        path=yes_target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq"), ("web automation", "y")]),
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    assert "ships in a later release" in _wizard_text(out, err_console)
    cfg = load_config(yes_target, env={}, home=tmp_path)
    assert cfg.agent.browser is True

    console2, err_console2, out2 = _string_console()
    no_target = tmp_path / "no.yaml"
    code2 = run_onboarding(
        path=no_target,
        console=console2,
        err_console=err_console2,
        ask=_scripted_ask([("provider", "groq")]),  # browser prompt: default = no
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code2 == 0
    assert "ships in a later release" not in _wizard_text(out2, err_console2)
    cfg2 = load_config(no_target, env={}, home=tmp_path)
    assert cfg2.agent.browser is False


def test_onboarding_smoke_ping_failure_is_note_exit_0(tmp_path):
    """A9: a failed smoke ping is a note; the run still exits 0 and writes."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_boom_ping,
        checks_fn=_fake_checks,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    text = _wizard_text(out, err_console)
    assert "smoke test failed" in text
    assert "wrote" in text
    assert target.is_file()


def test_onboarding_key_is_never_echoed(tmp_path):
    """A10: the pasted sentinel never touches stdout/stderr — only keys.env."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    keys_path = tmp_path / ".hunteros" / "keys.env"
    code = run_onboarding(
        path=tmp_path / "config.yaml",
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq"), ("key", "1")]),
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={},
        home=tmp_path,
    )
    assert code == 0
    text = _wizard_text(out, err_console)
    assert SENTINEL not in text
    assert keys_path.is_file()
    assert SENTINEL in keys_path.read_text(encoding="utf-8")


def test_onboarding_disclaimer_on_every_terminal_path(tmp_path):
    """A11: the scope disclaimer is the last line on every terminal path."""
    from hunter.cli.init_wizard import run_onboarding

    runs: list[tuple[str, int, str]] = []

    def _run(label, **kwargs):
        console, err_console, out = _string_console()
        code = run_onboarding(
            console=console,
            err_console=err_console,
            checks_fn=_fake_checks,
            home=tmp_path,
            **kwargs,
        )
        runs.append((label, code, _wizard_text(out, err_console)))

    _run(
        "success",
        path=tmp_path / "ok.yaml",
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
    )
    _run(
        "smoke-failure",
        path=tmp_path / "smoke-fail.yaml",
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_boom_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
    )
    existing = tmp_path / "existing.yaml"
    existing.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")
    _run(
        "clobber-decline",
        path=existing,
        ask=_scripted_ask([("config already exists", "n")]),
        environ={},
    )

    eof_out = io.StringIO()
    eof_err = io.StringIO()
    code = run_onboarding(
        path=tmp_path / "eof.yaml",
        console=_EofConsole(file=eof_out, width=200, legacy_windows=False),
        err_console=Console(file=eof_err, width=200, legacy_windows=False),
        secret=lambda _prompt: "",  # the EOF paste is empty
        checks_fn=_fake_checks,
        environ={},
        home=tmp_path,
    )
    runs.append(("eof-default", code, eof_out.getvalue() + eof_err.getvalue()))

    for label, run_code, text in runs:
        assert run_code == 0, label
        assert text.strip().endswith(DISCLAIMER), label


def test_onboarding_decline_overwrite_keeps_config(tmp_path):
    """A12: the v2 clobber guard matches v1 — decline keeps the file bytes."""
    from hunter.cli.init_wizard import run_onboarding

    console, err_console, out = _string_console()
    target = tmp_path / "config.yaml"
    target.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")
    before = target.read_bytes()
    code = run_onboarding(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("config already exists", "n")]),
        environ={},
        home=tmp_path,
    )
    assert code == 0
    text = _wizard_text(out, err_console)
    assert "kept" in text
    assert "--path" in text
    assert target.read_bytes() == before


def test_onboarding_updates_shape_auto_and_no_provider():
    """A32: the pure write_config fragment for auto and no-provider answers."""
    from hunter.cli.init_wizard import OnboardingAnswers, onboarding_updates

    auto = OnboardingAnswers(
        provider="corp",
        base_url="https://corp.example.com/v1",
        endpoint="chat",
        key_env="CORP_KEY",
        role_models={tier: "corp-model" for tier in TIERS},
    )
    assert onboarding_updates(auto) == {
        "agent": {"tier": "basic", "browser": False},
        "providers": {
            "corp": {
                "key_env": "CORP_KEY",
                "base_url": "https://corp.example.com/v1",
                "endpoint": "chat",
            }
        },
        "model_tiers": {
            tier: {"provider": "corp", "model": "corp-model"} for tier in TIERS
        },
    }
    bare = OnboardingAnswers(provider="", browser=True)
    assert onboarding_updates(bare) == {"agent": {"tier": "basic", "browser": True}}


# ------------------------------------------------------- init routing + offer --


def test_init_command_routes_v2_interactive_v1_flagged(monkeypatch, tmp_path):
    """A13: interactive `init` runs v2; `--provider/--yes` still runs v1."""
    import hunter.cli.init_wizard as init_wizard_module

    _cli_env(monkeypatch, tmp_path)
    calls: list[str] = []

    def fake_v2(**_kwargs):
        calls.append("v2")
        return 0

    def fake_v1(**_kwargs):
        calls.append("v1")
        return 0

    monkeypatch.setattr(init_wizard_module, "run_onboarding", fake_v2)
    monkeypatch.setattr(init_wizard_module, "run_init", fake_v1)

    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == ["v2"]

    calls.clear()
    result_yes = runner.invoke(app, ["init", "--provider", "groq", "--yes"])
    assert result_yes.exit_code == 0, (result_yes.output, result_yes.exception)
    assert calls == ["v1"]


def test_bare_hunter_offer_accept_runs_wizard(monkeypatch, tmp_path):
    """A14: bare `hunter` offers the wizard; 'y' invokes run_onboarding once."""
    import hunter.cli.init_wizard as init_wizard_module

    _cli_env(monkeypatch, tmp_path)
    calls: list[int] = []

    def fake_wizard(*_args, **_kwargs):
        calls.append(1)
        return 0

    monkeypatch.setattr(init_wizard_module, "run_onboarding", fake_wizard)
    result = runner.invoke(app, [], input="y\n")
    assert result.exit_code == 0, (result.output, result.exception)
    assert "no brain configured yet" in result.output
    assert calls == [1]
    assert not (tmp_path / "config.yaml").exists()


def test_bare_hunter_offer_decline_sets_flag_once(monkeypatch, tmp_path):
    """A15: decline keeps the panel, writes nothing, sets the declined flag."""
    from hunter.cli.init_wizard import DECLINED_ENV

    assert DECLINED_ENV == DECLINED_FLAG
    _cli_env(monkeypatch, tmp_path)
    result = runner.invoke(app, [], input="n\n")
    assert result.exit_code == 0, (result.output, result.exception)
    assert "won't be asked again" in result.output
    assert "HunterOs Harness v" in result.output  # the welcome panel still renders
    assert not (tmp_path / "config.yaml").exists()
    assert os.environ.get(DECLINED_ENV) == "1"
    os.environ.pop(DECLINED_ENV, None)  # production set it — pop so nothing leaks


def test_offer_suppressed_by_declined_env(monkeypatch, tmp_path):
    """A16: the declined flag short-circuits the offer — no prompt, no output."""
    from hunter.cli.init_wizard import DECLINED_ENV, offer_onboarding

    console, err_console, out = _string_console()
    ask, prompts = _recording_ask()
    offered = offer_onboarding(
        console=console,
        err_console=err_console,
        env={DECLINED_ENV: "1"},
        home=tmp_path,
        ask=ask,
    )
    assert offered is False
    assert prompts == []  # no prompt
    assert _wizard_text(out, err_console) == ""  # no output


def test_offer_suppressed_when_config_exists(monkeypatch, tmp_path):
    """A17: an existing config means no offer (a re-run is an update)."""
    from hunter.cli.init_wizard import offer_onboarding

    config_path = tmp_path / "config.yaml"
    config_path.write_text("agent:\n  tier: basic\n", encoding="utf-8")
    console, err_console, out = _string_console()
    ask, prompts = _recording_ask()
    offered = offer_onboarding(
        console=console,
        err_console=err_console,
        env={"HUNTEROS_CONFIG": str(config_path)},
        home=tmp_path,
        ask=ask,
    )
    assert offered is False
    assert prompts == []  # silently suppressed
    assert _wizard_text(out, err_console) == ""


def test_chat_offer_decline_then_repl_banner(monkeypatch, tmp_path):
    """A18: `hunter chat` offers once, declines, then still opens the REPL."""
    _cli_env(monkeypatch, tmp_path)
    result = runner.invoke(app, ["chat"], input="n\n")
    assert result.exit_code == 0, (result.output, result.exception)
    assert "no brain configured yet" in result.output
    assert result.output.count("no brain configured yet") == 1  # asked at most once
    assert "HUNTEROS — Evidence or Nothing" in result.output  # the chat banner
    os.environ.pop(DECLINED_FLAG, None)
