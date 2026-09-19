"""`hunter init` v2 onboarding wizard + auto-trigger (M1), rewritten per M11
§14 item 8 against the ONE unified wizard: ``run_init_wizard`` (M2).

The v1/v2 split is dead (Q9): ``run_onboarding``/``run_init`` are thin
deprecated wrappers. Surviving pins: EOF-defaults, disclaimer-last,
tools-never-abort, keys-before-config, keys.env-only secrets; the clobber
prompt is GONE (replaced by pre-write backup + keep-defaults); the browser
note is honest. Offer tests (``offer_onboarding``) keep the v2 API verbatim.

Conventions: string consoles, ``$HUNTEROS_CONFIG`` sandbox +
``HOME``/``USERPROFILE`` -> tmp_path, needle-matching scripted ``ask``,
injected ``ping_fn``/``probe_fn``/``list_models_fn``/``checks_fn`` — zero
network, zero machine-HOME writes. ``run_init_wizard`` is imported INSIDE the
tests so a missing implementation fails the test, not the collection.
"""

from __future__ import annotations

import io
import os

import pytest
from rich.console import Console
from typer.testing import CliRunner

from hunter.cli.main import app
from hunter.llm.base import TIERS
from hunter.llm.config import load_config
from hunter.llm.keys import keys_env_path
from hunter.llm.ping import PingResult
from hunter.llm.providers import known_provider

runner = CliRunner()
SENTINEL = "sk-sentinel-m1-never-echo-9137"
DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."
DECLINED_FLAG = "HUNTEROS_ONBOARD_DECLINED"
CUSTOM_BASE_URL = "https://llm.corp.example.com/v1"
STALE_BROWSER_COPY = "ships in a later release"
SILENT_FALLBACK_NOTE = "not recognized — using"
PROBE_UNVERIFIED = (
    "⚠️ Warning: could not verify this endpoint via {url}. Hunter will still save it."
)


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
    from hunter.cli.doctor_core import Check

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


def _run_wizard(tmp_path, **kwargs):
    """run_init_wizard with the shared seams pre-wired; returns (code, text)."""
    from hunter.cli.init_wizard import run_init_wizard

    console, err_console, out = _string_console()
    kwargs.setdefault("console", console)
    kwargs.setdefault("err_console", err_console)
    kwargs.setdefault("checks_fn", _fake_checks)
    code = run_init_wizard(**kwargs)
    return code, _wizard_text(out, err_console)


# ------------------------------------------------- unified wizard (M11 M2) --


def test_wizard_auto_mode_writes_all_four_tiers(tmp_path):
    """A1 (M11): quick mode + env-var key + table-default model -> config."""
    target = tmp_path / "config.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0, text
    assert "using $GROQ_API_KEY from the environment" in text
    cfg = load_config(target, env={}, home=tmp_path)
    table = known_provider("groq")
    for tier in TIERS:
        assert cfg.model_tiers[tier].provider == "groq"
        assert cfg.model_tiers[tier].model == table.default_model
    assert cfg.agent.tier == "basic"
    assert cfg.agent.browser is False


def test_wizard_pasted_key_goes_to_keys_env_not_config(tmp_path):
    """A2 (M11): the pasted key lands in keys.env; config carries key_env only."""
    target = tmp_path / "config.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=_scripted_ask([("provider", "groq"), ("key", "1")]),
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        environ={},
        home=tmp_path,
    )
    assert code == 0, text
    assert "api_key" not in target.read_text(encoding="utf-8")
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["groq"].key_env == "GROQ_API_KEY"
    keys_text = keys_env_path(env={}, home=tmp_path).read_text(encoding="utf-8")
    assert f'GROQ_API_KEY="{SENTINEL}"' in keys_text
    assert SENTINEL not in text


def test_wizard_advanced_mode_per_role_models(tmp_path):
    """A3 (M11): advanced mode assigns models per role; blanks inherit."""
    target = tmp_path / "config.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=_scripted_ask(
            [
                ("mode", "2"),
                ("orchestrator model", "m-orch"),
                ("hunter model", ""),
                ("verifier model", ""),
                ("utility model", ""),
                ("provider", "groq"),
            ]
        ),
        ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0, text
    cfg = load_config(target, env={}, home=tmp_path)
    cheap = known_provider("groq").cheap_model
    assert cfg.model_tiers["orchestrator"].model == "m-orch"
    assert cfg.model_tiers["hunter"].model == "m-orch"
    assert cfg.model_tiers["verifier"].model == cheap
    assert cfg.model_tiers["utility"].model == cheap


def test_wizard_custom_endpoint_probe_stores_chat_and_responses(tmp_path):
    """A4 (M11): the custom-provider probe result is stored in providers.<n>.endpoint."""
    for endpoint in ("chat", "responses"):
        target = tmp_path / f"probe-{endpoint}.yaml"
        seen: list[tuple] = []

        def probe(*args, _endpoint=endpoint, _seen=seen, **_kwargs):
            _seen.append(args)
            return _endpoint

        code, text = _run_wizard(
            tmp_path,
            path=target,
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
            environ={"CUSTOM_API_KEY": "sk-custom-123"},
            home=tmp_path,
        )
        assert code == 0, text
        cfg = load_config(target, env={}, home=tmp_path)
        assert cfg.providers["custom"].endpoint == endpoint
        assert seen[0][0] == CUSTOM_BASE_URL  # probed with the user-supplied URL...
        assert seen[0][1] == "sk-custom-123"  # ...and the captured key value


def test_wizard_probe_failure_is_the_advisory_warning(tmp_path):
    """A5 (M11): a failed probe is the pinned ⚠️ advisory line; still saves."""
    broken_probe = lambda *_args, **_kwargs: ""  # noqa: E731
    target = tmp_path / "fail.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("provider", "custom"),
                ("model", "1"),
            ]
        ),
        probe_fn=broken_probe,
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        ping_fn=_ok_ping,
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0, text
    assert PROBE_UNVERIFIED.format(url=CUSTOM_BASE_URL) in text
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["custom"].base_url == CUSTOM_BASE_URL  # still written


def test_wizard_model_autolist_menu_used_for_custom(tmp_path):
    """A6 (M11): the numbered model menu prints for custom and the pick fills tiers."""
    target = tmp_path / "config.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
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
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0, text
    assert "1. corp-alpha" in text and "2. corp-beta" in text
    cfg = load_config(target, env={}, home=tmp_path)
    for tier in TIERS:
        assert cfg.model_tiers[tier].model == "corp-beta"


def test_wizard_browser_true_writes_flag_and_honest_note(tmp_path):
    """A8 (M11): 'y' writes agent.browser true + the honest note; no stale copy."""
    yes_target = tmp_path / "yes.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=yes_target,
        ask=_scripted_ask([("provider", "groq"), ("web automation", "y")]),
        ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0, text
    assert "pip install 'hunteros-harness[browser]'" in text
    cfg = load_config(yes_target, env={}, home=tmp_path)
    assert cfg.agent.browser is True


def test_wizard_smoke_ping_failure_is_note_exit_0(tmp_path):
    """A9 (M11): a failed smoke ping is a note; the run still exits 0 and writes."""
    target = tmp_path / "config.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_boom_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0, text
    assert "smoke test failed" in text
    assert "wrote" in text
    assert target.is_file()


def test_wizard_key_is_never_echoed(tmp_path):
    """A10 (M11): the pasted sentinel never touches stdout/stderr."""
    keys_path = keys_env_path(env={}, home=tmp_path)
    code, text = _run_wizard(
        tmp_path,
        path=tmp_path / "config.yaml",
        ask=_scripted_ask([("provider", "groq"), ("key", "1")]),
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        environ={},
        home=tmp_path,
    )
    assert code == 0, text
    assert SENTINEL not in text
    assert keys_path.is_file()
    assert SENTINEL in keys_path.read_text(encoding="utf-8")


def test_wizard_disclaimer_on_every_terminal_path(tmp_path):
    """A11 (M11): the scope disclaimer is the last line on every terminal path
    (success, smoke-failure, cancel, eof-default) — the clobber-decline path
    no longer exists."""
    runs: list[tuple[str, int, str]] = []

    def _run(label, **kwargs):
        code, text = _run_wizard(tmp_path, **kwargs)
        runs.append((label, code, text))

    _run(
        "success",
        path=tmp_path / "ok.yaml",
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    _run(
        "smoke-failure",
        path=tmp_path / "smoke-fail.yaml",
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_boom_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )

    def cancelling_ask(prompt: str, default: str = "") -> str:
        if "provider" in prompt:
            raise KeyboardInterrupt
        return "1" if "mode" in prompt else default

    _run(
        "cancel",
        path=tmp_path / "cancel.yaml",
        ask=cancelling_ask,
        environ={},
        home=tmp_path,
    )

    eof_out = io.StringIO()
    eof_err = io.StringIO()
    from hunter.cli.init_wizard import run_init_wizard

    code = run_init_wizard(
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
        # Ctrl-C cancels with the 130 convention; every other terminal path is 0.
        assert run_code == (130 if label == "cancel" else 0), (label, text)
        assert text.strip().endswith(DISCLAIMER), label


def test_wizard_never_asks_clobber_and_backs_up_instead(tmp_path):
    """A12 (M11): the clobber prompt is GONE — an existing config is backed up
    and deep-merged, and the keep-defaults explainer prints."""
    target = tmp_path / "config.yaml"
    target.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")
    before = target.read_bytes()
    ask, prompts = _recording_ask()
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=ask,
        environ={},
        home=tmp_path,
    )
    assert code == 0, text
    assert not any("config already exists" in prompt for prompt in prompts)
    assert "Existing values are shown in brackets" in text
    assert list(tmp_path.glob("config.yaml.bak-*")), "a timestamped backup exists"
    # Deep-merge: the old key survives the wizard's write.
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.budget.max_iterations == 42
    assert target.read_bytes() != before  # the wizard DID write


def test_wizard_unrecognized_provider_pick_reasks_not_silent(tmp_path):
    """M11 §7: unrecognized menu input RE-ASKS with the numbered list."""
    answers = iter(["garbage-pick", "groq"])

    def ask(prompt: str, default: str = "") -> str:
        if "provider" in prompt:
            return next(answers)
        return default

    target = tmp_path / "config.yaml"
    code, text = _run_wizard(
        tmp_path,
        path=target,
        ask=ask,
        ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0, text
    assert text.count("1. openai") >= 2
    assert SILENT_FALLBACK_NOTE not in text
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.model_tiers["orchestrator"].provider == "groq"


def test_wizard_updates_shape_auto_and_no_provider():
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


# ------------------------------------------------- init routing + offers --


def test_init_command_routes_unified_wizard_for_both_modes(monkeypatch, tmp_path):
    """A13 (M11 Q9): interactive `init` AND `--provider/--yes` both run the ONE
    `run_init_wizard` (no separate v1 code path)."""
    import hunter.cli.init_wizard as init_wizard_module

    _cli_env(monkeypatch, tmp_path)
    calls: list[str] = []

    def fake_wizard(**_kwargs):
        calls.append("wizard")
        return 0

    monkeypatch.setattr(init_wizard_module, "run_init_wizard", fake_wizard)

    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == ["wizard"]

    calls.clear()
    result_yes = runner.invoke(app, ["init", "--provider", "groq", "--yes"])
    assert result_yes.exit_code == 0, (result_yes.output, result_yes.exception)
    assert calls == ["wizard"]


def test_bare_hunter_offer_accept_runs_wizard(monkeypatch, tmp_path):
    """A14: bare `hunter` offers the wizard; 'y' invokes run_init_wizard once."""
    import hunter.cli.init_wizard as init_wizard_module

    _cli_env(monkeypatch, tmp_path)
    calls: list[int] = []

    def fake_wizard(*_args, **_kwargs):
        calls.append(1)
        return 0

    monkeypatch.setattr(init_wizard_module, "run_init_wizard", fake_wizard)
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
