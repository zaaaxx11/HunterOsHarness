"""`hunter init` + bare-`hunter` welcome — first-run onboarding.

No test touches the network: the live ping is either skipped (no key) or
injected (ping_fn seam). Config writes go to tmp paths only.
"""

from __future__ import annotations

import io

import yaml
from rich.console import Console
from typer.testing import CliRunner

from hunter.cli.init_wizard import InitAnswers, build_config_yaml, run_init
from hunter.llm.config import load_config, resolve_key
from hunter.llm.ping import PingResult
from hunter.llm.providers import known_provider

runner = CliRunner()
SECRET = "sk-supersecret-42-never-echo"


def _string_console() -> tuple[Console, Console, io.StringIO]:
    out = io.StringIO()
    err = io.StringIO()
    console = Console(file=out, width=200, legacy_windows=False)
    err_console = Console(file=err, width=200, legacy_windows=False)
    return console, err_console, out


def _cli_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)


# ------------------------------------------------------------------ welcome --


def test_bare_hunter_shows_welcome_panel_and_writes_no_config(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    result = runner.invoke(__import__("hunter.cli.main", fromlist=["app"]).app, [])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "HunterOs Harness v" in result.output
    assert "hunter init" in result.output
    assert "hunter demo" in result.output
    assert "hunter doctor" in result.output
    assert "every finding is proven by a hash-chained ledger" in result.output
    assert "scan only what you own" in result.output
    assert not (tmp_path / "config.yaml").exists()


def test_hunter_help_still_prints_full_dump(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    from hunter.cli.main import app

    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.output and "scan" in result.output


# --------------------------------------------------------------------- init --


def test_init_provider_openrouter_yes_writes_loadable_config(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    from hunter.cli.main import app

    result = runner.invoke(app, ["init", "--provider", "openrouter", "--yes"])
    assert result.exit_code == 0, (result.output, result.exception)
    path = tmp_path / "config.yaml"
    assert path.is_file()
    cfg = load_config(path, env={}, home=tmp_path)
    table = known_provider("openrouter")
    assert cfg.model_tiers["planner"].model == table.default_model
    assert cfg.model_tiers["planner"].provider == "openrouter"
    assert cfg.providers["openrouter"].key_env == "OPENROUTER_API_KEY"
    assert cfg.agent.tier == "basic"
    assert "next: hunter doctor" in result.output


def test_init_refuses_to_clobber_existing_config(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    from hunter.cli.main import app

    path = tmp_path / "config.yaml"
    path.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "--provider", "openrouter", "--yes"])
    assert result.exit_code == 2, (result.output, result.exception)
    # rich soft-wraps long paths mid-token — assert on the stable fragments.
    assert "refusing to overwrite" in result.output
    assert "config.yaml" in result.output
    assert "--path" in result.output
    # The existing file is untouched.
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["budget"]["max_iterations"] == 42


def test_build_config_yaml_output_passes_loader(tmp_path):
    keyed = InitAnswers(
        tier="advanced",
        provider="groq",
        key_env="GROQ_API_KEY",
        model="llama-3.3-70b-versatile",
        verify_model="llama-3.1-8b-instant",
    )
    path = tmp_path / "keyed.yaml"
    path.write_text(build_config_yaml(keyed), encoding="utf-8")
    cfg = load_config(path, env={}, home=tmp_path)
    assert cfg.agent.tier == "advanced"
    assert cfg.model_tiers["planner"].model == "llama-3.3-70b-versatile"
    assert cfg.model_tiers["verify"].model == "llama-3.1-8b-instant"
    assert cfg.providers["groq"].key_env == "GROQ_API_KEY"

    # Keyless answers produce a base_url-only block that loads WITHOUT keys.
    keyless = InitAnswers(tier="basic", provider="ollama", base_url="http://127.0.0.1:11434",
                          model="llama3")
    path2 = tmp_path / "keyless.yaml"
    path2.write_text(build_config_yaml(keyless), encoding="utf-8")
    cfg2 = load_config(path2, env={}, home=tmp_path)
    assert cfg2.providers["ollama"].base_url == "http://127.0.0.1:11434"
    assert resolve_key("ollama", cfg2, env={}) == ""  # keyless, no auth error


def test_key_is_never_echoed_but_written_inline(tmp_path):
    console, err_console, out = _string_console()
    answers: list[tuple[str, str]] = []

    def ask(prompt: str, default: str = "") -> str:
        answers.append((prompt, default))
        scripted = {
            "API key env var name": "GROQ_API_KEY",  # most-specific needle first
            "tier": "basic",
            "provider": "groq",
        }
        for needle, reply in scripted.items():
            if needle in prompt:
                return reply
        return default  # model prompts take the table default

    def boom(*_args, **_kwargs):
        return PingResult(ok=False, message="[ERROR timeout] no net")

    code = run_init(
        path=tmp_path / "inline.yaml",
        yes=False,
        console=console,
        err_console=err_console,
        ask=ask,
        secret=lambda _prompt: SECRET,
        ping_fn=boom,
        environ={},
        home=tmp_path,
    )
    assert code == 0
    text = out.getvalue() + err_console.file.getvalue()
    assert SECRET not in text  # the key is never echoed
    assert "SetEnvironmentVariable('GROQ_API_KEY','<key>','User')" in text
    assert "export GROQ_API_KEY=<key>" in text
    written = yaml.safe_load((tmp_path / "inline.yaml").read_text(encoding="utf-8"))
    assert written["providers"]["groq"]["api_key"] == SECRET


def test_wizard_failure_is_a_step_note_with_exit_0(tmp_path):
    console, err_console, out = _string_console()

    def boom(*_args, **_kwargs):
        raise RuntimeError("no network in tests")

    code = run_init(
        path=tmp_path / "fail.yaml",
        provider="groq",
        yes=True,
        console=console,
        err_console=err_console,
        ping_fn=boom,
        environ={"GROQ_API_KEY": "sk-present"},
        home=tmp_path,
    )
    assert code == 0
    text = out.getvalue()
    assert "live test failed" in text
    assert "wrote" in text
    assert (tmp_path / "fail.yaml").is_file()


def test_init_custom_provider_yes_requires_base_url(tmp_path):
    console, err_console, out = _string_console()
    code = run_init(
        path=tmp_path / "custom.yaml",
        provider="custom",
        yes=True,
        console=console,
        err_console=err_console,
        home=tmp_path,
    )
    assert code == 2


def test_init_unknown_provider_exits_2(tmp_path):
    console, err_console, out = _string_console()
    code = run_init(
        path=tmp_path / "nope.yaml",
        provider="definitely-not-a-provider",
        yes=True,
        console=console,
        err_console=err_console,
        home=tmp_path,
    )
    assert code == 2
