"""`hunter init` + bare-`hunter` welcome — first-run onboarding.

M11 §14 item 9: the `--provider/--yes` scriptable contract is folded into the
ONE unified wizard (`run_init_wizard`, Q9) — same exit codes, no separate v1
code path, and the v1 inline-key renderer is gone (keys.env ONLY).

No test touches the network: the live ping is either skipped (no key) or
injected (ping_fn seam). Config writes go to tmp paths only.
"""

from __future__ import annotations

import io

from rich.console import Console
from typer.testing import CliRunner

from hunter.llm.config import load_config
from hunter.llm.keys import keys_env_path
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
    # HOME/USERPROFILE -> tmp_path: pytest's tmp_path sits under /tmp on Linux
    # CI, which the $HUNTEROS_CONFIG containment guard refuses; with the
    # sandbox as home the env target is in-home on every OS (see
    # writing.resolve_config_target).
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)


def _run_wizard(tmp_path, **kwargs):
    """run_init_wizard with string consoles; returns (code, text)."""
    from hunter.cli.init_wizard import run_init_wizard

    console, err_console, out = _string_console()
    kwargs.setdefault("console", console)
    kwargs.setdefault("err_console", err_console)
    code = run_init_wizard(**kwargs)
    return code, out.getvalue() + err_console.file.getvalue()


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
    assert "Scan only systems you own" in result.output
    assert not (tmp_path / "config.yaml").exists()


def test_hunter_help_still_prints_full_dump(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    from hunter.cli.main import app

    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.output and "scan" in result.output


# --------------------------------------------------------------------- init --


def test_init_provider_openrouter_yes_writes_loadable_config(monkeypatch, tmp_path):
    """Same scriptable exit codes through the unified wizard (Q9)."""
    _cli_env(monkeypatch, tmp_path)
    from hunter.cli.main import app

    result = runner.invoke(app, ["init", "--provider", "openrouter", "--yes"])
    assert result.exit_code == 0, (result.output, result.exception)
    path = tmp_path / "config.yaml"
    assert path.is_file()
    cfg = load_config(path, env={}, home=tmp_path)
    table = known_provider("openrouter")
    assert cfg.model_tiers["orchestrator"].model == table.default_model
    assert cfg.model_tiers["orchestrator"].provider == "openrouter"
    assert cfg.providers["openrouter"].key_env == "OPENROUTER_API_KEY"
    assert cfg.agent.tier == "basic"
    assert "next: hunter doctor" in result.output


def test_init_with_existing_config_backs_up_and_merges(monkeypatch, tmp_path):
    """M11 M2 (§14 item 9): the v1 refusal is GONE — an existing config is
    backed up and deep-merged, exit 0."""
    _cli_env(monkeypatch, tmp_path)
    from hunter.cli.main import app

    path = tmp_path / "config.yaml"
    path.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "--provider", "openrouter", "--yes"])
    assert result.exit_code == 0, (result.output, result.exception)
    backups = list(tmp_path.glob("config.yaml.bak-*"))
    assert backups, "a timestamped pre-write backup must exist"
    assert "42" in backups[0].read_text(encoding="utf-8")  # the ORIGINAL bytes
    cfg = load_config(path, env={}, home=tmp_path)
    assert cfg.budget.max_iterations == 42  # merged, not clobbered
    assert cfg.model_tiers["orchestrator"].provider == "openrouter"  # and updated


def test_yes_path_writes_loadable_config_without_prompts(tmp_path):
    """run_init_wizard(yes=True, provider=...) — the v1 `run_init` contract."""
    code, text = _run_wizard(
        tmp_path,
        path=tmp_path / "yes.yaml",
        yes=True,
        provider="groq",
        environ={"GROQ_API_KEY": "sk-present"},
    )
    assert code == 0, text
    cfg = load_config(tmp_path / "yes.yaml", env={}, home=tmp_path)
    assert cfg.providers["groq"].key_env == "GROQ_API_KEY"
    assert cfg.model_tiers["orchestrator"].provider == "groq"
    assert cfg.agent.tier == "basic"


def test_key_is_never_echoed_and_lands_in_keys_env_only(tmp_path):
    """M11: pasted keys go to keys.env ONLY — the v1 inline api_key write is
    dead; the sentinel never reaches stdout/stderr."""
    code, text = _run_wizard(
        tmp_path,
        path=tmp_path / "paste.yaml",
        ask=lambda prompt, default="": "1" if "key" in prompt else default,
        secret=lambda _prompt: SECRET,
        environ={},
        home=tmp_path,
    )
    assert code == 0, text
    assert SECRET not in text  # the key is never echoed
    assert SECRET not in (tmp_path / "paste.yaml").read_text(encoding="utf-8")
    keys_text = keys_env_path(env={}, home=tmp_path).read_text(encoding="utf-8")
    assert f'GROQ_API_KEY="{SECRET}"' in keys_text


def test_wizard_smoke_failure_is_a_step_note_with_exit_0(tmp_path):
    def boom(*_args, **_kwargs):
        raise RuntimeError("no network in tests")

    code, text = _run_wizard(
        tmp_path,
        path=tmp_path / "fail.yaml",
        provider="groq",
        yes=True,
        ping_fn=boom,
        environ={"GROQ_API_KEY": "sk-present"},
        home=tmp_path,
    )
    assert code == 0, text
    assert "smoke test failed" in text
    assert "wrote" in text
    assert (tmp_path / "fail.yaml").is_file()


def test_init_custom_provider_yes_requires_base_url(tmp_path):
    code, _text = _run_wizard(
        tmp_path,
        path=tmp_path / "custom.yaml",
        provider="custom",
        yes=True,
        environ={"CUSTOM_API_KEY": "sk-c"},
        home=tmp_path,
    )
    assert code == 2


def test_init_unknown_provider_exits_2(tmp_path):
    code, _text = _run_wizard(
        tmp_path,
        path=tmp_path / "nope.yaml",
        provider="definitely-not-a-provider",
        yes=True,
        environ={},
        home=tmp_path,
    )
    assert code == 2
