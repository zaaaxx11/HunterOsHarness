"""`hunter config provider add` interactive wizard + top-level shortcut (M2 §5).

Written against the M2 design doc. RED until the builder ships
``hunter.cli.provider_add`` (``run_provider_add_wizard`` / ``ProviderAddAnswers``
/ ``provider_add_updates``), the optional ``name`` argument and the top-level
``hunter provider`` shortcut — new symbols are imported inside the test bodies
so a missing implementation fails the test, not the collection.
Conventions copied from tests/test_cli_init_v2.py: string consoles,
``$HUNTEROS_CONFIG`` sandbox + ``HOME``/``USERPROFILE`` -> tmp_path,
needle-matching scripted ``ask`` (most-specific needle first), injected
``secret``/``ping_fn``/``probe_fn``/``list_models_fn`` — zero network, zero
machine-HOME writes, keys never echoed.
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
from hunter.errors import HunterError
from hunter.llm.base import TIERS
from hunter.llm.config import load_config
from hunter.llm.ping import PingResult
from hunter.llm.providers import known_provider
from hunter.llm.writing import write_config

runner = CliRunner()
SENTINEL = "sk-sentinel-m2-never-echo-9213"
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
    """Needle-matching ask: most-specific needle first (v1/v2 convention).

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


def _no_probe(*_args, **_kwargs):
    raise AssertionError("probe_fn must not be called")


def _no_list_models(*_args, **_kwargs):
    raise AssertionError("list_models_fn must not be called")


def _no_ping(*_args, **_kwargs):
    raise AssertionError("ping_fn must not be called")


def _cli_env(monkeypatch, tmp_path):
    # HOME/USERPROFILE -> tmp_path keeps the $HUNTEROS_CONFIG target in-home
    # for the containment guard on every OS (test_cli_init_v2 convention).
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)


@pytest.fixture(autouse=True)
def _m2_env_hygiene(monkeypatch):
    """No machine env leaks between tests (design doc §12 hygiene rules)."""
    for var in (
        "HUNTEROS_CONFIG", "HUNTEROS_TIER", "HUNTEROS_KEYS_FILE",
        "GROQ_API_KEY", "OPENAI_API_KEY", "CUSTOM_API_KEY", "CORP_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def _raw(path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


class _EofConsole(Console):
    """A console whose input() is already at EOF: drives the EOF-default path
    (same pattern as tests/test_cli_init_v2.py — _default_ask catches EOFError
    and returns the prompt's default)."""

    def input(self, *args, **kwargs) -> str:
        raise EOFError


# ------------------------------------------------------------- W1/W2/W3 --


def test_provider_add_wizard_auto_mode_writes_tiers(tmp_path):
    """W1: the name-omission trigger runs the wizard; auto mode writes the
    provider block + all four canonical tiers; the merge preserves the rest."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    target.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")
    console, err_console, out = _string_console()
    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        probe_fn=_no_probe,
        list_models_fn=_no_list_models,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    cfg = load_config(target, env={}, home=tmp_path)
    table = known_provider("groq")
    for tier in TIERS:
        assert cfg.model_tiers[tier].provider == "groq"
        assert cfg.model_tiers[tier].model == table.default_model
    assert cfg.providers["groq"].key_env == "GROQ_API_KEY"
    assert cfg.budget.max_iterations == 42  # untouched elsewhere — merge preserved
    assert cfg.agent.tier == "basic"


def test_provider_add_wizard_custom_key_and_endpoint(tmp_path):
    """W2: the pasted key lands in keys.env only; the probe result is stored."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    console, err_console, out = _string_console()
    seen: list[tuple] = []

    def probe(base_url, key, timeout, _seen=seen, **_kwargs):
        _seen.append((base_url, key, timeout))
        return "responses"

    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("env var name", "CORP_KEY"),
                ("endpoint", "3"),  # auto-detect
                ("model", "1"),
                ("provider", "custom"),
            ]
        ),
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        probe_fn=probe,
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        environ={},
        home=tmp_path,
    )
    assert code == 0
    assert seen[0] == (CUSTOM_BASE_URL, SENTINEL, 10)  # probed with the pasted key value
    text = target.read_text(encoding="utf-8")
    assert "api_key" not in text  # never in the config
    assert SENTINEL not in text and SENTINEL not in _wizard_text(out, err_console)
    keys_text = (tmp_path / ".hunteros" / "keys.env").read_text(encoding="utf-8")
    assert f'CORP_KEY="{SENTINEL}"' in keys_text
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["custom"].key_env == "CORP_KEY"
    assert cfg.providers["custom"].base_url == CUSTOM_BASE_URL
    assert cfg.providers["custom"].endpoint == "responses"


def test_provider_add_wizard_autodetect_and_failure_note(tmp_path):
    """W3: the probe seam receives (base_url, key_value, 10); empty/raised probes
    are a note with no endpoint stored, exit 0."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "probe-ok.yaml"
    console, err_console, out = _string_console()
    seen: list[tuple] = []

    def probe(base_url, key, timeout, _seen=seen, **_kwargs):
        _seen.append((base_url, key, timeout))
        return "chat"

    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("endpoint", "3"),
                ("model", "1"),
                ("provider", "custom"),
            ]
        ),
        ping_fn=_ok_ping,
        probe_fn=probe,
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0
    assert seen[0] == (CUSTOM_BASE_URL, "sk-custom-123", 10)
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["custom"].endpoint == "chat"

    def broken_probe(*_args, **_kwargs):
        raise RuntimeError("probe endpoint down")

    for index, probe_fn in enumerate((lambda *_args, **_kwargs: "", broken_probe)):
        console, err_console, out = _string_console()
        fail_target = tmp_path / f"probe-fail-{index}.yaml"
        code = run_provider_add_wizard(
            path=fail_target,
            console=console,
            err_console=err_console,
            ask=_scripted_ask(
                [
                    ("base URL", CUSTOM_BASE_URL),
                    ("endpoint", "3"),
                    ("model", "1"),
                    ("provider", "custom"),
                ]
            ),
            ping_fn=_ok_ping,
            probe_fn=probe_fn,
            list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
            environ={"CUSTOM_API_KEY": "sk-custom-123"},
            home=tmp_path,
        )
        assert code == 0
        assert "endpoint probe failed" in _wizard_text(out, err_console)
        cfg = load_config(fail_target, env={}, home=tmp_path)
        assert cfg.providers["custom"].endpoint == ""


# ------------------------------------------------------------- W4/W5/W6 --


def test_provider_add_wizard_endpoint_menu_semantics(tmp_path):
    """W4: default stores nothing; option 2 stores responses probe-free;
    without a base_url the auto-detect option is not offered."""
    from hunter.cli.provider_add import run_provider_add_wizard

    # (a) default (option 1) stores NO endpoint key; probe never called.
    target = tmp_path / "default.yaml"
    console, err_console, out = _string_console()
    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("model", "1"),
                ("provider", "custom"),
            ]
        ),  # the endpoint prompt takes its default (1)
        ping_fn=_ok_ping,
        probe_fn=_no_probe,
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0
    assert "endpoint" not in _raw(target)["providers"]["custom"]
    assert "3. auto-detect" in _wizard_text(out, err_console)  # base_url -> option 3 offered

    # (b) option 2 stores responses WITHOUT probe_fn being called.
    target2 = tmp_path / "responses.yaml"
    console, err_console, out2 = _string_console()
    code = run_provider_add_wizard(
        path=target2,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("endpoint", "2"),
                ("model", "1"),
                ("provider", "custom"),
            ]
        ),
        ping_fn=_ok_ping,
        probe_fn=_no_probe,
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0
    assert _raw(target2)["providers"]["custom"]["endpoint"] == "responses"

    # (c) a known provider without base_url renders a two-option menu only.
    target3 = tmp_path / "groq.yaml"
    console, err_console, out3 = _string_console()
    code = run_provider_add_wizard(
        path=target3,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        probe_fn=_no_probe,
        list_models_fn=_no_list_models,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    text3 = _wizard_text(out3, err_console)
    assert "1. chat" in text3 and "2. responses" in text3
    assert "auto-detect" not in text3


def test_provider_add_wizard_model_autolist_menu(tmp_path):
    """W5: the list_models menu renders and the pick fills all four tiers."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    console, err_console, out = _string_console()
    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("model", "2"),
                ("provider", "custom"),
            ]
        ),
        ping_fn=_ok_ping,
        probe_fn=lambda *_args, **_kwargs: "chat",
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha", "corp-beta", "corp-gamma"],
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
        assert cfg.model_tiers[tier].provider == "custom"
        assert cfg.model_tiers[tier].model == "corp-beta"


def test_provider_add_wizard_model_list_failure_fallback(tmp_path):
    """W6: an empty or raised model list is a note; the manual id fills all tiers."""
    from hunter.cli.provider_add import run_provider_add_wizard

    def broken_list(*_args, **_kwargs):
        raise RuntimeError("models endpoint down")

    for index, list_models_fn in enumerate((lambda *_args, **_kwargs: [], broken_list)):
        target = tmp_path / f"list-fail-{index}.yaml"
        console, err_console, out = _string_console()
        code = run_provider_add_wizard(
            path=target,
            console=console,
            err_console=err_console,
            ask=_scripted_ask(
                [
                    ("base URL", CUSTOM_BASE_URL),
                    ("model id", "manual-corp-model"),
                    ("provider", "custom"),
                ]
            ),
            ping_fn=_ok_ping,
            probe_fn=lambda *_args, **_kwargs: "chat",
            list_models_fn=list_models_fn,
            environ={"CUSTOM_API_KEY": "sk-custom-123"},
            home=tmp_path,
        )
        assert code == 0
        assert "model list failed" in _wizard_text(out, err_console)
        cfg = load_config(target, env={}, home=tmp_path)
        for tier in TIERS:
            assert cfg.model_tiers[tier].model == "manual-corp-model"


# ------------------------------------------------------------------- W7 --


def test_provider_add_wizard_advanced_role_assignment(tmp_path):
    """W7: advanced mode assigns per role; blanks inherit orchestrator/cheap."""
    from hunter.cli.provider_add import run_provider_add_wizard

    # Custom provider: no table -> "cheap" falls back to the orchestrator answer.
    target = tmp_path / "custom-advanced.yaml"
    console, err_console, out = _string_console()
    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("verifier model", "m-ver"),
                ("mode [1]", "2"),  # advanced
                ("model [1]", "1"),
                ("provider", "custom"),
            ]
        ),  # hunter/orchestrator/utility prompts: blank -> their defaults
        ping_fn=_ok_ping,
        probe_fn=lambda *_args, **_kwargs: "chat",
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        environ={"CUSTOM_API_KEY": "sk-custom-123"},
        home=tmp_path,
    )
    assert code == 0
    assert "step 5/6 roles: advanced" in _wizard_text(out, err_console)
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.model_tiers["orchestrator"].model == "corp-alpha"
    assert cfg.model_tiers["hunter"].model == "corp-alpha"  # blank -> the orchestrator answer
    assert cfg.model_tiers["verifier"].model == "m-ver"  # scripted exactly
    assert cfg.model_tiers["utility"].model == "corp-alpha"  # blank -> cheap (no table)

    # Known provider: blanks inherit the table's cheap model for verifier/utility.
    target2 = tmp_path / "groq-advanced.yaml"
    console2, err_console2, out2 = _string_console()
    code = run_provider_add_wizard(
        path=target2,
        console=console2,
        err_console=err_console2,
        ask=_scripted_ask(
            [
                ("hunter model", "m-hunter"),
                ("mode [1]", "2"),
                ("provider", "groq"),
            ]
        ),  # orchestrator/verifier/utility prompts: blank -> their defaults
        ping_fn=_ok_ping,
        probe_fn=_no_probe,
        list_models_fn=_no_list_models,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    table = known_provider("groq")
    cfg2 = load_config(target2, env={}, home=tmp_path)
    assert cfg2.model_tiers["orchestrator"].model == table.default_model
    assert cfg2.model_tiers["hunter"].model == "m-hunter"
    assert cfg2.model_tiers["verifier"].model == table.cheap_model
    assert cfg2.model_tiers["utility"].model == table.cheap_model


# ------------------------------------------------------------------- W8/W9 --


def test_provider_add_wizard_smoke_failure_and_key_silence(tmp_path):
    """W8: a failed smoke ping is a note with exit 0; the write still happened;
    the sentinel key never appears in stdout/stderr."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    console, err_console, out = _string_console()
    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask(
            [
                ("base URL", CUSTOM_BASE_URL),
                ("env var name", "CORP_KEY"),
                ("model", "1"),
                ("provider", "custom"),
            ]
        ),  # endpoint prompt: default
        secret=lambda _prompt: SENTINEL,
        ping_fn=_boom_ping,
        probe_fn=_no_probe,
        list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
        environ={},
        home=tmp_path,
    )
    assert code == 0
    text = _wizard_text(out, err_console)
    assert "smoke test failed" in text
    assert SENTINEL not in text
    assert target.is_file()  # the write still happened
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["custom"].key_env == "CORP_KEY"


def test_provider_add_wizard_known_provider_without_base_url(tmp_path):
    """W9: no auto-detect option, no list_models call, table-default model,
    and a providers block without base_url/endpoint keys."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    console, err_console, out = _string_console()
    code = run_provider_add_wizard(
        path=target,
        console=console,
        err_console=err_console,
        ask=_scripted_ask([("provider", "groq")]),
        ping_fn=_ok_ping,
        probe_fn=_no_probe,
        list_models_fn=_no_list_models,
        environ={"GROQ_API_KEY": "sk-env-groq"},
        home=tmp_path,
    )
    assert code == 0
    assert "auto-detect" not in _wizard_text(out, err_console)
    assert _raw(target)["providers"]["groq"] == {"key_env": "GROQ_API_KEY"}
    table = known_provider("groq")
    cfg = load_config(target, env={}, home=tmp_path)
    for tier in TIERS:
        assert cfg.model_tiers[tier].model == table.default_model


def test_provider_add_wizard_eof_defaults_exit_0(tmp_path):
    """Adversarial (doc §11 row 5): EOF on every prompt falls back to defaults —
    the run exits 0 and leaves a loadable config, never a key it did not
    receive, and never dials (v2 onboarding EOF precedent)."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    code = run_provider_add_wizard(
        path=target,
        console=_EofConsole(file=io.StringIO(), width=200, legacy_windows=False),
        err_console=Console(file=io.StringIO(), width=200, legacy_windows=False),
        secret=lambda _prompt: "",  # the EOF paste is empty
        ping_fn=_no_ping,
        probe_fn=_no_probe,
        list_models_fn=_no_list_models,
        environ={},
        home=tmp_path,
    )
    assert code == 0
    assert target.is_file()  # a loadable config (not a crash, not a half-write)
    cfg = load_config(target, env={}, home=tmp_path)
    assert cfg.providers["openai"].key_env == "OPENAI_API_KEY"  # the table default provider
    table = known_provider("openai")
    for tier in TIERS:
        assert cfg.model_tiers[tier].model == table.default_model
    assert not (tmp_path / ".hunteros" / "keys.env").exists()  # never a key it did not receive


# ----------------------------------------------------------------- W10/W11 --


def test_flagged_add_path_unchanged(monkeypatch, tmp_path):
    """W10: a NAME keeps today's flagged path — the wizard is name-omission
    only; --default-model pins the orchestrator tier and stores no endpoint."""
    import hunter.cli.provider_add as provider_add_module

    calls: list[int] = []
    monkeypatch.setattr(
        provider_add_module, "run_provider_add_wizard", lambda **_kwargs: calls.append(1) or 0
    )
    _cli_env(monkeypatch, tmp_path)

    result = runner.invoke(cli_main.app, ["config", "provider", "add", "mysterycorp"])
    assert result.exit_code == 2, (result.output, result.exception)
    assert "--base-url" in result.output
    assert calls == []  # the wizard was NOT triggered

    result = runner.invoke(
        cli_main.app,
        ["config", "provider", "add", "demo", "--base-url", "http://x/v1", "--default-model", "m1"],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == []
    cfg = load_config(os.environ["HUNTEROS_CONFIG"], env={})
    assert cfg.model_tiers["orchestrator"].model == "m1"
    assert "endpoint" not in _raw(os.environ["HUNTEROS_CONFIG"])["providers"]["demo"]


def test_provider_add_updates_pure_shape():
    """W11: the pure write_config fragment — exact dict equality."""
    from hunter.cli.provider_add import ProviderAddAnswers, provider_add_updates

    full = ProviderAddAnswers(
        provider="corp",
        base_url="https://corp.example.com/v1",
        endpoint="responses",
        key_env="CORP_KEY",
        role_models={
            "orchestrator": "m-o", "hunter": "m-h", "verifier": "m-v", "utility": "m-u",
        },
    )
    assert provider_add_updates(full) == {
        "providers": {
            "corp": {
                "key_env": "CORP_KEY",
                "base_url": "https://corp.example.com/v1",
                "endpoint": "responses",
            }
        },
        "model_tiers": {
            "orchestrator": {"provider": "corp", "model": "m-o"},
            "hunter": {"provider": "corp", "model": "m-h"},
            "verifier": {"provider": "corp", "model": "m-v"},
            "utility": {"provider": "corp", "model": "m-u"},
        },
    }

    no_model = ProviderAddAnswers(
        provider="corp", base_url="https://corp.example.com/v1", key_env="CORP_KEY",
    )
    assert provider_add_updates(no_model) == {
        "providers": {"corp": {"key_env": "CORP_KEY", "base_url": "https://corp.example.com/v1"}},
    }


# ----------------------------------------------------------------- W12/W13 --


def test_provider_top_level_shortcut_group(monkeypatch, tmp_path):
    """W12: `hunter provider ...` === `hunter config provider ...` (same app)."""
    import hunter.cli.provider_add as provider_add_module

    _cli_env(monkeypatch, tmp_path)
    write_config({"providers": {"demo": {"base_url": "http://x/v1"}}}, Path(os.environ["HUNTEROS_CONFIG"]))

    shortcut = runner.invoke(cli_main.app, ["provider", "list"])
    nested = runner.invoke(cli_main.app, ["config", "provider", "list"])
    assert shortcut.exit_code == 0, (shortcut.output, shortcut.exception)
    assert nested.exit_code == 0, (nested.output, nested.exception)
    assert shortcut.output == nested.output  # the same providers table

    calls: list[int] = []
    monkeypatch.setattr(
        provider_add_module, "run_provider_add_wizard", lambda **_kwargs: calls.append(1) or 0
    )
    add = runner.invoke(cli_main.app, ["provider", "add"])
    assert add.exit_code == 0, (add.output, add.exception)
    assert calls == [1]  # the wizard sentinel invoked exactly once


def test_provider_add_wizard_keys_env_written_first(tmp_path):
    """W13: keys.env is written BEFORE the config — a failing config write leaves
    the keys in place and propagates the classified error (no traceback)."""
    from hunter.cli.provider_add import run_provider_add_wizard

    target = tmp_path / "config.yaml"
    target.write_text("providers:\n  corp: flat-string\n", encoding="utf-8")
    before = target.read_bytes()
    console, err_console, out = _string_console()

    with pytest.raises(HunterError) as ei:
        run_provider_add_wizard(
            path=target,
            console=console,
            err_console=err_console,
            ask=_scripted_ask(
                [
                    ("base URL", CUSTOM_BASE_URL),
                    ("env var name", "CORP_KEY"),
                    ("model", "1"),
                    ("provider", "custom"),
                ]
            ),
            secret=lambda _prompt: SENTINEL,
            ping_fn=_no_ping,  # the write fails before any smoke dial
            probe_fn=_no_probe,
            list_models_fn=lambda *_args, **_kwargs: ["corp-alpha"],
            environ={},
            home=tmp_path,
        )
    assert ei.value.code == "config.write_failed"
    keys_text = (tmp_path / ".hunteros" / "keys.env").read_text(encoding="utf-8")
    assert f'CORP_KEY="{SENTINEL}"' in keys_text  # keys.env already exists
    assert target.read_bytes() == before  # the corrupted config is untouched
    assert SENTINEL not in _wizard_text(out, err_console)
