"""M11 M2 — init 3.0: ONE wizard (`run_init_wizard`) — §7 test plan.

Spec: docs/plans/m11-ux.md §2.2 Q9, §7. The unified wizard is NEW
(``run_init_wizard`` in ``src/hunter/cli/init_wizard.py``), so every test
imports it INSIDE the body — red (ImportError) until M2 lands, never a
collection error. Conventions copied from test_cli_init_v2.py: rich string
consoles (width 200 for byte-exact copy pins), needle-matching scripted
``ask``/``secret``, injected ``ping_fn``/``probe_fn``/``list_models_fn``/
``checks_fn`` — zero network, all writes under tmp_path homes.
"""

from __future__ import annotations

import io
from pathlib import Path

import yaml
from rich.console import Console

from hunter.llm.keys import keys_env_path
from hunter.llm.ping import PingResult

SENTINEL = "sk-m11-init-sentinel-never-echo"
DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."
CUSTOM_BASE_URL = "https://llm.corp.example.com/v1"
STALE_BROWSER_COPY = "ships in a later release"
SILENT_FALLBACK_NOTE = "not recognized — using"

# §7 pinned copy (byte-exact where the spec pins it).
MODE_PICKER_LINES = (
    "How should I set HunterOS up?",
    "1. Quick (recommended) — pick a provider, paste a key, done (~1 minute)",
    "2. Advanced — choose a model for every role (orchestrator / hunter / verifier / utility)",
    "3. Blank Slate — write a commented default config; add a provider later",
)
KEEP_DEFAULTS_LINE = (
    "Existing values are shown in brackets — Press Enter to keep it, "
    "or type a new value to change it."
)
CANCEL_NOTHING = "⏸️ cancelled — nothing was changed."
CANCEL_KEPT_CONFIG = "the config was written; run `hunter doctor` to verify."
REMAINING_SECTIONS = "Remaining sections were not changed."
BROWSER_NOTE_HONEST = (
    "agent.browser is stored; it activates with the optional extra — "
    "pip install 'hunteros-harness[browser]'"
)
PROBE_VERIFIED = "✅ Verified endpoint via {url} ({count} model(s) visible)"
PROBE_UNVERIFIED = (
    "⚠️ Warning: could not verify this endpoint via {url}. Hunter will still save it."
)


def _string_consoles():
    out = io.StringIO()
    err = io.StringIO()
    console = Console(file=out, width=200, legacy_windows=False)
    err_console = Console(file=err, width=200, legacy_windows=False)
    return console, err_console, out, err


def _wizard_text(out, err) -> str:
    return out.getvalue() + err.getvalue()


def _ok_ping(*_args, **_kwargs):
    return PingResult(ok=True, latency_ms=7, message="OK (7 ms)")


def _fake_checks():
    from hunter.cli.doctor_core import Check

    return [Check("python", "ok", "3.10 on Windows"), Check("state-dir", "ok", "sandbox")]


class _EofConsole(Console):
    """A console whose input() is already at EOF: drives the default contract."""

    def input(self, *args, **kwargs) -> str:
        raise EOFError


def _default_ask(prompt: str, default: str = "") -> str:
    """Every prompt takes its default (Quick mode, browser off, models kept)."""
    return default


def _run(**kwargs):
    """run_init_wizard with the shared seams pre-wired; returns (code, text)."""
    from hunter.cli.init_wizard import run_init_wizard

    console, err_console, out, err = _string_consoles()
    kwargs.setdefault("console", console)
    kwargs.setdefault("err_console", err_console)
    kwargs.setdefault("checks_fn", _fake_checks)
    code = run_init_wizard(**kwargs)
    return code, _wizard_text(out, err)


def _run_with_ask(ask, **kwargs):
    from hunter.cli.init_wizard import run_init_wizard

    console, err_console, out, err = _string_consoles()
    code = run_init_wizard(
        console=console, err_console=err_console, checks_fn=_fake_checks, ask=ask, **kwargs
    )
    return code, _wizard_text(out, err)


# -- 1 --------------------------------------------------------------------------


def test_mode_quick_default_via_blank_and_eof(tmp_path):
    """Blank mode answer -> Quick; EOF stdin -> the same defaults, completes."""
    target = tmp_path / "config.yaml"
    code, text = _run(
        path=target, ask=_default_ask,
        ping_fn=_ok_ping, environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    for line in MODE_PICKER_LINES:
        assert line in text, line
    cfg = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert cfg["model_tiers"]["orchestrator"]["provider"] == "groq"

    # EOF stdin (the real default-ask contract): the wizard still completes.
    from hunter.cli.init_wizard import run_init_wizard

    eof_out, eof_err = io.StringIO(), io.StringIO()
    code2 = run_init_wizard(
        path=tmp_path / "eof.yaml",
        console=_EofConsole(file=eof_out, width=200, legacy_windows=False),
        err_console=Console(file=eof_err, width=200, legacy_windows=False),
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={},
        home=tmp_path,
    )
    assert code2 == 0
    assert (tmp_path / "eof.yaml").is_file()
    assert DISCLAIMER in eof_out.getvalue() + eof_err.getvalue()


# -- 2 --------------------------------------------------------------------------


def test_mode_blank_slate_writes_default_config_only(tmp_path):
    """Blank Slate: ONE prompt total, commented default config, no provider."""
    prompts: list[str] = []

    def ask(prompt: str, default: str = "") -> str:
        prompts.append(prompt)
        return "3" if "mode" in prompt else default

    target = tmp_path / "config.yaml"
    code, text = _run_with_ask(ask, path=target, environ={}, home=tmp_path)
    assert code == 0, text
    assert len(prompts) == 1, prompts  # the mode picker is the only prompt
    cfg = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert not (cfg.get("providers") or {})
    assert "agent" in cfg and DISCLAIMER in text


# -- 3 --------------------------------------------------------------------------


def test_existing_config_is_backed_up_and_values_kept(tmp_path):
    """Existing values are keep-defaults; the write is a deep MERGE with a
    timestamped pre-write backup."""
    target = tmp_path / "config.yaml"
    target.write_text(
        "budget:\n  max_cost_usd: 5.0\n"
        "providers:\n  groq:\n    key_env: GROQ_API_KEY\n"
        "model_tiers:\n  orchestrator:\n    provider: groq\n    model: m-old\n",
        encoding="utf-8",
    )
    code, text = _run_with_ask(
        _default_ask, path=target, ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    assert KEEP_DEFAULTS_LINE in text
    backups = list(tmp_path.glob("config.yaml.bak-*"))
    assert backups, "a timestamped pre-write backup must exist"
    backup = backups[0]
    assert f"Previous config backed up to: {backup}" in text
    assert "m-old" in backup.read_text(encoding="utf-8")  # the ORIGINAL values
    cfg = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert cfg["budget"]["max_cost_usd"] == 5.0  # old key merged, not clobbered
    assert cfg["model_tiers"]["orchestrator"]["model"] == "m-old"  # kept


# -- 4 --------------------------------------------------------------------------


def test_existing_values_editable_by_typing_new_value(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(
        "providers:\n  groq:\n    key_env: GROQ_API_KEY\n"
        "model_tiers:\n  orchestrator:\n    provider: groq\n    model: m-old\n",
        encoding="utf-8",
    )

    def ask(prompt: str, default: str = "") -> str:
        if "orchestrator" in prompt and "model" in prompt:
            return "m-new"
        return default

    code, text = _run_with_ask(
        ask, path=target, ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    cfg = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert cfg["model_tiers"]["orchestrator"]["model"] == "m-new"


# -- 5/6/7 (adversarial: Ctrl+C at every wizard step) ----------------------------


def test_ctrl_c_before_writes_changes_nothing(tmp_path):
    """KI at the provider step: exit 130, cancelled copy, NO config/keys write,
    the pre-existing backup (taken at wizard start) still present."""
    target = tmp_path / "config.yaml"
    target.write_text("budget:\n  max_iterations: 42\n", encoding="utf-8")

    def ask(prompt: str, default: str = "") -> str:
        if "provider" in prompt:
            raise KeyboardInterrupt
        return "1" if "mode" in prompt else default

    code, text = _run_with_ask(ask, path=target, environ={}, home=tmp_path)
    assert code == 130, text
    assert CANCEL_NOTHING in text
    assert yaml.safe_load(target.read_text(encoding="utf-8"))["budget"]["max_iterations"] == 42
    assert list(tmp_path.glob("config.yaml.bak-*")), "backup taken at wizard start"
    assert not keys_env_path(env={}, home=tmp_path).exists()


def test_ctrl_c_after_writes_reports_config_kept(tmp_path):
    """KI during the post-write smoke ping: the config stays, exit 130."""
    target = tmp_path / "config.yaml"

    def boom_interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    code, text = _run(
        path=target, ask=_default_ask, ping_fn=boom_interrupt,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 130, text
    assert CANCEL_KEPT_CONFIG in text
    assert target.is_file()  # the write survived


def test_advanced_partial_abort_appends_remaining_sections_line(tmp_path):
    """KI mid-Advanced: cancelled copy + `Remaining sections were not changed.`"""
    target = tmp_path / "config.yaml"

    def ask(prompt: str, default: str = "") -> str:
        if "orchestrator" in prompt and "model" in prompt:
            raise KeyboardInterrupt
        if "mode" in prompt:
            return "2"  # Advanced
        return default

    code, text = _run_with_ask(
        ask, path=target, environ={"GROQ_API_KEY": "sk-env"}, home=tmp_path
    )
    assert code == 130, text
    assert CANCEL_NOTHING in text
    assert REMAINING_SECTIONS in text
    assert not target.exists()  # writes are buffered to the end: nothing landed


# -- 8 --------------------------------------------------------------------------


def test_yes_noninteractive_writes_basic_config(tmp_path):
    """--yes: prompts are IMPOSSIBLE (ask/secret would explode); basic config."""

    def forbidden(*_args, **_kwargs):
        raise AssertionError("--yes must never prompt")

    code, text = _run(
        path=tmp_path / "config.yaml", yes=True, provider="groq",
        ask=forbidden, secret=forbidden,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    assert "$GROQ_API_KEY" in text  # notes mention the env var
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["providers"]["groq"]["key_env"] == "GROQ_API_KEY"
    assert "api_key" not in (tmp_path / "config.yaml").read_text(encoding="utf-8")


# -- 9 (Q9 contract) -------------------------------------------------------------


def test_yes_with_provider_validates_like_v1(tmp_path):
    code, text = _run(
        path=tmp_path / "nope.yaml", yes=True, provider="definitely-not-a-provider",
        environ={}, home=tmp_path,
    )
    assert code == 2, text
    assert "groq" in text  # the known-provider list

    code2, text2 = _run(
        path=tmp_path / "custom.yaml", yes=True, provider="custom",
        environ={"CUSTOM_API_KEY": "sk-c"}, home=tmp_path,
    )
    assert code2 == 2, text2  # custom without a base URL


# -- 10 --------------------------------------------------------------------------


def test_yes_never_invents_a_key(tmp_path):
    code, text = _run(
        path=tmp_path / "config.yaml", yes=True, provider="groq",
        environ={}, home=tmp_path,  # no key anywhere
    )
    assert code == 0, text
    assert "set $GROQ_API_KEY" in text  # the pinned note
    assert not keys_env_path(env={}, home=tmp_path).exists()  # no keys.env
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["providers"]["groq"]["key_env"] == "GROQ_API_KEY"


# -- 11 (adversarial: EOF mid-wizard) ---------------------------------------------


def test_eof_falls_back_to_defaults_and_completes(tmp_path):
    from hunter.cli.init_wizard import run_init_wizard

    eof_out, eof_err = io.StringIO(), io.StringIO()
    code = run_init_wizard(
        path=tmp_path / "config.yaml",
        console=_EofConsole(file=eof_out, width=200, legacy_windows=False),
        err_console=Console(file=eof_err, width=200, legacy_windows=False),
        ping_fn=_ok_ping,
        checks_fn=_fake_checks,
        environ={},
        home=tmp_path,
    )
    text = eof_out.getvalue() + eof_err.getvalue()
    assert code == 0, text
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert "agent" in cfg  # a valid config landed
    assert "default" in text.lower()  # the notes list what defaulted


# -- 12 --------------------------------------------------------------------------


def test_unrecognized_provider_pick_reasks_not_silent(tmp_path):
    """Garbage pick -> the numbered menu AGAIN (no silent fallback to #1)."""
    answers = iter(["garbage-pick", "groq"])

    def ask(prompt: str, default: str = "") -> str:
        if "provider" in prompt:
            return next(answers)
        return default

    target = tmp_path / "config.yaml"
    code, text = _run_with_ask(
        ask, path=target, ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    assert text.count("1. openai") >= 2  # the numbered list re-asked
    assert SILENT_FALLBACK_NOTE not in text  # the old silent fallback is GONE
    cfg = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert cfg["model_tiers"]["orchestrator"]["provider"] == "groq"


# -- 13 --------------------------------------------------------------------------


def test_keys_env_written_before_config_and_never_echoed(tmp_path, monkeypatch):
    import hunter.cli.init_wizard as init_wizard_module

    order: list[str] = []
    real_keys = init_wizard_module.write_keys_env
    real_config = init_wizard_module.write_config

    def spy_keys(*args, **kwargs):
        order.append("keys")
        return real_keys(*args, **kwargs)

    def spy_config(*args, **kwargs):
        order.append("config")
        return real_config(*args, **kwargs)

    monkeypatch.setattr(init_wizard_module, "write_keys_env", spy_keys)
    monkeypatch.setattr(init_wizard_module, "write_config", spy_config)

    def ask(prompt: str, default: str = "") -> str:
        if "key" in prompt:
            return "1"  # paste route
        return default

    target = tmp_path / "config.yaml"
    code, text = _run_with_ask(
        ask, path=target, secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping, environ={}, home=tmp_path,
    )
    assert code == 0, text
    assert order[:2] == ["keys", "config"]  # keys.env BEFORE config
    keys_file = keys_env_path(env={}, home=tmp_path)
    assert keys_file.is_file() and SENTINEL in keys_file.read_text(encoding="utf-8")
    assert SENTINEL not in text  # the key is never echoed


# -- 14 --------------------------------------------------------------------------


def test_disclaimer_is_the_last_line(tmp_path):
    """SCOPE_DISCLAIMER is the final non-blank line on EVERY terminal path."""
    runs: list[tuple[str, int, str]] = []

    runs.append((
        "quick",
        *_run(
            path=tmp_path / "quick.yaml", ask=_default_ask, ping_fn=_ok_ping,
            environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
        ),
    ))

    def blank_ask(prompt: str, default: str = "") -> str:
        return "3" if "mode" in prompt else default

    runs.append(("blank", *_run_with_ask(blank_ask, path=tmp_path / "blank.yaml",
                                         environ={}, home=tmp_path)))
    runs.append((
        "yes",
        *_run(path=tmp_path / "yes.yaml", yes=True, provider="groq",
              environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path),
    ))

    def cancelling_ask(prompt: str, default: str = "") -> str:
        if "provider" in prompt:
            raise KeyboardInterrupt
        return "1" if "mode" in prompt else default

    runs.append(("cancel", *_run_with_ask(cancelling_ask, path=tmp_path / "cancel.yaml",
                                          environ={}, home=tmp_path)))

    for label, code, text in runs:
        assert code in (0, 130), (label, text)
        assert text.strip().endswith(DISCLAIMER), label


# -- 15 --------------------------------------------------------------------------


def test_browser_note_is_honest(tmp_path):
    """The pinned honest note replaces the stale 'ships in a later release'."""

    def yes_to_browser(prompt: str, default: str = "") -> str:
        if "web automation" in prompt:
            return "y"
        return default

    code, text = _run_with_ask(
        yes_to_browser, path=tmp_path / "config.yaml", ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    assert BROWSER_NOTE_HONEST in text
    # Static: the stale copy is gone from the module SOURCE.
    source = Path(__file__).parents[1] / "src" / "hunter" / "cli" / "init_wizard.py"
    assert STALE_BROWSER_COPY not in source.read_text(encoding="utf-8")


# -- 16 --------------------------------------------------------------------------


def test_next_command_hints_in_done_panel(tmp_path):
    code, text = _run(
        path=tmp_path / "config.yaml", ask=_default_ask, ping_fn=_ok_ping,
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, text
    for hint in ("hunter chat", "hunter demo", "hunter doctor", "hunter model"):
        assert hint in text, hint


# -- 17 (advisory probe copy; overlaps M4) ----------------------------------------


def test_custom_provider_advisory_probe_copy(tmp_path):
    def _run_custom(probe_fn):
        def ask(prompt: str, default: str = "") -> str:
            if "base URL" in prompt:
                return CUSTOM_BASE_URL
            if "provider" in prompt:
                return "custom"
            return default

        return _run_with_ask(
            ask, path=tmp_path / "custom.yaml", probe_fn=probe_fn,
            list_models_fn=lambda *_a, **_k: ["corp-alpha", "corp-beta"],
            ping_fn=_ok_ping, environ={"CUSTOM_API_KEY": "sk-custom-123"},
            home=tmp_path,
        )

    code, text = _run_custom(lambda *_a, **_k: "chat")
    assert code == 0, text
    assert PROBE_VERIFIED.format(url=CUSTOM_BASE_URL, count=2) in text

    code2, text2 = _run_custom(lambda *_a, **_k: "")
    assert code2 == 0, text2  # advisory, not fatal
    assert PROBE_UNVERIFIED.format(url=CUSTOM_BASE_URL) in text2


# -- 18 (v1/v2 split is dead) -----------------------------------------------------


def test_v1_v2_split_dead(tmp_path, monkeypatch):
    """run_onboarding/run_init still importable and DELEGATE to
    run_init_wizard (one release of import stability, then removable)."""
    import hunter.cli.init_wizard as init_wizard_module

    calls: list[dict] = []

    def fake_wizard(**kwargs):
        calls.append(kwargs)
        return 7  # a distinctive code proves the passthrough

    monkeypatch.setattr(init_wizard_module, "run_init_wizard", fake_wizard)
    assert init_wizard_module.run_onboarding(path=tmp_path / "a.yaml") == 7
    assert init_wizard_module.run_init(path=tmp_path / "b.yaml", yes=True) == 7
    assert len(calls) == 2
