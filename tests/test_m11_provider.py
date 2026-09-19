"""M11 M4 — provider/LLM as easy as Reference (§8 test plan).

Spec: docs/plans/m11-ux.md §8 + §3.2 copy. NEW symbols
(``key_env_for_endpoint``, ``is_local_endpoint``, ``run_model_picker``, the
``hunter model`` command) are imported INSIDE tests — red until M4. The
provider_add wizard re-point is driven through ``run_provider_add_wizard``
with injected probe/list/ping seams: ZERO network (the two
``run_model_picker`` list-tests seed loopback base URLs whose model lists are
fully faked via ``list_models_fn``).
"""

from __future__ import annotations

import io

import yaml
from rich.console import Console
from typer.testing import CliRunner

from hunter.cli.main import app
from hunter.llm.keys import keys_env_path
from hunter.llm.ping import PingResult

runner = CliRunner()

SENTINEL = "sk-m11-provider-sentinel-never-echo"
CUSTOM_BASE_URL = "https://llm.corp.example.com/v1"
DERIVED_VAR = "LLM_CORP_EXAMPLE_COM_API_KEY"  # key_env_for_endpoint(CUSTOM_BASE_URL)

PROBE_VERIFIED = "✅ Verified endpoint via {url} ({count} model(s) visible)"
PROBE_UNVERIFIED = (
    "⚠️ Warning: could not verify this endpoint via {url}. Hunter will still save it."
)
V1_HINT = "💡 If your server routes under /v1, try {url}/v1"
LOCAL_MODELS_HINT = "💡 is the server running? e.g. ollama serve (models appear at {url}/models)"
DETECTED = "Detected model: {model}"
MODEL_SET = "✅ model set: {model} → tiers orchestrator, hunter, verifier, utility, provider {name}"
KEY_SAVED = "✅ API key saved to keys.env as {var}"
NON_HTTP_REASK = "base URL must start with http:// or https:// — try again:"


def _string_console():
    out = io.StringIO()
    err = io.StringIO()
    console = Console(file=out, width=200, legacy_windows=False)
    err_console = Console(file=err, width=200, legacy_windows=False)
    return console, err_console, out, err


def _wizard_text(out, err) -> str:
    return out.getvalue() + err.getvalue()


def _scripted(script):
    """Needle-matching ask (v2 convention): unmatched prompts take the default."""

    def ask(prompt: str, default: str = "") -> str:
        for needle, reply in script:
            if needle in prompt:
                return reply if reply != "" else default
        return default

    return ask


def _ok_ping(*_args, **_kwargs):
    return PingResult(ok=True, latency_ms=5, message="OK (5 ms)")


# -- 1 --------------------------------------------------------------------------


def test_key_env_for_endpoint_table():
    """The pinned per-host(+port) derivation table (§8 change 1)."""
    from hunter.llm.providers import key_env_for_endpoint

    assert key_env_for_endpoint("https://api.atria-asi.ai/v1") == "ATRIA_ASI_AI_API_KEY"
    assert key_env_for_endpoint("http://127.0.0.1:8080/v1") == "K_127_0_0_1_8080_API_KEY"
    # Default port dropped.
    assert key_env_for_endpoint("https://api.example.com:443/v1") == "API_EXAMPLE_COM_API_KEY"
    assert key_env_for_endpoint("http://api.example.com/v1") == "API_EXAMPLE_COM_API_KEY"
    # Explicit non-default port appended.
    assert key_env_for_endpoint("http://api.example.com:8123/v1") == "API_EXAMPLE_COM_8123_API_KEY"


def test_is_local_endpoint_loopback_and_private():
    from hunter.llm.providers import is_local_endpoint

    assert is_local_endpoint("http://127.0.0.1:11434") is True
    assert is_local_endpoint("http://localhost:1234/v1") is True
    assert is_local_endpoint("http://192.168.1.10:8080/v1") is True
    assert is_local_endpoint("https://api.atria-asi.ai/v1") is False


# -- 2 (adversarial: bad URL inline re-ask, never a crash) ------------------------


def test_custom_flow_rejects_non_http_url_inline(tmp_path):
    from hunter.cli.provider_add import run_provider_add_wizard

    answers = iter(["ftp://x", CUSTOM_BASE_URL])

    def ask(prompt: str, default: str = "") -> str:
        if "base URL" in prompt:
            return next(answers)
        if "provider" in prompt:
            return "custom"
        return default

    console, err_console, out, err = _string_console()
    code = run_provider_add_wizard(
        path=tmp_path / "config.yaml",
        console=console,
        err_console=err_console,
        ask=ask,
        ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "chat",
        list_models_fn=lambda *_a, **_k: ["corp-alpha"],
        environ={"CUSTOM_API_KEY": "sk-c"},
        home=tmp_path,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert NON_HTTP_REASK in text  # the inline re-ask
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["providers"]["custom"]["base_url"] == CUSTOM_BASE_URL  # retry won


# -- 3 --------------------------------------------------------------------------


def test_custom_flow_probe_success_copy(tmp_path):
    from hunter.cli.provider_add import run_provider_add_wizard

    def ask(prompt: str, default: str = "") -> str:
        if "base URL" in prompt:
            return CUSTOM_BASE_URL
        if "provider" in prompt:
            return "custom"
        return default

    console, err_console, out, err = _string_console()
    code = run_provider_add_wizard(
        path=tmp_path / "config.yaml",
        console=console,
        err_console=err_console,
        ask=ask,
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "chat",
        list_models_fn=lambda *_a, **_k: ["corp-alpha", "corp-beta"],
        environ={},
        home=tmp_path,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert PROBE_VERIFIED.format(url=CUSTOM_BASE_URL, count=2) in text
    assert "1. corp-alpha" in text and "2. corp-beta" in text  # the numbered list


# -- 4 (advisory, not fatal) ------------------------------------------------------


def test_custom_flow_probe_failure_still_saves(tmp_path):
    from hunter.cli.provider_add import run_provider_add_wizard

    def ask(prompt: str, default: str = "") -> str:
        if "base URL" in prompt:
            return CUSTOM_BASE_URL
        if "provider" in prompt:
            return "custom"
        if "model" in prompt:
            return "corp-manual"
        return default

    console, err_console, out, err = _string_console()
    code = run_provider_add_wizard(
        path=tmp_path / "config.yaml",
        console=console,
        err_console=err_console,
        ask=ask,
        ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "",  # the probe found nothing
        list_models_fn=lambda *_a, **_k: [],
        environ={"CUSTOM_API_KEY": "sk-c"},
        home=tmp_path,
    )
    text = _wizard_text(out, err)
    assert code == 0, text  # advisory, not fatal
    assert PROBE_UNVERIFIED.format(url=CUSTOM_BASE_URL) in text
    assert V1_HINT.format(url=CUSTOM_BASE_URL) in text
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["providers"]["custom"]["base_url"] == CUSTOM_BASE_URL  # STILL written


# -- 5 --------------------------------------------------------------------------


def test_single_model_autodetected(tmp_path):
    from hunter.cli.model_cmd import run_model_picker

    home = tmp_path / "home"
    (home / ".hunter").mkdir(parents=True)
    (home / ".hunter" / "config.yaml").write_text(
        "providers:\n  custom:\n    base_url: http://127.0.0.1:9/v1\n"
        "    key_env: CUSTOM_API_KEY\n",
        encoding="utf-8",
    )
    console, err_console, out, err = _string_console()
    code = run_model_picker(
        console=console,
        err_console=err_console,
        ask=_scripted([("provider", "1"), ("model", "")]),
        list_models_fn=lambda *_a, **_k: ["only-model"],
        environ={},
        home=home,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert DETECTED.format(model="only-model") in text
    cfg = yaml.safe_load((home / ".hunter" / "config.yaml").read_text(encoding="utf-8"))
    for tier in ("orchestrator", "hunter", "verifier", "utility"):
        assert cfg["model_tiers"][tier]["model"] == "only-model"


# -- 6 --------------------------------------------------------------------------


def test_local_server_empty_models_hint(tmp_path):
    from hunter.cli.model_cmd import run_model_picker
    from hunter.llm.providers import is_local_endpoint

    home = tmp_path / "home"
    (home / ".hunter").mkdir(parents=True)
    (home / ".hunter" / "config.yaml").write_text(
        "providers:\n  ollama:\n    base_url: http://127.0.0.1:11434\n",
        encoding="utf-8",
    )
    assert is_local_endpoint("http://127.0.0.1:11434")

    console, err_console, out, err = _string_console()
    code = run_model_picker(
        console=console,
        err_console=err_console,
        ask=_scripted([("provider", "1"), ("model", "manual-llama")]),
        list_models_fn=lambda *_a, **_k: [],  # the server exposes nothing
        environ={},
        home=home,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert LOCAL_MODELS_HINT.format(url="http://127.0.0.1:11434") in text
    cfg = yaml.safe_load((home / ".hunter" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["model_tiers"]["orchestrator"]["model"] == "manual-llama"


# -- 7 (adversarial: key material only in keys.env) -------------------------------


def test_key_saved_confirmation_and_keys_env_only(tmp_path):
    from hunter.cli.provider_add import run_provider_add_wizard

    def ask(prompt: str, default: str = "") -> str:
        if "base URL" in prompt:
            return CUSTOM_BASE_URL
        if "provider" in prompt:
            return "custom"
        return default

    console, err_console, out, err = _string_console()
    code = run_provider_add_wizard(
        path=tmp_path / "config.yaml",
        console=console,
        err_console=err_console,
        ask=ask,
        secret=lambda _prompt: SENTINEL,
        ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "chat",
        list_models_fn=lambda *_a, **_k: ["corp-alpha", "corp-beta"],
        environ={},
        home=tmp_path,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert KEY_SAVED.format(var=DERIVED_VAR) in text  # per-host var, pinned copy
    keys_text = keys_env_path(env={}, home=tmp_path).read_text(encoding="utf-8")
    assert f'{DERIVED_VAR}="{SENTINEL}"' in keys_text
    raw_config = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert SENTINEL not in raw_config  # NO key material in the config
    assert SENTINEL not in text


# -- 8 --------------------------------------------------------------------------


def test_model_picker_writes_all_four_tiers(tmp_path):
    from hunter.cli.model_cmd import run_model_picker

    home = tmp_path / "home"
    home.mkdir()
    console, err_console, out, err = _string_console()
    code = run_model_picker(
        console=console,
        err_console=err_console,
        ask=_scripted([("provider", "groq"), ("model", "m-picked")]),
        environ={},
        home=home,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert MODEL_SET.format(model="m-picked", name="groq") in text
    cfg = yaml.safe_load((home / ".hunter" / "config.yaml").read_text(encoding="utf-8"))
    for tier in ("orchestrator", "hunter", "verifier", "utility"):
        assert cfg["model_tiers"][tier]["model"] == "m-picked"
        assert cfg["model_tiers"][tier]["provider"] == "groq"


# -- 9 --------------------------------------------------------------------------


def test_model_set_flag_direct_write(tmp_path, monkeypatch):
    home = tmp_path / "hunter-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)

    result = runner.invoke(app, ["model", "--set", "m1", "--provider", "openai"])
    assert result.exit_code == 0, (result.output, result.exception)
    cfg = yaml.safe_load((home / ".hunter" / "config.yaml").read_text(encoding="utf-8"))
    for tier in ("orchestrator", "hunter", "verifier", "utility"):
        assert cfg["model_tiers"][tier]["model"] == "m1"
        assert cfg["model_tiers"][tier]["provider"] == "openai"

    unknown = runner.invoke(app, ["model", "--set", "m1", "--provider", "nope"])
    assert unknown.exit_code == 2, (unknown.output, unknown.exception)


# -- 10 -------------------------------------------------------------------------


def test_model_tier_flag_restricts_write(tmp_path, monkeypatch):
    home = tmp_path / "hunter-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    (home / ".hunter").mkdir()
    (home / ".hunter" / "config.yaml").write_text(
        "model_tiers:\n"
        "  orchestrator: {provider: openai, model: old}\n"
        "  hunter: {provider: openai, model: old}\n"
        "  verifier: {provider: openai, model: old}\n"
        "  utility: {provider: openai, model: old}\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["model", "--set", "m1", "--provider", "openai",
                                 "--tier", "verifier"])
    assert result.exit_code == 0, (result.output, result.exception)
    cfg = yaml.safe_load((home / ".hunter" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["model_tiers"]["verifier"]["model"] == "m1"
    for tier in ("orchestrator", "hunter", "utility"):
        assert cfg["model_tiers"][tier]["model"] == "old"  # untouched


# -- 11 -------------------------------------------------------------------------


def test_model_picker_works_without_provider_config(tmp_path):
    from hunter.cli.model_cmd import run_model_picker

    home = tmp_path / "home"
    home.mkdir()
    console, err_console, out, err = _string_console()
    code = run_model_picker(
        console=console,
        err_console=err_console,
        ask=_scripted([("provider", "groq"), ("model", "m-picked")]),
        environ={},
        home=home,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert "1. openai" in text  # the known table is offered with no config
    cfg = yaml.safe_load((home / ".hunter" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["model_tiers"]["orchestrator"]["provider"] == "groq"
    assert cfg["model_tiers"]["orchestrator"]["model"] == "m-picked"


# -- 12 -------------------------------------------------------------------------


def test_model_help_documents_env_only_path():
    result = runner.invoke(app, ["model", "--help"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "HUNTEROS_MODEL" in result.output  # the env-only path is documented


# -- 13 (regression: provider_add after the re-point) -----------------------------


def test_provider_add_wizard_regressions_green(tmp_path):
    """Three representative scripted scenarios through provider_add (known
    provider with env key; custom with paste; keyless local)."""
    from hunter.cli.provider_add import run_provider_add_wizard
    from hunter.llm.config import load_config, resolve_key

    # (a) known provider, env-detected key.
    console, err_console, out, err = _string_console()
    code = run_provider_add_wizard(
        path=tmp_path / "a.yaml", console=console, err_console=err_console,
        ask=_scripted([("provider", "groq")]), ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "",
        list_models_fn=lambda *_a, **_k: [],
        environ={"GROQ_API_KEY": "sk-env-groq"}, home=tmp_path,
    )
    assert code == 0, _wizard_text(out, err)
    cfg = load_config(tmp_path / "a.yaml", env={}, home=tmp_path)
    assert cfg.providers["groq"].key_env == "GROQ_API_KEY"
    assert cfg.model_tiers["orchestrator"].provider == "groq"

    # (b) custom with a pasted key: keys.env only, never the config.
    console, err_console, out, err = _string_console()

    def custom_ask(prompt: str, default: str = "") -> str:
        if "base URL" in prompt:
            return CUSTOM_BASE_URL
        if "provider" in prompt:
            return "custom"
        if "env var name" in prompt:
            return "CORP_KEY"
        return default

    code = run_provider_add_wizard(
        path=tmp_path / "b.yaml", console=console, err_console=err_console,
        ask=custom_ask, secret=lambda _prompt: SENTINEL, ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "chat",
        list_models_fn=lambda *_a, **_k: ["corp-alpha"],
        environ={}, home=tmp_path,
    )
    text = _wizard_text(out, err)
    assert code == 0, text
    assert SENTINEL not in text
    keys_text = keys_env_path(env={}, home=tmp_path).read_text(encoding="utf-8")
    assert 'CORP_KEY="sk-' in keys_text and SENTINEL in keys_text
    cfg = load_config(tmp_path / "b.yaml", env={}, home=tmp_path)
    assert cfg.providers["custom"].base_url == CUSTOM_BASE_URL
    assert "api_key" not in (tmp_path / "b.yaml").read_text(encoding="utf-8")

    # (c) keyless local server: no key prompts at all.
    console, err_console, out, err = _string_console()
    code = run_provider_add_wizard(
        path=tmp_path / "c.yaml", console=console, err_console=err_console,
        ask=_scripted([("provider", "ollama"), ("model", "")]), ping_fn=_ok_ping,
        probe_fn=lambda *_a, **_k: "",
        list_models_fn=lambda *_a, **_k: [],
        environ={}, home=tmp_path,
    )
    assert code == 0, _wizard_text(out, err)
    cfg = load_config(tmp_path / "c.yaml", env={}, home=tmp_path)
    assert cfg.providers["ollama"].base_url == "http://127.0.0.1:11434"
    assert resolve_key("ollama", cfg, env={}) == ""  # keyless, no auth error
