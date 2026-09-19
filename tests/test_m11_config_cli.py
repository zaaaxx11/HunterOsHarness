"""M11 M1 — `hunter config` verbs: path/get/set/unset/edit/check/key (§5).

Spec: docs/plans/m11-ux.md §3.3-§3.5 + §5 (test plan 1-15). The verbs
live in the NEW `src/hunter/cli/config_cmd.py`; until M1 lands the subcommands
do not exist (CliRunner exits 2) and `validate_raw`/`KEY_NAME_RE` import
errors fail the tests — the red reasons. All config writes go to the isolated
home (`~/.hunter/config.yaml` post-M1); zero network; no key value is ever
asserted into an output (§3.5 masking rule).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from hunter.cli.main import app

runner = CliRunner()

SENTINEL = "sk-m11-sentinel-0xf00f-never-leak"
KEY_VAR = "CUSTOM_API_KEY"
CONFIG_DIRNAME = ".hunter"  # post-M1 home (M1 under test)


def _home() -> Path:
    return Path(os.environ["USERPROFILE"])


def _config_path() -> Path:
    return _home() / CONFIG_DIRNAME / "config.yaml"


def _keys_path() -> Path:
    return _home() / CONFIG_DIRNAME / "keys.env"


def _seed_config(text: str) -> Path:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


BASIC_CONFIG = (
    "agent:\n"
    "  tier: basic\n"
    "providers:\n"
    "  custom:\n"
    "    base_url: https://api.atria-asi.ai/v1\n"
    "    key_env: CUSTOM_API_KEY\n"
)


# -- plan 1 ---------------------------------------------------------------------


def test_config_path_prints_resolved_target(tmp_path, monkeypatch):
    """Explicit file wins over $HUNTEROS_CONFIG over the home default; the
    command prints exactly the config line."""
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("agent:\n  tier: basic\n", encoding="utf-8")
    from_env = tmp_path / "from-env.yaml"

    monkeypatch.setenv("HUNTEROS_CONFIG", str(from_env))
    result = runner.invoke(app, ["config", "path", "--path", str(explicit)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert result.output.strip() == str(explicit)  # explicit beats env

    result_env = runner.invoke(app, ["config", "path"])
    assert result_env.exit_code == 0, (result_env.output, result_env.exception)
    assert result_env.output.strip() == str(from_env)  # env beats home

    monkeypatch.delenv("HUNTEROS_CONFIG")
    result_home = runner.invoke(app, ["config", "path"])
    assert result_home.exit_code == 0, (result_home.output, result_home.exception)
    assert result_home.output.strip() == str(_config_path())


# -- plan 2 ---------------------------------------------------------------------


def test_config_get_leaf_and_nested_and_unknown(tmp_path, monkeypatch):
    _seed_config(BASIC_CONFIG)
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)

    leaf = runner.invoke(app, ["config", "get", "agent.tier"])
    assert leaf.exit_code == 0, (leaf.output, leaf.exception)
    assert "agent.tier: basic" in leaf.output  # markup=False key: value line

    nested = runner.invoke(app, ["config", "get", "providers"])
    assert nested.exit_code == 0, (nested.output, nested.exception)
    assert "providers.custom.base_url: https://api.atria-asi.ai/v1" in nested.output
    assert "providers.custom.key_env: CUSTOM_API_KEY" in nested.output

    unknown = runner.invoke(app, ["config", "get", "agent.nope"])
    assert unknown.exit_code == 8, (unknown.output, unknown.exception)
    assert "config.unknown_key" in unknown.output
    assert "valid keys under agent" in unknown.output


# -- plan 3 ---------------------------------------------------------------------


def test_config_set_string_coercion_and_string_flag(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(BASIC_CONFIG)

    set_tier = runner.invoke(app, ["config", "set", "agent.tier", "advanced"])
    assert set_tier.exit_code == 0, (set_tier.output, set_tier.exception)
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert cfg["agent"]["tier"] == "advanced"

    set_budget = runner.invoke(app, ["config", "set", "budget.max_cost_usd", "12.5"])
    assert set_budget.exit_code == 0, (set_budget.output, set_budget.exception)
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert cfg["budget"]["max_cost_usd"] == 12.5  # parsed as a NUMBER

    set_string = runner.invoke(app, ["config", "set", "--string", "agent.browser", "true"])
    assert set_string.exit_code == 0, (set_string.output, set_string.exception)
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert cfg["agent"]["browser"] == "true"  # the STRING survives the round-trip
    from hunter.llm.config import load_config

    reloaded = load_config(env={})
    assert reloaded.agent.browser is True  # the loader accepts it via _as_bool

    # Invalid enum refused: exit 8 and the file is byte-identical to before.
    before = path.read_bytes()
    set_bad = runner.invoke(app, ["config", "set", "agent.tier", "bogus"])
    assert set_bad.exit_code == 8, (set_bad.output, set_bad.exception)
    assert path.read_bytes() == before


# -- plan 4 (adversarial: unknown key via config set) ----------------------------


def test_config_set_unknown_key_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(BASIC_CONFIG)
    before = path.read_bytes()

    result = runner.invoke(app, ["config", "set", "agent.nope", "1"])
    assert result.exit_code == 8, (result.output, result.exception)
    assert "config.unknown_key" in result.output
    assert "valid keys under agent" in result.output
    assert "tier" in result.output  # the hint lists the valid agent keys
    assert path.read_bytes() == before  # the file is untouched


# -- plan 5 ---------------------------------------------------------------------


def test_config_set_none_value_refused_points_to_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(BASIC_CONFIG)
    before = path.read_bytes()

    result = runner.invoke(app, ["config", "set", "agent.tier", "null"])
    assert result.exit_code != 0
    assert "use hunter config unset to remove a key" in result.output
    assert path.read_bytes() == before


# -- plan 6 ---------------------------------------------------------------------


def test_config_unset_deletes_and_renders(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(BASIC_CONFIG)

    result = runner.invoke(app, ["config", "unset", "providers.custom"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "✅ removed providers.custom" in result.output
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "custom" not in (cfg.get("providers") or {})

    missing = runner.invoke(app, ["config", "unset", "agent.nope"])
    assert missing.exit_code == 2, (missing.output, missing.exception)


# -- plan 7 ---------------------------------------------------------------------


def _make_fake_editor(tmp_path: Path, new_content: bytes) -> Path:
    """Build a launcher 'editor' that overwrites argv[1] with ``new_content``
    when invoked as ``subprocess.call([editor, path])`` (NO shell)."""
    new_file = tmp_path / "m11-editor-new-config.yaml"
    new_file.write_bytes(new_content)
    editor_py = tmp_path / "m11_editor.py"
    editor_py.write_text(
        "import shutil, sys\n"
        f"shutil.copyfile({str(new_file)!r}, sys.argv[1])\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        launcher = tmp_path / "m11-fake-editor.cmd"
        launcher.write_text(
            f'@"{sys.executable}" "{editor_py}" %*\n', encoding="utf-8"
        )
    else:
        launcher = tmp_path / "m11-fake-editor.sh"
        launcher.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{editor_py}" "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o755)
    return launcher


def test_config_edit_roundtrip_with_fake_editor(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(BASIC_CONFIG)
    launcher = _make_fake_editor(
        tmp_path, b"budget:\n  max_iterations: 77\nagent:\n  tier: advanced\n"
    )
    monkeypatch.setenv("VISUAL", str(launcher))
    monkeypatch.delenv("EDITOR", raising=False)

    result = runner.invoke(app, ["config", "edit"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "Previous config backed up to:" in result.output  # printed BEFORE editing
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert cfg["budget"]["max_iterations"] == 77  # the edit landed
    assert cfg["agent"]["tier"] == "advanced"


# -- plan 8 (adversarial: config edit saves garbage) ------------------------------


def test_config_edit_invalid_result_keeps_file_and_points_at_bak(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(BASIC_CONFIG)
    launcher = _make_fake_editor(tmp_path, b"this: [is: not: valid")
    monkeypatch.setenv("VISUAL", str(launcher))
    monkeypatch.delenv("EDITOR", raising=False)

    result = runner.invoke(app, ["config", "edit"])
    assert result.exit_code == 8, (result.output, result.exception)
    assert "Previous config backed up to:" in result.output
    bak = Path(str(path) + ".bak")
    assert bak.is_file()
    assert str(bak) in result.output.replace("\\\\", "\\") or bak.name in result.output
    assert "your previous config is at" in result.output
    # The EDITED (garbage) file is kept on disk — never silently reverted.
    assert path.read_bytes() == b"this: [is: not: valid"
    # The backup holds the PRE-EDIT bytes.
    assert bak.read_text(encoding="utf-8") == BASIC_CONFIG


# -- plan 9 (adversarial: $EDITOR unset) ------------------------------------------


def test_config_edit_windows_default_editor_notepad(tmp_path, monkeypatch):
    """No $VISUAL/$EDITOR: win32 resolves `notepad`, POSIX `vi`; the editor is
    invoked WITHOUT a shell as [editor, config_path]."""
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    _seed_config(BASIC_CONFIG)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)

    calls: list[tuple[tuple, dict]] = []

    def fake_call(*args, **kwargs):
        calls.append((args, kwargs))
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)
    result = runner.invoke(app, ["config", "edit"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls, "the editor must be invoked via subprocess.call"
    argv = calls[0][0][0]
    assert isinstance(argv, (list, tuple))  # a list — never a shell string
    expected = "notepad" if os.name == "nt" else "vi"
    assert argv[0] == expected
    assert Path(argv[1]) == _config_path()


# -- plan 10 (adversarial: key value leaking through new output) ------------------


def test_config_key_set_and_list_masked(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    monkeypatch.delenv(KEY_VAR, raising=False)

    # --stdin reads ONE line; the confirmation names the VAR, never the value.
    result = runner.invoke(
        app, ["config", "key", "set", KEY_VAR, "--stdin"], input="sekret-value\n"
    )
    assert result.exit_code == 0, (result.output, result.exception)
    assert "✅ API key saved to keys.env as CUSTOM_API_KEY" in result.output
    assert "sekret-value" not in result.output
    keys_text = _keys_path().read_text(encoding="utf-8")
    assert f'{KEY_VAR}="sekret-value"' in keys_text  # written to keys.env ONLY

    # The interactive route prompts via getpass with the pinned prompt text.
    prompts: list[str] = []
    monkeypatch.setattr(
        "getpass.getpass", lambda prompt="": (prompts.append(prompt) or "getpass-value")
    )
    result2 = runner.invoke(app, ["config", "key", "set", "SECOND_VAR"])
    assert result2.exit_code == 0, (result2.output, result2.exception)
    assert prompts == ["value for SECOND_VAR (input hidden): "]
    assert "getpass-value" not in result2.output

    # key list: NAME + source, never a value.
    listed = runner.invoke(app, ["config", "key", "list"])
    assert listed.exit_code == 0, (listed.output, listed.exception)
    rows = [line for line in listed.output.splitlines() if KEY_VAR in line]
    assert rows and rows[0].split()[-1] == "keys.env"
    assert "sekret-value" not in listed.output

    # A var that is a real environment variable shows `env` (not `not set`).
    monkeypatch.setenv("SECOND_VAR", "from-real-env")
    listed2 = runner.invoke(app, ["config", "key", "list"])
    rows2 = [line for line in listed2.output.splitlines() if "SECOND_VAR" in line]
    assert rows2 and rows2[0].split()[-1] == "env"
    assert "from-real-env" not in listed2.output


# -- plan 11 ---------------------------------------------------------------------


def test_config_key_set_merges_existing_entries(tmp_path, monkeypatch):
    """Rewrites parse the existing mapping: VALUES preserved (Q13)."""
    from hunter.llm.keys import parse_keys_env

    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    _keys_path().parent.mkdir(parents=True, exist_ok=True)
    _keys_path().write_text('A_ONE="1"\nB_TWO="2"\n', encoding="utf-8")

    result = runner.invoke(
        app, ["config", "key", "set", "C_THREE", "--stdin"], input="3\n"
    )
    assert result.exit_code == 0, (result.output, result.exception)
    parsed = parse_keys_env(_keys_path().read_text(encoding="utf-8"))
    assert parsed == {"A_ONE": "1", "B_TWO": "2", "C_THREE": "3"}


# -- plan 12 ---------------------------------------------------------------------


def test_config_key_rejects_bad_name(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    result = runner.invoke(app, ["config", "key", "set", "9BAD", "--stdin"], input="x\n")
    assert result.exit_code == 2, (result.output, result.exception)
    from hunter.llm.keys import KEY_NAME_RE  # the public alias must exist

    assert KEY_NAME_RE.match("9BAD") is None
    assert KEY_NAME_RE.match("GOOD_NAME_1") is not None


# -- plan 13 (adversarial register: key value leaking through ANY new output) -----


def test_no_secret_values_in_any_new_output_path(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    monkeypatch.setenv(KEY_VAR, SENTINEL)  # a real env var carries the sentinel
    _seed_config(BASIC_CONFIG)
    _keys_path().parent.mkdir(parents=True, exist_ok=True)
    _keys_path().write_text(f'{KEY_VAR}="{SENTINEL}"\n', encoding="utf-8")

    combined: list[str] = []
    invocations = [
        ["where"],
        ["where", "--json"],
        ["config", "get", "providers.custom"],
        ["config", "set", "agent.tier", "advanced"],
        ["config", "unset", "agent.tier"],
        ["config", "key", "list"],
        ["config", "check"],
        ["config", "path"],
    ]
    for argv in invocations:
        result = runner.invoke(app, argv)
        combined.append(result.output)
        assert result.exit_code in (0, 8), (argv, result.output, result.exception)

    # The failing-edit path must not leak either.
    launcher = _make_fake_editor(tmp_path, b"garbage: [")
    monkeypatch.setenv("VISUAL", str(launcher))
    failed_edit = runner.invoke(app, ["config", "edit"])
    combined.append(failed_edit.output)
    assert failed_edit.exit_code == 8

    blob = "\n".join(combined)
    assert SENTINEL not in blob, "a key VALUE leaked into a new output path"
    assert KEY_VAR in blob  # env var NAMES are fine


# -- plan 14 (adversarial: approved_scopes rewritten away / browser_cloak bug) ----


def test_approved_scopes_roundtrip(tmp_path, monkeypatch):
    """`config set agent.scope_confirm true` must NOT drop approved_scopes (and
    pins the browser_cloak rewrite bug fix — §3.4)."""
    seeded = (
        "agent:\n"
        "  tier: basic\n"
        "  browser_cloak: true\n"
        "  approved_scopes:\n"
        "    - host: client-x.com\n"
        "      name: client-x\n"
        "      allow_subdomains: false\n"
        "      ts: 1700000000.0\n"
        "      source: hunt-start\n"
        "providers:\n"
        "  custom:\n"
        "    base_url: https://api.atria-asi.ai/v1\n"
        "    key_env: CUSTOM_API_KEY\n"
    )
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    path = _seed_config(seeded)

    result = runner.invoke(app, ["config", "set", "agent.scope_confirm", "true"])
    assert result.exit_code == 0, (result.output, result.exception)

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert raw["agent"]["scope_confirm"] is True
    # browser_cloak survives the rewrite (today render_config drops it).
    assert raw["agent"]["browser_cloak"] is True
    # approved_scopes survives with load-equal semantics.
    scopes = raw["agent"]["approved_scopes"]
    assert scopes == [
        {
            "host": "client-x.com",
            "name": "client-x",
            "allow_subdomains": False,
            "ts": 1700000000.0,
            "source": "hunt-start",
        }
    ]
    from hunter.llm.config import load_config

    cfg = load_config(env={})
    assert cfg.agent.scope_confirm is True
    assert cfg.agent.browser_cloak is True
    assert [(s.host, s.source) for s in cfg.agent.approved_scopes] == [
        ("client-x.com", "hunt-start")
    ]


# -- plan 15 (refactor guard: one source of truth for validation) -----------------


def test_validate_raw_is_pure_and_shared(tmp_path, monkeypatch):
    """validate_raw raises the SAME errors as load_config for an identical tree;
    `config set` refuses before any write."""
    from hunter.errors import HunterError
    from hunter.llm.config import load_config, validate_raw

    bad_tree = {"agent": {"nope": 1}}
    with pytest.raises(HunterError) as from_validator:
        validate_raw(bad_tree)
    assert from_validator.value.code == "config.unknown_key"

    path = tmp_path / "same-tree.yaml"
    path.write_text("agent:\n  nope: 1\n", encoding="utf-8")
    with pytest.raises(HunterError) as from_loader:
        load_config(path, env={})
    assert from_loader.value.code == from_validator.value.code

    # A valid tree validates and loads to the same shape.
    good = validate_raw({"agent": {"tier": "basic"}})
    good_path = tmp_path / "good.yaml"
    good_path.write_text("agent:\n  tier: basic\n", encoding="utf-8")
    assert load_config(good_path, env={}).agent.tier == good.agent.tier

    # The write guard: a refused set leaves the file byte-identical.
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)
    target = _seed_config(BASIC_CONFIG)
    before = target.read_bytes()
    refused = runner.invoke(app, ["config", "set", "budget.bogus", "1"])
    assert refused.exit_code == 8
    assert target.read_bytes() == before
