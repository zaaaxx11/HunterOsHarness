"""M1 keys.env — `hunter.llm.keys` parse/write/load contract.

keys.env holds pasted API keys OUTSIDE config.yaml. The module is new in M1,
so the tests import it inside their bodies (red until it exists, without
breaking collection of the rest of the suite). Everything runs in a tmp home;
HUNTEROS_KEYS_FILE is scrubbed so the default path sits under the sandbox.
"""

from __future__ import annotations

import os
import stat

import pytest
from typer.testing import CliRunner

from hunter.errors import HunterError
from hunter.llm.config import load_config, resolve_key

runner = CliRunner()

KEYS_FILENAME = "keys.env"
KEYS_ENV_VAR = "HUNTEROS_KEYS_FILE"
ACME_KEY_VAR = "HUNTEROS_M1_ACME_CORP_KEY"
ACME_KEY_VALUE = "sk-acme-xyz-never-in-config"


@pytest.fixture(autouse=True)
def _m1_env_hygiene(monkeypatch):
    for var in (KEYS_ENV_VAR, "HUNTEROS_ONBOARD_DECLINED", ACME_KEY_VAR):
        monkeypatch.delenv(var, raising=False)


def test_write_and_parse_keys_env_roundtrip(tmp_path):
    """A19: quoting/escaping survives a write -> parse round trip."""
    from hunter.llm.keys import KEYS_ENV_FILENAME, parse_keys_env, write_keys_env

    entries = {
        "SPACE_KEY": "value with spaces",
        "QUOTE_KEY": 'has "double quotes" inside',
        "SINGLE_KEY": "has 'single quotes' inside",
        "DOLLAR_KEY": "pa$$word-$HOME",
        "BACKSLASH_KEY": "back\\slash",
        "BACKTICK_KEY": "cmd`sub`output",
    }
    written = write_keys_env(entries, env={}, home=tmp_path)
    assert written == tmp_path / ".hunter" / KEYS_ENV_FILENAME  # M11: unified home
    text = written.read_text(encoding="utf-8")
    assert parse_keys_env(text) == entries
    assert text.startswith("# HunterOs API keys")


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode — Windows chmod is a no-op")
def test_write_keys_env_posix_mode_0600(tmp_path):
    """A20: POSIX perms are 0600 (best-effort chmod is a no-op on Windows)."""
    from hunter.llm.keys import write_keys_env

    path = write_keys_env({"K": "v"}, env={}, home=tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_load_keys_env_env_wins_setdefault(tmp_path):
    """A21: setdefault injection — a pre-set env var is never overwritten."""
    from hunter.llm.keys import load_keys_env, write_keys_env

    write_keys_env(
        {"M1_FROM_KEYS": "from-file", "M1_PRESET": "from-keys"}, env={}, home=tmp_path
    )
    target = {"M1_PRESET": "real-env-value"}
    injected = load_keys_env(env={}, home=tmp_path, target=target)
    assert target["M1_PRESET"] == "real-env-value"
    assert target["M1_FROM_KEYS"] == "from-file"
    assert injected == {"M1_FROM_KEYS": "from-file"}


def test_keys_env_path_env_override_and_default(tmp_path):
    """A22: $HUNTEROS_KEYS_FILE overrides; default is <home>/.hunter/keys.env (M11)."""
    from hunter.llm.keys import KEYS_ENV_ENVVAR, KEYS_ENV_FILENAME, keys_env_path

    override = tmp_path / "custom-dir" / KEYS_FILENAME
    assert keys_env_path(env={KEYS_ENV_ENVVAR: str(override)}, home=tmp_path) == override
    assert keys_env_path(env={}, home=tmp_path) == tmp_path / ".hunter" / KEYS_ENV_FILENAME


def test_write_keys_env_refuses_outside_home(tmp_path):
    """A23: a stray $HUNTEROS_KEYS_FILE outside home is refused, not written."""
    from hunter.llm.keys import write_keys_env

    home = tmp_path / "home"
    outside = tmp_path / "outside" / KEYS_FILENAME
    with pytest.raises(HunterError) as excinfo:
        write_keys_env({"K": "v"}, env={KEYS_ENV_VAR: str(outside)}, home=home)
    assert excinfo.value.layer == "config"
    assert excinfo.value.code == "keys.refused"
    assert not outside.exists()


def test_parse_keys_env_tolerates_malformed_lines():
    """A24: export prefixes, comments, blanks OK; malformed silently skipped."""
    from hunter.llm.keys import parse_keys_env

    text = "\n".join(
        [
            "# a comment line",
            "",
            "export EXPORTED_KEY=exported-value",
            "PLAIN_KEY=plain-value",
            'QUOTED_KEY="quoted-value"',
            "SINGLE_QUOTED_KEY='single-quoted-value'",
            "no_equals_sign_here",
            "1BAD_KEY=bad",
            "BAD-NAME=bad",
            "DUP_KEY=first",
            "DUP_KEY=second",
        ]
    )
    parsed = parse_keys_env(text)  # never raises
    assert parsed["EXPORTED_KEY"] == "exported-value"
    assert parsed["PLAIN_KEY"] == "plain-value"
    assert parsed["QUOTED_KEY"] == "quoted-value"
    assert parsed["SINGLE_QUOTED_KEY"] == "single-quoted-value"
    assert parsed["DUP_KEY"] == "second"  # last wins
    assert not any(key.startswith("1") or "-" in key for key in parsed)
    assert "no_equals_sign_here" not in parsed


def test_load_keys_env_missing_file_is_noop(tmp_path):
    """A25: a missing keys.env loads as {} and creates nothing."""
    from hunter.llm.keys import load_keys_env

    assert load_keys_env(env={}, home=tmp_path) == {}
    assert not (tmp_path / ".hunter").exists()


def test_cli_startup_loads_keys_env_and_resolve_key_sees_it(monkeypatch, tmp_path):
    """A26: the root callback loads keys.env; resolve_key resolves end-to-end."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "providers:\n  acme:\n    key_env: " + ACME_KEY_VAR + "\n", encoding="utf-8"
    )
    keys_path = tmp_path / ".hunter" / KEYS_FILENAME
    keys_path.parent.mkdir(parents=True)
    keys_path.write_text(f'{ACME_KEY_VAR}="{ACME_KEY_VALUE}"\n', encoding="utf-8")

    from hunter.cli.main import app

    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert os.environ.get(ACME_KEY_VAR) == ACME_KEY_VALUE

    cfg = load_config(config_path, env=os.environ, home=tmp_path)
    assert resolve_key("acme", cfg, env=os.environ) == ACME_KEY_VALUE

    # Cleanup: production code set the var via os.environ.setdefault — pop it
    # so nothing leaks into later tests (the autouse fixture scrubbed it first).
    os.environ.pop(ACME_KEY_VAR, None)
