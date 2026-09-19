"""Doctor — collect_checks rows, --json contract, corrupt-ledger/chat-db FAILs.

Notes never flip the exit code; FAILs do. Config parse errors carry YAML
line numbers (surfaced by the llm-config row).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import hunter.cli.main as cli_main
from hunter.cli.doctor_core import collect_checks

runner = CliRunner()


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HUNTEROS_CHAT_DB", str(tmp_path / "chat.db"))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))


def _checks_json(result) -> dict:
    return json.loads(result.output)


# ------------------------------------------------------------------- config --


def test_broken_indent_yaml_reports_line_number(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "model_tiers:\n  planner:\n     model: x\n   broken_indent: 1\n", encoding="utf-8"
    )
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 1, (result.output, result.exception)
    payload = _checks_json(result)
    assert payload["ok"] is False
    row = next(c for c in payload["checks"] if c["label"] == "llm-config")
    assert row["status"] == "fail"
    assert "line 4" in row["detail"] and "column" in row["detail"]


def test_unknown_key_hint_carries_line_number(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "budget:\n  max_iterations: 5\n  bogus_key: 1\n", encoding="utf-8"
    )
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 1
    row = next(c for c in _checks_json(result)["checks"] if c["label"] == "llm-config")
    assert "bogus_key" in row["detail"] and "line 3" in row["detail"]


# -------------------------------------------------------------------- json --


def test_doctor_json_parses_and_ok_true_on_fresh_state(tmp_path):
    result = runner.invoke(cli_main.app, ["doctor", "--json", "--state", str(tmp_path / "fresh")])
    assert result.exit_code == 0, (result.output, result.exception)
    payload = _checks_json(result)
    assert set(payload) == {"checks", "ok"}
    assert payload["ok"] is True
    labels = [c["label"] for c in payload["checks"]]
    for expected in ("home",  # M11 M1 (§14 item 7): the resolved-home row
                     "python", "dep:typer", "state-dir", "ledger-chain", "engines", "workflow",
                     "llm-config", "llm-litellm", "chat-db"):
        assert expected in labels
    assert "All checks passed" in result.output or payload["ok"]  # json mode skips the footer


def test_json_ok_reflects_forced_fail(monkeypatch, tmp_path):
    # A broken ledger in the state dir must flip ok to False (exit 1).
    state = tmp_path / "broken-state"
    state.mkdir()
    (state / "ledger.db").write_bytes(b"this is not a sqlite database at all")
    result = runner.invoke(cli_main.app, ["doctor", "--json", "--state", str(state)])
    assert result.exit_code == 1, (result.output, result.exception)
    payload = _checks_json(result)
    assert payload["ok"] is False
    assert any(c["status"] == "fail" and "state-dir" in c["label"] for c in payload["checks"])


# ----------------------------------------------------------------- chat db --


def test_corrupted_chat_db_fails(monkeypatch, tmp_path):
    (tmp_path / "chat.db").write_bytes(b"garbage bytes, definitely not sqlite\x00\x01")
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 1, (result.output, result.exception)
    payload = _checks_json(result)
    row = next(c for c in payload["checks"] if c["label"] == "chat-db")
    assert row["status"] == "fail"
    assert "unreadable" in row["detail"] or "corrupt" in row["detail"]


def test_missing_chat_db_is_only_a_note(tmp_path):
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 0
    row = next(c for c in _checks_json(result)["checks"] if c["label"] == "chat-db")
    assert row["status"] == "note"


def test_healthy_chat_db_is_ok(tmp_path):
    from hunter.chat.sessions import ChatStore

    store = ChatStore(tmp_path / "chat.db")
    store.create_session("hello")
    store.close()
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 0
    row = next(c for c in _checks_json(result)["checks"] if c["label"] == "chat-db")
    assert row["status"] == "ok" and "1 session(s)" in row["detail"]


# --------------------------------------------------------------- providers --


def test_provider_rows_key_set_not_and_keyless_note(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "providers:\n"
        "  groq:\n"
        "    key_env: GROQ_API_KEY\n"
        "  mylocal:\n"
        "    base_url: http://127.0.0.1:9/v1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GROQ_API_KEY", "sk-set")
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    rows = {c["label"]: c for c in _checks_json(result)["checks"]}
    assert rows["provider:groq"]["status"] == "ok"
    assert "key set (GROQ_API_KEY)" in rows["provider:groq"]["detail"]
    assert rows["provider:mylocal"]["status"] == "note"
    assert "keyless" in rows["provider:mylocal"]["detail"]
    assert "http://127.0.0.1:9/v1" in rows["provider:mylocal"]["detail"]


def test_provider_key_not_set_is_a_note_that_does_not_flip_exit(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "providers:\n  groq:\n    key_env: GROQ_API_KEY\n", encoding="utf-8"
    )
    result = runner.invoke(cli_main.app, ["doctor", "--json"])
    assert result.exit_code == 0  # a missing key is an opt-in gap, never a FAIL
    payload = _checks_json(result)
    row = next(c for c in payload["checks"] if c["label"] == "provider:groq")
    assert row["status"] == "note" and "NOT set" in row["detail"]
    assert payload["ok"] is True


def test_notes_never_change_plain_doctor_exit(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "providers:\n  groq:\n    key_env: GROQ_API_KEY\n", encoding="utf-8"
    )
    result = runner.invoke(cli_main.app, ["doctor"])
    assert result.exit_code == 0
    assert "All checks passed" in result.output
    assert "provider:groq" in result.output


def test_live_probe_unreachable_is_note_not_fail(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "providers:\n  mylocal:\n    base_url: http://127.0.0.1:1/v1\n", encoding="utf-8"
    )
    checks = collect_checks(tmp_path / "fresh", live=True)
    row = next(c for c in checks if c.label == "provider:mylocal")
    assert row.status == "note"
    assert "unreachable" in row.detail
    assert all(c.status != "fail" for c in checks)
