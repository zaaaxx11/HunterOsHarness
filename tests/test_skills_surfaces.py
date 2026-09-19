"""M5 chat/CLI skills listings, banners, registry, and retro surfaces (SU1-SU5)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner


def _card(name: str, *, description: str = "A user-authored technique.", quarantined: bool = False) -> str:
    extra = "\nquarantined: true" if quarantined else ""
    return (
        f"---\nname: {name}\ndescription: {description}\nversion: 0.1.0\n"
        f"metadata:\n  min_tier: basic{extra}\n---\n\n# {name}\n\nEvidence or nothing.\n"
    )


def _write_skill(
    home: Path,
    name: str,
    *,
    description: str = "A user-authored technique.",
    quarantined=False,
):
    path = home / ".hunter" / "skills" / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(
        _card(name, description=description, quarantined=quarantined), encoding="utf-8"
    )
    return path


@pytest.fixture(autouse=True)
def _clean_selector():
    from hunter.agent.prompts import install_skill_selector

    install_skill_selector(None)
    yield
    install_skill_selector(None)


def _chat_context(tmp_path, monkeypatch):
    from hunter.chat.commands import CommandContext
    from hunter.chat.sessions import ChatStore
    from hunter.llm.config import default_config

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    store = ChatStore(tmp_path / "chat.db")
    sid = store.create_session()
    return store, CommandContext(
        store=store,
        config=default_config(),
        ledger_factory=None,
        args="",
        options={"session_id": sid, "state_dir": str(tmp_path)},
    )


def test_chat_skills_marks_sources_and_quarantine(tmp_path, monkeypatch):
    from hunter.chat.commands import safe_execute

    _write_skill(tmp_path, "my-technique")
    _write_skill(tmp_path, "recon-basics", description="User shadow of bundled recon.")
    _write_skill(tmp_path, "suspect-thing", quarantined=True)
    store, ctx = _chat_context(tmp_path, monkeypatch)
    try:
        reply = safe_execute("skills", ctx)
    finally:
        store.close()
    assert "recon-basics" in reply.text
    assert "recon-basics [user]" in reply.text
    assert reply.text.count("recon-basics") == 2  # effective row + shadow note
    assert "my-technique [user]" in reply.text
    assert "suspect-thing [quarantined]" in reply.text
    assert "not mounted until reviewed" in reply.text
    assert "user skill 'recon-basics' shadows the bundled skill 'recon-basics'" in reply.text
    assert "[bundled]" in reply.text


def test_cli_skills_source_column_and_view_shadow(tmp_path, monkeypatch):
    from hunter.cli.main import app

    _write_skill(tmp_path, "my-technique", description="Local staging technique.")
    _write_skill(tmp_path, "recon-basics", description="User replacement recon.")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    runner = CliRunner()
    listed = runner.invoke(app, ["skills"])
    assert listed.exit_code == 0, (listed.output, listed.exception)
    assert "source" in listed.output
    assert "my-technique" in listed.output and "user" in listed.output
    viewed = runner.invoke(app, ["skills", "--view", "recon-basics"])
    assert viewed.exit_code == 0, (viewed.output, viewed.exception)
    assert "shadows the bundled" in viewed.output
    assert "User replacement recon." in viewed.output
    unknown = runner.invoke(app, ["skills", "--view", "nope"])
    assert unknown.exit_code == 1


def test_registry_curate_command_and_no_runs_message(tmp_path, monkeypatch):
    from hunter.chat.commands import COMMAND_REGISTRY, safe_execute

    names = [command.name for command in COMMAND_REGISTRY]
    # 20 commands + /approve, /deny (F1) and /compress (F8) = 23, + /mode, /note = 25.
    assert len(names) == 25
    assert "curate" in names
    for m8_command in ("approve", "deny", "compress"):
        assert m8_command in names
    store, ctx = _chat_context(tmp_path, monkeypatch)
    try:
        reply = safe_execute("curate", ctx)
    finally:
        store.close()
    assert "no runs" in reply.text.lower() or "no skill candidates" in reply.text.lower()
    assert not (tmp_path / ".hunter" / "skills").exists()


def test_hunt_banner_line_shows_selected_sources(monkeypatch, tmp_path):
    from hunter.cli.main import app
    from hunter.vault.server import start_server

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    handle, port = start_server()
    try:
        result = CliRunner().invoke(
            app,
            [
                "hunt",
                f"http://127.0.0.1:{port}/",
                "--engine",
                "deterministic",
                "--yes",
                "--state",
                str(tmp_path / "state"),
            ],
        )
    finally:
        handle.shutdown()
    assert "skills mounted:" in result.output
    line = next(line for line in result.output.splitlines() if "skills mounted:" in line)
    assert line.startswith("skills mounted: ")
    count = int(line.split(":", 1)[1].split("(", 1)[0].strip())
    assert count <= 5
    if count:
        assert "[bundled]" in line
        from hunter.agent.skills import load_corpus

        corpus_names = {skill.name for skill in load_corpus().skills}
        for name in line.split("(", 1)[1].rstrip(")").split(", "):
            assert name.rsplit(" [", 1)[0] in corpus_names


def _verified_ledger(tmp_path, run_id="R-SURFACE"):
    from hunter.kernel.findings import Finding, FindingStatus, Severity
    from hunter.kernel.ledger import Ledger

    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run(run_id, "https://example.test/", "deterministic", "test")
    evidence = ledger.add_evidence(run_id, "http_exchange", {"method": "GET", "url": "https://example.test/"})
    finding = ledger.create_finding(
        Finding(
            id="",
            run_id=run_id,
            key="reflected-xss|GET|/search|q",
            title="Reflected XSS",
            severity=Severity.HIGH,
            cwe="CWE-79",
            endpoint="/search",
            remediation="Replay the marker.",
            evidence_ids=(evidence,),
        )
    )
    replay = ledger.add_evidence(run_id, "http_exchange", {"replay": True, "finding_id": finding.id})
    assert replay
    ledger.set_finding_status(finding.id, FindingStatus.VERIFIED, "independent replay")
    return ledger


def test_retro_record_hint_line_both_surfaces(tmp_path, monkeypatch):
    from hunter.chat.commands import CommandContext, safe_execute
    from hunter.chat.sessions import ChatStore
    from hunter.cli.main import app
    from hunter.kernel.ledger import Ledger
    from hunter.llm.config import default_config

    ledger = _verified_ledger(tmp_path)
    store = ChatStore(tmp_path / "chat.db")
    try:
        sid = store.create_session()
        ctx = CommandContext(
            store=store,
            config=default_config(),
            ledger_factory=lambda: ledger,
            args="R-SURFACE --record",
            options={"session_id": sid, "state_dir": str(tmp_path)},
        )
        reply = safe_execute("retro", ctx)
        assert "curator:" in reply.text
        assert "run /curate" in reply.text
    finally:
        store.close()
        ledger.close()

    cli_state = tmp_path / "clean-state"
    clean = Ledger(cli_state / "ledger.db")
    clean.create_run("R-CLEAN", "https://example.test/", "deterministic", "test")
    clean.close()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "home" / "config.yaml"))
    clean_result = CliRunner().invoke(app, ["retro", "R-CLEAN", "--record", "--state", str(cli_state)])
    assert clean_result.exit_code == 0
    assert "curator:" not in clean_result.output

    cli_result = CliRunner().invoke(app, ["retro", "R-SURFACE", "--record", "--state", str(tmp_path)])
    assert "curator:" in cli_result.output
    assert "run /curate" in cli_result.output
