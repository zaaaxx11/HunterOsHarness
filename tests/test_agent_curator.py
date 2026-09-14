"""M5 curator extraction, drafting, quarantine, review, and surface contracts (CU1-CU12)."""

from __future__ import annotations

import inspect
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner


def _retro(*, gaps=(), lessons=("Verified findings require replay evidence.",)):
    return SimpleNamespace(gaps=list(gaps), lessons=list(lessons), stats={})


def _finding(
    key: str,
    title: str,
    *,
    status: str = "verified",
    remediation: str = "replay the behavior and bind evidence",
):
    return SimpleNamespace(
        key=key,
        title=title,
        remediation=remediation,
        status=status,
    )


def _draft_card(name: str, *, flagged: bool = False):
    from hunter.agent.curator import SkillDraft

    return SkillDraft(
        name=name,
        description="A concise curated doctrine card.",
        version="0.1.0",
        min_tier="basic",
        tags=("curated", "verified-finding"),
        body="# Curated doctrine\n\nEvidence or nothing.",
        flagged=flagged,
        flag_reasons=("ignore previous instructions",) if flagged else (),
    )


@pytest.fixture(autouse=True)
def _clean_selector():
    from hunter.agent.prompts import install_skill_selector

    install_skill_selector(None)
    yield
    install_skill_selector(None)


def _verified_run(tmp_path: Path, run_id: str = "R-CURATE"):
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
            title="Reflected XSS in search",
            severity=Severity.HIGH,
            cwe="CWE-79",
            endpoint="/search",
            remediation="Replay the reflected marker and bind both exchanges.",
            evidence_ids=(evidence,),
        )
    )
    replay = ledger.add_evidence(
        run_id,
        "http_exchange",
        {"method": "GET", "url": "https://example.test/search", "replay": True, "finding_id": finding.id},
    )
    assert replay
    ledger.set_finding_status(finding.id, FindingStatus.VERIFIED, "independent replay reproduced")
    return ledger, run_id


def test_extract_candidates_table_and_cap():
    from hunter.agent.curator import extract_candidates

    findings = [
        _finding("sql-injection|GET|/a|q", "SQL injection one"),
        _finding("sql-injection|POST|/b|body", "SQL injection two"),
        _finding("reflected-xss|GET|/x|q", "Reflected XSS"),
        _finding("open-redirect|GET|/r|url", "Open redirect", status="ruled_out"),
    ]
    retro = _retro(gaps=("gate failed: recon — no surface map",))
    candidates = extract_candidates(retro, findings)
    assert [candidate.origin for candidate in candidates] == [
        "verified-finding",
        "verified-finding",
        "debunk",
    ]
    assert candidates[0].title
    assert all(candidate.lessons for candidate in candidates)
    many = [
        _finding(f"class-{index}|GET|/{index}|q", f"Class {index}")
        for index in range(3)
    ]
    capped = extract_candidates(_retro(), many, max_candidates=3)
    assert len(capped) <= 3
    assert len(extract_candidates(retro, findings, max_candidates=2)) == 2


def test_no_signal_run_yields_no_candidates(tmp_path):
    from hunter.agent.curator import curate, extract_candidates

    from hunter.kernel.ledger import Ledger

    retro = _retro(gaps=("gate failed: hunting — no probes",), lessons=())
    assert extract_candidates(retro, []) == []
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        result = curate("R-NONE", ledger=ledger, home=tmp_path, ask=lambda _prompt: True)
    finally:
        ledger.close()
    assert "no skill candidates from this retro" in result
    assert not (tmp_path / ".hunteros" / "skills").exists()


def test_dedupe_name_and_jaccard_boundary():
    from hunter.agent.curator import DUPLICATE_JACCARD, Candidate, dedupe_candidate, similarity

    assert similarity(frozenset({"a", "b", "c"}), frozenset({"a", "b", "c", "d", "e"})) == 0.6
    assert similarity(
        frozenset({"a", "b", "c", "d", "e", "f"}),
        frozenset({"a", "b", "c", "d", "e", "x"}),
    ) == pytest.approx(5 / 7)
    assert DUPLICATE_JACCARD == 0.6
    existing = SimpleNamespace(
        skills=(
            SimpleNamespace(name="new", description="old doctrine", tags=()),
            SimpleNamespace(name="existing", description="new card alpha delta", tags=()),
        )
    )
    named = Candidate("New", "anything", (), "gap")
    assert "new" in dedupe_candidate(named, existing)
    boundary = Candidate("new-card", "alpha", (), "gap")
    assert "existing" in dedupe_candidate(boundary, existing)
    below = Candidate("new-card", "alpha beta", (), "gap")
    assert "existing" not in dedupe_candidate(below, existing)
    novel = Candidate("unusual orbital technique", "zebra quanta", (), "gap")
    assert dedupe_candidate(novel, existing) == ()


def test_template_draft_is_canonical_and_valid():
    from hunter.agent.curator import Candidate, draft_skill
    from hunter.agent.skills import parse_skill_md

    candidate = Candidate(
        "Replay reflected input",
        "A very long summary that should be cut at a word boundary while preserving doctrine grounding.",
        ("Replay the request.", "Bind independent evidence."),
        "verified-finding",
    )
    draft = draft_skill(candidate, provider=None)
    text = (
        "---\n"
        f"name: {draft.name}\n"
        f"description: {draft.description}\n"
        f"version: {draft.version}\n"
        f"metadata:\n  min_tier: {draft.min_tier}\n"
        "tags:\n- curated\n- verified-finding\n"
        "---\n\n"
        f"{draft.body}\n"
    )
    parsed = parse_skill_md(text, directory_id=draft.name)
    assert parsed.name == draft.name
    assert draft.version == "0.1.0"
    assert draft.min_tier == "basic"
    assert "curated" in draft.tags and "verified-finding" in draft.tags
    assert len(draft.description) <= 60
    assert 0 < len(draft.body.splitlines()) <= 45
    assert parsed is not None


def test_llm_draft_canonicalized_and_provider_failure_falls_back():
    from hunter.agent.curator import Candidate, draft_skill
    from hunter.agent.skills import parse_skill_md

    candidate = Candidate(
        "Messy Candidate",
        "Candidate summary embedded in the fixed curator request.",
        ("Lesson one",),
        "gap",
    )
    messy_body = "\n".join(f"line {index}" for index in range(60))

    class FakeProvider:
        def __init__(self, response):
            self.response = response
            self.calls = []

        def complete(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return self.response

    provider = FakeProvider(
        "prose before\n---\nname: My Skill!!\ndescription: " + "d" * 90 + "\nversion: 4\n"
        "metadata:\n  min_tier: basic\n---\n" + messy_body + "\n---\nprose after"
    )
    draft = draft_skill(candidate, provider=provider)
    assert draft.name == "my-skill"
    assert len(draft.description) <= 60
    assert len(draft.body.splitlines()) <= 45
    text = (
        f"---\nname: {draft.name}\ndescription: {draft.description}\nversion: {draft.version}\n"
        f"metadata:\n  min_tier: {draft.min_tier}\n---\n{draft.body}\n"
    )
    assert parse_skill_md(text, directory_id=draft.name).name == draft.name
    assert provider.calls
    assert provider.calls[0][0][0] == "utility"
    assert candidate.summary in str(provider.calls[0][0][1])
    assert "tools" not in provider.calls[0][1]

    class RaisingProvider:
        def complete(self, *_args, **_kwargs):
            raise RuntimeError("provider offline")

    fallback = draft_skill(candidate, provider=RaisingProvider())
    assert fallback.name == "messy-candidate"
    assert fallback.body


def test_injection_scan_denylist_table():
    from hunter.agent.curator import INJECTION_MARKERS, scan_draft

    for marker in INJECTION_MARKERS:
        flagged, reasons = scan_draft(f"safe prefix {marker} suffix")
        assert flagged is True
        assert any(marker.lower() in reason.lower() for reason in reasons)
    flagged, reasons = scan_draft("clean doctrine\n\twith evidence\n")
    assert flagged is False and reasons == ()
    flagged, reasons = scan_draft("clean\x01 doctrine")
    assert flagged is True and reasons


def test_flagged_draft_saved_quarantined_and_never_mounted(tmp_path):
    from hunter.agent.curator import review_and_save
    from hunter.agent.skills import load_corpus, match_skills, selected_skill_names

    output = io.StringIO()
    draft = _draft_card("injected-card", flagged=True)
    path = review_and_save(
        draft,
        home=tmp_path,
        ask=lambda prompt: True,
        console=Console(file=output, width=200),
    )
    assert path is not None
    preview = output.getvalue().lower()
    assert "warning:" in preview and "quarantined" in preview
    loaded = load_corpus(home=tmp_path)
    skill = next(skill for skill in loaded.skills if skill.name == "injected-card")
    assert skill.quarantined is True
    matched = {skill.name for skill in match_skills("injected-card", "injected-card", loaded.skills)}
    assert "injected-card" not in matched
    assert all(
        name != "injected-card"
        for name, _source in selected_skill_names("injected-card", home=tmp_path)
    )
    assert "inert" in preview or "inert" in str(path)


def test_ask_seam_fail_closed_never_saves_on_error(tmp_path):
    from hunter.agent.curator import review_and_save

    def raise_eof(_prompt):
        raise EOFError

    def raise_runtime(_prompt):
        raise RuntimeError("no")

    asks = (lambda _prompt: False, raise_eof, raise_runtime)
    for ask in asks:
        home = tmp_path / str(len(list(tmp_path.iterdir())))
        result = review_and_save(
            _draft_card("declined-card"),
            home=home,
            ask=ask,
            console=Console(file=io.StringIO()),
        )
        assert result is None
        assert not (home / ".hunteros" / "skills").exists()


def test_no_auto_save_path_exists(tmp_path, monkeypatch):
    from hunter.agent.curator import Candidate, dedupe_candidate, draft_skill, extract_candidates

    from hunter.agent import curator
    from hunter.kernel.ledger import Ledger

    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure curator path attempted a write")

    monkeypatch.setattr(curator, "write_skill", forbidden)
    candidate = Candidate("Pure candidate", "Pure summary", ("lesson",), "gap")
    assert extract_candidates(_retro(), []) == []
    assert dedupe_candidate(candidate, SimpleNamespace(skills=())) == ()
    assert draft_skill(candidate, provider=None).body
    source = inspect.getsource(curator)
    assert "import os" not in source and "import tempfile" not in source
    assert "import httpx" not in source and "import socket" not in source

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        result = curator.curate("R-NONE", ledger=ledger, home=tmp_path, ask=lambda _prompt: False)
    finally:
        ledger.close()
    assert "no skill candidates" in result
    assert not (tmp_path / ".hunteros" / "skills").exists()


def test_preview_contains_verdict_flags_and_body(tmp_path):
    from hunter.agent.curator import review_and_save

    output = io.StringIO()
    review_and_save(
        _draft_card("preview-card", flagged=True),
        home=tmp_path,
        ask=lambda _prompt: False,
        console=Console(file=output, width=240),
    )
    text = output.getvalue()
    assert "preview-card" in text
    assert "A concise curated doctrine card." in text
    assert "unique against" in text or "duplicates existing" in text
    assert str(tmp_path / ".hunteros" / "skills" / "preview-card" / "SKILL.md") in text
    assert "# Curated doctrine" in text
    assert "warning:" in text and "quarantined" in text


def test_curate_never_overwrites_existing_skill(tmp_path):
    from hunter.agent.curator import review_and_save
    from hunter.agent.skills import write_skill

    existing = _draft_card("existing-card")
    path = write_skill(existing, home=tmp_path)
    before = path.read_bytes()
    output = io.StringIO()
    result = review_and_save(
        existing,
        home=tmp_path,
        ask=lambda _prompt: True,
        console=Console(file=output, width=240),
    )
    assert result is None
    assert "exists" in output.getvalue().lower()
    assert path.read_bytes() == before


def test_curate_surfaces_end_to_end(tmp_path, monkeypatch):
    from hunter.chat.commands import CommandContext, safe_execute
    from hunter.chat.sessions import ChatStore
    from hunter.cli.main import app
    from hunter.kernel.ledger import Ledger
    from hunter.llm.config import default_config

    ledger, run_id = _verified_run(tmp_path)
    store = ChatStore(tmp_path / "chat.db")
    try:
        sid = store.create_session()
        ctx = CommandContext(
            store=store,
            config=default_config(),
            ledger_factory=lambda: ledger,
            args=run_id,
            options={"session_id": sid, "state_dir": str(tmp_path), "curator_ask": lambda _prompt: True},
        )
        reply = safe_execute("curate", ctx)
        assert "saved" in reply.text
        assert "Reflected XSS" in reply.text or "reflected" in reply.text.lower()
        assert list((tmp_path / ".hunteros" / "skills").glob("*/SKILL.md"))
    finally:
        store.close()
        ledger.close()

    cli_home = tmp_path / "cli-home"
    cli_home.mkdir()
    cli_state = tmp_path / "cli-state"
    cli_ledger, cli_run = _verified_run(cli_state, "R-CLI")
    cli_ledger.close()
    monkeypatch.setenv("HOME", str(cli_home))
    monkeypatch.setenv("USERPROFILE", str(cli_home))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(cli_home / "config.yaml"))
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    result = CliRunner().invoke(app, ["curate", cli_run, "--state", str(cli_state)], input="n\n")
    assert "skipped — not saved" in result.output
    assert not (cli_home / ".hunteros" / "skills").exists()

    empty_state = tmp_path / "empty-state"
    empty_ledger = Ledger(empty_state / "ledger.db")
    empty_ledger.create_run("R-EMPTY", "https://example.test/", "deterministic", "test")
    empty_ledger.close()
    no_cli = CliRunner().invoke(app, ["curate", "R-EMPTY", "--state", str(empty_state)], input="n\n")
    assert "no skill candidates" in no_cli.output
