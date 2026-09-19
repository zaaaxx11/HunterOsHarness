"""M5 corpus, validation, quarantine, and atomic-writer contracts (SK1-SK10)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _clean_selector():
    from hunter.agent.prompts import install_skill_selector

    install_skill_selector(None)
    yield
    install_skill_selector(None)


def _card(
    name: str,
    *,
    description: str = "A useful local doctrine card.",
    version: str = "0.1.0",
    metadata: str = "",
    tags: tuple[str, ...] = (),
    quarantined: bool = False,
    body: str = "# Doctrine\n\nEvidence or nothing.",
) -> str:
    lines = ["---", f"name: {name}", f"description: {description}", f"version: {version}"]
    if metadata:
        lines.extend(["metadata:", f"  min_tier: {metadata}"])
    if tags:
        lines.append("tags: [" + ", ".join(tags) + "]")
    if quarantined:
        lines.append("quarantined: true")
    lines.extend(["---", "", body])
    return "\n".join(lines) + "\n"


def _user_skill(home: Path, name: str, text: str | None = None) -> Path:
    path = home / ".hunter" / "skills" / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(text or _card(name), encoding="utf-8")
    return path


def test_bundled_corpus_loads_with_tags():
    from hunter.agent.skills import load_corpus

    corpus = load_corpus()
    assert len(corpus.skills) == 7
    assert all(skill.source == "bundled" for skill in corpus.skills)
    assert all(skill.name == Path(skill.path).parent.name if skill.path else True for skill in corpus.skills)
    assert all(skill.tags for skill in corpus.skills)
    by_name = {skill.name: skill for skill in corpus.skills}
    assert "core" in by_name["scope-discipline"].tags
    assert "core" in by_name["verification-ladder"].tags
    assert "recon" in by_name["recon-basics"].tags
    assert corpus.notes == ()


def test_malformed_frontmatter_skips_with_notes(tmp_path):
    from hunter.agent.skills import load_corpus

    malformed = {
        "missing-name": "---\ndescription: missing name\nversion: 0.1.0\n---\nbody\n",
        "wrong-name": _card("other-name"),
        "bad-tier": _card("bad-tier", metadata="expert"),
        "empty-description": _card("empty-description", description="''"),
        "long-description": _card("long-description", description="x" * 201),
        "bad-yaml": "---\nname: [unclosed\ndescription: broken\n---\nbody\n",
    }
    for name, text in malformed.items():
        _user_skill(tmp_path, name, text)
    _user_skill(tmp_path, "valid-sibling")

    corpus = load_corpus(home=tmp_path)
    assert any(skill.name == "valid-sibling" for skill in corpus.skills)
    for name in malformed:
        notes = [note for note in corpus.notes if name in note]
        assert len(notes) == 1


def test_skill_id_regex_blocks_traversal_and_garbage(tmp_path):
    from hunter.agent.skills import load_corpus

    names = ("Foo", "foo_bar", "..hidden", "x y")
    for name in names:
        _user_skill(tmp_path, name, _card(name))
    _user_skill(tmp_path, "sneaky", _card("../escape"))
    outside = tmp_path / "escape" / "SKILL.md"
    corpus = load_corpus(home=tmp_path)
    assert not any(skill.name in {*names, "../escape", "escape"} for skill in corpus.skills)
    assert all(any(name in note for note in corpus.notes) for name in (*names, "sneaky"))
    assert not outside.exists()


def test_skill_size_caps_skip_huge_files(tmp_path):
    from hunter.agent.skills import load_corpus

    body_400 = "\n".join(f"line {index}" for index in range(400))
    body_401 = "\n".join(f"line {index}" for index in range(401))
    _user_skill(tmp_path, "four-hundred-lines", _card("four-hundred-lines", body=body_400))
    _user_skill(tmp_path, "four-hundred-one-lines", _card("four-hundred-one-lines", body=body_401))
    huge = _card("huge-bytes", body="x" * 33_000)
    _user_skill(tmp_path, "huge-bytes", huge)

    corpus = load_corpus(home=tmp_path)
    names = {skill.name for skill in corpus.skills}
    assert "four-hundred-lines" in names
    assert "four-hundred-one-lines" not in names
    assert "huge-bytes" not in names
    assert any("four-hundred-one-lines" in note and "too large" in note for note in corpus.notes)
    assert any("huge-bytes" in note and "too large" in note for note in corpus.notes)


def test_user_skill_shadows_bundled_with_note(tmp_path):
    from hunter.agent.skills import load_corpus

    _user_skill(tmp_path, "recon-basics", _card("recon-basics", tags=("recon",)))
    _user_skill(tmp_path, "my-technique", _card("my-technique", description="A local staging trick."))
    corpus = load_corpus(home=tmp_path)
    by_name = {skill.name: skill for skill in corpus.skills}
    assert by_name["recon-basics"].source == "user"
    assert sum(skill.name == "recon-basics" for skill in corpus.skills) == 1
    assert by_name["my-technique"].source == "user"
    assert sum(skill.source == "bundled" for skill in corpus.skills) == 6
    assert "user skill 'recon-basics' shadows the bundled skill 'recon-basics'" in corpus.notes


def test_quarantined_skill_listed_but_never_matched(tmp_path):
    from hunter.agent.skills import load_corpus, match_skills, selected_skill_names

    _user_skill(
        tmp_path,
        "hostile-card",
        _card("hostile-card", description="quarantine trigger unique", quarantined=True),
    )
    corpus = load_corpus(home=tmp_path)
    skill = next(skill for skill in corpus.skills if skill.name == "hostile-card")
    assert skill.quarantined is True
    assert not match_skills("", "quarantine trigger unique", corpus.skills)
    assert all(
        name != "hostile-card"
        for name, _source in selected_skill_names("quarantine trigger unique", home=tmp_path)
    )


def test_missing_corpus_and_resources_failure_tolerated(tmp_path, monkeypatch):
    from hunter.agent import skills

    corpus = skills.load_corpus(home=tmp_path)
    assert corpus.skills
    assert not (tmp_path / ".hunter" / "skills").exists()
    _user_skill(tmp_path, "survives-bundled-error")

    def broken_files(*_args, **_kwargs):
        raise OSError("bundled resources unavailable")

    monkeypatch.setattr(skills.resources, "files", broken_files)
    corpus = skills.load_corpus(home=tmp_path)
    assert [skill.name for skill in corpus.skills] == ["survives-bundled-error"]


def test_parse_skill_md_minimal_card_and_defaults():
    from hunter.agent.skills import parse_skill_md

    card = _card(
        "minimal",
        version="9.9.9",
        body="# Body\n\nline",
    ).replace("version: 9.9.9", "version: 9.9.9\ntags: [valid-tag, BAD_TAG, also-valid]")
    skill = parse_skill_md(card, directory_id="minimal")
    assert skill.name == "minimal"
    assert skill.version == "9.9.9"
    assert skill.min_tier == "basic"
    assert skill.tags == ("valid-tag", "also-valid")
    assert skill.quarantined is False
    assert "name: minimal" not in skill.body
    assert skill.body.startswith("# Body")


def test_write_skill_success_and_refusals(tmp_path, monkeypatch):
    from hunter.agent.skills import write_skill

    from hunter.errors import HunterError

    draft = SimpleNamespace(
        name="saved-card",
        description="A saved card.",
        version="0.1.0",
        min_tier="basic",
        tags=("curated", "verified-finding"),
        body="# Saved\n\nEvidence or nothing.",
        flagged=True,
    )
    path = write_skill(draft, home=tmp_path)
    assert path == tmp_path / ".hunter" / "skills" / "saved-card" / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    assert text.startswith(
        "---\nname: saved-card\ndescription: A saved card.\nversion: 0.1.0\n"
        "metadata:\n  min_tier: basic\ntags:\n- curated\n- verified-finding\nquarantined: true\n---\n"
    )
    assert "# Saved" in text

    with pytest.raises(HunterError) as traversal:
        write_skill(SimpleNamespace(**{**vars(draft), "name": "../escape"}), home=tmp_path)
    assert traversal.value.code == "skills.refused"

    before = path.read_bytes()
    with pytest.raises(HunterError) as exists:
        write_skill(draft, home=tmp_path)
    assert exists.value.code == "skills.exists"
    assert path.read_bytes() == before

    outside = tmp_path / "outside"
    outside.mkdir()
    original_resolve = Path.resolve

    def resolve_outside(self, strict=False):
        resolved = original_resolve(self, strict=strict)
        if self.name == "outside-target":
            return outside / self.name
        return resolved

    monkeypatch.setattr(Path, "resolve", resolve_outside)
    with pytest.raises(HunterError) as out_of_root:
        write_skill(SimpleNamespace(**{**vars(draft), "name": "outside-target"}), home=tmp_path)
    assert out_of_root.value.code == "skills.refused"


def test_keys_atomic_write_text_public_wrapper(tmp_path):
    from hunter.llm.keys import atomic_write_text, write_keys_env

    target = tmp_path / "atomic" / "value.txt"
    atomic_write_text(target, "first\n")
    atomic_write_text(target, "second\n")
    assert target.read_bytes() == b"second\n"
    assert not list(target.parent.glob("*.tmp"))
    keys = write_keys_env({"M5_TEST_KEY": "value"}, home=tmp_path)
    assert keys.read_text(encoding="utf-8").endswith('M5_TEST_KEY="value"\n')
