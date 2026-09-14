"""M5 documentation pins (D1)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docs_describe_user_skills_and_curator():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    first_run = (ROOT / "docs" / "FIRST-RUN.md").read_text(encoding="utf-8")
    assert "~/.hunteros/skills" in readme
    assert "/curate" in readme
    assert "preview" in first_run.lower() or "[quarantined]" in first_run
