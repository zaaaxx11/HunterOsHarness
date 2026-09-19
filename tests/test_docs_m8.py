"""M8 F10 — docs, gitignore, and release bookkeeping gates (test-first).

Mirrors tests/test_docs_m3.py: static file reads plus one ``git ls-files``
subprocess (offline). These assert the END STATE of F10 — they stay red until
the builder lands the docs/gitignore/tracking changes, which is the intended
red phase. The 0.4.0 CHANGELOG block must remain intact (a release test
guards it); 0.5.0 goes ABOVE it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TOUCHED_DOCS = (
    "SOUL.md",
    "README.md",
    "QUICKSTART.md",
    "docs/LLM.md",
    "docs/GATEWAY.md",
    "docs/ARCHITECTURE.md",
)

LEVEL_LANGUAGE_RE = re.compile(r"\b(?:level|levels|tier)\s*\d", re.IGNORECASE)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_readme_drops_roadmap_links_and_documents_m8():
    readme = _read("README.md")
    assert "docs/ROADMAP" not in readme  # untracked docs would 404
    assert "hunt start" in readme
    assert "/approve" in readme
    assert "shell_exec" in readme


def test_llm_md_zero_unlimited_and_min_wall():
    llm_md = _read("docs/LLM.md")
    assert "0 = unlimited" in llm_md
    assert "min_wall_seconds" in llm_md


def test_gateway_md_discord_and_chat_approvals():
    gateway_md = _read("docs/GATEWAY.md")
    assert "HUNTEROS_DISCORD_TOKEN" in gateway_md
    assert "HUNTEROS_DISCORD_ALLOWED_USERS" in gateway_md
    assert "/approve" in gateway_md


def test_architecture_md_daemon_layer():
    architecture_md = _read("docs/ARCHITECTURE.md")
    assert "daemon.py" in architecture_md
    assert "hunt start" in architecture_md


def test_changelog_050_entry():
    changelog = _read("CHANGELOG.md")
    assert "## [0.5.0]" in changelog
    assert "## [0.4.0]" in changelog  # previous entry kept intact
    assert changelog.index("## [0.5.0]") < changelog.index("## [0.4.0]")
    for milestone in ("M1", "M2", "M3", "M4", "M5", "M6"):
        assert f"### {milestone}" in changelog
    assert "### Security" in changelog  # the 0.4.0 security block survives


def test_quickstart_hunt_lifecycle_and_approval():
    quickstart = _read("QUICKSTART.md")
    assert "hunt stop" in quickstart
    assert "hunt status" in quickstart
    assert "/approve" in quickstart


def test_no_level_language_in_new_docs_and_soul():
    for relative in TOUCHED_DOCS:
        text = _read(relative)
        assert not LEVEL_LANGUAGE_RE.search(text), relative
        assert "ninja level" not in text.lower(), relative


def test_gitignore_and_tracking_contract():
    gitignore = _read(".gitignore")
    for pattern in (
        "docs/ROADMAP*.md",
        "docs/plans/",
        ".hunter*/",
        "*.log",
        "artifacts/",
        "reports/",
        # F10 delta: tests and the CLI-smoke scratch dir are also untracked
        # (owner directive: no testing products on GitHub).
        "tests/",
        ".hunter-cli-smoke/",
    ):
        assert pattern in gitignore, pattern
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout.splitlines()
    assert not any(name.startswith("docs/ROADMAP") for name in tracked)
    assert not any(name.startswith("docs/plans/") for name in tracked)
    assert not any(name.startswith("tests/") for name in tracked)
