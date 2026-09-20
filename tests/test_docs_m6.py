"""M6 packaging and user-facing documentation contract tests."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_browser_extra_is_optional_and_no_download_contract_is_documented():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'browser = ["playwright>=1.40"]' in text
    deps_section = text.split("[project.optional-dependencies]")[0]
    assert "playwright" not in deps_section.lower()

    plan = (ROOT / "docs" / "plans" / "v0.4" / "M6-browser-automation.md").read_text(encoding="utf-8")
    assert "pip install 'hunteros-harness[browser]'" in plan
    assert "python -m playwright install chromium" in plan
    assert re.search(r"no (?:test )?starts a real browser", plan, re.IGNORECASE)
    assert re.search(r"never invokes `playwright install`", plan, re.IGNORECASE)
    assert "tests do not download Chromium" in plan


def test_user_docs_describe_optional_hunt_only_browser():
    user_docs = "\n".join(
        [
            (ROOT / "README.md").read_text(encoding="utf-8"),
            (ROOT / "docs" / "FIRST-RUN.md").read_text(encoding="utf-8"),
        ]
    ).lower()
    assert "browser" in user_docs
    assert re.search(r"optional", user_docs)
    assert re.search(r"hunt[- ]only|authorized hunt|governed hunt", user_docs)
    assert "scope" in user_docs and "scope-gated" in user_docs
    assert "chromium" in user_docs
    assert "agent.browser" in user_docs
    assert "without the extra" in user_docs or "without [browser]" in user_docs
