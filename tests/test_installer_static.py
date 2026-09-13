"""M1 installer/docs static contract — reads repo files, no execution.

Every test here reads install.sh / install.ps1 / README.md / QUICKSTART.md /
docs/FIRST-RUN.md from the repo root (no network, no subprocess). They pin the
M1 target state and FAIL until the builder ships the new installers, the
``hunt`` pyproject alias, and the docs one-liners. The script-execution checks
(S1-S8) are orchestrator checks, deliberately NOT pytest.
"""

from __future__ import annotations

from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_REPO_URL = "https://github.com/zaaaxx11/HunterOsHarness.git"
PATH_MARKER = "# >>> hunteros PATH >>>"
PATH_MARKER_END = "# <<< hunteros PATH <<<"
DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."

CURL_ONE_LINER = (
    "curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash"
)
IRM_ONE_LINER = (
    "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
)

# Exact banner bytes from the M1 design doc (§2.2): pure ASCII, tagline uses a
# plain hyphen so the installer stays byte-ASCII.
BANNER_LINE_1 = " _   _   _   _   _   _   _____   _____   ____"
BANNER_LINE_2 = "| | | | | | | | | \\ | | |_   _| | ____| |  _ \\   / _ \\  / ____|"
BANNER_LINE_4 = "|_| |_|  \\___/  |_| \\_|   |_|   |_____| |_| \\_\\  \\___/  |____/"
BANNER_TAGLINE = "HunterOs Harness - evidence or nothing"


def test_pyproject_declares_hunt_script():
    """A35: pyproject [project.scripts] gains `hunt` (and keeps `hunter`)."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    assert scripts["hunt"] == "hunter.cli.main:main"
    assert scripts["hunter"] == "hunter.cli.main:main"


def test_installer_static_contract():
    """A36: both installers carry the M1 static contract (no execution)."""
    sh = (ROOT / "install.sh").read_text(encoding="utf-8")
    ps1 = (ROOT / "install.ps1").read_text(encoding="utf-8")

    # Real repo URL (today it is the OWNER placeholder) + env override.
    for text in (sh, ps1):
        assert DEFAULT_REPO_URL in text
        assert "INSTALL_REPO_URL" in text

    # Shim targets: POSIX wraps bin/hunter + bin/hunt, Windows hunter.cmd/hunt.cmd.
    assert "bin/hunter" in sh
    assert "bin/hunt" in sh
    assert "hunter.cmd" in ps1
    assert "hunt.cmd" in ps1

    # Tagged PATH block + dedupe mechanism in each script's native tooling.
    for text in (sh, ps1):
        assert PATH_MARKER in text
        assert PATH_MARKER_END in text
    assert "grep -qF" in sh
    assert "Select-String" in ps1
    assert "-SimpleMatch" in ps1

    # Flags and the interactive-handoff tty checks.
    assert "--skip-setup" in sh
    assert "--dry-run" in sh
    assert "-SkipSetup" in ps1
    assert "-DryRun" in ps1
    assert "[ -t 0 ]" in sh
    assert "[Console]::IsInputRedirected" in ps1

    # The scope disclaimer is the unconditional final-printout line in both.
    for text in (sh, ps1):
        assert DISCLAIMER in text

    # Banner block: exact art bytes present and every banner byte ASCII.
    for text in (sh, ps1):
        lines = text.splitlines()
        assert BANNER_LINE_1 in lines
        assert BANNER_LINE_2 in lines
        assert BANNER_LINE_4 in lines
        start = lines.index(BANNER_LINE_1)
        block = lines[start : start + 5]  # 4 art lines + tagline
        assert block[-1].strip() == BANNER_TAGLINE
        assert all(ord(char) < 128 for line in block for char in line)


def test_docs_one_liner_urls():
    """A37: README + QUICKSTART carry both raw.githubusercontent one-liners."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    quickstart = (ROOT / "QUICKSTART.md").read_text(encoding="utf-8")
    for doc in (readme, quickstart):
        assert CURL_ONE_LINER in doc
        assert IRM_ONE_LINER in doc
    first_run = (ROOT / "docs" / "FIRST-RUN.md").read_text(encoding="utf-8")
    assert "~/.hunteros/bin" in first_run
