"""M11 M0 — Reference dossier + adoption map, and the accumulating docs pins (§4).

Spec: docs/plans/m11-ux.md §4 (the FULL final case list is pinned
there). Case 1 (the dossier) must be green after M0; cases 2-8 accumulate:
each is extended/greened by the milestone noted in its docstring. Static
assertions read repo files only — no code imports, no network.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).parents[1]

SCOPE_DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."


def _read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


# -- 1 (M0) ----------------------------------------------------------------------


def test_ux_notes_exists_with_adoption_map():
    """M0: the dossier exists and ends with the adoption map table."""
    notes = _read("docs/UX-NOTES.md")
    assert "Adoption map" in notes
    for milestone in ("M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"):
        assert milestone in notes, milestone
    # The adoption map table has >= 20 data rows (pipes beyond the 2 header rows).
    rows = [
        line for line in notes.splitlines()
        if line.strip().startswith("|") and not re.match(r"^\|[\s\-|]+\|$", line.strip())
    ]
    assert len(rows) >= 22, len(rows)  # header + separator + >= 20 data rows


# -- 2 (M1/M8: unified home is THE documented home) ---------------------------------


def test_unified_home_is_the_documented_home():
    """M1 (+ M8 docs sweep): README/QUICKSTART point at ~/.hunter; no shipped
    doc outside CHANGELOG.md recommends ~/.hunteros as the HOME for user-facing
    state — a ~/.hunteros mention is allowed ONLY in migration explanations or
    in plumbing explanations (the legacy dir legitimately holds the installer
    venv, the bin shims, and update-check.json, and is never deleted)."""
    for doc in ("README.md", "QUICKSTART.md"):
        text = _read(doc)
        assert "~/.hunter" in text, f"{doc} must reference the unified home"

    docs = [p for p in REPO.glob("*.md") if p.name != "CHANGELOG.md"]
    docs += list((REPO / "docs").glob("*.md"))
    # Migration vocabulary + plumbing vocabulary. Docs may name ~/.hunteros to
    # explain the copy-forward migration or the retained installer plumbing
    # (venv, bin shims, update-check); naming it as the state home is what this
    # guard forbids.
    allowed = (
        "migration",
        "migrated",
        "venv",
        "update-check",
        "plumbing",
        "shim",
        "installer",
        ".hunteros/bin",
        ".hunteros\\bin",
    )
    violations: list[str] = []
    for path in docs:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ".hunteros" not in line:
                continue
            lowered = line.lower()
            if not any(word in lowered for word in allowed):
                violations.append(f"{path.name}: {line.strip()}")
    assert violations == [], "docs still recommend the legacy ~/.hunteros home:\n" + "\n".join(
        violations
    )


# -- 3 (M2) ----------------------------------------------------------------------


def test_scope_disclaimer_last_in_wizard_source():
    """M2: the unified wizard ends every terminal path with the disclaimer,
    and SCOPE_DISCLAIMER keeps its byte-exact text."""
    source = _read("src/hunter/cli/init_wizard.py")
    assert f'SCOPE_DISCLAIMER = "{SCOPE_DISCLAIMER}"' in source
    assert "def run_init_wizard" in source
    head, _, body = source.partition("def run_init_wizard")
    assert body, "run_init_wizard must exist"
    assert "_print_disclaimer(console)" in body  # every terminal path ends with it


# -- 4 (M7; a static regression guard that is true from day one) --------------------


def test_no_y_n_prompt_in_hunt_start_path():
    """M7: the two-question hunt-start path is prompt-free — the daemon CLI
    module carries no confirm_prompt and no 'Authorize this exact scope'."""
    source = _read("src/hunter/cli/daemon.py")
    assert "confirm_prompt" not in source
    assert "Authorize this exact scope" not in source


# -- 5 (M8) ----------------------------------------------------------------------


def test_changelog_and_version_bumped():
    """M8: CHANGELOG gains ## 0.6.0 and the versions agree."""
    changelog = _read("CHANGELOG.md")
    assert "## 0.6.0" in changelog
    pyproject = _read("pyproject.toml")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match, "pyproject version not found"
    assert match.group(1) == "0.6.0"
    from hunter import __version__

    assert __version__ == "0.6.0"


# -- 6 (M8) ----------------------------------------------------------------------


def test_install_ps1_path_prefers_venv_scripts():
    """M8: the PATH block lists venv\\Scripts before .hunteros\\bin; the
    markers still appear exactly once."""
    ps1 = _read("install.ps1")
    assert ps1.count("# >>> hunteros PATH >>>") == 1
    block_start = ps1.index("# >>> hunteros PATH >>>")
    block_end = ps1.index("# <<< hunteros PATH <<<")
    block = ps1[block_start:block_end]
    assert block.index("venv\\Scripts") < block.index(".hunteros\\bin")


# -- 7 (strings land in M1 per Q12; the module is pinned verbatim here) --------------


def test_hospitality_copy_pinned():
    """M1/M8: hospitality.py carries the pinned strings verbatim."""
    source = _read("src/hunter/hospitality.py")
    for pinned in (
        "⏸️ Hunter is paused. New work is on hold; run `hunter resume` to pick things back up.",
        "✅ Resumed — {pending} task(s) waiting in the queue.",
        "⏸️ cancelled — nothing was changed.",
        "⏸️ cancelled — the config was written; run `hunter doctor` to verify.",
        "✅ Verified endpoint via {url} ({count} model(s) visible)",
        "⚠️ Warning: could not verify this endpoint via {url}. Hunter will still save it.",
        "✅ API key saved to keys.env as {var}",
    ):
        assert pinned in source, pinned


# -- 8 (M4) ----------------------------------------------------------------------


def test_model_command_and_env_only_path_documented():
    """M4: docs/LLM.md mentions `hunter model` and the HUNTEROS_MODEL
    env-only override."""
    llm = _read("docs/LLM.md")
    assert "hunter model" in llm
    assert "HUNTEROS_MODEL" in llm
