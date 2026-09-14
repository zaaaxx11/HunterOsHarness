"""D1 (M3) — the docs describe the unified hunt surfaces. Static file reads
only; the fragments anchor on the chat/hunt sections (never the M4 update
sections). No execution, no network."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docs_describe_hunt_surfaces():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "/hunt on" in readme  # session hunt mode
    assert "hunter hunt" in readme  # the one-shot CLI
    assert "scope manifest" in readme  # the unchanged gate, named in the chat docs

    first_run = (ROOT / "docs" / "FIRST-RUN.md").read_text(encoding="utf-8")
    assert (
        "hunt mode: starting audit of" in first_run or "hunter hunt" in first_run
    )  # the captured hunt transcript marker
