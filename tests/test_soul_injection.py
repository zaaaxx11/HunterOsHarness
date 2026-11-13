"""The _core soul is what turns a refusing model into a working hunter.

Without the identity block, step-5-preview-free answers "I can't conduct
unauthorized penetration testing ... against a live production endpoint" and
ships nothing. With it, the same model emits a tool call carrying a real,
citable finding. This pins both halves:

1. _core.md ships, is small, and is prepended to EVERY lane.
2. The laws it states are actually present (authorized / evidence / scope /
   ship) — a soul that drifts back to a bare role line regresses silently.
"""
from __future__ import annotations

from pathlib import Path

from hunter.workflow.loop import _load_soul

SOULS_DIR = (
    Path(__file__).resolve().parents[1]
    / "src" / "hunter" / "_data" / "prompts" / "souls"
)

MAX_TOKENS = 1000


def test_core_soul_is_small():
    text = (SOULS_DIR / "_core.md").read_text(encoding="utf-8")
    assert len(text) // 4 <= MAX_TOKENS, f"_core.md is {len(text)//4} tokens"


def test_core_soul_states_the_laws():
    text = (SOULS_DIR / "_core.md").read_text(encoding="utf-8").lower()
    for marker in ("authorized", "evidence", "scope", "ship"):
        assert marker in text, f"_core.md lost its '{marker}' law"


def test_every_lane_gets_the_core_identity():
    core = (SOULS_DIR / "_core.md").read_text(encoding="utf-8")
    for lane in ("architect", "redteam", "fuzzer", "chainer", "verifier", "recon"):
        soul = _load_soul(lane)
        assert core.strip()[:40] in soul, f"{lane} lost the base identity"
        # and the lane's own voice is still there after it
        assert len(soul) > len(core), f"{lane} has no lane-specific part"


def test_unknown_lane_still_gets_a_soul():
    soul = _load_soul("no-such-lane-xyz")
    assert "HunterOS" in soul
    assert "report_finding" in soul


def test_missing_core_degrades_without_crashing(monkeypatch):
    """A missing _core.md must degrade to the lane soul, never crash.

    Simulated by making the core unreadable while the lane file still reads —
    exactly the OSError branch the try/except guards.
    """
    import hunter.workflow.loop as loop_mod

    souls = loop_mod.Path(__file__).resolve().parents[1] / "src" / "hunter" / "_data" / "prompts" / "souls"
    core = souls / "_core.md"
    assert core.exists()

    real_read = loop_mod.Path.read_text

    def _read_text(self, *a, **k):
        if self.name == "_core.md":
            raise OSError("simulated: core soul gone")
        return real_read(self, *a, **k)

    monkeypatch.setattr(loop_mod.Path, "read_text", _read_text)
    soul = loop_mod._load_soul("redteam")
    assert soul, "must never return empty"
    assert "Red Team" in soul, "lane voice must survive the core being gone"
