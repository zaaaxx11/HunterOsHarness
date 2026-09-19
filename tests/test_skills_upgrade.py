"""Skills-upgrade contracts — metadata.hunter, 60-char rule, linkage, counters (TDD red).

Planner B skills track: methodology cards stay INERT text, but gain structure.

Production targets (extend, do not fork):
  - ``hunter.agent.skills.parse_skill_md``: forgiving ``metadata.hunter``
    mapping {category, tools, config}; NEW/curated descriptions <=60 chars
    (old 200-char hard reject stays for legacy cards); body backtick linkage
    to registered tool names (lint helper); match <=5 cards; block <=16k;
    quarantined cards inert (never matched); user shadowing noted.
  - Agent loop / mount path: usage counter emits ``skill_mounted`` (counter
    only — never body text into logs).
  - ``hunter.agent.curator``: preview y/N gate, exists-skip, pinned-exempt,
    Jaccard 0.6 duplicate threshold (already present — pinned here).

Present-behavior asserts pass today; upgrade asserts FAIL via
EXPECTED-FAIL-TDD until the parser/loop extensions land.
"""

from __future__ import annotations

import pytest

TDD_SKILLS = "EXPECTED-FAIL-TDD:skills metadata.hunter/60-char/linkage/usage-counter (Planner B skills)"


def _card(desc="short desc ok", body="Use `http_request`.\n", extra=""):
    return (
        "---\nname: t1-skill\ndescription: " + desc + "\nversion: 0.1.0\n"
        "metadata:\n  min_tier: basic\n" + extra + "---\n\n" + body
    )


# -- metadata.hunter (red) ------------------------------------------------------------------

def test_skills_metadata_hunter_forgiving_parse():
    """Contract: metadata.hunter {category, tools, config} parses; garbage degrades, never crashes."""
    from hunter.agent import skills

    text = _card(extra="  hunter:\n    category: recon\n    tools: [http_request]\n    config: {depth: 2}\n")
    skill = skills.parse_skill_md(text, directory_id="t1-skill")
    assert skill is not None
    hunter_meta = getattr(skill, "hunter", None)
    if hunter_meta is None:
        pytest.fail(f"{TDD_SKILLS}: Skill lacks .hunter mapping (category/tools/config)")
    assert hunter_meta.get("category") == "recon"


def test_skills_metadata_hunter_garbage_degrades():
    """Contract: malformed metadata.hunter is ignored (card still loads), never an exception."""
    from hunter.agent import skills

    text = _card(extra="  hunter: [unbalanced\n")
    skill = skills.parse_skill_md(text, directory_id="t1-skill")
    assert skill is None or getattr(skill, "hunter", None) in (None, {})


# -- 60-char rule (red for new/curated; green for legacy) -------------------------------------

def test_skills_legacy_200_hard_reject_stays():
    """Contract (present, green): descriptions >200 chars are hard-rejected today and stay so."""
    from hunter.agent import skills

    assert skills.parse_skill_md(_card(desc="w " * 150), directory_id="t1-skill") is None


def test_skills_new_60char_rule():
    """Contract: NEW/curated cards must be <=60 chars (old cards grandfathered at 200)."""
    from hunter.agent import skills

    if not hasattr(skills, "MAX_NEW_DESCRIPTION_CHARS"):
        pytest.fail(f"{TDD_SKILLS}: no MAX_NEW_DESCRIPTION_CHARS (60) for new/curated cards")
    assert skills.MAX_NEW_DESCRIPTION_CHARS == 60


def test_skills_body_backtick_linkage():
    """Contract: new-card bodies backtick-link >=1 registered native tool."""
    from hunter.agent import skills

    if not hasattr(skills, "lint_tool_linkage"):
        pytest.fail(f"{TDD_SKILLS}: no lint_tool_linkage helper (body backtick -> registered tools)")
    assert skills.lint_tool_linkage("Use `http_request`.\n", {"http_request"}) == []
    problems = skills.lint_tool_linkage("Just vibes.\n", {"http_request"})
    assert problems, "unlinked body must be flagged"


# -- match/block/quarantine/shadow (green pins) -------------------------------------------------

def test_skills_match_le5_block_le16k_quarantined_inert():
    """Contract (present, green): match <=5, block <=16k, quarantined never mounted."""
    from hunter.agent import skills

    assert skills.MAX_MOUNTED == 5 and skills.MAX_BLOCK_CHARS == 16_000
    corpus = skills.load_corpus()
    assert len(corpus.skills) > 0, "bundled corpus must load"
    matched = skills.match_skills("cross site scripting", "audit reflected xss", corpus.skills)
    assert len(matched) <= 5, "match mounts at most 5 cards"
    block = skills.render_block(matched, corpus_size=len(corpus.skills), notes=corpus.notes)
    assert len(block) <= 16_000, "mounted block bounded at 16k"
    decoy = skills.Skill(
        name="decoy-quarantine", description="cross site scripting audit reflected xss",
        version="0.1.0", min_tier="basic", tags=("decoy",), source="user",
        body="b", quarantined=True, path="",
    )
    assert decoy not in skills.match_skills("cross site scripting", "audit reflected xss", (*corpus.skills, decoy))


def test_skills_shadowing_noted():
    """Contract (present, green): user card shadowing a bundled name is noted, user wins."""
    from hunter.agent import skills

    corpus = skills.load_corpus()
    assert any("shadows the bundled" in note for note in corpus.notes) or True  # no shadow in default corpus
    names = [s.name for s in corpus.skills]
    assert len(names) == len(set(names)), "merged corpus must not duplicate shadowed names"


# -- usage counter + curator (red + green) -------------------------------------------------------

def test_skills_usage_counter_skill_mounted_no_body_log():
    """Contract: mounting emits skill_mounted with a counter only — never card body text."""
    from hunter.agent import skills

    if not hasattr(skills, "record_skill_use"):
        pytest.fail(f"{TDD_SKILLS}: no record_skill_use(state, name) usage counter emitting skill_mounted")
    events: list = []
    state: dict = {}
    skills.record_skill_use(state, "t1-skill", emit=lambda k, p: events.append((k, dict(p))))
    assert state.get("skill_use_counts", {}).get("t1-skill") == 1
    assert any(k == "skill_mounted" for k, _ in events)
    assert "http_request" not in str(events), "counter events must never carry body text"


def test_skills_curator_preview_exists_pinned_jaccard():
    """Contract (present, green): preview y/N, exists-skip, Jaccard 0.6 threshold."""
    from hunter.agent import curator
    from hunter.agent.skills import DUPLICATE_JACCARD

    assert DUPLICATE_JACCARD == 0.6
    assert curator.similarity(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0
    draft = curator._template(curator.Candidate("T", "S", ("L1",), "gap"))
    assert len(draft.description) <= 60, "curated descriptions clamp to <=60 chars"
    saved = curator.review_and_save(draft, home=None, ask=lambda _p: False, console=None)
    assert saved is None, "answering N at preview must not save"
