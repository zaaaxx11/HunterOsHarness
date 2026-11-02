"""Per-state output formats: the format follows the role, not the target.

A verifier that is handed the hunter's finding format ships findings it was
supposed to be adjudicating; an architect handed the same format ships
half-formed findings instead of the map the hunters need. The output format
is therefore a function of state.
"""

from __future__ import annotations

import pytest

from hunter.agent.output_formats import (
    OUTPUT_FORMATS,
    STATES,
    output_format_block,
    resolve_state,
)
from hunter.agent.prompts import build_system_prompt


def _prompt(state: str | None) -> str:
    return build_system_prompt(
        target_url="http://127.0.0.1:1/",
        scope_summary={"name": "test"},
        skills_index="(none)",
        state=state,
    )


def _section(prompt: str, label: str) -> str:
    marker = f"### Output format — {label} state"
    start = prompt.find(marker)
    assert start >= 0, f"no {label} section rendered"
    nxt = prompt.find("### Output format —", start + len(marker))
    return prompt[start : nxt if nxt >= 0 else len(prompt)]


# -- the four canonical states ------------------------------------------------


def test_every_state_renders_its_own_section():
    for state in STATES:
        prompt = _prompt(state)
        assert f"### Output format — {state.upper()} state" in prompt, state


def test_the_four_states_are_mutually_distinct():
    prompts = {state: _prompt(state) for state in STATES}
    assert len(set(prompts.values())) == len(STATES)


def test_hunter_format_carries_the_canonical_finding_fields():
    section = _section(_prompt("hunter"), "HUNTER")
    for field in ("VULNERABILITY", "ENTRY", "CHAIN", "IMPACT", "POC",
                  "EVIDENCE", "CONFIDENCE", "MITIGATION", "VERIFICATION"):
        assert field in section, field


def test_verifier_returns_a_verdict_block_not_a_finding_block():
    section = _section(_prompt("verifier"), "VERIFIER")
    for field in ("CLAIM", "VERDICT", "BASIS", "GAP", "CHALLENGE", "RESIDUAL"):
        assert field in section, field
    # The verifier must not be handed the finding shape it would copy.
    assert "VULNERABILITY:" not in section
    assert "You ship findings" not in section


def test_architect_returns_a_map_and_ranked_questions():
    section = _section(_prompt("architect"), "ARCHITECT")
    for field in ("SURFACE", "TRUST_BOUNDARIES", "ASSUMPTIONS", "UNVERIFIED",
                  "RANKED_QUESTIONS", "ELIMINATED"):
        assert field in section, field
    assert "VULNERABILITY:" not in section


def test_orchestrator_returns_a_handoff_with_a_checkpoint():
    section = _section(_prompt("orchestrator"), "ORCHESTRATOR")
    for field in ("MISSION", "STATE", "WHY", "BUDGET", "HANDOFF", "CHECKPOINT"):
        assert field in section, field
    assert "VULNERABILITY:" not in section


# -- alias resolution --------------------------------------------------------


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("redteam", "hunter"),
        ("red_team", "hunter"),
        ("fuzzer", "hunter"),
        ("chainer", "hunter"),
        ("hunt", "hunter"),
        ("verify", "verifier"),
        ("verification", "verifier"),
        ("recon", "architect"),
        ("plan", "architect"),
        ("orchestrate", "orchestrator"),
        ("sovereign", "orchestrator"),
        ("Red-Team", "hunter"),
        ("VERIFIER", "verifier"),
    ],
)
def test_soul_names_alias_onto_the_state_that_fits_their_work(alias, expected):
    assert resolve_state(alias) == expected


def test_unknown_state_falls_back_to_hunter():
    # An unrecognised label is far more likely to mean "go hunt" than "go
    # plan": a hunt that ships nothing is recoverable, a plan that never
    # hunts is not.
    assert resolve_state("nonsense") == "hunter"
    assert resolve_state("") == "hunter"
    assert resolve_state(None) == "hunter"


def test_empty_state_suppresses_the_section_entirely():
    assert output_format_block("") == ""
    # None is NOT suppression: it renders the hunter default.
    assert "HUNTER" in output_format_block(None)
    assert "### Output format — HUNTER state" in _prompt(None)


# -- the section actually lands in the rendered prompt -----------------------


def test_default_render_carries_the_hunter_section():
    prompt = build_system_prompt(
        target_url="http://127.0.0.1:1/",
        scope_summary={"name": "t"},
        skills_index="(n)",
    )
    assert "### Output format — HUNTER state" in prompt


def test_state_survives_the_template_round_trip():
    # The placeholder must be consumed, not left literal in the output.
    for state in STATES:
        assert "{output_format_block}" not in _prompt(state), state


def test_each_state_keeps_the_shared_doctrine_sections():
    # The per-state block REPLACES the generic format; it must not displace
    # the evidence doctrine or the tool protocol that every state obeys.
    for state in STATES:
        prompt = _prompt(state)
        assert "## 6. Evidence doctrine" in prompt, state
        assert "## 8. Tool protocol" in prompt, state
        assert "create_finding_request" in prompt, state


def test_output_formats_table_is_not_empty():
    assert STATES
    for state, body in OUTPUT_FORMATS.items():
        assert body.strip(), state
        assert "```" in body, state  # every state ships a literal block
