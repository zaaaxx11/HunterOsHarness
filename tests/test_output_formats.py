"""Output formats: after v1.1 the prompt is uniform — no per-state section."""

from __future__ import annotations

import pytest

from hunter.agent.output_formats import (
    OUTPUT_FORMATS,
    STATES,
    resolve_state,
)
from hunter.agent.prompts import build_system_prompt


def _prompt(state: str | None = None) -> str:
    return build_system_prompt(
        target_url="http://127.0.0.1:1/",
        scope_summary={"name": "test"},
        skills_index="(none)",
        state=state,
    )


# -- alias resolution (unchanged) --------------------------------------------


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("redteam", "hunter"),
        ("fuzzer", "hunter"),
        ("chainer", "hunter"),
        ("verify", "verifier"),
        ("recon", "architect"),
        ("sovereign", "orchestrator"),
    ],
)
def test_soul_names_alias(alias, expected):
    assert resolve_state(alias) == expected


def test_unknown_falls_back_to_hunter():
    assert resolve_state("nonsense") == "hunter"
    assert resolve_state("") == "hunter"
    assert resolve_state(None) == "hunter"


def test_output_formats_table_not_empty():
    assert STATES
    for state, body in OUTPUT_FORMATS.items():
        assert body.strip(), state


# -- v1.1: uniform prompt, no per-state sections ------------------------------


def test_prompt_has_no_output_format_placeholder():
    assert "{output_format_block}" not in _prompt()


def test_prompt_directs_agent_to_ship_finding():
    prompt = _prompt()
    assert "create_finding_request" in prompt
    assert "finish_scan" in prompt
    assert "MUST ship" in prompt


def test_prompt_has_finding_format():
    prompt = _prompt()
    assert "VULNERABILITY:" in prompt
    assert "IMPACT:" in prompt
    assert "EVIDENCE:" in prompt


def test_prompt_mentions_slither():
    prompt = _prompt()
    assert "slither_run" in prompt


def test_all_states_produce_same_prompt():
    prompts = {state: _prompt(state) for state in STATES}
    assert len(set(prompts.values())) == 1  # uniform now