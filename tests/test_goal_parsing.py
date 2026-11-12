"""Goal parsing: the documented CLI form must survive into the state.

The regression this pins: ``--goals 'findings-min:100'`` is the format the CLI
help advertises, but the colon form parsed to a bogus key, was dropped by
``_canon_goal_key``, and the operator's goal was silently ignored for the whole
run — no error, no warning, just a hunt that never reports its own objective.
"""
from __future__ import annotations

from hunter.workflow.state import (
    normalize_goals,
    save,
    load,
    new_state,
    state_path_for,
)


def test_colon_form_parses():
    assert normalize_goals("findings-min:5") == {"findings-min": 5}


def test_cli_comma_list_parses():
    """Exactly what ``--goals 'a:1,b:2'`` becomes after the CLI splits it."""
    raw = "findings-min:100,rce-proven-live:1"
    parsed = [g.strip() for g in raw.split(",") if g.strip()]
    assert normalize_goals(parsed) == {"findings-min": 100, "exploitable-min": 1}


def test_alias_keys_canonicalise():
    # rce-proven-live is a deliberate alias for the canonical exploitable-min.
    assert normalize_goals("rce-proven-live:2") == {"exploitable-min": 2}
    assert normalize_goals("verified-min:3") == {"verified-min": 3}


def test_legacy_and_dict_forms_still_work():
    assert normalize_goals({"findings-min": 5}) == {"findings-min": 5}
    assert normalize_goals([{"kind": "verified-min", "count": 2}]) == {"verified-min": 2}
    assert normalize_goals(["findings-min:5"]) == {"findings-min": 5}
    assert normalize_goals(None) == {}
    assert normalize_goals("") == {}


def test_goal_survives_save_load_roundtrip(tmp_path):
    state = new_state(
        target="/tmp/hunt-target-pv",
        goals=["findings-min:7"],
        wall_seconds=3600,
        idle_seconds=15,
    )
    path = save(state, state_path_for(state.target, tmp_path))
    assert load(path).goals == {"findings-min": 7}
