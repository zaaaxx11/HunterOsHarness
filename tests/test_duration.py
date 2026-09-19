"""M8 F3 — ``hunter.duration.parse_duration`` contract tests (test-first).

The parser backs CLI ``--time`` / ``--min-time`` and the scripts. Grammar
(pinned in docs/plans/v0.5/M8-ninja.md): ``[Nh][Nm][Ns]`` with optional
seconds suffix, bare numbers = seconds, empty/None = 0.0, everything else is
a HunterError in the config layer. Pure functions — no IO, no network.
"""

from __future__ import annotations

import pytest

from hunter.duration import parse_duration
from hunter.errors import HunterError


def test_parse_duration_units_and_mixed():
    assert parse_duration("90m") == 5400.0
    assert parse_duration("2h") == 7200.0
    assert parse_duration("1h30m") == 5400.0


def test_parse_duration_bare_number_is_seconds():
    assert parse_duration("120") == 120.0


def test_parse_duration_decimal_and_zero():
    assert parse_duration("1.5h") == 5400.0
    assert parse_duration("0") == 0.0


def test_parse_duration_empty_is_zero():
    assert parse_duration("") == 0.0
    assert parse_duration(None) == 0.0


def test_parse_duration_garbage_raises_hunter_error():
    for bad in ("abc", "2x"):
        with pytest.raises(HunterError) as excinfo:
            parse_duration(bad)
        assert excinfo.value.layer == "config"
        assert excinfo.value.code == "config.value"
        # the hint shows the accepted grammar
        assert "h" in excinfo.value.hint and "m" in excinfo.value.hint


def test_parse_duration_negative_raises():
    # minus signs are not in the grammar — a negative duration is garbage.
    with pytest.raises(HunterError):
        parse_duration("-5")
