"""Duration parser — the shared ``[Nh][Nm][Ns]`` grammar (M8 F3).

Backs CLI ``--time`` / ``--min-time`` (daemon + hunt verbs) and the helper
scripts. Contract (pinned in docs/plans/v0.5/M8-ninja.md):

- ``"90"`` -> 90.0, ``"90s"`` -> 90.0, ``"90m"`` -> 5400.0, ``"2h"`` -> 7200.0,
  ``"1h30m"`` -> 5400.0, ``"1.5h"`` -> 5400.0;
- ``0`` / ``""`` / ``None`` -> 0.0 (0 means "off" / unlimited per F4);
- everything else (``"abc"``, ``"2x"``, ``"-5"``) raises HunterError in the
  ``config`` layer with the accepted grammar in the hint.

Pure functions — no IO, no network, Windows/POSIX identical.
"""

from __future__ import annotations

import re

from hunter.errors import HunterError

__all__ = ["parse_duration"]

# Grammar: optional hours, optional minutes, optional seconds.
_DURATION_RE = re.compile(r"^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s?)?$")

_DURATION_HINT = (
    "durations use [Nh][Nm][Ns] or bare seconds — e.g. 90, 3600, 2h, 1h30m "
    "(a bare number is seconds; 0 means unlimited)"
)


def _duration_error(text: str) -> HunterError:
    return HunterError(
        code="config.value",
        layer="config",
        message=f"invalid duration: {text!r}",
        hint=_DURATION_HINT,
    )


def parse_duration(text: str | int | float | None) -> float:
    """Parse a human duration into seconds (float).

    Accepts ``[Nh][Nm][Ns]``, bare numbers (seconds), ``None`` / empty (0).
    Garbage raises :class:`hunter.errors.HunterError`.
    """
    if text is None:
        return 0.0
    if isinstance(text, bool):
        raise _duration_error(str(text))
    if isinstance(text, (int, float)):
        value = float(text)
        if value < 0 or value != value or value in (float("inf"), float("-inf")):
            raise _duration_error(str(text))
        return value
    token = str(text).strip()
    if not token:
        return 0.0
    match = _DURATION_RE.match(token)
    if match is None:
        raise _duration_error(token)
    hours, minutes, seconds = match.groups()
    total = 0.0
    if hours:
        total += float(hours) * 3600.0
    if minutes:
        total += float(minutes) * 60.0
    if seconds:
        total += float(seconds)
    return total
