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

# Pinned grammar: optional hours, optional minutes, optional seconds (the
# ``s`` suffix itself is optional). Anchored both ends, so any other shape
# (minus signs, bare units, prose) simply fails to match.
_DURATION_RE = re.compile(r"^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s?)?$")

_DURATION_HINT = (
    "durations use the grammar [Nh][Nm][Ns] — e.g. 90, 90s, 90m, 2h, 1h30m, 1.5h "
    "(bare numbers are seconds; 0 or empty means off/unlimited)"
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

    Accepts the pinned ``[Nh][Nm][Ns]`` grammar, bare numbers (seconds),
    numeric seconds, ``None`` and empty strings (both 0.0). Garbage —
    including negatives, which are not in the grammar — raises
    :class:`hunter.errors.HunterError` (layer ``config``, code
    ``config.value``) with the accepted grammar in the hint.
    """
    if text is None:
        return 0.0
    if isinstance(text, bool):  # bool is an int subclass — never a duration
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
