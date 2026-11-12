"""Backward-compat shim — imports from hunter.workflow.loop.

``from ... import *`` skips underscore-prefixed names (loop.py has no
``__all__``), so the private helpers that tests and old callers import by name
are re-exported explicitly below.
"""

from hunter.workflow.loop import *  # noqa: F401, F403
from hunter.workflow.loop import (  # noqa: F401
    _calls_from_text,
    _candidates_from_args,
    _norm_response,
    _parse_verdict,
    _repair_args,
    HuntLoop,
    LANE_SOULS,
    run_v4,
)

HuntLoopV4 = HuntLoop  # noqa: F405
