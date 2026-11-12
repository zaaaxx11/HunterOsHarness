"""HunterOS agent tools.

Two surfaces live here and both are re-exported so every importer keeps working:

* ``registry`` — the v0.2 agent tool registry (``build_registry``, the probe
  sets ``ACTIVE_PROBES`` / ``PASSIVE_PROBES`` / ``KNOWN_PROBES`` ...
  ). Everything the LLM brain may call.
* ``all_tools`` — standalone CLI wrappers with JSON in/out, importable without
  the rest of the package.

Historically ``registry`` was the module ``tools.py``; the plugins package took
the ``tools`` name and silently shadowed it, which broke every
``from hunter.agent.tools import build_registry``. Keep the bridge explicit.
"""

from .all_tools import *  # noqa: F401,F403
from .registry import (  # noqa: F401
    _SHELL_OUTPUT_LIMIT,
    _shell_cwd,
    ACTIVE_PROBES,
    KNOWN_PROBES,
    PASSIVE_PROBES,
    build_registry,
)
from ..tools_base import ToolSpec  # noqa: F401  (canonical home since the split)

__all__ = [
    "_SHELL_OUTPUT_LIMIT",
    "ACTIVE_PROBES",
    "KNOWN_PROBES",
    "PASSIVE_PROBES",
    "ToolSpec",
    "_shell_cwd",
    "build_registry",
]
