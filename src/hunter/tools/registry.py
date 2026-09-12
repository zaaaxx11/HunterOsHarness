"""Engine registry — maps engine names to :class:`EngineDriver` factories.

The registry is the single mount point between the workflow layer and the
engine layer: ``run_scan`` never imports a concrete engine, it asks for one
by name. Imports are lazy (inside :func:`get_engine`) so that importing the
registry — and everything that depends on it — stays cheap and never drags
in probe modules or optional dependencies.

Registered names: ``deterministic`` | ``llm`` | ``mock``.

Note: the ``llm`` entry returns the :class:`LLMEngine` stub. Its ``run``
raises the v0.2 ``RuntimeError`` BY DESIGN — that is the shipped-dark brain,
not a registry error, and the pipeline handles it like any engine failure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.engine.base import EngineDriver

__all__ = ["available_engines", "get_engine"]

# Registry order is stable: it is what available_engines() and error
# messages show, and what tests assert on.
_ENGINES: tuple[str, ...] = ("deterministic", "llm", "mock")


def available_engines() -> list[str]:
    """Names of every registered engine, in stable registry order."""
    return list(_ENGINES)


def get_engine(name: str) -> EngineDriver:
    """Instantiate the engine registered under ``name``.

    Raises:
        ValueError: when ``name`` is not a registered engine; the message
            lists the available names so callers (and the CLI) can recover.
    """
    if name == "deterministic":
        from hunter.engine.deterministic.engine import DeterministicEngine

        return DeterministicEngine()
    if name == "mock":
        from hunter.engine.mock import MockEngine

        return MockEngine()
    if name == "llm":
        from hunter.engine.llm import LLMEngine

        return LLMEngine()
    available = ", ".join(available_engines())
    raise ValueError(f"unknown engine {name!r}; available engines: {available}")
