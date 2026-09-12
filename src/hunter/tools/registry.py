"""Engine registry — maps engine names to :class:`EngineDriver` factories.

The registry is the single mount point between the workflow layer and the
engine layer: ``run_scan`` never imports a concrete engine, it asks for one
by name. Imports are lazy (inside :func:`get_engine`) so that importing the
registry — and everything that depends on it — stays cheap and never drags
in probe modules or optional dependencies.

Registered names: ``deterministic`` | ``llm`` | ``mock``.

``llm`` resolution (v0.2): with an explicit ``provider`` argument the
:class:`LLMEngine` is built with it; otherwise the registry tries the
default provider seam (``hunter.llm.router.ProviderRouter``, owned by the
LLM-wave builder — imported defensively because the module and its litellm
dependency are optional). Any failure degrades to ``LLMEngine(None)``, which
keeps the v0.1 ships-dark behavior: ``run``/``replay`` refuse with an
actionable message and ``run_scan`` records a failed run. The registry
deliberately does NOT raise for ``"llm"``: run_scan's contract requires
engine resolution to raise ValueError ONLY for unknown names before any
ledger write, and to fail configured-but-unready engines gracefully at run
time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hunter.engine.base import EngineDriver

__all__ = ["available_engines", "get_engine"]

# Registry order is stable: it is what available_engines() and error
# messages show, and what tests assert on.
_ENGINES: tuple[str, ...] = ("deterministic", "llm", "mock")


def available_engines() -> list[str]:
    """Names of every registered engine, in stable registry order."""
    return list(_ENGINES)


def _default_llm_provider() -> Any | None:
    """Best-effort default provider for the ``llm`` engine (B5's seam).

    Tries ``hunter.llm.router.ProviderRouter`` via ``from_env()`` when B5
    ships that classmethod, else the no-arg constructor. ANY failure — module
    not shipped yet, litellm missing, construction error — returns None so
    the engine keeps its ships-dark stub behavior with an actionable message.
    """
    try:
        from hunter.llm.router import ProviderRouter  # noqa: PLC0415 — optional, B5-owned
    except Exception:  # noqa: BLE001 — ImportError or import-time failure
        return None
    factory = getattr(ProviderRouter, "from_env", None) or ProviderRouter
    try:
        return factory()
    except Exception:  # noqa: BLE001 — broken config degrades to the stub
        return None


def get_engine(name: str, *, provider: Any | None = None) -> EngineDriver:
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

        return LLMEngine(provider if provider is not None else _default_llm_provider())
    available = ", ".join(available_engines())
    raise ValueError(f"unknown engine {name!r}; available engines: {available}")
