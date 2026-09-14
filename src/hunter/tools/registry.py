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
    from hunter.llm.config import HunterConfig

__all__ = ["available_engines", "get_engine"]

# Registry order is stable: it is what available_engines() and error
# messages show, and what tests assert on.
_ENGINES: tuple[str, ...] = ("deterministic", "llm", "mock")


def available_engines() -> list[str]:
    """Names of every registered engine, in stable registry order."""
    return list(_ENGINES)


def _default_llm_provider(config: HunterConfig | None = None) -> Any | None:
    """Best-effort default provider for the ``llm`` engine.

    The provider is always built from one explicitly loaded config.  Config
    errors, missing optional dependencies, and other construction failures
    intentionally degrade to ``LLMEngine(None)`` so explicit LLM runs retain
    their ledgered failed-run behavior.
    """
    try:
        from hunter.llm.config import (  # noqa: PLC0415 — optional LLM path
            find_config_path,
            load_config,
        )
        from hunter.llm.router import provider_from_config  # noqa: PLC0415 — optional LLM path

        if config is None:
            # HUNTEROS_CONFIG is an explicit operator choice.  A stale path
            # must not turn into a provider backed by pure defaults.
            configured_path = find_config_path()
            if configured_path is not None and not configured_path.is_file():
                return None
            config = load_config()
        return provider_from_config(config)
    except Exception:  # noqa: BLE001 — broken config/provider degrades to stub
        return None


def get_engine(
    name: str, *, provider: Any | None = None, config: HunterConfig | None = None
) -> EngineDriver:
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

        return LLMEngine(
            provider if provider is not None else _default_llm_provider(config)
        )
    available = ", ".join(available_engines())
    raise ValueError(f"unknown engine {name!r}; available engines: {available}")
