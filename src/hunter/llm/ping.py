"""One-token live probe — "is this brain actually dialed in?"

``ping_provider`` dials a provider with a 1-token completion (the same
LiteLLM seam the router uses, including the ``max_tokens`` the
anthropic-family wire models require) and measures latency. Every failure is
classified through :class:`hunter.llm.router.ProviderRouter.classify` so the
user sees the SAME error language chat and scan would show. NO test touches
the network: ``litellm_module`` is a test seam, exactly like the router's.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from typing import Any

from hunter.errors import HunterError

__all__ = ["PingResult", "ping_provider"]


@dataclass(frozen=True)
class PingResult:
    """Outcome of one probe. ``message`` is always user-safe (the classifier
    redacts credentials); ``exit_code`` is the CLI mapping (0 ok, else the
    classified HunterError's exit code)."""

    ok: bool
    latency_ms: int = 0
    message: str = ""
    exit_code: int = 0


def load_litellm() -> Any:
    """Import litellm or raise the classified "extra missing" error."""
    try:
        import litellm
    except ImportError as exc:
        raise HunterError(
            code="config.llm_extra_missing",
            layer="config",
            message="litellm is not installed — the LLM brain is missing",
            hint="pip install 'hunteros-harness[llm]'",
        ) from exc
    return litellm


def ping_provider(
    provider_name: str,
    model: str,
    base_url: str = "",
    api_key: str = "",
    timeout: float = 15,
    *,
    litellm_module: Any | None = None,
) -> PingResult:
    """One 1-token completion against ``provider_name``/``model``.

    Returns ``PingResult(ok=True, latency_ms=...)`` or a classified failure —
    never raises for provider problems (config problems still raise
    HunterError: unknown model shape, missing litellm extra).
    """
    from hunter.llm.config import default_config
    from hunter.llm.router import ProviderRouter, _wire_model, hunter_error_from_classified

    module = litellm_module if litellm_module is not None else load_litellm()
    with contextlib.suppress(Exception):
        module.suppress_debug_info = True  # keep litellm's issue-URL banner out of the UX
    wire_model = _wire_model(provider_name, model, base_url)
    if not wire_model:
        raise HunterError(
            code="config.value",
            layer="config",
            message=f"no model to ping for provider '{provider_name}'",
            hint="pass --model <model-id> (the provider's model id)",
        )
    kwargs: dict[str, Any] = {
        "model": wire_model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,  # anthropic-family wire models require max_tokens
        "api_key": api_key or None,  # None → LiteLLM's own env resolution
        "timeout": timeout,
    }
    if base_url:
        kwargs["base_url"] = base_url

    # classify() is table-driven; the router instance only supplies the seam.
    router = ProviderRouter(default_config(), litellm_module=module)

    started = time.perf_counter()
    try:
        module.completion(**kwargs)
    except Exception as exc:  # noqa: BLE001 — classified below, never a traceback
        classified = router.classify(exc)
        error = hunter_error_from_classified(classified)
        return PingResult(ok=False, message=error.user_message(), exit_code=error.exit_code)
    latency_ms = int((time.perf_counter() - started) * 1000)
    return PingResult(ok=True, latency_ms=latency_ms, message=f"OK ({latency_ms} ms)")
