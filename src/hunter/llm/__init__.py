"""LLM layer: provider routing, budgets, config. LiteLLM is the wire (extra `[llm]`).

Public surface (import from here, not from submodules):
- Contracts: Tier, TIERS, ClassifiedError, ToolCall, TurnResult, ChatProvider
- RunBudget — the concrete budget (implements hunter.llm.base.RunBudget)
- HunterConfig / load_config / resolve_model / resolve_key / config_example_yaml
- ProviderRouter — the LiteLLM-backed ChatProvider (lazy litellm import)
"""

from hunter.engine.base import EmitFn  # re-export convenience  # noqa: F401
from hunter.llm.base import (  # noqa: F401
    LEGACY_TIER_ALIASES,
    LEGACY_TIERS,
    TIERS,
    ChatProvider,
    ClassifiedError,
    Tier,
    ToolCall,
    TurnResult,
    normalize_tier,
)
from hunter.llm.budget import RunBudget  # noqa: F401
from hunter.llm.config import (  # noqa: F401
    AGENT_TIERS,
    AgentConfig,
    BudgetConfig,
    FallbackEntry,
    HunterConfig,
    ProviderConfig,
    TierConfig,
    config_example_yaml,
    default_model,
    load_config,
    resolve_key,
    resolve_model,
)
from hunter.llm.router import (  # noqa: F401
    ProviderRouter,
    hunter_error_from_classified,
    provider_from_config,
)

__all__ = [
    "AGENT_TIERS",
    "TIERS",
    "AgentConfig",
    "BudgetConfig",
    "ChatProvider",
    "ClassifiedError",
    "EmitFn",
    "FallbackEntry",
    "HunterConfig",
    "LEGACY_TIERS",
    "LEGACY_TIER_ALIASES",
    "ProviderConfig",
    "ProviderRouter",
    "RunBudget",
    "Tier",
    "TierConfig",
    "ToolCall",
    "TurnResult",
    "config_example_yaml",
    "default_model",
    "hunter_error_from_classified",
    "load_config",
    "normalize_tier",
    "resolve_key",
    "resolve_model",
]
