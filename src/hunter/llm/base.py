"""LLM contracts — the seam between HunterOs and any provider brain.

``ChatProvider`` is the ONLY interface the agent loop sees; LiteLLM lives
behind it (implemented by ``hunter.llm.router.ProviderRouter`` in Wave 1).
Tests fake it with deterministic providers — CI never needs a key.

Message format is OpenAI-style dicts throughout:
    {"role": "system"|"user"|"assistant"|"tool", "content": str,
     "tool_calls": [{"id","name","arguments"}]?, "tool_call_id": str?}
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Tier = Literal["orchestrator", "hunter", "verifier", "utility"]
TIERS: tuple[str, ...] = ("orchestrator", "hunter", "verifier", "utility")

# Old names load fine but never render again (v0.4 rename). Order matters
# only for hint text; keep the rename history order. These are the ONLY
# places the old-name string literals may live in src/hunter (static scan).
LEGACY_TIERS: tuple[str, ...] = ("planner", "exploit", "verify")
LEGACY_TIER_ALIASES: dict[str, str] = {
    "planner": "orchestrator",
    "exploit": "hunter",
    "verify": "verifier",
}


def normalize_tier(name: str) -> str:
    """Canonical tier for ``name``; unknown names pass through unchanged so
    the validator's unknown-tier error still fires with the input echoed."""
    return LEGACY_TIER_ALIASES.get(name, name)


StreamCb = Callable[[str], None]

# ClassifiedError.reason vocabulary (ported from hermes error_classifier)
ERROR_REASONS: tuple[str, ...] = (
    "auth", "auth_permanent", "billing", "rate_limit", "overloaded", "server_error",
    "timeout", "context_overflow", "model_not_found", "content_policy_blocked",
    "format_error", "empty_response", "unknown",
)


@dataclass(frozen=True, slots=True)
class ClassifiedError:
    """Provider failure, classified ONCE; the retry loop reads these fields
    instead of re-matching strings (hermes pattern)."""

    reason: str = "unknown"
    retryable: bool = False
    should_fallback: bool = False
    status_code: int | None = None
    message: str = ""  # redacted — safe for logs and user display

    def __post_init__(self) -> None:
        if self.reason not in ERROR_REASONS:
            object.__setattr__(self, "reason", "unknown")


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TurnResult:
    """One provider completion, normalized across providers."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)
    finish_reason: str = ""  # "stop" | "tool_calls" | "length" | ...
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""
    provider: str = ""
    error_surface: dict[str, Any] | None = None  # errors.build_error_surface output


@dataclass
class RunBudget:
    """Iteration + wall-clock + cost governor for one agent run (hermes
    IterationBudget + Strix usage hooks, merged). Implement logic in
    ``hunter.llm.budget``; this is the data contract."""

    max_cost_usd: float = 5.0
    max_iterations: int = 60
    wall_seconds: float = 1800.0
    started_monotonic: float = 0.0
    spent_usd: float = 0.0
    iterations_used: int = 0
    warned_levels: tuple[int, ...] = ()  # staged-warning levels already fired

    def consume_iteration(self) -> bool:
        raise NotImplementedError

    def refund_iteration(self) -> None:
        raise NotImplementedError

    def add_cost(self, usd: float) -> None:
        raise NotImplementedError

    def cost_breakpoint(self) -> str | None:
        """Staged warning at 70/85/95% of max_cost_usd, each fired once."""

    def exhausted(self) -> str | None:
        """Human reason when the run must wind down, else None."""


class ChatProvider(Protocol):
    """The brain seam. Implementations: LiteLLM router (production), fake
    provider (tests). Must convert every provider failure into either a
    TurnResult with error_surface set, or raise HunterError."""

    name: str

    def complete(
        self,
        tier: Tier,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream_cb: StreamCb | None = None,
        budget: RunBudget | None = None,
    ) -> TurnResult: ...

    def classify(self, exc: BaseException) -> ClassifiedError: ...
