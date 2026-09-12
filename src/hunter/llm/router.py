"""ProviderRouter — the LiteLLM-backed ChatProvider (``name = "litellm"``).

Turns one :class:`hunter.llm.config.HunterConfig` into a working brain for ANY
provider: model/key resolution, a failover chain (primary + configured
fallbacks, deduped), bounded retries with exponential backoff, hermes-grade
error classification, and budget governance. Every provider failure becomes
either a :class:`hunter.llm.base.TurnResult` or a
:class:`hunter.errors.HunterError` — never a bare traceback.

Model prefix mapping (``_MODEL_PREFIXES``): config provider names map onto
LiteLLM's ``provider/model`` wire strings (``openai`` → ``openai/gpt-4o``,
``ollama`` → ``ollama_chat/llama3``, ...). A model that already carries the
provider's own prefix passes through untouched; ``auto`` (or an unknown
provider name without ``base_url``) passes the model string as-is for LiteLLM
to infer; an unknown provider name (or ``auto``) WITH a ``base_url`` is treated
as an OpenAI-compatible endpoint (``openai/`` prefix).

The ``litellm_module`` constructor parameter is a test seam — tests inject a
fake module; NO test or constructor call ever touches the network.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from hunter.errors import EXIT_RATE_LIMIT, HunterError
from hunter.llm.base import (
    TIERS,
    ClassifiedError,
    StreamCb,
    ToolCall,
    TurnResult,
)
from hunter.llm.config import FallbackEntry, HunterConfig, TierConfig, resolve_key, resolve_model

# --------------------------------------------------------------------------
# Model prefix table: config provider name → LiteLLM wire prefix.
# --------------------------------------------------------------------------
_MODEL_PREFIXES: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "azure": "azure",
    "bedrock": "bedrock",
    "vertex_ai": "vertex_ai",
    "openrouter": "openrouter",
    "groq": "groq",
    "mistral": "mistral",
    "deepseek": "deepseek",
    "together_ai": "together_ai",
    "together": "together_ai",
    "xai": "xai",
    "gemini": "gemini",
    "google": "gemini",
    "cohere": "cohere",
    "huggingface": "huggingface",
    "ollama": "ollama_chat",
    "ollama_chat": "ollama_chat",
    # OpenAI-compatible local/managed servers speak the OpenAI wire format:
    "lmstudio": "openai",
    "vllm": "openai",
    "openai-compatible": "openai",
    # "auto": no prefix — LiteLLM infers from the model string.
    "auto": "",
}

# Model strings already carrying one of these LiteLLM prefixes are never
# double-prefixed when the configured provider matches the prefix head.
_KNOWN_LITELLM_PREFIXES = frozenset(
    {
        "openai", "anthropic", "azure", "azure_ai", "bedrock", "vertex_ai",
        "vertex_ai_beta", "openrouter", "groq", "mistral", "deepseek",
        "together_ai", "xai", "gemini", "cohere", "huggingface", "ollama",
        "ollama_chat", "databricks", "watsonx", "perplexity", "dashscope",
    }
)


def _wire_model(provider: str, model: str, base_url: str) -> str:
    """Config (provider, model) → the ``provider/model`` string LiteLLM dials."""
    model = (model or "").strip()
    if not model:
        return model
    prefix = _MODEL_PREFIXES.get(provider)
    if prefix is None:
        # Unknown provider name: a custom base_url means OpenAI-compatible;
        # otherwise hand the model string to LiteLLM untouched.
        prefix = "openai" if base_url else ""
    elif prefix == "" and base_url:
        # "auto" pointed at a custom endpoint — assume OpenAI-compatible.
        prefix = "openai"
    if not prefix or model.startswith(f"{prefix}/"):
        return model
    return f"{prefix}/{model}"


# --------------------------------------------------------------------------
# Message-pattern tables (lowercased substrings; first hit wins).
# --------------------------------------------------------------------------

_OVERFLOW_PATTERNS = (
    "context length", "context_length", "maximum context", "context window",
    "context_length_exceeded", "prompt is too long", "input is too long",
    "max_model_len", "too many tokens", "reduce the length",
)
_CONTENT_POLICY_PATTERNS = (
    "content filter", "content_filter", "content policy", "usage policies",
    "responsibleaipolicyviolation", "was flagged",
)
_EMPTY_RESPONSE_PATTERNS = ("empty response", "no choices", "returned nothing")
_AUTH_PERMANENT_PATTERNS = (
    # Reserved for refresh/rotation flows that confirmed the key is dead —
    # distinct from a plain 401, which is worth a fallback attempt.
    "auth_permanent", "key rejected after refresh", "authorization permanently failed",
)
_AUTH_PATTERNS = (
    "invalid api key", "invalid_api_key", "authentication", "unauthorized",
    "invalid token", "token expired", "access denied", "forbidden",
)
_BILLING_PATTERNS = (
    "insufficient credits", "insufficient_quota", "insufficient balance",
    "credit balance", "billing", "payment required", "exceeded your current quota",
)
_OVERLOADED_PATTERNS = ("overloaded", "at capacity", "over capacity")
_RATE_LIMIT_PATTERNS = (
    "rate limit", "rate_limit", "too many requests", "throttled",
    "quota exceeded", "try again in", "resource_exhausted",
)
_TIMEOUT_PATTERNS = (
    "timed out", "timeout", "deadline exceeded", "connection", "network",
    "getaddrinfo", "ssl",
)
_FORMAT_PATTERNS = (
    "json", "parse error", "parsing", "invalid character", "expecting value",
    "malformed",
)

# Litellm/SDK exception class names → verdicts (duck-typed: no import needed).
_LITELLM_CLASS_VERDICTS: dict[str, ClassifiedError] = {
    "AuthenticationError": ClassifiedError(
        reason="auth", retryable=False, should_fallback=True, status_code=401),
    "PermissionDeniedError": ClassifiedError(
        reason="auth", retryable=False, should_fallback=True, status_code=403),
    "NotFoundError": ClassifiedError(
        reason="model_not_found", retryable=False, should_fallback=True, status_code=404),
    "RateLimitError": ClassifiedError(
        reason="rate_limit", retryable=True, status_code=429),
    "BudgetExceededError": ClassifiedError(
        reason="billing", retryable=False, should_fallback=True, status_code=402),
    "BadRequestError": ClassifiedError(
        reason="format_error", retryable=False, status_code=400),
    "UnprocessableEntityError": ClassifiedError(
        reason="format_error", retryable=False, status_code=422),
    "ContextWindowExceededError": ClassifiedError(reason="context_overflow"),
    "ContentPolicyViolationError": ClassifiedError(reason="content_policy_blocked"),
    "APITimeoutError": ClassifiedError(reason="timeout", retryable=True),
    "APIConnectionError": ClassifiedError(reason="timeout", retryable=True),
    "InternalServerError": ClassifiedError(
        reason="server_error", retryable=True, status_code=500),
    "ServiceUnavailableError": ClassifiedError(
        reason="overloaded", retryable=True, status_code=503),
    "APIError": ClassifiedError(reason="unknown", retryable=True),
    "TimeoutError": ClassifiedError(reason="timeout", retryable=True),
    "ConnectionError": ClassifiedError(reason="timeout", retryable=True),
}

# Backoff: 1s, 2s, 4s, ... capped at 8s.
_BACKOFF_CAP_SECONDS = 8.0
_MAX_MESSAGE_CHARS = 300

# Reason → (HunterError layer, code, hint). Exit codes follow errors.py's
# layer map (auth/billing → 4, config → 8, provider → 1). NOTE: "rate_limit"
# is not in errors.LAYERS, so rate-limit errors carry layer "provider" with an
# explicit EXIT_RATE_LIMIT — the exit code (5) is the stable script contract.
_REASON_TO_ERROR: dict[str, tuple[str, str, str]] = {
    "auth": (
        "auth", "provider.auth",
        "set the API key (providers.<name>.key_env in ~/.hunteros/config.yaml) — "
        "`hunter doctor` reports what is missing",
    ),
    "auth_permanent": (
        "auth", "provider.auth_permanent",
        "rotate this provider's API key — it was rejected after refresh",
    ),
    "billing": (
        "billing", "provider.billing",
        "top up the provider account, or switch via /model / fallback_providers",
    ),
    "rate_limit": (
        "provider", "provider.rate_limit",
        "slow down, or switch model via /model or fallback_providers",
    ),
    "timeout": (
        "provider", "provider.timeout",
        "raise model_tiers.<tier>.timeout or retry — the provider did not answer in time",
    ),
    "server_error": (
        "provider", "provider.server_error",
        "the provider had an internal error — retry, or switch via /model",
    ),
    "overloaded": (
        "provider", "provider.overloaded",
        "the provider is at capacity — retry shortly, or switch via /model",
    ),
    "empty_response": (
        "provider", "provider.empty_response",
        "the provider returned nothing — retry, or switch via /model",
    ),
    "model_not_found": (
        "config", "config.model_not_found",
        "check the model name in ~/.hunteros/config.yaml or via /model",
    ),
    "content_policy_blocked": (
        "provider", "provider.content_policy_blocked",
        "the provider safety filter rejected this prompt — rephrase the request",
    ),
    "format_error": (
        "provider", "provider.format_error",
        "the request shape was rejected — check messages and tool schemas",
    ),
    "context_overflow": (
        "provider", "provider.context_overflow",
        "compact or shorten the conversation",
    ),
    "unknown": (
        "provider", "provider.unknown",
        "run `hunter doctor` and check the provider's status page",
    ),
}

_SECRET_RES = (
    re.compile(r"sk-[A-Za-z0-9_-]{6,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(api[_-]?key|authorization)(?:\"|')?\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{8,}"),
)


def _redact(text: str) -> str:
    """Strip anything that looks like a credential (sk- keys, Bearer tokens,
    api_key=... assignments) — classified messages are safe for logs/UI."""
    redacted = _SECRET_RES[0].sub("sk-***", text)
    redacted = _SECRET_RES[1].sub("Bearer ***", redacted)
    redacted = _SECRET_RES[2].sub(r"\1=***", redacted)
    return redacted


def _chain(exc: BaseException) -> Iterator[BaseException]:
    """The exception and its __cause__/__context__ chain (max 5 deep)."""
    current: BaseException | None = exc
    for _ in range(5):
        if current is None:
            return
        yield current
        nxt = current.__cause__ or current.__context__
        if nxt is current:
            return
        current = nxt


def _status_of(exc: BaseException) -> int | None:
    for candidate in _chain(exc):
        for attr in ("status_code", "status"):
            code = getattr(candidate, attr, None)
            if isinstance(code, int) and 100 <= code < 600:
                return code
    return None


def _message_of(exc: BaseException) -> str:
    parts = [str(exc)]
    extra = getattr(exc, "message", "")
    if isinstance(extra, str) and extra and extra not in parts:
        parts.append(extra)
    text = " ".join(part for part in parts if part).strip()
    return _redact(text)[:_MAX_MESSAGE_CHARS] or type(exc).__name__


def _first_pattern(text: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        if pattern in text:
            return pattern
    return None


def hunter_error_from_classified(ce: ClassifiedError) -> HunterError:
    """Bridge ClassifiedError → HunterError with errors.py layers/exit codes."""
    layer, code, hint = _REASON_TO_ERROR.get(ce.reason, _REASON_TO_ERROR["unknown"])
    status = f" (HTTP {ce.status_code})" if ce.status_code is not None else ""
    message = ce.message or f"provider failure: {ce.reason}"
    return HunterError(
        code=code,
        layer=layer,
        message=f"{message}{status}",
        hint=hint,
        retryable=ce.retryable,
        # "rate_limit" is not a valid errors.py layer — pin its exit code (5).
        exit_code=EXIT_RATE_LIMIT if ce.reason == "rate_limit" else None,
    )


@dataclass(frozen=True)
class _Candidate:
    """One dialable route: provider name + resolved credentials + wire model."""

    provider: str
    model: str
    wire_model: str
    base_url: str
    api_key: str
    timeout: int
    reasoning_effort: str = ""


class ProviderRouter:
    """ChatProvider over LiteLLM with failover, retries, and budget checks."""

    name = "litellm"

    def __init__(self, config: HunterConfig, *, litellm_module: Any | None = None) -> None:
        self.config = config
        self._litellm = litellm_module
        if self._litellm is None:
            try:
                import litellm as module
            except ImportError as exc:
                raise HunterError(
                    code="config.llm_extra_missing",
                    layer="config",
                    message="litellm is not installed — the LLM brain is missing",
                    hint="pip install 'hunteros-harness[llm]'",
                ) from exc
            self._litellm = module

    # ------------------------------------------------------------ public --

    def complete(
        self,
        tier: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream_cb: StreamCb | None = None,
        budget: Any | None = None,
    ) -> TurnResult:
        """One provider turn: resolve the tier's route, dial it (with retries
        and fallbacks), normalize to TurnResult, and govern the budget."""
        if budget is not None and budget.exhausted() is not None:
            raise self._budget_error(budget)
        tier_cfg = self._tier_config(tier)
        model = resolve_model(tier, self.config)
        candidates = self._build_chain(tier_cfg, model)
        attempts = max(1, int(self.config.agent.api_max_retries))

        last: ClassifiedError | None = None
        for index, candidate in enumerate(candidates):
            outcome = self._attempt(candidate, messages, tools, stream_cb, budget, attempts)
            if isinstance(outcome, TurnResult):
                return outcome
            last = outcome
            has_next = index + 1 < len(candidates)
            if last.should_fallback:
                if has_next:
                    continue
                raise hunter_error_from_classified(last)
            if last.retryable:
                continue  # retries burned on this route — try the next one
            raise hunter_error_from_classified(last)

        # Every route's attempts are exhausted with retryable failures.
        assert last is not None  # candidates is never empty
        raise self._terminal_error(last)

    def classify(self, exc: BaseException) -> ClassifiedError:
        """Classify ANY provider exception ONCE (hermes pattern): the retry
        loop reads the verdict instead of re-matching strings."""
        status = _status_of(exc)
        display = _message_of(exc)  # redacted — safe for logs and user display
        text = display.lower()

        # Deterministic rejections first — status codes misroute these.
        if _first_pattern(text, _OVERFLOW_PATTERNS):
            return ClassifiedError(
                reason="context_overflow", status_code=status, message=display)
        if _first_pattern(text, _CONTENT_POLICY_PATTERNS):
            return ClassifiedError(
                reason="content_policy_blocked", retryable=False, status_code=status, message=display)
        if _first_pattern(text, _EMPTY_RESPONSE_PATTERNS):
            return ClassifiedError(
                reason="empty_response", retryable=True, status_code=status, message=display)

        by_class = _LITELLM_CLASS_VERDICTS.get(type(exc).__name__)
        if by_class is not None:
            return ClassifiedError(
                reason=by_class.reason,
                retryable=by_class.retryable,
                should_fallback=by_class.should_fallback,
                status_code=status if status is not None else by_class.status_code,
                message=display,
            )

        by_status = self._classify_status(status, display)
        if by_status is not None:
            return by_status

        by_message = self._classify_message(display)
        if by_message is not None:
            return by_message

        if isinstance(exc, json.JSONDecodeError):
            return ClassifiedError(reason="format_error", message=display)
        if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
            return ClassifiedError(reason="timeout", retryable=True, message=display)
        return ClassifiedError(reason="unknown", retryable=True, status_code=status, message=display)

    # ----------------------------------------------------------- routing --

    def _tier_config(self, tier: str) -> TierConfig:
        tier_cfg = self.config.model_tiers.get(tier)
        if tier_cfg is None:
            raise HunterError(
                code="config.value",
                layer="config",
                message=f"unknown tier '{tier}'",
                hint=f"valid tiers: {', '.join(TIERS)}",
            )
        return tier_cfg

    def _provider_base_url(self, provider: str) -> str:
        block = self.config.providers.get(provider)
        return block.base_url if block is not None else ""

    def _fallback_key(self, entry: FallbackEntry) -> str | None:
        """API key for a fallback entry; None when a declared credential is
        unresolvable (the link is skipped). "" means keyless/undeclared."""
        if entry.key_env:
            from_env = (os.environ.get(entry.key_env) or "").strip()
            return from_env if from_env else None
        try:
            return resolve_key(entry.provider, self.config)
        except HunterError:
            return None  # credential declared but missing — skip this link quietly

    def _build_chain(self, tier_cfg: TierConfig, model: str) -> list[_Candidate]:
        """Primary route + configured fallbacks, deduped by (provider, model,
        effective base_url). Unkeyed fallback links are skipped."""
        provider = (tier_cfg.provider or "auto").strip()
        base_url = tier_cfg.base_url or self._provider_base_url(provider)
        candidates = [
            _Candidate(
                provider=provider,
                model=model,
                wire_model=_wire_model(provider, model, base_url),
                base_url=base_url,
                api_key=resolve_key(provider, self.config),
                timeout=tier_cfg.timeout,
                reasoning_effort=tier_cfg.reasoning_effort,
            )
        ]
        seen = {(candidates[0].provider, candidates[0].model, candidates[0].base_url)}
        for entry in self.config.fallback_providers:
            base_url = entry.base_url or self._provider_base_url(entry.provider)
            identity = (entry.provider, entry.model, base_url)
            if identity in seen:
                continue
            seen.add(identity)
            key = self._fallback_key(entry)
            if key is None:
                continue  # credential declared but unresolvable
            candidates.append(
                _Candidate(
                    provider=entry.provider,
                    model=entry.model,
                    wire_model=_wire_model(entry.provider, entry.model, base_url),
                    base_url=base_url,
                    api_key=key or "",
                    timeout=tier_cfg.timeout,
                )
            )
        return candidates

    def _attempt(
        self,
        candidate: _Candidate,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        stream_cb: StreamCb | None,
        budget: Any | None,
        attempts: int,
    ) -> TurnResult | ClassifiedError:
        """Run one route up to ``attempts`` times. Returns the TurnResult, or
        the final ClassifiedError for the failover/terminal decision."""
        last: ClassifiedError | None = None
        for attempt in range(attempts):
            try:
                return self._invoke(candidate, messages, tools, stream_cb, budget)
            except HunterError:
                raise  # budget exhaustion / config errors are terminal
            except Exception as exc:
                last = self.classify(exc)
                if last.should_fallback:
                    return last
                if last.retryable and attempt + 1 < attempts:
                    time.sleep(min(_BACKOFF_CAP_SECONDS, 2.0**attempt))
                    continue
                return last
        assert last is not None  # attempts >= 1 guarantees the except path ran
        return last

    def _invoke(
        self,
        candidate: _Candidate,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        stream_cb: StreamCb | None,
        budget: Any | None,
    ) -> TurnResult:
        kwargs: dict[str, Any] = {
            "model": candidate.wire_model,
            "messages": messages,
            "api_key": candidate.api_key or None,  # None → LiteLLM's own env resolution
            "timeout": candidate.timeout,
            "stream": stream_cb is not None,
        }
        if tools:
            kwargs["tools"] = tools
        if candidate.base_url:
            kwargs["base_url"] = candidate.base_url
        if candidate.reasoning_effort:
            kwargs["reasoning_effort"] = candidate.reasoning_effort
        response = self._litellm.completion(**kwargs)
        result = (
            self._normalize_stream(response, candidate, stream_cb)
            if stream_cb is not None
            else self._normalize(response, candidate)
        )
        if budget is not None:
            budget.add_cost(result.cost_usd)
            if budget.exhausted() is not None:
                raise self._budget_error(budget)
        return result

    # ------------------------------------------------------- normalization --

    def _completion_cost(self, response: Any) -> float:
        cost_fn = getattr(self._litellm, "completion_cost", None)
        if cost_fn is None:
            return 0.0
        try:
            return float(cost_fn(response))
        except Exception:
            return 0.0  # unknown pricing must never break a good turn

    def _parse_tool_call(self, tc: Any) -> ToolCall | None:
        function = getattr(tc, "function", None)
        name = (getattr(function, "name", "") or "") if function is not None else ""
        raw_args = (getattr(function, "arguments", "") or "") if function is not None else ""
        arguments: dict[str, Any] = {}
        if isinstance(raw_args, str) and raw_args.strip():
            try:
                parsed = json.loads(raw_args)
                if isinstance(parsed, dict):
                    arguments = parsed
            except (json.JSONDecodeError, TypeError, ValueError):
                arguments = {}  # malformed JSON tolerated; tool layer handles it
        elif isinstance(raw_args, dict):
            arguments = raw_args
        call_id = getattr(tc, "id", "") or ""
        if not name and not call_id:
            return None
        return ToolCall(id=call_id, name=name, arguments=arguments)

    def _finish_reason(self, raw: str, has_tool_calls: bool) -> str:
        if raw:
            return raw
        return "tool_calls" if has_tool_calls else "stop"

    def _normalize(self, response: Any, candidate: _Candidate) -> TurnResult:
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise ValueError("provider returned an empty response (no choices)")
        choice = choices[0]
        message = getattr(choice, "message", None)
        text = (getattr(message, "content", None) or "") if message is not None else ""
        raw_tool_calls = (getattr(message, "tool_calls", None) or []) if message is not None else []
        tool_calls = tuple(
            parsed for parsed in (self._parse_tool_call(tc) for tc in raw_tool_calls) if parsed is not None
        )
        usage = getattr(response, "usage", None)
        return TurnResult(
            text=text,
            tool_calls=tool_calls,
            finish_reason=self._finish_reason(
                getattr(choice, "finish_reason", "") or "", bool(tool_calls)),
            input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0) if usage is not None else 0,
            output_tokens=int(getattr(usage, "completion_tokens", 0) or 0) if usage is not None else 0,
            cost_usd=self._completion_cost(response),
            model=getattr(response, "model", "") or candidate.wire_model,
            provider=candidate.provider,
        )

    def _normalize_stream(
        self, chunks: Any, candidate: _Candidate, stream_cb: StreamCb | None
    ) -> TurnResult:
        parts: list[str] = []
        tool_acc: dict[int, dict[str, str]] = {}
        finish = ""
        input_tokens = output_tokens = 0
        model = ""
        for chunk in chunks:  # mid-stream failures propagate → classified/retried
            model = model or (getattr(chunk, "model", "") or "")
            usage = getattr(chunk, "usage", None)
            if usage is not None:
                input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0) or input_tokens
                output_tokens = int(getattr(usage, "completion_tokens", 0) or 0) or output_tokens
            choices = getattr(chunk, "choices", None) or []
            if not choices:
                continue
            choice = choices[0]
            delta = getattr(choice, "delta", None)
            if delta is not None:
                text = getattr(delta, "content", None) or ""
                if text:
                    parts.append(text)
                    if stream_cb is not None:
                        stream_cb(text)
                for tc in getattr(delta, "tool_calls", None) or []:
                    index = int(getattr(tc, "index", 0) or 0)
                    acc = tool_acc.setdefault(index, {"id": "", "name": "", "arguments": ""})
                    if getattr(tc, "id", None):
                        acc["id"] = tc.id
                    function = getattr(tc, "function", None)
                    if function is not None:
                        if getattr(function, "name", None):
                            acc["name"] = function.name
                        acc["arguments"] += getattr(function, "arguments", "") or ""
            if getattr(choice, "finish_reason", None):
                finish = choice.finish_reason

        tool_calls = tuple(
            parsed
            for parsed in (self._parse_tool_call(_StreamToolCall(acc)) for acc in tool_acc.values())
            if parsed is not None
        )
        return TurnResult(
            text="".join(parts),
            tool_calls=tool_calls,
            finish_reason=self._finish_reason(finish, bool(tool_calls)),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=self._completion_cost(chunks),
            model=model or candidate.wire_model,
            provider=candidate.provider,
        )

    # ---------------------------------------------------------- classify --

    def _classify_status(self, status: int | None, display: str) -> ClassifiedError | None:
        if status is None:
            return None
        if status in (401, 403):
            return ClassifiedError(
                reason="auth", retryable=False, should_fallback=True, status_code=status, message=display)
        if status == 402:
            return ClassifiedError(
                reason="billing", retryable=False, should_fallback=True, status_code=status, message=display)
        if status == 404:
            return ClassifiedError(
                reason="model_not_found", retryable=False, should_fallback=True,
                status_code=status, message=display,
            )
        if status == 408:
            return ClassifiedError(reason="timeout", retryable=True, status_code=status, message=display)
        if status == 429:
            return ClassifiedError(reason="rate_limit", retryable=True, status_code=status, message=display)
        if 500 <= status < 600:
            return ClassifiedError(reason="server_error", retryable=True, status_code=status, message=display)
        if 400 <= status < 500:
            return ClassifiedError(
                reason="format_error", retryable=False, status_code=status, message=display)
        return None

    def _classify_message(self, display: str) -> ClassifiedError | None:
        text = display.lower()
        if _first_pattern(text, _AUTH_PERMANENT_PATTERNS):
            return ClassifiedError(reason="auth_permanent", retryable=False, message=display)
        if _first_pattern(text, _AUTH_PATTERNS):
            return ClassifiedError(reason="auth", retryable=False, should_fallback=True, message=display)
        if _first_pattern(text, _BILLING_PATTERNS):
            return ClassifiedError(reason="billing", retryable=False, should_fallback=True, message=display)
        if _first_pattern(text, _OVERLOADED_PATTERNS):
            return ClassifiedError(reason="overloaded", retryable=True, message=display)
        if _first_pattern(text, _RATE_LIMIT_PATTERNS):
            return ClassifiedError(reason="rate_limit", retryable=True, message=display)
        if _first_pattern(text, _TIMEOUT_PATTERNS):
            return ClassifiedError(reason="timeout", retryable=True, message=display)
        if _first_pattern(text, _FORMAT_PATTERNS):
            return ClassifiedError(reason="format_error", retryable=False, message=display)
        return None

    # ------------------------------------------------------------ errors --

    def _budget_error(self, budget: Any) -> HunterError:
        reason = budget.exhausted() or "budget exhausted"
        return HunterError(
            code="budget.exhausted",
            layer="usage",
            message=f"run budget stopped: {reason}",
            hint="raise the budget in ~/.hunteros/config.yaml or via /model",
        )

    def _terminal_error(self, last: ClassifiedError) -> HunterError:
        detail = last.message or f"last failure: {last.reason}"
        chain_hint = (
            "switch model with /model or add fallback_providers in ~/.hunteros/config.yaml — "
            "the whole fallback chain was exhausted"
        )
        if last.reason == "rate_limit":
            return HunterError(
                code="provider.rate_limit",
                layer="provider",  # errors.LAYERS has no "rate_limit"; exit 5 carries it
                exit_code=EXIT_RATE_LIMIT,
                message=f"all provider routes exhausted by rate limiting — {detail}",
                hint=chain_hint,
                retryable=True,
            )
        return HunterError(
            code=f"provider.{last.reason}",
            layer="provider",
            message=f"all provider routes failed — {detail}",
            hint=chain_hint,
        )


class _StreamToolCall:
    """Adapter so streamed tool-call fragments reuse _parse_tool_call."""

    def __init__(self, acc: dict[str, str]) -> None:
        self.id = acc.get("id", "")
        self.function = _StreamFunction(acc.get("name", ""), acc.get("arguments", ""))


class _StreamFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


__all__ = ["ProviderRouter", "hunter_error_from_classified", "_wire_model"]
