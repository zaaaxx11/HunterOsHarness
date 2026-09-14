"""HunterConfig — plug ANY LLM into HunterOs with one YAML file or env var.

Search order (first hit wins): explicit ``path`` arg → ``$HUNTEROS_CONFIG`` →
``~/.hunteros/config.yaml`` → none (pure defaults). Environment overrides win
over YAML values: ``HUNTEROS_MODEL`` (default model), ``HUNTEROS_TIER``
(``agent.tier``), ``HUNTEROS_BUDGET_USD``, ``HUNTEROS_MAX_ITERATIONS``.

Model resolution for any tier (``hunter.llm.config.resolve_model``):
    tier.model  →  $HUNTEROS_MODEL  →  orchestrator.model (other tiers inherit
    the top default)  →  HunterError at use time.

Every failure is a :class:`hunter.errors.HunterError` in the ``config`` or
``auth`` layer — never a bare exception (errors.py doctrine).

v0.4 tier rename: legacy model_tiers keys / agent.tier / $HUNTEROS_TIER values
(the pre-v0.4 vocabulary, see ``hunter.llm.base.LEGACY_TIER_ALIASES``) load
mapped onto the canonical tier names and record one
:attr:`HunterConfig.legacy_notes` entry per rename — surfaces print the notes
at most once per command; the resolution paths never warn.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from hunter.errors import EXIT_AUTH, HunterError
from hunter.llm.base import LEGACY_TIERS, TIERS, normalize_tier

# agent.tier vocabulary: the four model tiers, plus "basic" — the shipped
# default meaning "no LLM pinned; deterministic/utility behavior".
AGENT_TIERS: tuple[str, ...] = ("basic", "advanced", *TIERS)

VALID_TOP_KEYS: tuple[str, ...] = (
    "model_tiers", "providers", "fallback_providers", "budget", "agent",
)
_TIER_KEYS: tuple[str, ...] = (
    "provider", "model", "base_url", "key_env", "timeout", "reasoning_effort",
)
_PROVIDER_KEYS: tuple[str, ...] = ("key_env", "api_key", "base_url", "endpoint")
_BUDGET_KEYS: tuple[str, ...] = ("max_cost_usd", "max_iterations", "wall_seconds")
_AGENT_KEYS: tuple[str, ...] = ("tier", "api_max_retries", "browser")
_FALLBACK_KEYS: tuple[str, ...] = ("provider", "model", "base_url", "key_env")

# M1: the endpoint SHAPE is stored ("" = unset) so M2 can branch to the
# responses API without another migration. Nothing reads it in M1.
_ENDPOINTS: tuple[str, ...] = ("", "chat", "responses")

_CONFIG_DIRNAME = ".hunteros"
_CONFIG_FILENAME = "config.yaml"

# Suffix of every legacy-rename note (model_tiers keys, agent.tier, $HUNTEROS_TIER).
_LEGACY_NOTE_SUFFIX = "(old names are accepted; update your config)"


@dataclass
class TierConfig:
    """One model tier (orchestrator/hunter/verifier/utility). Empty or
    ``"auto"`` model means "inherit the top default model" (see
    ``resolve_model``)."""

    provider: str = "auto"
    model: str = ""
    base_url: str = ""
    key_env: str = ""
    timeout: int = 120
    reasoning_effort: str = ""


@dataclass
class ProviderConfig:
    """Named provider credentials. A block that declares NEITHER ``key_env``
    NOR ``api_key`` is KEYLESS (a local/OpenAI-compatible endpoint reached
    without auth — ``resolve_key`` returns ``""`` and LiteLLM dials it with no
    key). An unlisted provider lets LiteLLM use its standard env resolution
    (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...). ``endpoint`` records the API
    shape for M2 ("" unset | "chat" | "responses") — nothing reads it in M1."""

    key_env: str = ""
    api_key: str = ""
    base_url: str = ""
    endpoint: str = ""


@dataclass
class FallbackEntry:
    """One link of the failover chain (hermes ``fallback_providers`` shape),
    tried in order when the primary provider fails with a fallback-worthy
    error (auth, billing, model-not-found, ...)."""

    provider: str
    model: str
    base_url: str = ""
    key_env: str = ""


@dataclass
class BudgetConfig:
    max_cost_usd: float = 5.0
    max_iterations: int = 60
    wall_seconds: float = 1800.0


@dataclass
class AgentConfig:
    """Agent-loop settings. ``tier`` selects the chat/scan model tier
    (AGENT_TIERS); ``api_max_retries`` is attempts per provider before
    failing over to the fallback chain. ``browser`` opts into web automation
    (the optional [browser] extra) — enabled only for an authorized hunt."""

    tier: str = "basic"
    api_max_retries: int = 3
    browser: bool = False


@dataclass
class HunterConfig:
    """Effective HunterOs LLM configuration (validated). ``source_path`` is
    the file it was loaded from, or None for pure defaults."""

    model_tiers: dict[str, TierConfig] = field(default_factory=dict)
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    fallback_providers: list[FallbackEntry] = field(default_factory=list)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    source_path: str | None = None
    # One entry per legacy tier name mapped at load time (model_tiers keys,
    # then agent.tier, then $HUNTEROS_TIER). Nothing in resolve/complete ever
    # warns — surfaces print these at most once per command.
    legacy_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # All four tiers always exist; fill any the loader/constructor omitted.
        for tier in TIERS:
            self.model_tiers.setdefault(tier, TierConfig())


# ------------------------------------------------------------------ helpers --


def _config_error(code: str, message: str, hint: str) -> HunterError:
    return HunterError(code=code, layer="config", message=message, hint=hint)


def _as_str(value: Any, key: str) -> str:
    """Coerce an optional scalar to a stripped string; reject non-strings."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    raise _config_error(
        "config.type",
        f"{key} must be a string, got {type(value).__name__}",
        f"set {key} to a quoted string, e.g. {key}: my-value",
    )


def _as_int(value: Any, key: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config_error(
            "config.type",
            f"{key} must be an integer, got {type(value).__name__}",
            f"set {key} to a whole number, e.g. {key}: {minimum + 1}",
        )
    as_int = int(value)
    if as_int != value or as_int < minimum:
        raise _config_error(
            "config.value",
            f"{key} must be an integer >= {minimum}, got {value!r}",
            f"set {key} to a whole number >= {minimum}",
        )
    return as_int


def _as_bool(value: Any, key: str) -> bool:
    """Accept a YAML bool or the strings "true"/"false" (any case); anything
    else (1, "yes", ...) is a type error — silent coercion hides typos."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise _config_error(
        "config.type",
        f"{key} must be a boolean, got {type(value).__name__}",
        f"set {key} to true or false (a quoted \"true\"/\"false\" string is accepted)",
    )


def _as_number(value: Any, key: str, minimum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config_error(
            "config.type",
            f"{key} must be a number, got {type(value).__name__}",
            f"set {key} to a number, e.g. {key}: {minimum + 1}",
        )
    number = float(value)
    if number < minimum:
        raise _config_error(
            "config.value",
            f"{key} must be >= {minimum}, got {value!r}",
            f"set {key} to a number >= {minimum}",
        )
    return number


def _reject_unknown(
    raw: Mapping[str, Any],
    valid: tuple[str, ...],
    where: str,
    *,
    source_text: str | None = None,
) -> None:
    unknown = sorted(set(raw) - set(valid))
    if unknown:
        hint = f"valid keys under {where}: {', '.join(valid)}"
        line_no = _find_key_line(source_text, unknown[0]) if source_text else None
        if line_no is not None:
            hint += f" (line {line_no} of the config file)"
        raise _config_error(
            "config.unknown_key",
            f"unknown config key(s) under {where}: {', '.join(unknown)}",
            hint,
        )


def _find_key_line(source_text: str | None, key: str) -> int | None:
    """Cheap raw-text scan: the 1-based line where ``key:`` appears, so the
    hint can point at the offending line even though we only parsed a tree."""
    if not source_text:
        return None
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:")
    for number, line in enumerate(source_text.splitlines(), start=1):
        if pattern.match(line):
            return number
    return None


def _yaml_location(exc: Exception) -> str:
    """`` (line N, column M)`` from a YAML error's problem_mark, best-effort."""
    mark = getattr(exc, "problem_mark", None)
    if mark is not None and hasattr(mark, "line") and hasattr(mark, "column"):
        return f" (line {mark.line + 1}, column {mark.column + 1})"
    return ""


def default_config() -> HunterConfig:
    """Pure-default configuration (no file, no env overrides)."""
    return HunterConfig(
        model_tiers={tier: TierConfig() for tier in TIERS},
        providers={},
        fallback_providers=[],
        budget=BudgetConfig(),
        agent=AgentConfig(),
    )


# ------------------------------------------------------------------- loader --


def find_config_path(
    path: str | Path | None = None, *, env: Mapping[str, str] | None = None, home: Path | None = None
) -> Path | None:
    """Where load_config would read from: explicit path → $HUNTEROS_CONFIG →
    ~/.hunteros/config.yaml → None (defaults). Explicit paths must exist; the
    home default is returned even when the file does not exist yet."""
    env = os.environ if env is None else env
    if path is not None:
        return Path(path)
    from_env = (env.get("HUNTEROS_CONFIG") or "").strip()
    if from_env:
        return Path(from_env)
    base = (home or Path.home()) / _CONFIG_DIRNAME / _CONFIG_FILENAME
    return base if base.is_file() else None


def load_config(
    path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> HunterConfig:
    """Load, validate, and env-override the HunterOs LLM configuration.

    Raises HunterError (layer "config") for missing explicit files, YAML
    syntax errors, unknown keys, and type/value violations — the hint always
    names the exact key and the expected type.
    """
    env = os.environ if env is None else env
    resolved = find_config_path(path, env=env, home=home)

    raw: dict[str, Any] = {}
    source: Path | None = None
    text = ""
    if resolved is not None and (path is not None or resolved.is_file()):
        source = resolved
        if not resolved.is_file():
            raise _config_error(
                "config.not_found",
                f"config file not found: {resolved}",
                "pass an existing YAML path, unset HUNTEROS_CONFIG, or run `hunter config example`",
            )
        try:
            text = resolved.read_text(encoding="utf-8")
            loaded = yaml.safe_load(text)
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
            raise _config_error(
                "config.parse",
                f"config file {resolved} is not valid YAML: {type(exc).__name__}{_yaml_location(exc)}",
                "fix the YAML syntax — indent with spaces, quote strings with special chars",
            ) from exc
        if loaded is None:
            raw = {}
        elif isinstance(loaded, dict):
            raw = loaded
        else:
            raise _config_error(
                "config.parse",
                f"config file {resolved} must be a YAML mapping, got {type(loaded).__name__}",
                "top level must look like:\nmodel_tiers:\n  orchestrator:\n    model: ...",
            )

    _reject_unknown(raw, VALID_TOP_KEYS, "the config top level", source_text=text or None)

    cfg = default_config()
    cfg.source_path = str(source) if source is not None else None
    notes: list[str] = []

    # --- model_tiers -------------------------------------------------------
    tiers_raw = raw.get("model_tiers") or {}
    if not isinstance(tiers_raw, dict):
        raise _config_error(
            "config.type",
            f"model_tiers must be a mapping of tier names, got {type(tiers_raw).__name__}",
            f"valid tier names: {', '.join(TIERS)}",
        )
    # v0.4 rename: legacy keys normalize BEFORE validation; a legacy key and
    # its canonical twin in one file fail closed (no silent merge precedence).
    seen_tiers: dict[str, str] = {}  # canonical name -> the name as written
    for raw_name, block in tiers_raw.items():
        written = str(raw_name)
        name = normalize_tier(written)
        if name not in TIERS:
            raise _config_error(
                "config.unknown_key",
                f"unknown tier '{raw_name}' under model_tiers",
                f"valid tier names: {', '.join(TIERS)} "
                f"(legacy names {', '.join(LEGACY_TIERS)} are accepted)",
            )
        first = seen_tiers.setdefault(name, written)
        if first != written:
            legacy = written if first == name else first
            raise _config_error(
                "config.value",
                f"model_tiers has both '{legacy}' (legacy) and '{name}' — remove the legacy key",
                f"keep one of model_tiers.{legacy} / model_tiers.{name} — "
                "the legacy name is the pre-v0.4 vocabulary",
            )
        if name != written:
            note = f"model_tiers.{written} renamed to model_tiers.{name} {_LEGACY_NOTE_SUFFIX}"
            if note not in notes:
                notes.append(note)
        if block is None:
            block = {}
        if not isinstance(block, dict):
            raise _config_error(
                "config.type",
                f"model_tiers.{name} must be a mapping, got {type(block).__name__}",
                f"valid keys under model_tiers.{name}: {', '.join(_TIER_KEYS)}",
            )
        _reject_unknown(block, _TIER_KEYS, f"model_tiers.{name}", source_text=text or None)
        cfg.model_tiers[name] = TierConfig(
            provider=_as_str(block.get("provider"), f"model_tiers.{name}.provider") or "auto",
            model=_as_str(block.get("model"), f"model_tiers.{name}.model"),
            base_url=_as_str(block.get("base_url"), f"model_tiers.{name}.base_url"),
            key_env=_as_str(block.get("key_env"), f"model_tiers.{name}.key_env"),
            timeout=_as_int(block.get("timeout", 120), f"model_tiers.{name}.timeout", minimum=1),
            reasoning_effort=_as_str(block.get("reasoning_effort"), f"model_tiers.{name}.reasoning_effort"),
        )

    # --- providers ---------------------------------------------------------
    providers_raw = raw.get("providers") or {}
    if not isinstance(providers_raw, dict):
        raise _config_error(
            "config.type",
            f"providers must be a mapping of provider names, got {type(providers_raw).__name__}",
            "example:\nproviders:\n  openai:\n    key_env: OPENAI_API_KEY",
        )
    for name, block in providers_raw.items():
        if block is None:
            block = {}
        if not isinstance(block, dict):
            raise _config_error(
                "config.type",
                f"providers.{name} must be a mapping, got {type(block).__name__}",
                f"valid keys under providers.{name}: {', '.join(_PROVIDER_KEYS)}",
            )
        _reject_unknown(block, _PROVIDER_KEYS, f"providers.{name}", source_text=text or None)
        endpoint = _as_str(block.get("endpoint"), f"providers.{name}.endpoint")
        if endpoint not in _ENDPOINTS:
            raise _config_error(
                "config.value",
                f"providers.{name}.endpoint must be 'chat' or 'responses' — got '{endpoint}'",
                f"set providers.{name}.endpoint to chat (OpenAI chat completions) "
                f"or responses, or remove the key ({', '.join(v for v in _ENDPOINTS if v)})",
            )
        cfg.providers[str(name)] = ProviderConfig(
            key_env=_as_str(block.get("key_env"), f"providers.{name}.key_env"),
            api_key=_as_str(block.get("api_key"), f"providers.{name}.api_key"),
            base_url=_as_str(block.get("base_url"), f"providers.{name}.base_url"),
            endpoint=endpoint,
        )

    # --- fallback_providers ------------------------------------------------
    fallback_raw = raw.get("fallback_providers") or []
    if not isinstance(fallback_raw, list):
        raise _config_error(
            "config.type",
            f"fallback_providers must be a list, got {type(fallback_raw).__name__}",
            "example:\nfallback_providers:\n  - provider: openrouter\n    model: anthropic/claude-sonnet-4.5",
        )
    for i, entry in enumerate(fallback_raw):
        if not isinstance(entry, dict):
            raise _config_error(
                "config.type",
                f"fallback_providers[{i}] must be a mapping, got {type(entry).__name__}",
                f"valid keys: {', '.join(_FALLBACK_KEYS)}",
            )
        _reject_unknown(entry, _FALLBACK_KEYS, f"fallback_providers[{i}]", source_text=text or None)
        provider = _as_str(entry.get("provider"), f"fallback_providers[{i}].provider")
        model = _as_str(entry.get("model"), f"fallback_providers[{i}].model")
        if not provider or not model:
            raise _config_error(
                "config.value",
                f"fallback_providers[{i}] needs both 'provider' and 'model'",
                "example: {provider: openrouter, model: anthropic/claude-sonnet-4.5, "
                "key_env: OPENROUTER_API_KEY}",
            )
        cfg.fallback_providers.append(
            FallbackEntry(
                provider=provider,
                model=model,
                base_url=_as_str(entry.get("base_url"), f"fallback_providers[{i}].base_url"),
                key_env=_as_str(entry.get("key_env"), f"fallback_providers[{i}].key_env"),
            )
        )

    # --- budget ------------------------------------------------------------
    budget_raw = raw.get("budget") or {}
    if not isinstance(budget_raw, dict):
        raise _config_error(
            "config.type",
            f"budget must be a mapping, got {type(budget_raw).__name__}",
            f"valid keys under budget: {', '.join(_BUDGET_KEYS)}",
        )
    _reject_unknown(budget_raw, _BUDGET_KEYS, "budget", source_text=text or None)
    cfg.budget = BudgetConfig(
        max_cost_usd=_as_number(budget_raw.get("max_cost_usd", 5.0), "budget.max_cost_usd", minimum=0.0),
        max_iterations=_as_int(budget_raw.get("max_iterations", 60), "budget.max_iterations", minimum=1),
        wall_seconds=_as_number(budget_raw.get("wall_seconds", 1800.0), "budget.wall_seconds", minimum=0.0),
    )

    # --- agent -------------------------------------------------------------
    agent_raw = raw.get("agent") or {}
    if not isinstance(agent_raw, dict):
        raise _config_error(
            "config.type",
            f"agent must be a mapping, got {type(agent_raw).__name__}",
            f"valid keys under agent: {', '.join(_AGENT_KEYS)}",
        )
    _reject_unknown(agent_raw, _AGENT_KEYS, "agent", source_text=text or None)
    tier = _as_str(agent_raw.get("tier", "basic"), "agent.tier") or "basic"
    canonical_tier = normalize_tier(tier)
    if canonical_tier != tier:
        note = f"agent.tier '{tier}' renamed to '{canonical_tier}' {_LEGACY_NOTE_SUFFIX}"
        if note not in notes:
            notes.append(note)
    tier = canonical_tier
    if tier not in AGENT_TIERS:
        raise _config_error(
            "config.value",
            f"agent.tier must be one of: {', '.join(AGENT_TIERS)} — got '{tier}'",
            f"set agent.tier to basic, advanced, or one of {', '.join(TIERS)} "
            f"(legacy names {', '.join(LEGACY_TIERS)} are accepted)",
        )
    cfg.agent = AgentConfig(
        tier=tier,
        api_max_retries=_as_int(agent_raw.get("api_max_retries", 3), "agent.api_max_retries", minimum=1),
        browser=_as_bool(agent_raw.get("browser", False), "agent.browser"),
    )

    # --- env overrides (WIN over YAML) -------------------------------------
    _apply_env_overrides(cfg, env, notes)
    cfg.legacy_notes = tuple(notes)
    return cfg


def _apply_env_overrides(
    cfg: HunterConfig, env: Mapping[str, str], notes: list[str]
) -> HunterConfig:
    tier_env = (env.get("HUNTEROS_TIER") or "").strip()
    if tier_env:
        canonical_env = normalize_tier(tier_env)
        if canonical_env != tier_env:
            note = f"$HUNTEROS_TIER '{tier_env}' renamed to '{canonical_env}' {_LEGACY_NOTE_SUFFIX}"
            if note not in notes:
                notes.append(note)
        tier_env = canonical_env
        if tier_env not in AGENT_TIERS:
            raise _config_error(
                "config.value",
                f"$HUNTEROS_TIER must be one of: {', '.join(AGENT_TIERS)} — got '{tier_env}'",
                f"set HUNTEROS_TIER to basic or one of {', '.join(TIERS)} "
                f"(legacy names {', '.join(LEGACY_TIERS)} are accepted)",
            )
        cfg.agent.tier = tier_env

    budget_env = (env.get("HUNTEROS_BUDGET_USD") or "").strip()
    if budget_env:
        try:
            value = float(budget_env)
        except ValueError as exc:
            raise _config_error(
                "config.value",
                f"$HUNTEROS_BUDGET_USD must be a number — got '{budget_env}'",
                "e.g. export HUNTEROS_BUDGET_USD=10.0",
            ) from exc
        if value < 0:
            raise _config_error(
                "config.value",
                f"$HUNTEROS_BUDGET_USD must be >= 0 — got '{budget_env}'",
                "e.g. export HUNTEROS_BUDGET_USD=10.0",
            )
        cfg.budget.max_cost_usd = value

    iter_env = (env.get("HUNTEROS_MAX_ITERATIONS") or "").strip()
    if iter_env:
        try:
            value = int(iter_env)
        except ValueError as exc:
            raise _config_error(
                "config.value",
                f"$HUNTEROS_MAX_ITERATIONS must be an integer — got '{iter_env}'",
                "e.g. export HUNTEROS_MAX_ITERATIONS=100",
            ) from exc
        if value < 1:
            raise _config_error(
                "config.value",
                f"$HUNTEROS_MAX_ITERATIONS must be >= 1 — got '{iter_env}'",
                "e.g. export HUNTEROS_MAX_ITERATIONS=100",
            )
        cfg.budget.max_iterations = value

    # HUNTEROS_MODEL is deliberately NOT baked in here: resolve_model() reads
    # it at use time so the env can change between load and call.
    return cfg


# --------------------------------------------------------------- resolution --


def resolve_model(
    tier: str, cfg: HunterConfig, *, env: Mapping[str, str] | None = None
) -> str:
    """Model string for a tier: tier.model → $HUNTEROS_MODEL → orchestrator.model
    (other tiers inherit the top default) → HunterError at use time. Legacy
    tier names normalize first (defensive — the loader already mapped)."""
    env = os.environ if env is None else env
    tier = normalize_tier(tier)
    tier_cfg = cfg.model_tiers.get(tier)
    if tier_cfg is None:
        raise _config_error(
            "config.value",
            f"unknown tier '{tier}'",
            f"valid tiers: {', '.join(TIERS)}",
        )
    own = (tier_cfg.model or "").strip()
    if own and own != "auto":
        return own
    override = (env.get("HUNTEROS_MODEL") or "").strip()
    if override:
        return override
    if tier != "orchestrator":
        top = (cfg.model_tiers.get("orchestrator", TierConfig()).model or "").strip()
        if top and top != "auto":
            return top
    raise _config_error(
        "config.model_unresolved",
        f"no model resolved for tier '{tier}'",
        "set model under model_tiers in ~/.hunteros/config.yaml or export HUNTEROS_MODEL",
    )


def default_model(cfg: HunterConfig, *, env: Mapping[str, str] | None = None) -> str:
    """The top default (orchestrator) model, or "" when nothing is configured."""
    try:
        return resolve_model("orchestrator", cfg, env=env)
    except HunterError:
        return ""


def resolve_key(
    provider_name: str, cfg: HunterConfig, *, env: Mapping[str, str] | None = None
) -> str:
    """API key for a provider: ``key_env`` env lookup first, inline ``api_key``
    fallback. A provider block that declares NEITHER ``key_env`` NOR
    ``api_key`` is KEYLESS — this returns ``""`` and the caller dials without
    auth (LiteLLM sends no key). Raises HunterError (auth layer, exit 4) only
    when a key is DECLARED (``key_env``, or a ``key_env`` whose env var is
    unset) but cannot be resolved. Returns "" for providers with NO block —
    LiteLLM then applies its own standard env resolution."""
    env = os.environ if env is None else env
    provider = cfg.providers.get(provider_name)
    if provider is None:
        return ""
    if provider.key_env:
        from_env = (env.get(provider.key_env) or "").strip()
        if from_env:
            return from_env
        inline = (provider.api_key or "").strip()
        if inline:
            return inline
        raise HunterError(
            code="auth.missing_key",
            layer="auth",
            message=f"no API key for provider '{provider_name}'",
            hint=f"set {provider.key_env} "
            "in the environment or ~/.hunteros/config.yaml",
            exit_code=EXIT_AUTH,
        )
    return (provider.api_key or "").strip()


# ------------------------------------------------------------------- docs ----


def config_example_yaml() -> str:
    """A complete, commented, loadable example (docs + `hunter config example`)."""
    return """\
# HunterOs LLM configuration — copy to ~/.hunteros/config.yaml
# Any provider reachable through LiteLLM works: set a key env var and a model.
# Every value here can be overridden per-run with env vars:
#   HUNTEROS_MODEL, HUNTEROS_TIER, HUNTEROS_BUDGET_USD, HUNTEROS_MAX_ITERATIONS

model_tiers:
  orchestrator:                # task decomposition — the "top default" model
    provider: anthropic        # auto | openai | anthropic | openrouter | groq | gemini | ollama | ...
    model: claude-sonnet-4-5   # empty or "auto" inherits $HUNTEROS_MODEL
    # base_url: https://internal-gateway.example.com/v1
    # key_env: ANTHROPIC_API_KEY
    timeout: 120               # seconds per completion
    # reasoning_effort: medium # low | medium | high (models that support it)

  hunter:                      # payload/craft tier — inherits orchestrator unless set
    provider: auto
    model: ""

  verifier:                    # evidence checking — a cheap, careful model
    provider: auto
    model: ""

  utility:                     # summarizing/formatting — cheapest model
    provider: auto
    model: ""

providers:                     # credentials per provider name
  anthropic:
    key_env: ANTHROPIC_API_KEY # env var is preferred over inline api_key
  openai:
    key_env: OPENAI_API_KEY
# A block with ONLY base_url (no key_env / api_key) is a KEYLESS endpoint —
# no auth error, LiteLLM dials it without a key (local servers, corp proxies):
#   mylocal:
#     base_url: http://127.0.0.1:11434

# Tried in order when the primary provider fails with auth/billing/404-class
# errors (deduped against the primary by provider+model+base_url).
fallback_providers: []
#  - provider: openrouter
#    model: anthropic/claude-sonnet-4.5
#    key_env: OPENROUTER_API_KEY

budget:                        # per-run governor (RunBudget)
  max_cost_usd: 5.0            # hard spend cap; warnings at 70/85/95%
  max_iterations: 60           # agent tool-loop turns
  wall_seconds: 1800           # 30 minute wall clock

agent:
  tier: basic                  # basic | advanced | orchestrator | hunter | verifier | utility
  api_max_retries: 3           # attempts per provider before failing over
"""
