"""Known LLM providers — the wizard's pick-list and sane defaults.

A *known* provider carries its default endpoint (when it has one), the env
var that holds its key (``""`` = keyless), a suggested orchestrator model, and
a cheap sibling for the verifier tier. Anything NOT in this table is still
fully supported — ``hunter config provider add <name> --base-url ...`` accepts
any OpenAI-compatible endpoint, and LiteLLM dials hundreds more by model
prefix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["CUSTOM_NAME", "PROVIDER_NAME_RE", "KnownProvider", "known_provider", "known_provider_names"]

CUSTOM_NAME = "custom"

# Provider names live in config files and on the command line: lowercase,
# start with a letter, then letters/digits/underscore/dash.
PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


@dataclass(frozen=True)
class KnownProvider:
    """One row of the pick-list. ``key_env=""`` means keyless; ``base_url=""``
    means LiteLLM's own default endpoint for that provider."""

    name: str
    base_url: str = ""
    key_env: str = ""
    default_model: str = ""
    cheap_model: str = ""
    note: str = ""


_KNOWN_PROVIDERS: dict[str, KnownProvider] = {
    "openai": KnownProvider(
        "openai", key_env="OPENAI_API_KEY", default_model="gpt-4o",
        cheap_model="gpt-4o-mini", note="OpenAI official API",
    ),
    "anthropic": KnownProvider(
        "anthropic", key_env="ANTHROPIC_API_KEY", default_model="claude-sonnet-4-5",
        cheap_model="claude-haiku-4-5", note="Claude models",
    ),
    "openrouter": KnownProvider(
        "openrouter", base_url="https://openrouter.ai/api/v1", key_env="OPENROUTER_API_KEY",
        default_model="anthropic/claude-sonnet-4.5", cheap_model="anthropic/claude-3.5-haiku",
        note="400+ models behind one key",
    ),
    "deepseek": KnownProvider(
        "deepseek", key_env="DEEPSEEK_API_KEY", default_model="deepseek-chat",
        cheap_model="deepseek-chat", note="DeepSeek V3 / R1",
    ),
    "groq": KnownProvider(
        "groq", key_env="GROQ_API_KEY", default_model="llama-3.3-70b-versatile",
        cheap_model="llama-3.1-8b-instant", note="very fast open-model inference",
    ),
    "together": KnownProvider(
        "together", key_env="TOGETHER_API_KEY", default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        cheap_model="meta-llama/Llama-3.2-3B-Instruct-Turbo", note="open models, one key",
    ),
    "ollama": KnownProvider(
        "ollama", base_url="http://127.0.0.1:11434", default_model="llama3",
        cheap_model="llama3", note="local, keyless — nothing leaves your machine",
    ),
    "lmstudio": KnownProvider(
        "lmstudio", base_url="http://127.0.0.1:1234/v1", default_model="local-model",
        cheap_model="local-model", note="local OpenAI-compatible server, keyless",
    ),
    "vllm": KnownProvider(
        "vllm", base_url="http://127.0.0.1:8000/v1", default_model="local-model",
        cheap_model="local-model", note="self-hosted OpenAI-compatible server, keyless",
    ),
}


def known_provider(name: str) -> KnownProvider | None:
    """The table row for ``name`` (custom is deliberately NOT in the table —
    it always needs an explicit base URL)."""
    return _KNOWN_PROVIDERS.get(name)


def known_provider_names() -> tuple[str, ...]:
    """Pick-list order: the table order, then ``custom`` last."""
    return (*_KNOWN_PROVIDERS.keys(), CUSTOM_NAME)
