"""Known LLM providers — the wizard's pick-list and sane defaults.

A *known* provider carries its default endpoint (when it has one), the env
var that holds its key (``""`` = keyless), a suggested orchestrator model, and
a cheap sibling for the verifier tier. Anything NOT in this table is still
fully supported — ``hunter config provider add <name> --base-url ...`` accepts
any OpenAI-compatible endpoint, and LiteLLM dials hundreds more by model
prefix.

M11 adds the Hermes per-host key-variable helpers (:func:`key_env_for_endpoint`
derives the keys.env name from the endpoint host, :func:`is_local_endpoint`
drives the local-server auto-probe messaging) — pure functions, no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

__all__ = [
    "CUSTOM_NAME",
    "PROVIDER_NAME_RE",
    "KnownProvider",
    "is_local_endpoint",
    "key_env_for_endpoint",
    "known_provider",
    "known_provider_names",
]

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


# ------------------------------------------------------------- M11 helpers --


_LOCAL_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
)


def is_local_endpoint(base_url: str) -> bool:
    """True for loopback/private-URL hosts (drives the local-server
    auto-probe messaging — "is the server running?")."""
    try:
        host = (urlparse(base_url).hostname or "").lower()
    except ValueError:
        return False
    if host in _LOCAL_HOSTS:
        return True
    # RFC1918 / link-local private ranges (the common LAN inference box).
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        octets = [int(p) for p in parts]
        if octets[0] in (10, 127) or (octets[0] == 192 and octets[1] == 168) or (
            octets[0] == 172 and 16 <= octets[1] <= 31
        ):
            return True
    return host.endswith(".local")


def key_env_for_endpoint(base_url: str) -> str:
    """Per-host(+port) keys.env variable name (the Hermes pattern).

    host: dots/dashes → '_', upper; explicit non-default port appended;
    a leading digit is prefixed ``K_`` —
    https://api.atria-asi.ai/v1 → ``ATRIA_ASI_AI_API_KEY``;
    http://127.0.0.1:8080/v1 → ``K_127_0_0_1_8080_API_KEY``;
    https://api.example.com:443/v1 → ``API_EXAMPLE_COM_API_KEY`` (the default
    port is dropped); http://api.example.com:8123/v1 →
    ``API_EXAMPLE_COM_8123_API_KEY``."""
    try:
        parsed = urlparse(base_url)
    except ValueError:
        return "CUSTOM_API_KEY"
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return "CUSTOM_API_KEY"
    labels = host.split(".")
    # A leading "api." service label is dropped when the organization label
    # is hyphenated (multi-word brands read better as one slug:
    # api.atria-asi.ai → ATRIA_ASI_AI_API_KEY); single-word orgs keep it
    # (api.example.com → API_EXAMPLE_COM_API_KEY).
    if (
        len(labels) > 2
        and labels[0] == "api"
        and any("-" in label for label in labels[1:-1])
    ):
        labels = labels[1:]
        host = ".".join(labels)
    port = parsed.port  # None when absent
    scheme = (parsed.scheme or "").lower()
    default_ports = {"https": 443, "http": 80}
    if port is not None and default_ports.get(scheme) != port:
        host = f"{host}_{port}"
    slug = re.sub(r"[^A-Za-z0-9]+", "_", host).strip("_").upper()
    if not slug:
        return "CUSTOM_API_KEY"
    if slug[0].isdigit():
        slug = f"K_{slug}"
    return f"{slug}_API_KEY"
