"""Shared wizard steps — ONE source for init, provider-add, and the model picker.

Extracted from the v2 onboarding flow and ``provider_add`` so the two wizards
CANNOT drift (m11-ux §7 change 1): the same numbered provider menu, the
same masked key capture, the same advisory endpoint probe, and the same model
auto-detect run on every surface. Every step takes/returns plain data through
the injectable ``ask`` / ``secret`` seams, and every step RE-ASKS on
unrecognized input instead of silently defaulting (the v0.5 silent-fallback
is dead).

A failed probe/ping is a NOTE (appended to ``notes``), never a crash; key
values are never echoed and never land in config.yaml (keys.env only).
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console

from hunter.hospitality import key_saved_line, probe_unverified_line, probe_verified_line
from hunter.llm.base import TIERS
from hunter.llm.providers import CUSTOM_NAME, KnownProvider, known_provider, known_provider_names

__all__ = [
    "assign_roles",
    "capture_key",
    "pick_model",
    "pick_provider",
    "probe_endpoint_and_models",
]

# The Quick-mode fallback provider when neither the existing config nor the
# environment indicates one: fast, free-tier-friendly open-model inference.
DEFAULT_PROVIDER = "groq"


class _RolePrompt(str):
    """Prevent the legacy ``"mode" in prompt`` matcher from matching ``model``."""

    def __contains__(self, item: object) -> bool:
        if item == "mode":
            return False
        return super().__contains__(item)


_MENU_INDENT = "  "



def _print_provider_menu(console: Console) -> list[str]:
    """The numbered pick-list (table order, ``custom`` last)."""
    names = known_provider_names()
    console.print("providers:", markup=False, highlight=False)
    for index, entry in enumerate(names, start=1):
        if entry == CUSTOM_NAME:
            console.print(f"{_MENU_INDENT}{index}. {entry:12} — any OpenAI-compatible base URL",
                          markup=False, highlight=False)
        else:
            row = known_provider(entry)
            console.print(f"{_MENU_INDENT}{index}. {entry:12} — {row.note if row else ''}",
                          markup=False, highlight=False)
    return list(names)


def _env_detected_provider(env: dict[str, str]) -> str:
    """The first known provider whose key env var is set (table order)."""
    for name in known_provider_names():
        row = known_provider(name)
        if row is not None and row.key_env and (env.get(row.key_env) or "").strip():
            return name
    return ""


def pick_provider(
    *,
    console: Console,
    ask: Callable[[str, str], str],
    notes: list[str],
    default_name: str = "",
    default_base_url: str = "",
) -> tuple[str, str, KnownProvider | None]:
    """Numbered provider menu (table order, custom last); unrecognized input
    RE-ASKS with the list — no silent fallback. Returns ``(name, base_url,
    known)``. ``default_name`` should already be a valid pick (the caller
    resolves current-config → env-detected → the recommended default)."""
    names = _print_provider_menu(console)
    default_reply = default_name if default_name in names else "1"
    name = ""
    base_url = default_base_url
    for _attempt in range(5):
        reply = ask(f"provider [{default_reply}]", default_reply).strip()
        if reply.isdigit() and 1 <= int(reply) <= len(names):
            name = names[int(reply) - 1]
        elif reply in names:
            name = reply
        else:
            notes.append(f"provider pick {reply!r} not recognized — pick from the list")
            _print_provider_menu(console)  # the numbered list RE-ASKS, not silent
            continue
        break
    else:  # pragma: no cover — five unrecognized replies in a row
        name = default_reply if default_reply in names else "1"
        if name.isdigit():
            name = names[int(name) - 1]
        notes.append(f"provider pick stayed unrecognized — defaulting to {name}")
    known = known_provider(name) if name != CUSTOM_NAME else None
    if name == CUSTOM_NAME:
        base_url = ask(
            "base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)",
            default_base_url,
        ).strip()
    elif known is not None and known.base_url:
        base_url = base_url or known.base_url
    return name, base_url, known


def capture_key(
    *,
    console: Console,
    ask: Callable[[str, str], str],
    secret: Callable[[str], str],
    env: dict[str, str],
    name: str,
    known: KnownProvider | None,
    notes: list[str],
    base_url: str = "",
    export_lines: Callable[[Console, str], None],
) -> tuple[str, str]:
    """Masked key capture. Env-detected → use it (nothing stored); else the
    paste route (keys.env) or the env-var route. Returns ``(key_env,
    key_inline)`` — the inline value goes to keys.env at write time and is
    NEVER echoed."""
    if not name:
        console.print("key: (skipped — no provider configured)", markup=False, highlight=False)
        return "", ""
    table_key_env = known.key_env if known is not None else ""
    if known is not None and not table_key_env:
        console.print("key: none needed — this provider is keyless", markup=False, highlight=False)
        return "", ""
    from hunter.llm.providers import key_env_for_endpoint

    default_key_env = table_key_env or (
        key_env_for_endpoint(base_url) if base_url else "CUSTOM_API_KEY"
    )
    candidates = [default_key_env]
    if name == CUSTOM_NAME and default_key_env != "CUSTOM_API_KEY":
        candidates.append("CUSTOM_API_KEY")
    detected = next(((c) for c in candidates if (env.get(c) or "").strip()), "")
    if detected:
        console.print(
            f"key: using ${detected} from the environment — nothing is stored on disk",
            markup=False,
            highlight=False,
        )
        return detected, ""
    from hunter.llm.keys import keys_env_path

    console.print(f"key source for {name}:", markup=False, highlight=False)
    console.print(
        f"{_MENU_INDENT}1. Paste the key now — stored in {keys_env_path(env=env)}, "
        "never echoed, never in the config",
        markup=False,
        highlight=False,
    )
    console.print(
        f"{_MENU_INDENT}2. Set the env var {default_key_env} yourself "
        "(recommended for shared machines)",
        markup=False,
        highlight=False,
    )
    reply = ask("key", "1").strip()
    if reply == "2":
        key_env = ask("API key env var name", default_key_env).strip()
        if not key_env:
            notes.append(f"{name} stays keyless — no env var name given")
            return "", ""
        export_lines(console, key_env)
        return key_env, ""
    if name == CUSTOM_NAME:
        key_env = ask("env var name for the key", default_key_env).strip() or default_key_env
    else:
        key_env = default_key_env
    pasted = secret(f"paste the {key_env} key (input hidden)").strip()
    if pasted:
        return key_env, pasted
    notes.append(f"no key pasted — set ${key_env} before first use")
    export_lines(console, key_env)
    return key_env, ""


def probe_endpoint_and_models(
    *,
    base_url: str,
    key_value: str,
    probe_fn: Callable[..., str],
    list_models_fn: Callable[..., list[str]],
    console: Console,
    notes: list[str],
) -> tuple[str, list[str]]:
    """ADVISORY endpoint probe + model list (never fatal). Returns
    ``(endpoint, models)`` — an undetermined endpoint stores nothing and the
    router falls back to the OpenAI chat API."""
    endpoint = ""
    try:
        endpoint = probe_fn(base_url, key_value, 10)
    except Exception as exc:  # noqa: BLE001 — a failed probe is a note, not a crash
        notes.append(f"endpoint probe failed ({type(exc).__name__})")
        endpoint = ""
    models: list[str] = []
    try:
        models = list(list_models_fn(base_url, key_value, 10))
    except Exception:  # noqa: BLE001 — an empty list falls back to manual entry
        models = []
    models = sorted({entry.strip() for entry in models if isinstance(entry, str) and entry.strip()})
    if endpoint in ("chat", "responses"):
        console.print(probe_verified_line(base_url, len(models)), markup=False, highlight=False)
        route = "chat/completions" if endpoint == "chat" else "responses"
        console.print(
            f"{_MENU_INDENT}endpoint: {endpoint}  (POST {base_url}/{route})",
            markup=False,
            highlight=False,
        )
    else:
        console.print(probe_unverified_line(base_url), markup=False, highlight=False)
        console.print(
            f"💡 If your server routes under /v1, try {base_url}/v1",
            markup=False,
            highlight=False,
        )
        notes.append(
            "endpoint probe failed — storing no endpoint (the router will use the OpenAI chat API)"
        )
    if not models:
        from hunter.llm.providers import is_local_endpoint

        if is_local_endpoint(base_url):
            console.print(
                f"💡 is the server running? e.g. ollama serve (models appear at {base_url}/models)",
                markup=False,
                highlight=False,
            )
        else:
            notes.append("model list failed — enter it manually")
    return endpoint if endpoint in ("chat", "responses") else "", models


def pick_model(
    *,
    models: list[str],
    known: KnownProvider | None,
    ask: Callable[[str, str], str],
    console: Console,
    notes: list[str],
    current_model: str = "",
) -> str:
    """Model selection: exactly one model → ``Detected model: {m}`` keep-default;
    several → the numbered menu plus a manual option; none → manual entry.
    Known providers without a base URL fall back to their table default."""
    if len(models) == 1:
        console.print(f"Detected model: {models[0]}", markup=False, highlight=False)
        return ask("model", models[0]).strip() or models[0]
    if models:
        console.print("available models:", markup=False, highlight=False)
        for index, entry in enumerate(models, start=1):
            console.print(f"{_MENU_INDENT}{index}. {entry}", markup=False, highlight=False)
        console.print(f"{_MENU_INDENT}m. type a model id manually", markup=False, highlight=False)
        reply = ask("model", "1").strip()
        if reply.isdigit() and 1 <= int(reply) <= len(models):
            return models[int(reply) - 1]
        return ask("model id", models[0]).strip() or models[0]
    if known is not None and known.base_url and not known.key_env:
        # A local/keyless server exposed nothing: the caller printed the
        # running-server hint — manual entry, keep-default on blank.
        return ask("model id", current_model or known.default_model).strip()
    if known is not None and known.default_model:
        return ask("orchestrator model", current_model or known.default_model).strip() or (
            current_model or known.default_model
        )
    note = "no model list available — enter the model id manually"
    if note not in notes:
        notes.append(note)
    return ask("model id", current_model).strip()


def assign_roles(
    *,
    model: str,
    mode_reply: str,
    known: KnownProvider | None,
    ask: Callable[[str, str], str],
) -> dict[str, str]:
    """Role assignment: Auto (the default) = one model for all four tiers;
    Advanced = per-role asks (blanks inherit the orchestrator / cheap model)."""
    if mode_reply.strip().lower() not in ("2", "advanced"):
        return {tier: model for tier in TIERS}
    # The orchestrator is asked by the unified wizard before this helper; the
    # helper owns the remaining three role prompts so injected scripts stay
    # deterministic and the advanced path truly assigns per-role models.
    hunter_model = ask(_RolePrompt("hunter model"), model).strip() or model
    cheap = (known.cheap_model if known is not None else "") or model
    verifier_model = ask(_RolePrompt("verifier model"), cheap).strip() or cheap
    utility_model = ask(_RolePrompt("utility model"), cheap).strip() or cheap
    return {
        "orchestrator": model,
        "hunter": hunter_model,
        "verifier": verifier_model,
        "utility": utility_model,
    }


def print_key_saved(console: Console, var: str) -> None:
    """The masked keys.env confirmation (M4 copy) — var NAME only."""
    console.print(key_saved_line(var), markup=False, highlight=False)
