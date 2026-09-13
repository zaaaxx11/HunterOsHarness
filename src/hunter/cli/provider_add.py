"""``provider add`` interactive wizard — add a provider WITHOUT hand-editing YAML.

Triggered by OMITTING the NAME argument of ``hunter config provider add``
(the flagged path keeps its exact scripted semantics — the wizard is
name-omission only). Flow: provider pick → key capture (keys.env or env var)
→ endpoint menu (chat | responses | auto-detect via
:func:`hunter.llm.probe.detect_endpoint`) → model auto-add
(:func:`hunter.llm.probe.list_models`, manual fallback) → role assignment
(auto = one model for all four canonical tiers) → endpoint-aware smoke ping
→ atomic :func:`hunter.llm.writing.write_config`.

Every prompt goes through the injectable ``ask`` / ``secret`` callables and
every probe/ping through injectable seams, so tests drive the wizard without
a tty or a network. A failed step is a NOTE in the final summary — it never
crashes the run (exit 0 on every normal terminal path); only the config
write itself may raise :class:`hunter.errors.HunterError` (handle.py renders
it). The pasted key goes to keys.env, NEVER into config.yaml, and is never
echoed: prompts print key ENV NAMES only, probe/ping failures print the
redacted classified message.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from hunter.errors import HunterError
from hunter.llm.base import TIERS
from hunter.llm.keys import keys_env_path, write_keys_env
from hunter.llm.ping import ping_provider
from hunter.llm.providers import CUSTOM_NAME, known_provider, known_provider_names
from hunter.llm.writing import resolve_config_target, write_config

__all__ = ["ProviderAddAnswers", "provider_add_updates", "run_provider_add_wizard"]


@dataclass
class ProviderAddAnswers:
    """What one wizard run decided. ``notes`` collects every skipped/failed
    step — they print in the final summary, they never abort. The pasted key
    (``key_inline``) goes to keys.env, NEVER into config.yaml, never echoed."""

    provider: str = ""
    base_url: str = ""
    endpoint: str = ""                 # "" (chat default) | "chat" | "responses"
    key_env: str = ""
    key_inline: str = ""               # keys.env ONLY, never config.yaml, never echoed
    role_models: dict[str, str] = field(default_factory=dict)  # canonical tier -> model
    notes: list[str] = field(default_factory=list)


def provider_add_updates(a: ProviderAddAnswers) -> dict[str, Any]:
    """Pure. The write_config fragment: the providers block (+ ``endpoint``
    only when set) + model_tiers for the four canonical tiers, each pinned to
    ``a.provider`` (or "auto"). The pasted key is NEVER in this fragment."""
    updates: dict[str, Any] = {}
    if a.provider:
        block: dict[str, Any] = {}
        if a.key_env:
            block["key_env"] = a.key_env
        if a.base_url:
            block["base_url"] = a.base_url
        if a.endpoint:
            block["endpoint"] = a.endpoint
        updates["providers"] = {a.provider: block}
    if a.role_models:
        updates["model_tiers"] = {
            tier: {"provider": a.provider or "auto", "model": model}
            for tier, model in a.role_models.items()
        }
    return updates


# --------------------------------------------------------------------- flow --


def run_provider_add_wizard(
    *,
    path: str | Path | None = None,
    console: Console | None = None,
    err_console: Console | None = None,
    ask: Callable[[str, str], str] | None = None,
    secret: Callable[[str], str] | None = None,
    ping_fn: Callable[..., Any] | None = None,
    probe_fn: Callable[..., str] | None = None,      # hunter.llm.probe.detect_endpoint
    list_models_fn: Callable[..., list[str]] | None = None,  # hunter.llm.probe.list_models
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> int:
    """Run the wizard; return 0 on every normal terminal path (failures are
    notes); lets HunterError from the writes propagate (handle.py renders it).
    EOF falls back to every prompt's default — a fully non-interactive run
    writes a valid config and exits 0 with notes, never a key it did not
    receive."""
    from hunter.cli.init_wizard import _default_ask, _default_secret, _print_export_lines

    console = console if console is not None else Console()
    ask = ask if ask is not None else _default_ask(console)
    secret = secret if secret is not None else _default_secret()
    ping_fn = ping_fn if ping_fn is not None else ping_provider
    if probe_fn is None or list_models_fn is None:
        from hunter.llm.probe import detect_endpoint, list_models

        probe_fn = probe_fn if probe_fn is not None else detect_endpoint
        list_models_fn = list_models_fn if list_models_fn is not None else list_models
    env = dict(os.environ) if environ is None else dict(environ)
    keys_path = keys_env_path(env=env, home=home)

    target = resolve_config_target(path, env=env, home=home)
    console.print("[bold]hunter config provider add[/bold] — wizard")
    console.print(f"config target: {target}", markup=False, highlight=False)
    console.print("Your key is sent nowhere except the provider you pick.",
                  markup=False, highlight=False)
    answers = ProviderAddAnswers()
    notes = answers.notes

    # ---- step 1/6: provider (onboarding step-2 menu: table order, custom last) ---
    names = known_provider_names()
    console.print("providers:")
    for index, entry in enumerate(names, start=1):
        if entry == CUSTOM_NAME:
            console.print(f"  {index}. {entry:12} — any OpenAI-compatible base URL")
        else:
            row = known_provider(entry)
            console.print(f"  {index}. {entry:12} — {row.note if row else ''}")
    reply = ask("provider [1]", "1")
    name = ""
    base_url = ""
    if reply.isdigit() and 1 <= int(reply) <= len(names):
        name = names[int(reply) - 1]
    elif reply in names:
        name = reply
    else:
        name = names[0]
        notes.append(f"provider pick {reply!r} not recognized — using {name}")
    known = known_provider(name) if name != CUSTOM_NAME else None
    if name == CUSTOM_NAME:
        base_url = ask(
            "base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)", ""
        ).strip()
        if not base_url:
            notes.append("custom provider skipped — no base URL given")
            console.print("notes:", markup=False, highlight=False)
            for note in notes:
                console.print(f"  - {note}", markup=False, highlight=False)
            return 0
    if name and known is not None and known.base_url:
        base_url = base_url or known.base_url
    answers.provider = name
    answers.base_url = base_url
    if name:
        console.print(f"step 1/6 provider: {name}" + (f" ({base_url})" if base_url else ""),
                      markup=False, highlight=False)
    else:
        console.print("step 1/6 provider: (skipped — no provider configured)",
                      markup=False, highlight=False)

    # ---- step 2/6: key (onboarding step-3 logic and copy) --------------------------
    key_env = ""
    key_inline = ""
    if not name:
        console.print("step 2/6 key: (skipped — no provider configured)",
                      markup=False, highlight=False)
    else:
        table_key_env = known.key_env if known is not None else ""
        if known is not None and not table_key_env:
            console.print("step 2/6 key: none needed — this provider is keyless",
                          markup=False, highlight=False)
        else:
            default_key_env = table_key_env or "CUSTOM_API_KEY"
            if env.get(default_key_env, "").strip():
                key_env = default_key_env
                console.print(
                    f"step 2/6 key: using ${key_env} from the environment — "
                    "nothing is stored on disk",
                    markup=False,
                    highlight=False,
                )
            else:
                console.print(f"key source for {name}:", markup=False, highlight=False)
                console.print(
                    f"  1. Paste the key now — stored in {keys_path}, "
                    "never echoed, never in the config",
                    markup=False,
                    highlight=False,
                )
                console.print(
                    f"  2. Set the env var {default_key_env} yourself "
                    "(recommended for shared machines)",
                    markup=False,
                    highlight=False,
                )
                reply = ask("key", "1")
                if reply.strip() == "2":
                    key_env = ask("API key env var name", default_key_env).strip()
                    if not key_env:
                        notes.append(f"{name} stays keyless — no env var name given")
                    else:
                        _print_export_lines(console, key_env)
                else:
                    if name == CUSTOM_NAME:
                        key_env = (
                            ask("env var name for the key", default_key_env).strip()
                            or default_key_env
                        )
                    else:
                        key_env = default_key_env
                    pasted = secret(f"paste the {key_env} key (input hidden)").strip()
                    if pasted:
                        key_inline = pasted
                    else:
                        notes.append(f"no key pasted — set ${key_env} before first use")
                        _print_export_lines(console, key_env)
    answers.key_env = key_env
    answers.key_inline = key_inline
    key_value = env.get(key_env, "").strip() or key_inline

    # ---- step 3/6: endpoint -------------------------------------------------------
    if name:
        console.print(f"endpoint for {name}:", markup=False, highlight=False)
        console.print("  1. chat — OpenAI chat completions (default, works everywhere)",
                      markup=False, highlight=False)
        console.print("  2. responses — OpenAI Responses API",
                      markup=False, highlight=False)
        if base_url:
            console.print("  3. auto-detect — probe the base URL now",
                          markup=False, highlight=False)
        reply = ask("endpoint [1]", "").strip().lower()
        if reply in ("2", "responses"):
            answers.endpoint = "responses"
            console.print("step 3/6 endpoint: responses", markup=False, highlight=False)
        elif reply in ("3", "auto", "auto-detect") and base_url:
            try:
                endpoint = probe_fn(base_url, key_value, 10)
            except Exception:  # noqa: BLE001 — a failed probe is a note, not a crash
                endpoint = ""
            if endpoint in ("chat", "responses"):
                answers.endpoint = endpoint
                route = "chat/completions" if endpoint == "chat" else "responses"
                console.print(f"  endpoint: {endpoint}  (POST {base_url}/{route})",
                              markup=False, highlight=False)
            else:
                console.print("  endpoint: undetermined", markup=False, highlight=False)
                notes.append(
                    "endpoint probe failed — storing no endpoint "
                    "(the router will use the OpenAI chat API)"
                )
        else:
            console.print("step 3/6 endpoint: chat (default)", markup=False, highlight=False)

    # ---- step 4/6: model ------------------------------------------------------------
    model = ""
    if name and base_url:
        models: list[str] = []
        try:
            models = list(list_models_fn(base_url, key_value, 10))
        except Exception:  # noqa: BLE001 — an empty list falls back to manual entry
            models = []
        models = sorted({entry.strip() for entry in models if isinstance(entry, str) and entry.strip()})
        if models:
            console.print(f"available models (GET {base_url}/models):",
                          markup=False, highlight=False)
            for index, entry in enumerate(models, start=1):
                console.print(f"  {index}. {entry}", markup=False, highlight=False)
            console.print("  m. type a model id manually", markup=False, highlight=False)
            reply = ask("model", "1")
            if reply.strip().isdigit() and 1 <= int(reply) <= len(models):
                model = models[int(reply) - 1]
            else:
                model = ask("model id", models[0]).strip() or models[0]
        else:
            notes.append("model list failed — enter it manually")
            model = ask("model id", "").strip()
    elif name and known is not None:
        # Known provider without base_url: take the table default (custom never
        # reaches here — it cannot pass step 1 without a base URL).
        model = ask("orchestrator model", known.default_model or "").strip()
    if model:
        console.print(f"step 4/6 model: orchestrator={model}", markup=False, highlight=False)
    else:
        notes.append("no model given — provider stored without a model")

    # ---- step 5/6: role assignment -----------------------------------------------------
    if model:
        console.print("How should this model be assigned?", markup=False, highlight=False)
        console.print(
            "  1. Auto — one model for every role (orchestrator / hunter / verifier / utility)",
            markup=False,
            highlight=False,
        )
        console.print("  2. Advanced — pick per role", markup=False, highlight=False)
        reply = ask("mode [1]", "")
        if reply.strip().lower() in ("2", "advanced"):
            orchestrator = ask("orchestrator model", model).strip() or model
            hunter_model = ask("hunter model", orchestrator).strip() or orchestrator
            cheap = (known.cheap_model if known is not None else "") or orchestrator
            verifier_model = ask("verifier model", cheap).strip() or cheap
            utility_model = ask("utility model", cheap).strip() or cheap
            answers.role_models = {
                "orchestrator": orchestrator,
                "hunter": hunter_model,
                "verifier": verifier_model,
                "utility": utility_model,
            }
            console.print("step 5/6 roles: advanced", markup=False, highlight=False)
        else:
            answers.role_models = {tier: model for tier in TIERS}
            console.print("step 5/6 roles: auto (one model for all roles)",
                          markup=False, highlight=False)

    # ---- write phase (keys.env BEFORE config — a crash can only leave keys
    #      without a config, which the next wizard run heals) ---------------------------
    if answers.key_inline and answers.key_env:
        written_keys = write_keys_env({answers.key_env: answers.key_inline}, env=env, home=home)
        console.print("[green]wrote[/green]", written_keys)
    written = write_config(provider_add_updates(answers), target, env=env, home=home)
    console.print(f"[green]added provider '{name}'[/green] → {written}")

    # ---- step 6/6: endpoint-aware smoke test --------------------------------------------
    if not model:
        notes.append("smoke test skipped — no model configured")
    elif key_env and not key_value:
        console.print(f"step 6/6 smoke test: skipped — {key_env} is not set",
                      markup=False, highlight=False)
        notes.append(f"smoke test skipped — {key_env} is not set")
    else:
        console.print(
            f"step 6/6 smoke test: dialing {name}/{model} with a 1-token ping...",
            markup=False,
            highlight=False,
        )
        try:
            result = ping_fn(name, model, base_url, key_value, 15, endpoint=answers.endpoint)
        except HunterError as exc:
            notes.append(f"smoke test unavailable: {exc.user_message().splitlines()[0]}")
        except Exception as exc:  # noqa: BLE001 — a failed probe is a note, not a crash
            notes.append(f"smoke test failed: {type(exc).__name__}: {exc}")
        else:
            if result.ok:
                console.print(f"  smoke test: [green]{result.message}[/green]")
            else:
                flat = result.message.replace("\n", " / ")
                console.print(f"  smoke test: {flat}")
                notes.append(f"smoke test failed: {flat}")

    console.print(f"next: [bold]hunter config provider test {name}[/bold] · provider list")
    if notes:
        console.print("notes:", markup=False, highlight=False)
        for note in notes:
            console.print(f"  - {note}", markup=False, highlight=False)
    return 0
