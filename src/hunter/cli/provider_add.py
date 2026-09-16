"""``provider add`` interactive wizard — add a provider WITHOUT hand-editing YAML.

Triggered by OMITTING the NAME argument of ``hunter config provider add``
(the flagged path keeps its exact scripted semantics — the wizard is
name-omission only). Flow: provider pick → key capture (keys.env or env var)
→ ADVISORY endpoint probe + model list → endpoint menu (chat | responses |
auto-detect) → model pick (:mod:`hunter.cli.wizard_steps` — the SAME steps
`hunter init` runs, so the wizards cannot drift) → role assignment
→ endpoint-aware smoke ping → atomic :func:`hunter.llm.writing.write_config`.

Every prompt goes through the injectable ``ask`` / ``secret`` callables and
every probe/ping through injectable seams, so tests drive the wizard without
a tty or a network. A failed step is a NOTE in the final summary — it never
crashes the run (exit 0 on every normal terminal path); only the config write
itself may raise :class:`hunter.errors.HunterError` (handle.py renders it).
The pasted key goes to keys.env, NEVER into config.yaml, and is never echoed:
prompts print key ENV NAMES only, probe/ping failures print the redacted
classified message.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from hunter.errors import HunterError
from hunter.llm.keys import write_keys_env
from hunter.llm.ping import ping_provider
from hunter.llm.providers import CUSTOM_NAME
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


_NON_HTTP_REASK = "base URL must start with http:// or https:// — try again:"


def _settle_custom_base_url(
    url: str, ask: Callable[[str, str], str], notes: list[str], console: Console
) -> str:
    """Validate (or ask for) the custom base URL: non-http(s) RE-ASKS inline
    (three strikes → note + skip, never a crash)."""
    for _strike in range(3):
        if url.startswith(("http://", "https://")):
            return url
        if url:
            console.print(_NON_HTTP_REASK, markup=False, highlight=False)
        prompt = _NON_HTTP_REASK if url else (
            "base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)"
        )
        url = ask(prompt, "").strip()
    if not url.startswith(("http://", "https://")):
        if url:
            notes.append(f"base URL {url!r} rejected — must start with http:// or https://")
        return ""
    return url


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
    from hunter.cli.wizard_steps import (
        assign_roles,
        capture_key,
        pick_model,
        pick_provider,
        print_key_saved,
        probe_endpoint_and_models,
    )

    console = console if console is not None else Console()
    ask = ask if ask is not None else _default_ask(console)
    secret = secret if secret is not None else _default_secret()
    ping_fn = ping_fn if ping_fn is not None else ping_provider
    if probe_fn is None or list_models_fn is None:
        from hunter.llm.probe import detect_endpoint, list_models

        probe_fn = probe_fn if probe_fn is not None else detect_endpoint
        list_models_fn = list_models_fn if list_models_fn is not None else list_models
    env = dict(os.environ) if environ is None else dict(environ)
    target = resolve_config_target(path, env=env, home=home)
    console.print("[bold]hunter config provider add[/bold] — wizard")
    console.print(f"config target: {target}", markup=False, highlight=False)
    console.print("Your key is sent nowhere except the provider you pick.",
                  markup=False, highlight=False)
    answers = ProviderAddAnswers()
    notes = answers.notes

    # ---- step 1/6: provider (shared numbered menu: table order, custom last) ---
    name, base_url, known = pick_provider(console=console, ask=ask, notes=notes)
    if name == CUSTOM_NAME:
        base_url = _settle_custom_base_url(base_url, ask, notes, console)
        if not base_url:
            notes.append("custom provider skipped — no base URL given")
            name = ""
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

    # ---- step 2/6: key (shared masked capture: keys.env or env var) ------------
    key_env = ""
    key_inline = ""
    if not name:
        console.print("step 2/6 key: (skipped — no provider configured)",
                      markup=False, highlight=False)
    else:
        key_env, key_inline = capture_key(
            console=console, ask=ask, secret=secret, env=env, name=name, known=known,
            notes=notes, base_url=base_url, export_lines=_print_export_lines,
        )
        if not key_env:
            console.print("step 2/6 key: (skipped)", markup=False, highlight=False)
        elif known is not None and not known.key_env:
            console.print("step 2/6 key: none needed — this provider is keyless",
                          markup=False, highlight=False)
    answers.key_env = key_env
    answers.key_inline = key_inline
    key_value = env.get(key_env, "").strip() or key_inline

    # ---- advisory probe + model list (M4 copy; the endpoint MENU below still
    #      decides what is STORED — the probe itself is advisory only) ----------
    models: list[str] = []
    if name and base_url:
        _endpoint_seen, models = probe_endpoint_and_models(
            base_url=base_url, key_value=key_value, probe_fn=probe_fn,
            list_models_fn=list_models_fn, console=console, notes=notes,
        )

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

    # ---- step 4/6: model (shared pick: auto-detect / menu / manual) ---------------
    model = ""
    if name:
        model = pick_model(
            models=models, known=known, ask=ask, console=console, notes=notes,
        )
    if model:
        console.print(f"step 4/6 model: orchestrator={model}", markup=False, highlight=False)
    else:
        notes.append("no model given — provider stored without a model")

    # ---- step 5/6: role assignment (shared auto/advanced) --------------------------
    if model:
        reply = ask("mode [1]", "")
        answers.role_models = assign_roles(model=model, mode_reply=reply, known=known, ask=ask)
        if reply.strip().lower() in ("2", "advanced"):
            console.print("step 5/6 roles: advanced", markup=False, highlight=False)
        else:
            console.print("step 5/6 roles: auto (one model for all roles)",
                          markup=False, highlight=False)

    # ---- write phase (keys.env BEFORE config — a crash can only leave keys
    #      without a config, which the next wizard run heals) ---------------------------
    if answers.key_inline and answers.key_env:
        written_keys = write_keys_env({answers.key_env: answers.key_inline}, env=env, home=home)
        console.print("[green]wrote[/green]", written_keys)
        print_key_saved(console, answers.key_env)
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
