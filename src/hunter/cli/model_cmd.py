"""``hunter model`` — the Polished model picker (M11 M4).

One command to point every tier at a brain: a numbered provider menu
(configured providers first, then known table rows), the advisory endpoint
probe + model list for any base URL, single-model auto-detect, and a direct
``--set`` form for scripts. Writes flow through
:func:`hunter.llm.writing.write_config` (deep-merge, atomic); the env-only
path is documented in ``--help``: ``HUNTEROS_MODEL`` overrides the model at
USE time without any config change.

No prompts when ``--set`` is given (scriptable); every other prompt rides the
injectable ``ask`` seam; the probe is advisory and offline-safe (a failed
probe still saves the pick).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from rich.console import Console

from hunter.errors import HunterError
from hunter.llm.base import TIERS
from hunter.llm.config import load_config
from hunter.llm.providers import CUSTOM_NAME, KnownProvider, known_provider, known_provider_names
from hunter.llm.writing import resolve_config_target, write_config
from hunter.palette import make_console

__all__ = ["run_model_picker"]

console = make_console()
err_console = make_console(stderr=True)

_MODEL_SET_LINE = "✅ model set: {model} → tiers {tiers}{provider}"


def _menu_rows(
    env: Mapping[str, str], home: Path | None
) -> list[tuple[str, str, KnownProvider | None]]:
    """(name, base_url, known) rows: configured providers first (table order),
    then known rows not yet configured, then ``custom``."""
    rows: list[tuple[str, str, KnownProvider | None]] = []
    seen: set[str] = set()
    try:
        cfg = load_config(env=dict(env), home=home)
    except HunterError:
        cfg = None
    configured = cfg.providers if cfg is not None else {}
    for name, block in configured.items():
        known = known_provider(name)
        rows.append((name, block.base_url or (known.base_url if known else ""), known))
        seen.add(name)
    for entry in known_provider_names():
        if entry not in seen:
            known = known_provider(entry)
            rows.append((entry, known.base_url if known else "", known))
            seen.add(entry)
    if CUSTOM_NAME not in seen:
        rows.append((CUSTOM_NAME, "", None))
    return rows


def run_model_picker(
    *,
    console: Console | None = None,
    err_console: Console | None = None,
    ask: Callable[[str, str], str] | None = None,
    secret: Callable[[str], str] | None = None,
    set_model: str | None = None,
    provider: str | None = None,
    tier: str | None = None,
    list_models_fn: Callable[..., list[str]] | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> int:
    """The ``hunter model`` core. ``--set`` (``set_model``) writes directly
    (no prompts); otherwise a numbered provider menu → advisory probe → model
    pick → all four tiers pinned. Returns the process exit code."""
    from hunter.cli.init_wizard import _default_ask
    from hunter.cli.wizard_steps import pick_model, probe_endpoint_and_models

    console = console if console is not None else Console()
    err = err_console if err_console is not None else Console(stderr=True)
    ask = ask if ask is not None else _default_ask(console)
    if list_models_fn is None:
        from hunter.llm.probe import list_models

        list_models_fn = list_models
    env = dict(os.environ) if environ is None else dict(environ)

    tiers = [tier] if tier else list(TIERS)
    if tier is not None and tier not in TIERS:
        err.print(
            f"[hunter.error]unknown tier:[/hunter.error] '{tier}' — valid tiers: {', '.join(TIERS)}"
        )
        return 2

    if set_model is not None:
        # Direct write — never prompts (scriptable).
        name = (provider or "").strip().lower()
        if not name or (known_provider(name) is None and name != CUSTOM_NAME):
            err.print(
                f"[hunter.error]unknown provider:[/hunter.error] '{provider}' — pick one of: "
                f"{', '.join(known_provider_names())}"
            )
            return 2
        updates: dict[str, Any] = {
            "model_tiers": {t: {"provider": name, "model": set_model} for t in tiers}
        }
        written = write_config(updates, resolve_config_target(env=env, home=home),
                               env=env, home=home)
        _print_model_set(console, set_model, tiers, name)
        console.print(f"[dim]written: {written}[/dim]", markup=False, highlight=False)
        return 0

    # ---- interactive: numbered provider menu (configured first) --------------
    rows = _menu_rows(env, home)
    labels = [name for name, _url, _known in rows]
    console.print("providers:", markup=False, highlight=False)
    for index, (name, url, known) in enumerate(rows, start=1):
        note = known.note if known is not None else "any OpenAI-compatible base URL"
        suffix = f" ({url})" if url else ""
        console.print(f"  {index}. {name:12} — {note}{suffix}", markup=False, highlight=False)
    reply = ask("provider [1]", "1").strip()
    name = ""
    if reply.isdigit() and 1 <= int(reply) <= len(rows):
        name, base_url, known = rows[int(reply) - 1]
    elif reply in labels:
        index = labels.index(reply)
        name, base_url, known = rows[index]
    else:
        err.print(
            f"[hunter.error]unknown provider:[/hunter.error] {reply!r} — pick one of: "
            f"{', '.join(known_provider_names())}"
        )
        return 2
    if name == CUSTOM_NAME and not base_url:
        base_url = ask(
            "base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)", ""
        ).strip()
        if not base_url:
            console.print("[dim]custom provider skipped — no base URL given[/dim]",
                          markup=False, highlight=False)
            return 0
    if name == CUSTOM_NAME:
        known = None

    # ---- advisory probe + model pick ------------------------------------------
    model = ""
    if base_url:
        key_env = known.key_env if known is not None else ""
        key_value = (env.get(key_env) or "").strip()
        notes: list[str] = []
        _endpoint, models = probe_endpoint_and_models(
            base_url=base_url, key_value=key_value, probe_fn=_default_probe,
            list_models_fn=list_models_fn, console=console, notes=notes,
        )
        model = pick_model(models=models, known=known, ask=ask, console=console, notes=notes)
    else:
        notes = []
        model = pick_model(models=[], known=known, ask=ask, console=console, notes=notes)
    if not model:
        console.print("[dim]no model given — nothing was changed[/dim]",
                      markup=False, highlight=False)
        return 0

    updates = {"model_tiers": {t: {"provider": name, "model": model} for t in tiers}}
    write_config(updates, resolve_config_target(env=env, home=home), env=env, home=home)
    _print_model_set(console, model, tiers, name)
    return 0


def _default_probe(base_url: str, key_value: str, timeout: int) -> str:
    """The advisory endpoint probe — never fatal here (probe_endpoint_and_models
    catches); returns the detected shape or ""."""
    from hunter.llm.probe import detect_endpoint

    return detect_endpoint(base_url, key_value, timeout)


def _print_model_set(console: Console, model: str, tiers: list[str], name: str) -> None:
    tiers_text = ", ".join(tiers)
    provider_text = f", provider {name}" if name else ""
    console.print(
        _MODEL_SET_LINE.format(model=model, tiers=tiers_text, provider=provider_text),
        markup=False,
        highlight=False,
    )
