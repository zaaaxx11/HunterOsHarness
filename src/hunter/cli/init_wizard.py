"""``hunter init`` — the first-run wizard (pure core + injectable prompts).

Every prompt goes through the injectable ``ask`` / ``secret`` callables so
tests drive the wizard without a tty, and every failure is a STEP NOTE in the
final summary — a bad key or a dead endpoint must never crash an init.
:func:`build_config_yaml` is the pure builder (deterministic, test-visible);
:func:`run_init` orchestrates prompts, the live ping, and the write through
:mod:`hunter.llm.writing`.
"""

from __future__ import annotations

import importlib.util
import os
import platform
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from hunter.errors import HunterError
from hunter.llm.ping import ping_provider
from hunter.llm.providers import CUSTOM_NAME, known_provider, known_provider_names
from hunter.llm.writing import render_config, resolve_config_target, write_config

__all__ = ["InitAnswers", "build_config_yaml", "config_updates", "run_init"]


@dataclass
class InitAnswers:
    """What one init run decided. ``notes`` collects every skipped/failed
    step — they print in the final summary, they never abort."""

    tier: str = "basic"
    provider: str = ""
    base_url: str = ""
    key_env: str = ""
    api_key_inline: str = ""
    model: str = ""
    verify_model: str = ""
    notes: list[str] = field(default_factory=list)


def config_updates(answers: InitAnswers) -> dict[str, Any]:
    """The config-file fragment this init writes (merged, never clobbered)."""
    updates: dict[str, Any] = {"agent": {"tier": answers.tier}}
    if answers.model:
        planner: dict[str, Any] = {
            "provider": answers.provider or "auto",
            "model": answers.model,
        }
        updates["model_tiers"] = {"planner": planner}
        if answers.verify_model:
            updates["model_tiers"]["verify"] = {"model": answers.verify_model}
    if answers.provider:
        block: dict[str, Any] = {}
        if answers.key_env:
            block["key_env"] = answers.key_env
        if answers.api_key_inline:
            block["api_key"] = answers.api_key_inline
        if answers.base_url:
            block["base_url"] = answers.base_url
        updates["providers"] = {answers.provider: block}
    return updates


def build_config_yaml(answers: InitAnswers) -> str:
    """Pure: the full canonical config text for ``answers`` (no file I/O)."""
    return render_config(config_updates(answers))


# ------------------------------------------------------------------ prompts --


def _default_ask(console: Console) -> Callable[[str, str], str]:
    def ask(prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            reply = console.input(f"{prompt}{suffix}: ")
        except EOFError:
            return default
        return reply.strip() or default

    return ask


def _default_secret() -> Callable[[str], str]:
    def secret(prompt: str) -> str:
        import getpass

        try:
            return getpass.getpass(f"{prompt}: ")
        except Exception:  # noqa: BLE001 — no tty / interrupted: skip the paste
            return ""

    return secret


def _print_export_lines(console: Console, key_env: str) -> None:
    # markup=False on purpose: '[Environment]' must not be read as a rich tag.
    console.print(f"  set {key_env} in a NEW shell (the key itself is never printed here):",
                  markup=False, highlight=False)
    console.print(
        f"  PowerShell: [Environment]::SetEnvironmentVariable('{key_env}','<key>','User')",
        markup=False,
        highlight=False,
    )
    console.print(f"  bash:       echo 'export {key_env}=<key>' >> ~/.bashrc",
                  markup=False, highlight=False)


# --------------------------------------------------------------------- flow --


def run_init(
    *,
    path: str | Path | None = None,
    provider: str | None = None,
    yes: bool = False,
    console: Console | None = None,
    err_console: Console | None = None,
    ask: Callable[[str, str], str] | None = None,
    secret: Callable[[str], str] | None = None,
    ping_fn: Callable[..., Any] | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> int:
    """Run the wizard; return the process exit code (0 normal, 2 usage)."""
    console = console if console is not None else Console()
    err = err_console if err_console is not None else Console(stderr=True)
    ask = ask if ask is not None else _default_ask(console)
    secret = secret if secret is not None else _default_secret()
    ping_fn = ping_fn if ping_fn is not None else ping_provider
    env = dict(os.environ) if environ is None else dict(environ)

    # ---- clobber guard ----------------------------------------------------
    target = resolve_config_target(path, env=env, home=home)
    if target.exists():
        if yes:
            err.print("[red]refusing to overwrite the existing config:[/red]", target)
            err.print("pass --path <file> to write elsewhere")
            return 2
        reply = ask(f"config already exists at {target} — overwrite it", "n")
        if reply.lower() not in ("y", "yes"):
            console.print(f"kept {target} — pass --path <file> to write elsewhere")
            return 0

    console.print("[bold]hunter init[/bold] — first-run wizard")
    console.print(f"config target: {target}", markup=False, highlight=False)
    answers = InitAnswers()
    notes = answers.notes

    # ---- step 1: environment ----------------------------------------------
    litellm_ok = importlib.util.find_spec("litellm") is not None
    console.print(f"step 1/6 environment: Python {platform.python_version()}")
    basic_only = False
    if litellm_ok:
        console.print("  litellm installed — the LLM brain is available")
    else:
        note = "litellm is not installed — LLM features need: pip install 'hunteros-harness[llm]'"
        notes.append(note)
        console.print(f"  NOTE: {note}")
        if provider is not None:
            # The operator asked for THIS provider explicitly — configure it
            # anyway (the live ping below degrades to a note, and installing
            # the [llm] extra later completes the setup).
            console.print("  continuing — provider setup was requested explicitly")
        elif not yes:
            reply = ask("continue in basic-only mode (deterministic core, no LLM)", "y")
            if reply.lower() in ("n", "no"):
                console.print("install the [llm] extra, then re-run `hunter init`")
                return 0
        basic_only = provider is None

    # ---- step 2: tier --------------------------------------------------------
    if basic_only:
        answers.tier = "basic"
        console.print("step 2/6 tier: basic (basic-only mode)")
    elif yes:
        answers.tier = "basic"
        console.print("step 2/6 tier: basic (default — `agent.tier` in the config file)")
    else:
        reply = ask(
            "tier — basic | advanced (advanced lets audits run active probes in scope)", "basic"
        )
        answers.tier = reply if reply in ("basic", "advanced") else "basic"
        console.print(f"step 2/6 tier: {answers.tier}", markup=False, highlight=False)

    # ---- step 3: provider -----------------------------------------------------
    name = ""
    base_url = ""
    known = None
    if not basic_only:
        if provider is not None:
            name = provider.strip().lower()
            known = known_provider(name)
            if name == CUSTOM_NAME:
                err.print(
                    "a custom provider needs a base URL — use "
                    "`hunter config provider add <name> --base-url <url>` instead"
                )
                return 2
            if known is None:
                err.print(
                    f"unknown provider '{name}' — known providers: "
                    f"{', '.join(known_provider_names())}"
                )
                return 2
        elif not yes:
            names = known_provider_names()
            console.print("providers:")
            for index, entry in enumerate(names, start=1):
                if entry == CUSTOM_NAME:
                    console.print(f"  {index}. {entry:12} — any OpenAI-compatible base URL")
                else:
                    row = known_provider(entry)
                    console.print(f"  {index}. {entry:12} — {row.note if row else ''}")
            reply = ask("provider [1]", "1")
            if reply.isdigit() and 1 <= int(reply) <= len(names):
                name = names[int(reply) - 1]
            elif reply in names:
                name = reply
            else:
                name = names[0]
                notes.append(f"provider pick {reply!r} not recognized — using {name}")
            known = known_provider(name) if name != CUSTOM_NAME else None
            if name == CUSTOM_NAME:
                base_url = ask("base URL (OpenAI-compatible, e.g. https://llm.corp.example.com/v1)", "")
                if not base_url:
                    notes.append("custom provider skipped — no base URL given")
                    name = ""
        else:
            name = ""
        if name and known is not None and known.base_url:
            base_url = base_url or known.base_url
        if name:
            console.print(f"step 3/6 provider: {name}" + (f" ({base_url})" if base_url else ""),
                        markup=False, highlight=False)

    # ---- step 4: key ------------------------------------------------------------
    key_env = ""
    api_key_inline = ""
    if name:
        table_key_env = known.key_env if known is not None else ""
        if table_key_env == "" and known is not None:
            console.print("step 4/6 key: none needed — this provider is keyless")
        else:
            default_key_env = table_key_env or ""
            if yes:
                key_env = default_key_env
            else:
                key_env = ask("API key env var name (blank = keyless provider)", default_key_env)
            if key_env:
                console.print(f"step 4/6 key: {key_env}", markup=False, highlight=False)
                if env.get(key_env, "").strip():
                    console.print("  key found in the environment — it is never stored on disk")
                else:
                    _print_export_lines(console, key_env)
                    if not yes:
                        pasted = secret(
                            f"paste the {key_env} key to store it inline instead (blank = skip)"
                        ).strip()
                        if pasted:
                            api_key_inline = pasted
                            notes.append(
                                "inline api_key written to the config file — the env var is preferred"
                            )
                    else:
                        notes.append(f"{key_env} is not set — set it before first use")

    # ---- step 5: models -----------------------------------------------------------
    if name and known is not None and known.default_model:
        answers.model = known.default_model
        answers.verify_model = known.cheap_model
        if not yes:
            answers.model = ask("planner model", known.default_model)
            answers.verify_model = ask("verify model (cheap sibling)", known.cheap_model)
        console.print(
            f"step 5/6 model: planner={answers.model} verify={answers.verify_model or '(inherits)'}",
            markup=False,
            highlight=False,
        )
    else:
        console.print("step 5/6 model: (none — basic-only or unconfigured provider)")

    # ---- step 6: live test -----------------------------------------------------------
    answers.provider = name
    answers.base_url = base_url
    answers.key_env = key_env
    answers.api_key_inline = api_key_inline
    if not answers.model:
        notes.append("live test skipped — no model configured")
    elif key_env and not env.get(key_env, "").strip() and not api_key_inline:
        console.print("step 6/6 live test: skipped — no key yet")
        notes.append(f"live test skipped — {key_env} is not set")
    else:
        console.print("step 6/6 live test: dialing with a 1-token ping...")
        try:
            result = ping_fn(
                name,
                answers.model,
                base_url,
                env.get(key_env, "") or api_key_inline,
                15,
            )
        except HunterError as exc:
            notes.append(f"live test unavailable: {exc.user_message().splitlines()[0]}")
        except Exception as exc:  # noqa: BLE001 — a failed probe is a note, not a crash
            notes.append(f"live test failed: {type(exc).__name__}: {exc}")
        else:
            if result.ok:
                console.print(f"  live test: [green]{result.message}[/green]")
            else:
                flat = result.message.replace("\n", " / ")
                console.print(f"  live test: {flat}")
                notes.append(f"live test failed: {flat}")

    # ---- write ---------------------------------------------------------------
    try:
        written = write_config(config_updates(answers), target, env=env, home=home)
    except HunterError:
        raise
    console.print("[green]wrote[/green]", written)
    if notes:
        console.print("notes:")
        for note in notes:
            console.print(f"  - {note}")
    console.print("next: hunter doctor · hunter demo · hunter chat")
    return 0
