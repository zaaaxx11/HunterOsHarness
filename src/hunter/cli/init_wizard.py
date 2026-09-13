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
from rich.panel import Panel
from rich.text import Text

from hunter.errors import HunterError
from hunter.llm.config import find_config_path
from hunter.llm.keys import keys_env_path, write_keys_env
from hunter.llm.ping import ping_provider
from hunter.llm.providers import CUSTOM_NAME, known_provider, known_provider_names
from hunter.llm.writing import render_config, resolve_config_target, write_config

__all__ = [
    "InitAnswers", "build_config_yaml", "config_updates", "run_init",
    "OnboardingAnswers", "onboarding_updates", "run_onboarding",
    "config_missing", "offer_onboarding", "DECLINED_ENV",
]

# The one-line scope authorization reminder — the LAST line of every
# `hunter init` v2 terminal path (and of both installers' final printout).
SCOPE_DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."

# Process-local decline flag for the auto-triggered onboarding offer (§5):
# set on decline/EOF so a chat REPL (or scripted run) is never asked twice
# in one session; never persisted, so a NEW process may offer again.
DECLINED_ENV = "HUNTEROS_ONBOARD_DECLINED"


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
        orchestrator: dict[str, Any] = {
            "provider": answers.provider or "auto",
            "model": answers.model,
        }
        updates["model_tiers"] = {"orchestrator": orchestrator}
        if answers.verify_model:
            updates["model_tiers"]["verifier"] = {"model": answers.verify_model}
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
            answers.model = ask("orchestrator model", known.default_model)
            answers.verify_model = ask("verifier model (cheap sibling)", known.cheap_model)
        console.print(
            f"step 5/6 model: orchestrator={answers.model} "
            f"verifier={answers.verify_model or '(inherits)'}",
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


# ----------------------------------------------------------------- wizard v2 --


@dataclass
class OnboardingAnswers:
    """What one v2 onboarding run decided. ``notes`` collects every
    skipped/failed step — they print in the final summary, they never abort.
    The pasted key (``key_inline``) goes to keys.env, NEVER into config.yaml,
    and is never echoed."""

    mode: str = "auto"                 # "auto" | "advanced"
    tier: str = "basic"                # always written; v2 does NOT prompt tier
    provider: str = ""
    base_url: str = ""
    endpoint: str = ""                 # "chat" | "responses" | "" (empty = store nothing)
    key_env: str = ""
    key_inline: str = ""               # goes to keys.env, never in the config
    browser: bool = False
    role_models: dict[str, str] = field(default_factory=dict)  # tier -> model
    notes: list[str] = field(default_factory=list)


def onboarding_updates(a: OnboardingAnswers) -> dict[str, Any]:
    """Pure. The write_config fragment for v2. ``write_config`` deep-merges,
    so re-running the wizard upgrades all four tiers and preserves unrelated
    keys (budget, fallbacks). The pasted key is NEVER in this fragment:
    ``api_key`` stays reserved for explicit
    ``hunter config provider add --api-key-stdin`` flows."""
    updates: dict[str, Any] = {"agent": {"tier": a.tier, "browser": a.browser}}
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


def _print_disclaimer(console: Console) -> None:
    # markup=False on purpose: the line is verbatim copy, never style input.
    console.print(SCOPE_DISCLAIMER, markup=False, highlight=False)


def _print_tools_row(console: Console, mark: str, label: str, detail: str) -> None:
    console.print(f"  {mark}  {label} {detail}".rstrip(), markup=False, highlight=False)


def run_onboarding(
    *,
    path: str | Path | None = None,
    console: Console | None = None,
    err_console: Console | None = None,
    ask: Callable[[str, str], str] | None = None,
    secret: Callable[[str], str] | None = None,
    ping_fn: Callable[..., Any] | None = None,
    probe_fn: Callable[..., str] | None = None,
    list_models_fn: Callable[..., list[str]] | None = None,
    checks_fn: Callable[[], list] | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> int:
    """v2 wizard. Returns 0 on every normal terminal path (failures are
    notes); lets HunterError from the writes propagate (handle.py renders it).
    EOF falls back to every prompt's default — a fully non-interactive run
    writes a valid config and exits 0 with notes, never a key it did not
    receive."""
    console = console if console is not None else Console()
    ask = ask if ask is not None else _default_ask(console)
    secret = secret if secret is not None else _default_secret()
    ping_fn = ping_fn if ping_fn is not None else ping_provider
    if probe_fn is None or list_models_fn is None:
        from hunter.llm.probe import detect_endpoint, list_models

        probe_fn = probe_fn if probe_fn is not None else detect_endpoint
        list_models_fn = list_models_fn if list_models_fn is not None else list_models
    if checks_fn is None:
        from hunter.cli.doctor_core import collect_checks

        checks_fn = collect_checks
    env = dict(os.environ) if environ is None else dict(environ)
    keys_path = keys_env_path(env=env, home=home)

    # ---- clobber guard (v1 behavior: decline keeps the file, exit 0) --------
    target = resolve_config_target(path, env=env, home=home)
    if target.exists():
        reply = ask(f"config already exists at {target} — overwrite it", "n")
        if reply.lower() not in ("y", "yes"):
            console.print(
                f"kept {target} — pass --path <file> to write elsewhere",
                markup=False,
                highlight=False,
            )
            _print_disclaimer(console)
            return 0

    console.print("[bold]hunter init[/bold] — onboarding wizard")
    console.print(f"config target: {target}", markup=False, highlight=False)
    console.print(
        f"About 60 seconds. Writes {target} (+ keys.env only if you paste a key).",
        markup=False,
        highlight=False,
    )
    console.print("Your key is sent nowhere except the provider you pick.",
                  markup=False, highlight=False)
    answers = OnboardingAnswers()
    notes = answers.notes

    # ---- step 1/7: role mode ---------------------------------------------------
    console.print("How should models be assigned?")
    console.print("  1. Auto — one model for every role (fastest setup)")
    console.print("  2. Advanced — pick a model per role (orchestrator / hunter / verifier / utility)")
    reply = ask("mode", "1")
    if reply.strip().lower() in ("2", "advanced"):
        answers.mode = "advanced"
    console.print(f"step 1/7 mode: {answers.mode}", markup=False, highlight=False)

    # ---- step 2/7: provider (v1 menu: table order, custom last) ------------------
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
    known = None
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
            name = ""
    if name and known is not None and known.base_url:
        base_url = base_url or known.base_url
    answers.provider = name
    answers.base_url = base_url
    if name:
        console.print(f"step 2/7 provider: {name}" + (f" ({base_url})" if base_url else ""),
                      markup=False, highlight=False)
    else:
        console.print("step 2/7 provider: (skipped — no provider configured)",
                      markup=False, highlight=False)

    # ---- step 3/7: key -------------------------------------------------------------
    key_env = ""
    key_inline = ""
    if not name:
        console.print("step 3/7 key: (skipped — no provider configured)",
                      markup=False, highlight=False)
    else:
        table_key_env = known.key_env if known is not None else ""
        if known is not None and not table_key_env:
            console.print("step 3/7 key: none needed — this provider is keyless",
                          markup=False, highlight=False)
        else:
            default_key_env = table_key_env or "CUSTOM_API_KEY"
            if env.get(default_key_env, "").strip():
                key_env = default_key_env
                console.print(
                    f"step 3/7 key: using ${key_env} from the environment — "
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

    # ---- step 4/7: endpoint probe (custom only) + models ------------------------------
    key_value = env.get(key_env, "").strip() or key_inline
    if name == CUSTOM_NAME and base_url:
        console.print(f"probing {base_url} for the API shape...", markup=False, highlight=False)
        endpoint = ""
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

    orchestrator_model = ""
    if not name:
        console.print("step 4/7 model: (skipped — no provider configured)",
                      markup=False, highlight=False)
    elif name == CUSTOM_NAME:
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
                orchestrator_model = models[int(reply) - 1]
            else:
                orchestrator_model = ask("model id", models[0]).strip() or models[0]
        else:
            notes.append("model list failed — enter it manually")
            orchestrator_model = ask("model id", "").strip()
    elif known is not None:
        # name comes from the pick-list (custom handled above), so `known`
        # is always the table row here.
        orchestrator_model = ask("orchestrator model", known.default_model).strip() or known.default_model
    if orchestrator_model:
        if answers.mode == "advanced":
            hunter_model = ask("hunter model", orchestrator_model).strip() or orchestrator_model
            cheap = (known.cheap_model if known is not None else "") or orchestrator_model
            verifier_model = ask("verifier model", cheap).strip() or cheap
            utility_model = ask("utility model", cheap).strip() or cheap
        else:
            hunter_model = verifier_model = utility_model = orchestrator_model
        answers.role_models = {
            "orchestrator": orchestrator_model,
            "hunter": hunter_model,
            "verifier": verifier_model,
            "utility": utility_model,
        }
        console.print(f"step 4/7 model: orchestrator={orchestrator_model}",
                      markup=False, highlight=False)

    # ---- step 5/7: web automation (inert in M1 — the [browser] extra lands in M6) -----
    reply = ask("Enable web automation (browser-driven hunting)? [y/N]", "")
    if reply.strip().lower() in ("y", "yes"):
        answers.browser = True
        notes.append(
            "browser automation (the [browser] extra) ships in a later release — "
            "'agent.browser: true' is stored now; nothing else changes yet"
        )
    console.print(f"step 5/7 browser: {'on' if answers.browser else 'off'}",
                  markup=False, highlight=False)

    # ---- step 6/7: tools check (same rows as `hunter doctor`; never aborts) ------------
    console.print("step 6/7 tools:", markup=False, highlight=False)
    try:
        checks = checks_fn()
    except Exception as exc:  # noqa: BLE001 — the tools check never aborts the wizard
        note = f"tools check failed: {type(exc).__name__}: {exc}"
        notes.append(note)
        console.print(f"  NOTE: {note}", markup=False, highlight=False)
    else:
        marks = {"ok": "OK", "fail": "FAIL", "note": "NOTE"}
        for check in checks:
            status = getattr(check, "status", "")
            label = getattr(check, "label", "?")
            detail = getattr(check, "detail", "")
            _print_tools_row(console, marks.get(status, "NOTE"), label, detail)
            if status == "fail":
                notes.append(f"tools check: {label} — {detail}")

    # ---- write phase (keys.env BEFORE config — a crash can only leave keys
    #      without a config, which the next wizard run heals) ---------------------------
    if answers.key_inline and answers.key_env:
        written_keys = write_keys_env({answers.key_env: answers.key_inline}, env=env, home=home)
        console.print("[green]wrote[/green]", written_keys)
    written = write_config(onboarding_updates(answers), target, env=env, home=home)
    console.print("[green]wrote[/green]", written)

    # ---- step 7/7: smoke test ------------------------------------------------------------
    model = answers.role_models.get("orchestrator", "")
    if not model:
        notes.append("smoke test skipped — no model configured")
    elif key_env and not key_value:
        console.print(f"step 7/7 smoke test: skipped — {key_env} is not set",
                      markup=False, highlight=False)
        notes.append(f"smoke test skipped — {key_env} is not set")
    else:
        console.print(
            f"step 7/7 smoke test: dialing {answers.provider}/{model} with a 1-token ping...",
            markup=False,
            highlight=False,
        )
        try:
            result = ping_fn(answers.provider, model, answers.base_url, key_value, 15)
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

    # ---- done panel + notes + disclaimer (the disclaimer is ALWAYS last) -----------------
    if answers.key_inline:
        keys_line = f"{keys_path} ({answers.key_env})"
    elif answers.key_env:
        keys_line = f"${answers.key_env}"
    else:
        keys_line = "keyless"
    brain_line = "none"
    if answers.provider and model:
        brain_line = f"{answers.provider} / {model}"
        if answers.endpoint:
            brain_line += f" (endpoint: {answers.endpoint})"
    body = Text(
        "\n".join(
            [
                f"config:  {target}",
                f"keys:    {keys_line}",
                f"brain:   {brain_line}",
                "tier:    basic",
                f"browser: {'on' if answers.browser else 'off'}",
                "next:",
                "  hunter chat        — talk to your brain",
                "  hunter demo        — first blood, no keys needed",
                "  hunter doctor      — verify the environment",
            ]
        )
    )
    console.print(Panel(body, title="done", subtitle="Evidence or Nothing"))
    if notes:
        console.print("notes:", markup=False, highlight=False)
        for note in notes:
            console.print(f"  - {note}", markup=False, highlight=False)
    _print_disclaimer(console)
    return 0


# --------------------------------------------------------------- auto-trigger --


def config_missing(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> bool:
    """True when load_config would find no config file anywhere:
    find_config_path(...) is None or the resolved path does not exist."""
    env = os.environ if env is None else env
    resolved = find_config_path(None, env=env, home=home)
    return resolved is None or not resolved.is_file()


def _offer_ask(console: Console) -> Callable[[str, str], str]:
    """The offer's ask. EOF (piped stdin, scripted runs) means DECLINE — an
    absent user must not have a wizard launched over their head."""

    def ask(prompt: str, default: str = "") -> str:
        try:
            return console.input(f"{prompt}: ", markup=False).strip()
        except EOFError:
            return "n"

    return ask


def offer_onboarding(
    *,
    console: Console | None = None,
    err_console: Console | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    ask: Callable[[str, str], str] | None = None,
    run: Callable[..., int] | None = None,
) -> bool:
    """Offer the wizard when no config exists. Returns True iff it ran.
    A decline (or EOF) sets $HUNTEROS_ONBOARD_DECLINED for THIS process only —
    the chat REPL asks at most once per session; the flag is never persisted,
    so a new `hunter` invocation may offer again by design."""
    console = console if console is not None else Console()
    err = err_console if err_console is not None else Console(stderr=True)
    env_map = os.environ if env is None else env
    if env_map.get(DECLINED_ENV):
        return False
    if not config_missing(env=env_map, home=home):
        return False
    ask_fn = ask if ask is not None else _offer_ask(console)
    try:
        reply = ask_fn("no brain configured yet — run the setup wizard now? [Y/n]", "y")
    except Exception:  # noqa: BLE001 — a broken prompt must not break the command
        reply = "n"
    if reply.strip().lower() in ("n", "no"):
        console.print(
            "skipped — run 'hunter init' anytime; you won't be asked again this session",
            markup=False,
            highlight=False,
        )
        os.environ[DECLINED_ENV] = "1"
        return False
    wizard = run if run is not None else run_onboarding
    wizard(console=console, err_console=err, home=home)
    return True
