"""``hunter init`` — the ONE setup wizard (init 3.0, M11).

:func:`run_init_wizard` is the single flow behind every ``hunter init`` shape
(interactive, ``--provider X --yes``, and the bare-``hunter`` offer): a mode
picker (Quick / Advanced / Blank Slate), existing values as keep-defaults, a
timestamped pre-write backup, buffered writes (keys.env BEFORE config) so a
Ctrl+C before the write truly changed nothing, and ``SCOPE_DISCLAIMER`` as the
LAST line of every terminal path — cancels included.

Doctrine (m11-hermes-ux §7):

- every prompt goes through the injectable ``ask`` / ``secret`` callables;
  EOF falls back to the prompt's default — a piped wizard still completes;
- unrecognized menu input RE-ASKS (no silent fallback to the first row);
- the shared steps live in :mod:`hunter.cli.wizard_steps` so init and
  provider-add cannot drift;
- a pasted key goes to keys.env, NEVER into config.yaml, and is never echoed;
- a failed probe/ping is a NOTE in the final summary — it never aborts;
- ``run_onboarding`` / ``run_init`` are thin deprecated wrappers delegating
  here (one release of import stability, then removable).
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from hunter.errors import HunterError
from hunter.llm.config import find_config_path
from hunter.llm.keys import atomic_write_text, keys_env_path, write_keys_env
from hunter.llm.ping import ping_provider
from hunter.llm.providers import CUSTOM_NAME, known_provider, known_provider_names
from hunter.llm.writing import render_config, resolve_config_target, write_config

__all__ = [
    "DECLINED_ENV",
    "SCOPE_DISCLAIMER",
    "OnboardingAnswers",
    "config_missing",
    "offer_onboarding",
    "onboarding_updates",
    "run_init",
    "run_init_wizard",
    "run_onboarding",
]

# The one-line scope authorization reminder — the LAST line of every
# `hunter init` terminal path (and of both installers' final printout).
SCOPE_DISCLAIMER = "Scan only systems you own or are explicitly authorized to test."

# Process-local decline flag for the auto-triggered onboarding offer (§5):
# set on decline/EOF so a chat REPL (or scripted run) is never asked twice
# in one session; never persisted, so a NEW process may offer again.
DECLINED_ENV = "HUNTEROS_ONBOARD_DECLINED"

KEEP_DEFAULTS_LINE = (
    "Existing values are shown in brackets — Press Enter to keep it, "
    "or type a new value to change it."
)
BROWSER_NOTE_HONEST = (
    "agent.browser is stored; it activates with the optional extra — "
    "pip install 'hunteros-harness[browser]'"
)
REMAINING_SECTIONS_LINE = "Remaining sections were not changed."

MODE_PICKER_LINES = (
    "How should I set HunterOS up?",
    "  1. Quick (recommended) — pick a provider, paste a key, done (~1 minute)",
    "  2. Advanced — choose a model for every role (orchestrator / hunter / verifier / utility)",
    "  3. Blank Slate — write a commented default config; add a provider later",
)


@dataclass
class OnboardingAnswers:
    """What one wizard run decided. ``notes`` collects every skipped/failed
    step — they print in the final summary, they never abort. The pasted key
    (``key_inline``) goes to keys.env, NEVER into config.yaml, and is never
    echoed."""

    mode: str = "quick"                # "quick" | "advanced"
    tier: str = "basic"                # always written; the wizard does NOT prompt tier
    provider: str = ""
    base_url: str = ""
    endpoint: str = ""                 # "chat" | "responses" | "" (empty = store nothing)
    key_env: str = ""
    key_inline: str = ""               # goes to keys.env, never in the config
    browser: bool = False
    role_models: dict[str, str] = field(default_factory=dict)  # tier -> model
    notes: list[str] = field(default_factory=list)


def onboarding_updates(a: OnboardingAnswers) -> dict[str, Any]:
    """Pure. The write_config fragment for the wizard. ``write_config``
    deep-merges, so re-running the wizard upgrades all four tiers and
    preserves unrelated keys (budget, fallbacks). The pasted key is NEVER in
    this fragment: ``api_key`` stays reserved for explicit
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


def _print_disclaimer(console: Console) -> None:
    # markup=False on purpose: the line is verbatim copy, never style input.
    console.print(SCOPE_DISCLAIMER, markup=False, highlight=False)


def _backup_existing(target: Path) -> Path | None:
    """Timestamped pre-write backup (``{config}.bak-YYYYmmdd-HHMMSS``); the
    hospitality contract: nothing the user wrote is ever silently clobbered."""
    if not target.is_file():
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    bak = target.with_name(f"{target.name}.bak-{stamp}")
    bak.write_bytes(target.read_bytes())
    return bak


def _current_values(target: Path) -> tuple[str, str, str]:
    """The current orchestrator (provider, base_url, model) from the existing
    config — the keep-defaults the wizard offers. Unreadable files yield
    blanks (the loader will diagnose them elsewhere)."""
    try:
        loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return "", "", ""
    if not isinstance(loaded, dict):
        return "", "", ""
    tiers = loaded.get("model_tiers") or {}
    orch = tiers.get("orchestrator") if isinstance(tiers, dict) else None
    if not isinstance(orch, dict):
        orch = {}
    provider = str(orch.get("provider") or "")
    base_url = str(orch.get("base_url") or "")
    if not base_url:
        providers = loaded.get("providers") or {}
        block = providers.get(provider) if isinstance(providers, dict) else None
        if isinstance(block, dict):
            base_url = str(block.get("base_url") or "")
    return provider, base_url, str(orch.get("model") or "")


def _print_tools_check(console: Console, checks_fn: Callable[[], list], notes: list[str]) -> None:
    """The tools rows (same checks as `hunter doctor`) — never aborts."""
    console.print("tools:", markup=False, highlight=False)
    try:
        checks = checks_fn()
    except Exception as exc:  # noqa: BLE001 — the tools check never aborts the wizard
        note = f"tools check failed: {type(exc).__name__}: {exc}"
        notes.append(note)
        console.print(f"  NOTE: {note}", markup=False, highlight=False)
        return
    marks = {"ok": "OK", "fail": "FAIL", "note": "NOTE"}
    for check in checks:
        status = getattr(check, "status", "")
        label = getattr(check, "label", "?")
        detail = getattr(check, "detail", "")
        console.print(f"  {marks.get(status, 'NOTE')}  {label} {detail}".rstrip(),
                      markup=False, highlight=False)
        if status == "fail":
            notes.append(f"tools check: {label} — {detail}")


def _done_panel(console: Console, answers: OnboardingAnswers, target: Path, env: Mapping[str, str]) -> None:
    keys_line = "keyless"
    if answers.key_inline:
        keys_line = f"{keys_env_path(env=env)} ({answers.key_env})"
    elif answers.key_env:
        keys_line = f"${answers.key_env}"
    model = answers.role_models.get("orchestrator", "")
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
                "next: hunter doctor · hunter demo · hunter chat · hunter model",
            ]
        )
    )
    console.print(Panel(body, title="done", subtitle="Evidence or Nothing"))


# --------------------------------------------------------------------- flow --


def run_init_wizard(
    *,
    path: str | Path | None = None,
    provider: str | None = None,
    yes: bool = False,
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
    interactive: bool | None = None,
) -> int:
    """Run the ONE wizard; return the process exit code (0 normal, 2 usage,
    130 interrupted). ``interactive`` records the caller's TTY knowledge (the
    prompt seams fully determine interactivity for tests). Terminal paths:
    success, smoke-failure (notes), cancel (130), and EOF-defaults — the
    SCOPE_DISCLAIMER is the last line of each."""
    from hunter.cli.wizard_steps import (
        DEFAULT_PROVIDER,
        assign_roles,
        capture_key,
        pick_model,
        pick_provider,
        print_key_saved,
        probe_endpoint_and_models,
    )

    console = console if console is not None else Console()
    err = err_console if err_console is not None else Console(stderr=True)
    ask = ask if ask is not None else _default_ask(console)
    secret = secret if secret is not None else _default_secret()
    ping_fn = ping_fn if ping_fn is not None else ping_provider
    if probe_fn is None or list_models_fn is None:
        from hunter.llm.probe import detect_endpoint, list_models

        probe_fn = probe_fn if probe_fn is not None else detect_endpoint
        list_models_fn = list_models_fn if list_models_fn is not None else list_models
    if interactive is None:
        with_open_stream = hasattr(sys.stdin, "isatty")
        interactive = with_open_stream and sys.stdin.isatty()
    env = dict(os.environ) if environ is None else dict(environ)

    target = resolve_config_target(path, env=env, home=home)
    answers = OnboardingAnswers()
    notes = answers.notes
    wrote_config = False

    try:
        # ---- keep-defaults context: backup + current values ----------------
        bak = _backup_existing(target)
        if bak is not None:
            console.print(f"Previous config backed up to: {bak}", markup=False, highlight=False)
        current_provider, current_base_url, current_model = _current_values(target)

        console.print("[bold]hunter init[/bold] — setup wizard")
        console.print(f"config target: {target}", markup=False, highlight=False)
        console.print(
            f"About 60 seconds. Writes {target} (+ keys.env only if you paste a key).",
            markup=False,
            highlight=False,
        )
        console.print("Your key is sent nowhere except the provider you pick.",
                      markup=False, highlight=False)

        # ---- step 0: mode picker (skipped for --yes / --provider) ----------
        blank_slate = False
        if provider is None and not yes:
            for line in MODE_PICKER_LINES:
                console.print(line, markup=False, highlight=False)
            reply = ask("mode", "1").strip().lower()
            if reply in ("2", "advanced"):
                answers.mode = "advanced"
            elif reply in ("3", "blank", "blank slate"):
                blank_slate = True
            console.print(f"mode: {answers.mode if not blank_slate else 'blank'}",
                          markup=False, highlight=False)
            if blank_slate:
                # Blank Slate: the backup (taken above) is the safety net; the
                # canonical commented default REPLACES the file. Zero prompts.
                atomic_write_text(target, render_config({}))
                wrote_config = True
                console.print("[green]wrote[/green]", target)
                _done_panel(console, answers, target, env)
                if notes:
                    console.print("notes:", markup=False, highlight=False)
                    for note in notes:
                        console.print(f"  - {note}", markup=False, highlight=False)
                _print_disclaimer(console)
                return 0
        if bak is not None and not yes:
            console.print(KEEP_DEFAULTS_LINE, markup=False, highlight=False)

        # ---- provider step ---------------------------------------------------
        name = ""
        base_url = ""
        known = None
        if provider is not None:
            name = provider.strip().lower()
            if name == CUSTOM_NAME:
                err.print(
                    "a custom provider needs a base URL — use "
                    "`hunter config provider add <name> --base-url <url>` instead"
                )
                return 2
            known = known_provider(name)
            if known is None:
                err.print(
                    f"unknown provider '{name}' — known providers: "
                    f"{', '.join(known_provider_names())}"
                )
                return 2
            base_url = known.base_url or ""
        elif not yes:
            from hunter.cli.wizard_steps import _env_detected_provider

            default_name = current_provider if current_provider in known_provider_names() else ""
            if not default_name:
                default_name = _env_detected_provider(env)
            if not default_name:
                default_name = DEFAULT_PROVIDER
            name, base_url, known = pick_provider(
                console=console, ask=ask, notes=notes,
                default_name=default_name, default_base_url=current_base_url,
            )
            if name == CUSTOM_NAME and not base_url:
                notes.append("custom provider skipped — no base URL given")
                name = ""
        answers.provider = name
        answers.base_url = base_url
        if name:
            console.print(f"provider: {name}" + (f" ({base_url})" if base_url else ""),
                          markup=False, highlight=False)
        else:
            console.print("provider: (skipped — no provider configured)",
                          markup=False, highlight=False)

        # ---- key step (the --yes path reads the env only — never invents) ----
        key_env = ""
        key_inline = ""
        key_value = ""
        if yes:
            key_env = known.key_env if known is not None else ""
            if key_env:
                key_value = (env.get(key_env) or "").strip()
                if key_value:
                    console.print(
                        f"key: using ${key_env} from the environment — nothing is stored on disk",
                        markup=False,
                        highlight=False,
                    )
                else:
                    notes.append(f"set ${key_env} before first use")
            else:
                console.print("key: none needed — this provider is keyless",
                              markup=False, highlight=False)
            answers.key_env = key_env
        elif name:
            key_env, key_inline = capture_key(
                console=console, ask=ask, secret=secret, env=env, name=name, known=known,
                notes=notes, base_url=base_url, export_lines=_print_export_lines,
            )
            answers.key_env = key_env
            answers.key_inline = key_inline
            key_value = (env.get(key_env) or "").strip() or key_inline
        else:
            console.print("key: (skipped — no provider configured)",
                          markup=False, highlight=False)

        # ---- endpoint probe + model step --------------------------------------
        if yes:
            model = known.default_model if known is not None else ""
            if model:
                from hunter.llm.base import TIERS

                answers.role_models = {tier: model for tier in TIERS}
                console.print(f"model: orchestrator={model}", markup=False, highlight=False)
        else:
            models: list[str] = []
            if name and base_url:
                endpoint, models = probe_endpoint_and_models(
                    base_url=base_url, key_value=key_value, probe_fn=probe_fn,
                    list_models_fn=list_models_fn, console=console, notes=notes,
                )
                answers.endpoint = endpoint
            model = ""
            if name:
                # Advanced mode asks for the orchestrator model explicitly so
                # the role prompts cannot consume the mode/provider replies.
                if answers.mode == "advanced":
                    from hunter.cli.wizard_steps import _RolePrompt

                    model_prompt = _RolePrompt("orchestrator model")
                    model_default = current_model or (known.default_model if known else "")
                    model = ask(model_prompt, model_default).strip()
                    if not model:
                        model = pick_model(
                            models=models, known=known, ask=ask, console=console, notes=notes,
                            current_model=current_model,
                        )
                else:
                    model = pick_model(
                        models=models, known=known, ask=ask, console=console, notes=notes,
                        current_model=current_model,
                    )
            if model:
                answers.role_models = assign_roles(
                    model=model, mode_reply="2" if answers.mode == "advanced" else "1",
                    known=known, ask=ask,
                )
                console.print(f"model: orchestrator={model}", markup=False, highlight=False)

        # ---- web automation (skipped headless: --yes never prompts) -----------
        if not yes:
            reply = ask("Enable web automation (browser-driven hunting)? [y/N]", "")
            if reply.strip().lower() in ("y", "yes"):
                answers.browser = True
                notes.append(BROWSER_NOTE_HONEST)
            console.print(f"browser: {'on' if answers.browser else 'off'}",
                          markup=False, highlight=False)

        # ---- tools check (same rows as `hunter doctor`; never aborts) ----------
        if not yes:
            _print_tools_check(console, checks_fn, notes)

        # ---- write phase (keys.env BEFORE config — a crash can only leave
        #      keys without a config, which the next wizard run heals) ----------
        if answers.key_inline and answers.key_env:
            written_keys = write_keys_env({answers.key_env: answers.key_inline}, env=env, home=home)
            console.print("[green]wrote[/green]", written_keys)
            print_key_saved(console, answers.key_env)
        written = write_config(onboarding_updates(answers), target, env=env, home=home)
        wrote_config = True
        console.print("[green]wrote[/green]", written)

        # ---- smoke test ---------------------------------------------------------
        model = answers.role_models.get("orchestrator", "")
        if not model:
            notes.append("smoke test skipped — no model configured")
        elif answers.key_env and not key_value:
            console.print(f"smoke test: skipped — {answers.key_env} is not set",
                          markup=False, highlight=False)
            notes.append(f"smoke test skipped — {answers.key_env} is not set")
        else:
            console.print(
                f"smoke test: dialing {answers.provider}/{model} with a 1-token ping...",
                markup=False,
                highlight=False,
            )
            try:
                result = ping_fn(answers.provider, model, answers.base_url, key_value, 15,
                                 endpoint=answers.endpoint)
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

        # ---- done panel + notes + disclaimer (the disclaimer is ALWAYS last) ----
        _done_panel(console, answers, target, env)
        if notes:
            console.print("notes:", markup=False, highlight=False)
            for note in notes:
                console.print(f"  - {note}", markup=False, highlight=False)
        _print_disclaimer(console)
        return 0
    except KeyboardInterrupt:
        # Buffered writes: a cancel BEFORE the write phase truly changed
        # nothing; after it, the config is already on disk and verified by
        # `hunter doctor`. The disclaimer remains the last line either way.
        from hunter.hospitality import cancelled_line

        console.print(cancelled_line(wrote_config=wrote_config),
                      markup=False, highlight=False)
        if answers.mode == "advanced" and not wrote_config:
            console.print(REMAINING_SECTIONS_LINE, markup=False, highlight=False)
        _print_disclaimer(console)
        return 130


# ------------------------------------------------- deprecated v1/v2 wrappers --


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
    """Deprecated v2 entry — delegates to :func:`run_init_wizard` (one release
    of import stability for out-of-tree callers, then removable)."""
    return run_init_wizard(
        path=path, console=console, err_console=err_console, ask=ask, secret=secret,
        ping_fn=ping_fn, probe_fn=probe_fn, list_models_fn=list_models_fn,
        checks_fn=checks_fn, environ=environ, home=home,
    )


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
    """Deprecated v1 entry — delegates to :func:`run_init_wizard` (the
    ``--provider/--yes`` scriptable contract rides the ONE wizard, Q9)."""
    return run_init_wizard(
        path=path, provider=provider, yes=yes, console=console, err_console=err_console,
        ask=ask, secret=secret, ping_fn=ping_fn, environ=environ, home=home,
    )


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
