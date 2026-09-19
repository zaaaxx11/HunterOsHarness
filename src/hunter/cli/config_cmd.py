"""`hunter config` verbs — path/get/set/unset/edit/check + key set/list (M11).

Polished config management (m11-ux §5): simple things are one
command, deep things are discoverable, and nothing ever prints a key VALUE
(§3.5 masking rule — env var NAMES and set/not-set states only).

Doctrine kept from the rest of the CLI:

- every write flows through :func:`hunter.llm.writing.write_config`
  (deep-merge + canonical render + atomic replace) or
  :func:`hunter.llm.keys.write_keys_env` — never a raw dump;
- ``config set`` pre-validates the merged tree with
  :func:`hunter.llm.config.validate_raw` BEFORE any write — one source of
  truth with the loader, so an invalid value can never land on disk;
- every failure is a classified :class:`hunter.errors.HunterError` rendered
  with its code visible (``[ERROR config] config.unknown_key: ...``) and the
  mapped exit code — never a traceback.
"""

from __future__ import annotations

import copy
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import typer
import yaml

from hunter.errors import HunterError
from hunter.llm.keys import KEY_NAME_RE, keys_env_path, parse_keys_env, write_keys_env
from hunter.llm.writing import resolve_config_target, write_config
from hunter.palette import make_console

__all__ = ["config_key_app", "register_config_commands"]

console = make_console()
err_console = make_console(stderr=True)

config_key_app = typer.Typer(help="Manage keys.env entries (values are never displayed).")


def register_config_commands(config_app: typer.Typer) -> None:
    """Attach the M11 verbs to the ``config`` sub-app (called from main.py)."""
    config_app.command("path")(_config_path_cmd)
    config_app.command("get")(_config_get_cmd)
    config_app.command("set")(_config_set_cmd)
    config_app.command("unset")(_config_unset_cmd)
    config_app.command("edit")(_config_edit_cmd)
    config_app.command("check")(_config_check_cmd)
    config_app.add_typer(config_key_app, name="key")


# ------------------------------------------------------------------ helpers --


def _render_config_error(exc: HunterError) -> int:
    """Classified rendering with the error CODE visible (the config verbs'
    contract: scripts match on ``config.unknown_key`` etc.)."""
    err_console.print(f"[ERROR {exc.layer}] {exc.code}: {exc.message}", markup=False, highlight=False)
    if exc.hint:
        err_console.print(f"Hint: {exc.hint}", markup=False, highlight=False)
    return exc.exit_code


def _display_path(path: Path | None) -> Path:
    """Where `config path` points: explicit → $HUNTEROS_CONFIG →
    ~/.hunter/config.yaml (returned even when the file does not exist yet —
    it is the write target)."""
    from hunter.runtime_paths import RuntimePaths

    return RuntimePaths.resolve(config=path, migrate=False).config


def _raw_tree(target: Path) -> dict[str, Any]:
    """The raw YAML mapping at ``target`` ({} when absent; parse failures are
    classified — a broken file is never silently treated as empty)."""
    if not target.is_file():
        return {}
    try:
        loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        raise HunterError(
            code="config.parse",
            layer="config",
            message=f"config file {target} is not readable YAML: {type(exc).__name__}",
            hint="fix the YAML syntax — or open `hunter config edit` to repair it",
        ) from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise HunterError(
            code="config.parse",
            layer="config",
            message=f"config file {target} must be a YAML mapping, got {type(loaded).__name__}",
            hint="top level must look like:\nmodel_tiers:\n  orchestrator:\n    model: ...",
        )
    return loaded


def _iter_leaves(node: Any, prefix: str) -> list[tuple[str, Any]]:
    """Every scalar leaf beneath ``node`` as ``(dotted.key, value)`` pairs."""
    if isinstance(node, dict):
        rows: list[tuple[str, Any]] = []
        for key, value in node.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_iter_leaves(value, child))
        return rows
    return [(prefix, node)]


def _walk(raw: dict[str, Any], key: str) -> Any:
    """Resolve a dotted key in the raw tree; unknown paths raise the
    classified ``config.unknown_key`` error with the sibling keys as hint."""
    parts = key.split(".")
    node: Any = raw
    walked: list[str] = []
    for _index, part in enumerate(parts):
        if not isinstance(node, dict) or part not in node:
            parent = ".".join(walked) if walked else "the config top level"
            siblings = sorted(str(k) for k in node) if isinstance(node, dict) else []
            raise HunterError(
                code="config.unknown_key",
                layer="config",
                message=f"unknown config key: {key}",
                hint=f"valid keys under {parent}: {', '.join(siblings) if siblings else '(none)'}",
            )
        walked.append(part)
        node = node[part]
    return node


# ------------------------------------------------------------------ commands --


def _config_path_cmd(
    path: Path | None = typer.Option(None, "--path", help="Explicit config file."),
) -> None:
    """Print the config file the read/write paths resolve to."""
    typer.echo(str(_display_path(path)))


def _config_get_cmd(
    key: str = typer.Argument(..., help="Dotted config key, e.g. agent.tier or providers."),
) -> None:
    """Print one key's value — non-leaf keys print every leaf beneath them."""
    target = _display_path(None)
    try:
        value = _walk(_raw_tree(target), key)
    except HunterError as exc:
        raise typer.Exit(_render_config_error(exc)) from exc
    for leaf_key, leaf_value in _iter_leaves(value, key):
        typer.echo(f"{leaf_key}: {leaf_value}")
    if isinstance(value, dict) and not value:
        typer.echo(f"{key}: {{}}")


def _config_set_cmd(
    key: str = typer.Argument(..., help="Dotted leaf key, e.g. budget.max_cost_usd."),
    value: str = typer.Argument(..., help="YAML-parsed value (or the literal with --string)."),
    string: bool = typer.Option(False, "--string", help="Store the literal string — no YAML parsing."),
) -> None:
    """Set one dotted leaf key (validated BEFORE the write — exit 8 refuses)."""
    parts = key.split(".")
    if len(parts) < 2:
        raise typer.Exit(
            _render_config_error(
                HunterError(
                    code="config.value",
                    layer="config",
                    message=f"'{key}' is not a leaf key — single-part keys are refused",
                    hint="set a leaf key, e.g. budget.max_cost_usd or agent.tier",
                )
            )
        )
    if string:
        parsed: Any = value
    else:
        try:
            parsed = yaml.safe_load(value)
        except yaml.YAMLError:
            parsed = value  # not YAML — keep the literal string
        if parsed is None:
            raise typer.Exit(
                _render_config_error(
                    HunterError(
                        code="config.value",
                        layer="config",
                        message=f"{key} cannot be set to null",
                        hint="use hunter config unset to remove a key",
                    )
                )
            )
    target = resolve_config_target()
    existing = _raw_tree(target)
    merged = copy.deepcopy(existing)
    node = merged
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = copy.deepcopy(parsed)
    try:
        from hunter.llm.config import validate_raw

        validate_raw(merged)  # pre-write guard: any loader error refuses the set
    except HunterError as exc:
        raise typer.Exit(_render_config_error(exc)) from exc
    update: dict[str, Any] = {}
    cursor = update
    for part in parts[:-1]:
        cursor[part] = {}
        cursor = cursor[part]
    cursor[parts[-1]] = parsed
    written = write_config(update, target)
    console.print(f"✅ {key} = {parsed!r} — saved to {written}", markup=False, highlight=False)


def _config_unset_cmd(
    key: str = typer.Argument(..., help="Dotted key to remove, e.g. providers.custom."),
) -> None:
    """Remove one key (deep-merge delete through the canonical writer)."""
    target = resolve_config_target()
    raw = _raw_tree(target)
    try:
        _walk(raw, key)
    except HunterError as exc:
        err_console.print(
            f"usage: hunter config unset <dotted.key> — nothing to remove: {exc.message} "
            f"({exc.hint})",
            markup=False,
            highlight=False,
        )
        raise typer.Exit(2) from exc
    parts = key.split(".")
    update: dict[str, Any] = {}
    cursor = update
    for part in parts[:-1]:
        cursor[part] = {}
        cursor = cursor[part]
    cursor[parts[-1]] = None  # write_config's None deletes the key
    write_config(update, target)
    console.print(f"✅ removed {key}", markup=False, highlight=False)


def _resolve_editor() -> str:
    """$VISUAL → $EDITOR → `notepad` (win32) → `vi` (POSIX).

    The value is a raw command STRING; :func:`_editor_argv` splits it with the
    platform-correct rules so ``code --wait`` and quoted Windows paths work.
    """
    for var in ("VISUAL", "EDITOR"):
        editor = (os.environ.get(var) or "").strip()
        if editor:
            return editor
    return "notepad" if os.name == "nt" else "vi"


def _editor_argv(editor: str, target: Path) -> list[str]:
    """Editor command string → argv ending in the file path (never a shell)."""
    from hunter.platform_command import split_command

    parts = split_command(editor)
    return [*parts, str(target)] if parts else [str(target)]


def _config_edit_cmd() -> None:
    """Back up to ``{config}.bak``, open $VISUAL/$EDITOR (no shell), then
    re-validate — invalid results are KEPT with the backup path announced."""
    target = resolve_config_target()
    if not target.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("", encoding="utf-8")  # a fresh edit session
    bak = Path(str(target) + ".bak")
    bak.write_bytes(target.read_bytes())  # overwrites the previous .bak
    console.print(f"Previous config backed up to: {bak}", markup=False, highlight=False)
    editor = _resolve_editor()
    # NO shell, and the editor string is split with host quoting rules so
    # values like `code --wait` or `"C:\Program Files\...\editor.exe"` work.
    try:
        subprocess.call(_editor_argv(editor, target))  # noqa: S603 — argv list only
    except OSError as exc:
        err_console.print(
            f"[hunter.error]cannot launch editor:[/hunter.error] {editor!r} "
            f"({type(exc).__name__}) — set $VISUAL or $EDITOR to a working editor",
            markup=False,
            highlight=False,
        )
        err_console.print(f"your previous config is at {bak}", markup=False, highlight=False)
        raise typer.Exit(1) from exc
    try:
        from hunter.llm.config import load_config

        load_config(target, env={})
    except HunterError as exc:
        err_console.print(f"[ERROR {exc.layer}] {exc.code}: {exc.message}", markup=False, highlight=False)
        if exc.hint:
            err_console.print(f"Hint: {exc.hint}", markup=False, highlight=False)
        err_console.print(
            f"your previous config is at {bak}", markup=False, highlight=False
        )
        raise typer.Exit(exc.exit_code) from exc
    console.print(f"✅ config OK — {target}", markup=False, highlight=False)


def _config_check_cmd() -> None:
    """Validate the config the way every command would load it."""
    from hunter.llm.config import load_config

    target = _display_path(None)
    try:
        if target.is_file():
            load_config(target, env={})
        else:
            load_config(env={})  # no file anywhere: pure defaults load fine
    except HunterError as exc:
        raise typer.Exit(_render_config_error(exc)) from exc
    console.print(f"✅ config OK — {target}", markup=False, highlight=False)


# ------------------------------------------------------------------- key app --


@config_key_app.command("set")
def key_set(
    name: str = typer.Argument(..., help="Env var name, e.g. CUSTOM_API_KEY."),
    stdin: bool = typer.Option(False, "--stdin", help="Read ONE line (the key) from stdin."),
) -> None:
    """Store one key in keys.env (merged — existing values are preserved).

    Values are NEVER echoed and NEVER land in config.yaml. The rewrite parses
    the existing mapping first, so other entries survive (comments and
    malformed lines do not — parser contract).
    """
    if not KEY_NAME_RE.match(name or ""):
        err_console.print(
            f"usage: hunter config key set <VAR> — invalid key variable name: {name!r} "
            "(use letters, digits and underscores, starting with a letter or underscore, "
            "e.g. CUSTOM_API_KEY)",
            markup=False,
            highlight=False,
        )
        raise typer.Exit(2)
    if stdin:
        value = sys.stdin.readline().rstrip("\r\n").strip()
    else:
        import getpass

        try:
            value = getpass.getpass(f"value for {name} (input hidden): ").strip()
        except Exception:  # noqa: BLE001 — no tty / interrupted: nothing saved
            err_console.print(
                "no key read — nothing was changed", markup=False, highlight=False
            )
            raise typer.Exit(1) from None
    if not value:
        raise typer.Exit(
            _render_config_error(
                HunterError(
                    code="config.value",
                    layer="config",
                    message=f"no value given for {name}",
                    hint="paste the key when prompted, or pipe it with --stdin",
                )
            )
        )
    entries: dict[str, str] = {}
    path = keys_env_path()
    if path.is_file():
        try:
            entries = parse_keys_env(path.read_text(encoding="utf-8"))
        except OSError:
            entries = {}
    entries[name] = value
    write_keys_env(entries)
    from hunter.hospitality import key_saved_line

    typer.echo(key_saved_line(name))


@config_key_app.command("list")
def key_list() -> None:
    """List key variable NAMES and where each effective value would come from
    — values are never displayed (``keys.env`` | ``env`` | ``not set``).

    The label is the RUNTIME source under the setdefault contract: a real
    environment variable whose value DIFFERS from the keys.env entry wins
    (``env``); an environment entry that equals the file's value came from
    the startup load (``keys.env``).
    """
    path = keys_env_path()
    file_values: dict[str, str] = {}
    if path.is_file():
        try:
            file_values = parse_keys_env(path.read_text(encoding="utf-8"))
        except OSError:
            file_values = {}
    names = set(file_values)
    from hunter.llm.config import load_config

    try:
        cfg = load_config()
    except HunterError:
        cfg = None
    if cfg is not None:
        names |= {p.key_env for p in cfg.providers.values() if p.key_env}
    for name in sorted(names):
        env_value = os.environ.get(name)
        if name in file_values:
            source = "env" if env_value is not None and env_value != file_values[name] else "keys.env"
        elif env_value is not None:
            source = "env"
        else:
            source = "not set"
        typer.echo(f"{name}  {source}")
    if not names:
        typer.echo("no keys configured — add one: hunter config key set <VAR>")
