"""Config write-back — the ONLY way code edits ``config.yaml``.

Hand-written YAML deserves better than ``yaml.safe_dump`` (which destroys
comments). Every mutation — `hunter init`, `hunter config provider add`,
chat's ``/model --global`` — flows through :func:`write_config`, which:

1. loads the existing file (or starts empty),
2. deep-merges the updates (a ``None`` value DELETES the key),
3. re-emits the whole file through a canonical commented template (same text
   family as ``hunter config example``) with the user's values interpolated,
4. writes atomically (temp file in the same directory, then ``os.replace``).

Inline ``api_key`` values are never invented here: they only appear when they
came from the existing file or were explicitly passed in the updates.
"""

from __future__ import annotations

import contextlib
import copy
import os
import re
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from hunter.errors import HunterError
from hunter.llm.base import LEGACY_TIER_ALIASES, TIERS, normalize_tier

__all__ = ["render_config", "write_config"]

_CONFIG_FILENAME = "config.yaml"

_HEADER = """\
# HunterOs LLM configuration — maintained by `hunter init` and
# `hunter config provider ...` (hand edits are preserved across those writes).
# Any provider reachable through LiteLLM works: set a key env var and a model.
# Environment overrides win over YAML values:
#   HUNTEROS_MODEL, HUNTEROS_TIER, HUNTEROS_BUDGET_USD, HUNTEROS_MAX_ITERATIONS
"""

_TIER_COMMENTS = {
    "orchestrator": 'task decomposition — the "top default" model',
    "hunter": "payload/craft tier — inherits orchestrator unless set",
    "verifier": "evidence checking — a cheap, careful model",
    "utility": "summarizing/formatting — cheapest model",
}

_FALLBACK_EXAMPLE = """\
#  - provider: openrouter
#    model: anthropic/claude-sonnet-4.5
#    key_env: OPENROUTER_API_KEY"""


def _config_write_error(message: str, hint: str) -> HunterError:
    return HunterError(code="config.write_failed", layer="config", message=message, hint=hint)


def _migrate_legacy_tiers(data: dict[str, Any]) -> dict[str, Any]:
    """model_tiers legacy keys → canonical (move when the twin is absent,
    ``config.write_failed`` when both exist); agent.tier legacy value →
    canonical (word-boundary safe: the VALUE is replaced, never a substring
    rewrite). Mutates + returns ``data``. Every write path applies this so
    rendered files NEVER regain an old-name key — first write heals the file
    (read-only sessions still work because the loader maps on read).
    ``providers``/``fallback_providers`` keys are PROVIDER names — never
    migrated."""
    tiers = data.get("model_tiers")
    if isinstance(tiers, dict):
        for old, new in LEGACY_TIER_ALIASES.items():
            if old not in tiers:
                continue
            if new in tiers:
                raise _config_write_error(
                    f"model_tiers has both '{old}' (legacy) and '{new}' — remove the legacy key",
                    f"keep one of model_tiers.{old} / model_tiers.{new} — "
                    "the legacy name is the pre-v0.4 vocabulary",
                )
            tiers[new] = tiers.pop(old)
    agent = data.get("agent")
    if isinstance(agent, dict) and isinstance(agent.get("tier"), str):
        agent["tier"] = normalize_tier(agent["tier"])
    return data


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _deep_merge(base: dict[str, Any], updates: Mapping[str, Any], path: str = "") -> dict[str, Any]:
    """Merge ``updates`` into ``base`` in place. ``None`` deletes the key.

    Replacing a mapping with a scalar (or a scalar with a mapping) is a type
    conflict and raises :class:`HunterError` — silently overwriting the other
    shape would corrupt the config's structure (``providers.corp: "flat"``)
    or crash the renderer later.
    """
    for key, value in updates.items():
        here = f"{path}.{key}" if path else str(key)
        if value is None:
            base.pop(key, None)
            continue
        current = base.get(key)
        if isinstance(value, Mapping):
            if isinstance(current, dict):
                _deep_merge(current, value, here)
                continue
            if current is not None:
                raise _config_write_error(
                    f"type conflict at '{here}': cannot replace the scalar "
                    f"{current!r} with a mapping",
                    "update mapping keys with a mapping (e.g. 'providers: {name: {key_env: ...}}'), "
                    "or delete the key first (None) and rewrite it",
                )
            base[key] = copy.deepcopy(dict(value))
            continue
        if isinstance(current, dict):
            raise _config_write_error(
                f"type conflict at '{here}': cannot replace the mapping with the scalar {value!r}",
                "pass a mapping to update a mapping key (e.g. 'providers: {name: {base_url: ...}}'), "
                "or a nested scalar path (e.g. 'providers: {name: {key_env: ...}}')",
            )
        base[key] = copy.deepcopy(value)
    return base


def _scalar(value: Any) -> str:
    """YAML-render one scalar safely (quoting, numbers, bools) — dumped as a
    mapping member so safe_dump's top-level document-end marker (``...``)
    never leaks into the file."""
    dumped = yaml.safe_dump({"k": value}, default_flow_style=False, sort_keys=False, width=4096)
    rendered = dumped.split(":", 1)[1].strip() if ":" in dumped else dumped.strip()
    return rendered or "null"


_PLAIN_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _yaml_key(name: Any, where: str) -> str:
    """YAML-render one mapping KEY (a provider or tier name) without corrupting
    the file. Plain-safe names (every name ``provider add`` accepts) are
    emitted verbatim — the canonical file stays byte-identical. Anything else
    is quoted via :func:`_scalar`, and the rendering is verified to parse back
    to the EXACT same key; a key that cannot survive the round trip at all
    (multiline, a non-scalar) is refused as a classified error instead of
    silently shattering the config or losing the provider block (v0.3 QA red
    audit: ``providers: {null: ...}`` used to come back with a None key)."""
    candidates: list[str] = []
    if isinstance(name, str) and _PLAIN_KEY_RE.match(name):
        candidates.append(name)
    if isinstance(name, (str, int, float, bool)) or name is None:
        candidates.append(_scalar(name))
    for candidate in candidates:
        try:
            parsed = yaml.safe_load(f"{candidate}: 0")
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict):
            keys = list(parsed)
            if len(keys) == 1 and keys[0] == name and isinstance(keys[0], type(name)):
                return candidate
    raise _config_write_error(
        f"{where} name {name!r} cannot be written to the config file",
        f"use a plain provider/tier name (letters, digits, '_', '-', '.') — "
        f"got {type(name).__name__}",
    )


# ------------------------------------------------------------------ emitter --


def render_config(data: Mapping[str, Any] | None) -> str:
    """The canonical commented config file for ``data`` (loadable as-is)."""
    data = dict(data or {})
    _migrate_legacy_tiers(data)  # old names never render (first write heals)
    tiers: Mapping[str, Any] = data.get("model_tiers") or {}
    providers: Mapping[str, Any] = data.get("providers") or {}
    fallback: Any = data.get("fallback_providers") or []
    budget: Mapping[str, Any] = data.get("budget") or {}
    agent: Mapping[str, Any] = data.get("agent") or {}

    lines: list[str] = [*_HEADER.splitlines(), ""]

    # --- model_tiers --------------------------------------------------------
    lines.append("model_tiers:")
    tier_order = [t for t in TIERS] + sorted(set(tiers) - set(TIERS), key=str)
    for tier in tier_order:
        block: Mapping[str, Any] = tiers.get(tier) or {}
        if not isinstance(block, Mapping):
            raise _config_write_error(
                f"model_tiers.{tier} must be a mapping, got {type(block).__name__}",
                "fix the model_tiers section — each tier needs provider/model keys",
            )
        comment = _TIER_COMMENTS.get(tier, "")
        suffix = f"  # {comment}" if comment else ""
        lines.append(f"  {_yaml_key(tier, 'model_tiers')}:{suffix}")
        lines.append(f"    provider: {_scalar(block.get('provider') or 'auto')}")
        lines.append(f"    model: {_scalar(block.get('model') or '')}")
        if block.get("base_url"):
            lines.append(f"    base_url: {_scalar(block['base_url'])}")
        if block.get("key_env"):
            lines.append(f"    key_env: {_scalar(block['key_env'])}")
        lines.append(f"    timeout: {_scalar(block.get('timeout', 120))}")
        if block.get("reasoning_effort"):
            lines.append(f"    reasoning_effort: {_scalar(block['reasoning_effort'])}")
    lines.append("")

    # --- providers ----------------------------------------------------------
    if providers:
        lines.append("providers:                     # credentials per provider name")
        for name in sorted(providers, key=str):
            block: Mapping[str, Any] = providers.get(name) or {}
            if not isinstance(block, Mapping):
                raise _config_write_error(
                    f"providers.{name} must be a mapping, got {type(block).__name__}",
                    "fix the providers section — each provider needs key_env/api_key/base_url keys",
                )
            lines.append(f"  {_yaml_key(name, 'providers')}:")
            if block.get("key_env"):
                lines.append(f"    key_env: {_scalar(block['key_env'])}")
            if block.get("api_key"):
                lines.append(
                    f"    api_key: {_scalar(block['api_key'])}  # env var is preferred"
                )
            if block.get("base_url"):
                lines.append(f"    base_url: {_scalar(block['base_url'])}")
            if block.get("endpoint"):
                lines.append(f"    endpoint: {_scalar(block['endpoint'])}")
    else:
        lines.append("providers: {}                   # add one: hunter config provider add <name>")
    lines.append("")

    # --- fallback_providers -------------------------------------------------
    if fallback:
        lines.append("# Tried in order when the primary provider fails with auth/billing/404-class")
        lines.append("fallback_providers:")
        for entry in fallback:
            if not isinstance(entry, Mapping):
                lines.append(f"  - {_scalar(entry)}")
                continue
            first = True
            for key in ("provider", "model", "base_url", "key_env"):
                if entry.get(key):
                    bullet = "  - " if first else "    "
                    lines.append(f"{bullet}{key}: {_scalar(entry[key])}")
                    first = False
            if first:  # empty entry — keep the list valid
                lines.append("  - {}")
    else:
        lines.append("# Tried in order when the primary provider fails with auth/billing/404-class")
        lines.append("fallback_providers: []")
        lines.append(_FALLBACK_EXAMPLE)
    lines.append("")

    # --- budget -------------------------------------------------------------
    lines.append("budget:                        # per-run governor (RunBudget)")
    lines.append(
        f"  max_cost_usd: {_scalar(budget.get('max_cost_usd', 5.0))}            # hard spend cap"
    )
    lines.append(
        f"  max_iterations: {_scalar(budget.get('max_iterations', 60))}           # agent tool-loop turns"
    )
    lines.append(
        f"  wall_seconds: {_scalar(budget.get('wall_seconds', 1800))}           # wall clock"
    )
    lines.append("")

    # --- agent --------------------------------------------------------------
    # M11 fix: EVERY agent key renders (browser_cloak used to be silently
    # dropped on rewrite — a latent data-loss bug), plus the M11 scope keys.
    lines.append("agent:")
    lines.append(f"  tier: {_scalar(agent.get('tier', 'basic'))}"
                 "                  # basic | advanced | orchestrator | hunter | verifier | utility")
    lines.append(f"  api_max_retries: {_scalar(agent.get('api_max_retries', 3))}"
                 "           # attempts per provider before failing over")
    lines.append(f"  browser: {_scalar(agent.get('browser', False))}")
    if "browser_cloak" in agent:
        lines.append(f"  browser_cloak: {_scalar(agent.get('browser_cloak', True))}")
    if agent.get("scope_confirm"):
        lines.append(f"  scope_confirm: {_scalar(agent.get('scope_confirm', False))}"
                     "      # true restores refuse-without---yes for hunt start")
    scopes = agent.get("approved_scopes")
    if isinstance(scopes, list) and scopes:
        lines.append("  approved_scopes:              # audit trail of auto-authorized minimal scopes")
        for entry in scopes:
            lines.extend(_render_scope_entry(entry))

    # --- ui -------------------------------------------------------------------
    # R2-C skins: ui.skin must survive every rewrite (it used to be silently
    # dropped — same data-loss class as the M11 browser_cloak bug). Always
    # rendered so write → load → rewrite is a fixpoint.
    ui_raw: Any = data.get("ui") or {}
    if not isinstance(ui_raw, Mapping):
        raise _config_write_error(
            f"ui must be a mapping, got {type(ui_raw).__name__}",
            "fix the ui section — it needs a skin key, e.g. ui:\n  skin: teal",
        )
    skin = ui_raw.get("skin", "teal") or "teal"
    lines.append("")
    lines.append("ui:                            # TUI surface (R2-C skins-as-data)")
    lines.append(f"  skin: {_scalar(skin)}"
                 "                   # teal | midnight | amber")
    return "\n".join(lines) + "\n"


_SCOPE_KEY_ORDER = ("host", "name", "allow_subdomains", "ts", "source")


def _render_scope_entry(entry: Any) -> list[str]:
    """YAML-render one ``approved_scopes`` entry (a mapping) as an indented
    block item — the dump must parse back to the SAME mapping (the round-trip
    is pinned: write → load → rewrite → identical ``agent:`` section)."""
    if not isinstance(entry, Mapping):
        rendered = _scalar(entry)
        return [f"    - {rendered}"]
    keys = [key for key in _SCOPE_KEY_ORDER if key in entry]
    keys += [key for key in entry if key not in _SCOPE_KEY_ORDER]
    lines: list[str] = []
    for index, key in enumerate(keys):
        prefix = "    - " if index == 0 else "      "
        lines.append(f"{prefix}{key}: {_scalar(entry[key])}")
    return lines or ["    - {}"]


# ------------------------------------------------------------------- writer --


def _load_existing_yaml(target: Path) -> Any:
    """Read + parse the existing config. A transient PermissionError (another
    `hunter` process replacing the file concurrently, or a brief AV/reader
    lock — a Windows specialty) is retried a bounded number of times before
    failing classified; every other read/parse problem keeps its honest
    "not valid YAML" diagnosis."""
    text: str | None = None
    error: Exception | None = None
    for attempt in range(5):
        try:
            text = target.read_text(encoding="utf-8")
            break
        except PermissionError as exc:
            error = exc
            time.sleep(0.01 * (attempt + 1))
        except (OSError, UnicodeDecodeError) as exc:
            error = exc
            break
    if text is None:
        if isinstance(error, PermissionError):
            raise _config_write_error(
                f"could not read config {target}: {error}",
                "close the program holding the file open, or check its permissions",
            ) from error
        raise _config_write_error(
            f"existing config {target} is not valid YAML: {type(error).__name__}",
            "fix or remove the file first — write-back refuses to build on a broken file",
        ) from error
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise _config_write_error(
            f"existing config {target} is not valid YAML: {type(exc).__name__}",
            "fix or remove the file first — write-back refuses to build on a broken file",
        ) from exc


def resolve_config_target(
    path: str | Path | None = None,
    *,
    force: bool = False,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Where a write lands: explicit ``path`` → ``$HUNTEROS_CONFIG`` →
    ``~/.hunteros/config.yaml``. An env-var path outside the home directory is
    refused unless ``force`` — a stray env var must not aim writes at
    arbitrary filesystem locations."""
    env = os.environ if env is None else env
    from hunter.runtime_paths import RuntimePaths

    paths = RuntimePaths.resolve(config=path, env=env, home=home, migrate=False)
    if path is not None:
        return paths.config
    from_env = (env.get("HUNTEROS_CONFIG") or "").strip()
    if from_env:
        target = paths.config
        if not force and not _is_within(target, paths.home.parent):
            raise _config_write_error(
                f"$HUNTEROS_CONFIG points outside the home directory: {target}",
                "set HUNTEROS_CONFIG to a path under your home directory, "
                "or pass an explicit config path",
            )
        return target
    return paths.config


def write_config(
    updates: Mapping[str, Any],
    path: str | Path | None = None,
    *,
    force: bool = False,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Deep-merge ``updates`` into the config file at ``path`` (default
    search order as in :func:`resolve_config_target`) and rewrite it through
    the canonical template, atomically. Returns the written path.

    A ``None`` value inside ``updates`` deletes that key (used by
    ``provider remove``). Raises HunterError (layer config) for a broken
    existing file, a mapping/scalar type conflict in ``updates``, or a
    refused out-of-home env target.
    """
    target = resolve_config_target(path, force=force, env=env, home=home)

    existing: dict[str, Any] = {}
    if target.is_file():
        loaded = _load_existing_yaml(target)
        if loaded is None:
            existing = {}
        elif isinstance(loaded, dict):
            existing = loaded
        else:
            raise _config_write_error(
                f"existing config {target} must be a YAML mapping, got {type(loaded).__name__}",
                "top level must look like:\nmodel_tiers:\n  orchestrator:\n    model: ...",
            )

    merged = _deep_merge(existing, dict(updates))
    _migrate_legacy_tiers(merged)  # old names never render (first write heals)
    text = render_config(merged)

    target.parent.mkdir(parents=True, exist_ok=True)
    # delete=False + manual replace: the tmp file must outlive the context so
    # os.replace can atomically move it onto the target.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(target.parent), suffix=".tmp", delete=False
    ) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    replaced = False
    error: OSError | None = None
    for attempt in range(5):
        try:
            os.replace(handle.name, target)
            replaced = True
            break
        except PermissionError as exc:
            # Windows: a concurrent replace (two `hunter` processes) or a brief
            # antivirus/reader lock on the destination fails transiently — a
            # bounded retry keeps the atomic replace the ONLY commit path.
            error = exc
            time.sleep(0.01 * (attempt + 1))
        except OSError as exc:
            error = exc
            break  # missing directory, cross-device, ... — not retryable
    if not replaced:
        with contextlib.suppress(OSError):
            os.unlink(handle.name)
        raise _config_write_error(
            f"could not write config {target}: {error}",
            "check the permissions of the config directory",
        ) from error
    return target
