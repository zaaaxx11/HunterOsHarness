"""Drop-in agent tools — tool cards loadable at runtime, no core edits.

WHY
---
Every capability used to be a hard-coded :class:`ToolSpec` inside
``agent/tools.py``, so teaching the harness a new verb meant patching HunterOS
itself.  This module makes tools *data*: any ``*.py`` dropped into a tool
directory is imported, and each public module-level function whose name starts
with ``tool_`` becomes a real, dispatchable tool.

SECURITY MODEL (this is the part that matters)
----------------------------------------------
A plugin tool is NOT more powerful than a built-in one.  It gets exactly what a
built-in handler gets — a ``ToolContext`` — and nothing else:

* it never sees the provider, the API keys, or ``os.environ`` credentials;
* it is dispatched through the same :class:`ToolRegistry`, so tier gating and
  the approval gate apply unchanged;
  is refused at load time rather than ignored;
* ``danger="approval"`` cannot be claimed by a plugin.  Approval-danger is a
  property of the *governed* tool set; letting a file declare it would let a
  drop-in tool masquerade as pre-approved.  Plugins are ``danger="none"`` and
  are therefore still fully subject to scope + tier checks in the handler.

Fail-closed: a module that raises on import, or a function with a malformed
schema, is skipped with a recorded reason.  A broken plugin never prevents the
harness from starting.

NON-GOALS
---------
Plugin tools cannot write findings directly: ``create_finding_request`` is the
only claim path and it machine-validates evidence against the ledger (RULE-E1).
A plugin that wants a finding must return evidence ids to the model, exactly
like ``http_request`` does.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .tools_base import ToolContext, ToolOutcome, ToolRegistry, ToolSpec

__all__ = [
    "PluginTool",
    "PluginLoadResult",
    "tool_dirs",
    "load_plugins",
    "scaffold_tool",
]

# A tool name has to survive being sent to an OpenAI-compatible gateway, so we
# keep it to the same charset the built-ins use.
_ALLOWED_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_")
_REQUIRED_SCHEMA_KEYS = ("type", "properties")


@dataclass
class PluginTool:
    """One discovered plugin function plus where it came from."""

    name: str
    spec: ToolSpec
    source: str
    origin: str


@dataclass
class PluginLoadResult:
    """Outcome of one ``load_plugins`` pass."""

    loaded: list[PluginTool] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    dirs: list[str] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        return [t.name for t in self.loaded]

    def summary(self) -> str:
        parts = [f"{len(self.loaded)} plugin tool(s) loaded"]
        if self.dirs:
            parts.append(f"from {', '.join(self.dirs)}")
        if self.skipped:
            detail = "; ".join(f"{name}: {reason}" for name, reason in self.skipped)
            parts.append(f"skipped {detail}")
        return " — ".join(parts)


def _normalize_name(raw: str) -> str:
    name = raw.strip()
    if name.startswith("tool_"):
        name = name[len("tool_") :]
    return name


def _valid_name(name: str) -> bool:
    return bool(name) and set(name) <= _ALLOWED_NAME_CHARS and name[0].isalpha()


def _coerce_schema(fn: Callable[..., Any]) -> dict[str, Any] | None:
    """Accept either an explicit ``schema=`` attribute or an inferred skeleton.

    A plugin may attach ``fn.schema = {...}`` for a precise contract.  Without
    one we synthesise a permissive object schema from the signature — good
    enough for the model to call it, and the handler still validates its own
    arguments at runtime.
    """
    declared = getattr(fn, "schema", None)
    if isinstance(declared, dict):
        if all(key in declared for key in _REQUIRED_SCHEMA_KEYS):
            return declared
        return None

    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param_name, param in sig.parameters.items():
        if param_name in ("ctx", "context"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        properties[param_name] = {"type": "string"}
        if param.default is inspect.Parameter.empty:
            required.append(param_name)
    return {"type": "object", "properties": properties, "required": required}


def _make_handler(fn: Callable[..., Any]) -> Callable[[dict[str, Any], ToolContext], ToolOutcome]:
    """Adapt a plugin function to the ``(args, ctx) -> ToolOutcome`` contract.

    The plugin is called as ``fn(args, ctx)``.  If it returns a plain string or
    dict, we wrap it — a plugin author should not have to import ToolOutcome
    just to return an observation.
    """

    def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
        try:
            result = fn(args, ctx)
        except Exception as exc:  # a plugin bug is the model's problem to report
            return ToolOutcome(
                ok=False,
                result_for_model=(
                    f"PLUGIN ERROR in {getattr(fn, '__name__', 'tool')}: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )
        if isinstance(result, ToolOutcome):
            return result
        if isinstance(result, str):
            return ToolOutcome(result_for_model=result)
        if isinstance(result, dict):
            import json

            return ToolOutcome(result_for_model=json.dumps(result, ensure_ascii=False))
        return ToolOutcome(result_for_model=str(result))

    return handler


def _load_module(path: Path) -> Any:
    module_name = f"hunter_plugin_{path.stem}_{abs(hash(str(path))) & 0xFFFFFF:x}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _discover_file(path: Path, *, origin: str) -> tuple[list[PluginTool], list[tuple[str, str]]]:
    loaded: list[PluginTool] = []
    skipped: list[tuple[str, str]] = []
    try:
        module = _load_module(path)
    except Exception as exc:
        detail = traceback.format_exception_only(type(exc), exc)[-1].strip()
        skipped.append((path.name, f"import failed: {detail}"))
        return loaded, skipped

    for attr in sorted(dir(module)):
        if not attr.startswith("tool_"):
            continue
        fn = getattr(module, attr)
        if not callable(fn) or inspect.isclass(fn):
            continue
        name = _normalize_name(attr)
        if not _valid_name(name):
            skipped.append((attr, f"invalid tool name {name!r}"))
            continue
        schema = _coerce_schema(fn)
        if schema is None:
            skipped.append((attr, "missing/malformed parameter schema"))
            continue
        description = str(getattr(fn, "description", "") or inspect.getdoc(fn) or name)
        spec = ToolSpec(
            name=name,
            description=description.strip().splitlines()[0][:300],
            parameters=schema,
            handler=_make_handler(fn),
            # Plugins never claim approval-danger: that would let a drop-in
            # file pretend to be pre-approved.  They stay "none".
            danger="none",
        )
        loaded.append(
            PluginTool(name=name, spec=spec, source=str(path), origin=origin)
        )
    return loaded, skipped


def tool_dirs(home: Path | None = None) -> list[Path]:
    """Directories searched for tool plugins, highest priority first.

    ``$HUNTEROS_TOOL_DIRS`` (os-path-separated) lets an operator point at a
    shared checkout; ``<home>/tools`` is the per-install drop-in folder.
    """
    import os

    out: list[Path] = []
    env = os.environ.get("HUNTEROS_TOOL_DIRS", "").strip()
    if env:
        for chunk in env.replace(";", ":").split(":"):
            chunk = chunk.strip()
            if chunk:
                out.append(Path(chunk).expanduser())
    base = Path(home) if home is not None else Path.home() / ".hunter"
    out.append(base / "tools")
    # de-dup, keep order
    seen: set[str] = set()
    unique: list[Path] = []
    for path in out:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def load_plugins(
    registry: ToolRegistry,
    *,
    home: Path | None = None,
    dirs: list[Path] | None = None,
    override: bool = False,
) -> PluginLoadResult:
    """Import every plugin file and register its ``tool_*`` functions.

    ``override=False`` means a plugin may NOT shadow a built-in tool: the
    collision is recorded in ``skipped`` and the built-in keeps working.  That
    is the safe default — a drop-in file must not be able to replace
    ``create_finding_request`` with something that skips the claim gate.
    """
    result = PluginLoadResult()
    search = dirs if dirs is not None else tool_dirs(home)
    for directory in search:
        try:
            if not Path(directory).is_dir():
                continue
        except OSError:
            continue
        result.dirs.append(str(directory))
        for path in sorted(Path(directory).glob("*.py")):
            if path.name.startswith("_"):
                continue
            origin = path.stem
            loaded, skipped = _discover_file(path, origin=origin)
            result.skipped.extend(skipped)
            for plugin in loaded:
                if registry.get(plugin.name) is not None and not override:
                    result.skipped.append(
                        (plugin.name, "would shadow a built-in tool (refused)")
                    )
                    continue
                try:
                    registry.register(plugin.spec, override=override)
                except Exception as exc:
                    result.skipped.append((plugin.name, f"register failed: {exc}"))
                    continue
                result.loaded.append(plugin)
    return result


_TOOL_TEMPLATE = '''"""Plugin tool: __NAME__.

Drop-in tool card for HunterOS.  Rename/replace freely.

The function receives ``(args, ctx)``:

* ``args``  — the decoded JSON arguments from the model.
* ``ctx``   — the same ToolContext a built-in handler gets
  (``ctx.scope``, ``ctx.http``, ``ctx.ledger``, ``ctx.target_url``, ``ctx.emit``).

Handlers MUST go through ``ctx.scope`` / ``ctx.http`` for anything network
facing — the scope gate is enforced there, not here.  Return a string, a dict,
or a ToolOutcome.
"""

from __future__ import annotations


def tool___NAME__(args, ctx):
    """__DESC__"""
    target = str(args.get("target", "") or ctx.target_url)
    # Scope check first: a plugin must not become an out-of-scope egress.
    host = ctx.scope.check_url(target)
    return f"__NAME__: target={target} host={host}"


# Optional precise schema (otherwise inferred from the signature):
tool___NAME__.schema = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "URL or path to operate on"},
    },
    "required": [],
}
tool___NAME__.description = "__DESC__"
'''


def scaffold_tool(name: str, *, directory: Path) -> Path:
    """Write a starter plugin so the operator has something to edit."""
    safe = _normalize_name(name)
    if not _valid_name(safe):
        raise ValueError(f"invalid tool name {name!r}")
    directory = Path(directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{safe}.py"
    rendered = _TOOL_TEMPLATE.replace("__NAME__", safe).replace(
        "__DESC__", f"TODO: describe {safe}."
    )
    path.write_text(rendered, encoding="utf-8")
    return path
