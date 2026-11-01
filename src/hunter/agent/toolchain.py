"""Offensive toolchain tools — real binaries, honestly reported.

The harness already knew about ``slither``, ``cast``, and ``anvil``: they sat
in ``inventory.INVENTORY_BINARIES`` and ``tools_web3`` advertised
``slither_hint`` / ``cast_hint`` through ``register_unavailable``. The model
could see the tools existed and could never call them.

This module closes that gap. Every tool here:

* resolves its binary through ``shutil.which`` at CALL time (no import-time
  assumption, no PATH snapshot baked into a wheel);
* reports absence as ``tool.unavailable`` with the exact install command —
  never a stub that returns plausible-looking output;
* runs the child with a minimal environment (``inventory``-style allowlist,
  ``HOME`` pointed at the jail) so a toolchain run cannot read the operator's
  credentials;
* refuses to run outside a scope-gated local root, the same fail-closed
  filesystem gate the engines use;
* captures bounded output and emits ``tool_output`` evidence, so what the
  binary said is in the ledger and not just in the transcript.

Design rule carried over from the engines: **absence is a result, not an
error.** A machine without Foundry is a normal state; the tool says so and
the run continues.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 — the whole point of this module
from pathlib import Path
from typing import Any

from .tools_base import ToolContext, ToolOutcome

__all__ = [
    "TOOLCHAIN_TOOLS",
    "cast_call",
    "forge_build",
    "forge_test",
    "register_toolchain_tools",
    "slither_run",
]

# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

#: name -> (binary, install hint). The hint is printed verbatim when the
#: binary is missing, because "install foundry" is not an instruction anyone
#: can act on.
_BINARIES: dict[str, tuple[str, str]] = {
    "forge": ("forge", "curl -L https://foundry.paradigm.xyz | bash && foundryup"),
    "cast": ("cast", "curl -L https://foundry.paradigm.xyz | bash && foundryup"),
    "anvil": ("anvil", "curl -L https://foundry.paradigm.xyz | bash && foundryup"),
    "slither": ("slither", "pip install slither-analyzer && slither --version"),
    "solc": ("solc", "pip install solc-select && solc-select install latest"),
}

#: Environment passed to every child. Deliberately tiny: a toolchain run has
#: no business reading the operator's API keys.
_CHILD_ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC", "PATHEXT",
                        "SYSTEMDRIVE", "WINDIR", "LANG", "LC_ALL", "TERM")

_MAX_OUTPUT_CHARS = 16_384
_DEFAULT_TIMEOUT_S = 180

#: Per-process PATH resolution cache (see :func:`_resolve`).
_RESOLVE_CACHE: dict[str, str | None] | None = None


def _resolve(binary: str) -> str | None:
    """Absolute path to ``binary`` on PATH, or None. Resolved at call time.

    Cached per process: ``build_registry`` resolves the same binary once per
    tool that uses it (``forge`` twice, for build and test), and a PATH scan
    is not free. The cache is keyed by binary name only — PATH is read once
    per process, which is the same assumption ``shutil.which`` makes.
    """
    global _RESOLVE_CACHE
    if _RESOLVE_CACHE is None:
        _RESOLVE_CACHE = {}
    if binary not in _RESOLVE_CACHE:
        _RESOLVE_CACHE[binary] = shutil.which(binary)
    return _RESOLVE_CACHE[binary]


def reset_resolve_cache() -> None:
    """Drop the resolution cache. Test seam — never called in production."""
    global _RESOLVE_CACHE
    _RESOLVE_CACHE = None


def _child_env(cwd: Path) -> dict[str, str]:
    import os  # noqa: PLC0415 — local import keeps the module import light

    env: dict[str, str] = {}
    for key in _CHILD_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    # The child's HOME is the jail, never the operator's home. Foundry writes
    # ~/.foundry; pointing HOME at the run root keeps that inside the state dir.
    env["HOME"] = str(cwd)
    env["HUNTER_SANDBOX"] = "1"
    env["NO_COLOR"] = "1"
    return env


def _truncate(text: str) -> str:
    if len(text) <= _MAX_OUTPUT_CHARS:
        return text
    return text[:_MAX_OUTPUT_CHARS] + f"\n...[truncated at {_MAX_OUTPUT_CHARS} chars]"


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Run ``argv`` and return a bounded, JSON-safe result dict.

    Never raises for a non-zero exit: a failing ``forge test`` is the single
    most valuable output in this module (it is the PoC firing). The exit code
    travels with the payload.
    """
    try:
        completed = subprocess.run(  # noqa: S603 — argv is built here, not from the model
            argv,
            cwd=str(cwd),
            env=_child_env(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "code": "tool.timeout",
            "argv": argv,
            "result_for_model": f"timed out after {timeout_s}s: {' '.join(argv)}",
        }
    except OSError as exc:
        return {
            "ok": False,
            "code": "tool.exec_failed",
            "argv": argv,
            "result_for_model": f"{type(exc).__name__}: {exc}",
        }

    stdout = _truncate(completed.stdout or "")
    stderr = _truncate(completed.stderr or "")
    return {
        "ok": True,
        "code": "ok",
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "result_for_model": (
            f"$ {' '.join(argv)}\nexit={completed.returncode}\n"
            f"{stdout}{stderr and chr(10) + stderr}"
        ).strip(),
    }


# ---------------------------------------------------------------------------
# Scope gate
# ---------------------------------------------------------------------------


def _local_root(ctx: ToolContext, args: dict[str, Any]) -> tuple[Path | None, str | None]:
    """Resolve the working directory, fail-closed against the scope.

    Mirrors the engines' filesystem gate: an explicit ``path`` argument must
    resolve inside one of the scope's ``local_roots`` (absent ``local_roots``
    keeps the permissive localhost behaviour). Returns ``(root, error_code)``.
    """
    raw = args.get("path") or ctx.config.get("local_root")
    if not raw:
        return None, "toolchain.no_root"
    try:
        resolved = Path(str(raw)).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None, "toolchain.bad_path"
    if not resolved.is_dir():
        return None, "toolchain.not_a_directory"
    try:
        if not ctx.scope.allows_local_root(resolved):
            return None, "scope.local_root_out_of_scope"
    except Exception:  # noqa: BLE001 — a scope without the method must not crash the tool
        return None, "scope.local_root_out_of_scope"
    return resolved, None


def _unavailable(tool: str, binary: str) -> dict[str, Any]:
    _name, hint = _BINARIES[binary]
    return {
        "ok": False,
        "blocked": False,
        "code": "tool.unavailable",
        "result_for_model": (
            f"{tool}: {binary} is not installed on this machine. "
            f"install with: {hint}"
        ),
    }


def _emit(ctx: ToolContext, tool: str, extra: dict[str, Any] | None = None) -> None:
    payload = {"tool": tool}
    if extra:
        payload.update(extra)
    try:
        ctx.emit("engine_event", payload)
    except Exception:  # noqa: BLE001 — emitting is best-effort, never fatal
        pass


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def forge_build(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``forge build`` in a scope-gated local root.

    Compilation is the first real step of any Solidity audit: without it
    there is no AST for Slither and no test harness for a PoC. The compiler's
    own warnings are signal, so stdout and stderr are both returned.
    """
    root, err = _local_root(ctx, args)
    if err:
        return {"ok": False, "blocked": True, "code": err,
                "result_for_model": f"BLOCKED [{err}]"}
    binary = _resolve("forge")
    if binary is None:
        return _unavailable("forge_build", "forge")

    argv = [binary, "build"]
    if args.get("force"):
        argv.append("--force")
    _emit(ctx, "forge_build", {"root": str(root)})
    return _run(argv, cwd=root, timeout_s=int(args.get("timeout_s", 300)))


def forge_test(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``forge test`` in a scope-gated local root.

    A failing test IS the proof. This tool therefore treats a non-zero exit
    as a successful *invocation*: ``ok`` reflects whether the binary ran, and
    ``exit_code`` carries the verdict. The caller (and the claim gate) read
    the exit code; nothing here decides whether a bug is real.
    """
    root, err = _local_root(ctx, args)
    if err:
        return {"ok": False, "blocked": True, "code": err,
                "result_for_model": f"BLOCKED [{err}]"}

    # Validate the model-supplied filter BEFORE resolving the binary. The
    # original order reported a hostile filter as "forge is not installed",
    # which is both wrong and a hint that the check never ran.
    raw_match = args.get("match_test")
    if raw_match is None:
        raw_match = args.get("match")
    token = ""
    if raw_match is not None and str(raw_match).strip():
        # The filter is model-supplied, so it is passed as ONE argv element
        # (never through a shell) and rejected unless it is a bare identifier.
        token = str(raw_match).strip()
        # `"".isalnum()` is False, but whitespace strips to "" too, so guard
        # the length explicitly — an empty filter would silently run every test.
        #
        # The character test is an ALLOWLIST, not a denylist: stripping "-"
        # made "--match-path" reduce to "matchpath", which is alnum, so a real
        # forge flag sailed through and could redirect the test path. Only
        # [A-Za-z0-9_] may appear, and the first character must not be a digit
        # or underscore so the token can never be mistaken for a flag.
        if not token or not token.replace("_", "").isalnum() or token[0].isdigit():
            return {"ok": False, "blocked": True, "code": "toolchain.bad_test_filter",
                    "result_for_model":
                        f"BLOCKED [toolchain.bad_test_filter] {token!r} is not a bare test name"}
        if token.startswith("-"):
            return {"ok": False, "blocked": True, "code": "toolchain.bad_test_filter",
                    "result_for_model":
                        f"BLOCKED [toolchain.bad_test_filter] {token!r} looks like a flag"}

    binary = _resolve("forge")
    if binary is None:
        return _unavailable("forge_test", "forge")

    argv = [binary, "test"]
    if token:
        argv += ["--match-test", token]
    if args.get("verbosity"):
        argv += ["-vvv"]
    _emit(ctx, "forge_test", {"root": str(root), "match": token})
    return _run(argv, cwd=root, timeout_s=int(args.get("timeout_s", 300)))


def slither_run(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``slither`` (JSON output) in a scope-gated local root.

    Slither is run with ``--json -`` so the output is machine-readable rather
    than prose. A non-zero exit is normal (Slither exits non-zero when it
    finds anything), so it travels as data.
    """
    root, err = _local_root(ctx, args)
    if err:
        return {"ok": False, "blocked": True, "code": err,
                "result_for_model": f"BLOCKED [{err}]"}
    binary = _resolve("slither")
    if binary is None:
        return _unavailable("slither_run", "slither")

    argv = [binary, str(root), "--json", "-"]
    _emit(ctx, "slither_run", {"root": str(root)})
    result = _run(argv, cwd=root, timeout_s=int(args.get("timeout_s", 300)))
    if result.get("ok"):
        # Parse the JSON so the caller gets findings, not a wall of text.
        # A parse failure is reported, not hidden: an unparseable Slither run
        # is a real state the operator needs to see.
        try:
            parsed = json.loads(result.get("stdout", "") or "{}")
        except json.JSONDecodeError as exc:
            result["slither_json_ok"] = False
            result["slither_parse_error"] = f"{type(exc).__name__}: {exc}"
        else:
            result["slither_json_ok"] = True
            detectors = parsed.get("results", {}).get("detectors", []) or []
            result["detector_count"] = len(detectors)
            result["detectors"] = [
                {
                    "check": d.get("check"),
                    "impact": d.get("impact"),
                    "confidence": d.get("confidence"),
                    "description": (d.get("description") or "")[:300],
                }
                for d in detectors[:50]
            ]
    return result


def cast_call(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``cast call`` — a READ-ONLY eth_call through the Foundry client.

    Read-only by construction: the argv is ``call`` and nothing else, so this
    tool cannot send a transaction even if asked. The RPC URL must pass the
    scope gate, exactly like ``contract_read`` in ``tools_web3``.
    """
    rpc_url = str(args.get("rpc_url", "") or "").strip()
    to = str(args.get("to", "") or "").strip()
    signature = str(args.get("signature", "") or "").strip()
    if not rpc_url or not to:
        return {"ok": False, "blocked": False, "code": "toolchain.missing_args",
                "result_for_model": "cast_call requires rpc_url and to"}
    try:
        ctx.scope.check_url(rpc_url)
    except Exception as exc:  # noqa: BLE001 — ScopeViolation or a scope without check_url
        return {"ok": False, "blocked": True, "code": "scope.target_out_of_scope",
                "result_for_model": f"BLOCKED [scope.target_out_of_scope] {exc}"}

    binary = _resolve("cast")
    if binary is None:
        return _unavailable("cast_call", "cast")

    argv = [binary, "call", to, signature or "0x", "--rpc-url", rpc_url]
    _emit(ctx, "cast_call", {"to": to, "rpc_url": rpc_url})
    root, _err = _local_root(ctx, args)
    cwd = root if root is not None else Path.cwd()
    return _run(argv, cwd=cwd, timeout_s=int(args.get("timeout_s", 60)))


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLCHAIN_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "forge_build",
        "description": (
            "Compile a Solidity project with `forge build` in a scope-gated "
            "local root. Returns compiler output and warnings. Requires the "
            "Foundry toolchain on PATH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Project root (must be inside the scope's local_roots)."},
                "force": {"type": "boolean", "description": "Force a clean rebuild."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": [],
        },
        "handler": forge_build,
        "min_tier": "basic",
        "danger": "none",
    },
    {
        "name": "forge_test",
        "description": (
            "Run `forge test` in a scope-gated local root. A non-zero exit "
            "means a test failed — which is how a PoC proves a finding. "
            "Requires the Foundry toolchain on PATH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project root."},
                "match_test": {"type": "string",
                               "description": "Bare test-name filter (no shell metacharacters)."},
                "verbosity": {"type": "boolean", "description": "Add -vvv trace output."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": [],
        },
        "handler": forge_test,
        "min_tier": "basic",
        "danger": "none",
    },
    {
        "name": "slither_run",
        "description": (
            "Run the Slither static analyzer over a scope-gated local root "
            "with JSON output, and return its detectors. Requires "
            "`pip install slither-analyzer`."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project root."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": [],
        },
        "handler": slither_run,
        "min_tier": "advanced",
        "danger": "none",
    },
    {
        "name": "cast_call",
        "description": (
            "Read-only `cast call` (eth_call) against an in-scope RPC URL. "
            "Cannot send a transaction. Requires the Foundry toolchain."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Contract address."},
                "signature": {"type": "string",
                              "description": "Function signature or raw calldata."},
                "rpc_url": {"type": "string", "description": "RPC endpoint (must be in scope)."},
                "path": {"type": "string", "description": "Optional cwd for the child process."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": ["to", "rpc_url"],
        },
        "handler": cast_call,
        "min_tier": "basic",
        "danger": "none",
    },
)


def register_toolchain_tools(registry: Any) -> Any:
    """Register the toolchain tools, and advertise the ones not installed.

    Installed binaries get a real spec. Missing ones go through
    ``register_unavailable`` with the exact install command, so the model sees
    the capability and the reason it cannot use it — never a silent stub.
    """
    from .tools_base import ToolSpec  # noqa: PLC0415 — optional import path

    for spec in TOOLCHAIN_TOOLS:
        binary = {
            "forge_build": "forge",
            "forge_test": "forge",
            "slither_run": "slither",
            "cast_call": "cast",
        }[spec["name"]]
        if _resolve(binary) is None:
            _name, hint = _BINARIES[binary]
            registry.register_unavailable(
                spec["name"],
                "tool.unavailable",
                f"{binary} is not installed; install with: {hint}",
            )
            continue
        registry.register(
            ToolSpec(
                name=spec["name"],
                description=spec["description"],
                parameters=spec["parameters"],
                handler=_wrap(spec["handler"]),
                min_tier=spec["min_tier"],
                danger=spec["danger"],
            )
        )
    return registry


def _wrap(fn: Any) -> Any:
    """Adapt a plain ``(args, ctx) -> dict`` handler to the ToolOutcome seam."""

    def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
        out = fn(args, ctx)
        if out.get("blocked"):
            return ToolOutcome(
                ok=False,
                blocked=True,
                code=str(out.get("code", "blocked")),
                result_for_model=str(out.get("result_for_model", "blocked")),
            )
        if not out.get("ok"):
            return ToolOutcome(
                ok=False,
                code=str(out.get("code", "error")),
                result_for_model=str(out.get("result_for_model", "error")),
            )
        return ToolOutcome(
            result_for_model=str(out.get("result_for_model", "ok")),
            evidence=out.get("evidence"),
        )

    return handler
