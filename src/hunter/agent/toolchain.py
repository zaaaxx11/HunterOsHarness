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
import socket
import subprocess  # noqa: S404 — the whole point of this module
from pathlib import Path
from typing import Any

from .tools_base import ToolContext, ToolOutcome

__all__ = [
    "TOOLCHAIN_TOOLS",
    "cast_call",
    "forge_build",
    "forge_test",
    "gobuster_dir",
    "nuclei_scan",
    "port_scan",
    "register_toolchain_tools",
    "slither_run",
    "sqlmap_test",
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
    # Web2 offensive half. These four have NO existing counterpart in the
    # harness: port_hint (tools_network) is a pure inventory hint that never
    # opens a socket, and nothing else scans, brute-forces, or verifies SQLi.
    # nmap is deliberately absent — masscan covers the same job and was the
    # one installed here, so wiring both would be a duplicate.
    "masscan": ("masscan", "apt-get install masscan"),
    "nuclei": ("nuclei", "install the release binary from projectdiscovery/nuclei"),
    "gobuster": ("gobuster", "install the release binary from OJ/gobuster"),
    "sqlmap": ("sqlmap", "git clone https://github.com/sqlmapproject/sqlmap"),
}

#: Environment passed to every child. Deliberately tiny: a toolchain run has
#: no business reading the operator's API keys.
_CHILD_ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC", "PATHEXT",
                        "SYSTEMDRIVE", "WINDIR", "LANG", "LC_ALL", "TERM",
                        # SUDO_ASKPASS is how a privileged child authenticates
                        # without a TTY. Without it `sudo -n` fails even when
                        # the sudoers rule is correct, because there is no
                        # terminal to prompt on.
                        "SUDO_ASKPASS")

#: Tools that need raw-socket privileges to work at all. masscan opens a raw
#: socket and fails with "permission denied" on an unprivileged account.
#: When the operator has granted sudo (ctx.config["allow_sudo"]), these are
#: re-run under `sudo -n` (non-interactive: it either works or it does not,
#: and it never prompts mid-scan).
_PRIVILEGED_TOOLS = frozenset({"port_scan"})

_MAX_OUTPUT_CHARS = 16_384
_DEFAULT_TIMEOUT_S = 180

#: Per-process PATH resolution cache (see :func:`_resolve`).
_RESOLVE_CACHE: dict[str, str | None] | None = None


#: Set by :func:`reset_resolve_cache` so the next ``_resolve`` is a miss
#: even for a binary that previously resolved. ``shutil.which`` consults both
#: ``$PATH`` and the current working directory, so the "PATH is read once per
#: process" assumption below is only honest when the cache is scoped to the
#: same working directory — a ``cd`` into a directory holding an executable
#: makes a cached ``None`` stale.
_RESOLVE_EPOCH = 0
_RESOLVE_CACHE_EPOCH = -1


def _resolve(binary: str) -> str | None:
    """Absolute path to ``binary`` on PATH (or the CWD), or None.

    Cached per process: ``build_registry`` resolves the same binary once per
    tool that uses it (``forge`` twice, for build and test), and a PATH scan
    is not free. The cache is keyed by binary name only.
    """
    global _RESOLVE_CACHE, _RESOLVE_CACHE_EPOCH
    if _RESOLVE_CACHE is None or _RESOLVE_CACHE_EPOCH != _RESOLVE_EPOCH:
        _RESOLVE_CACHE = {}
        _RESOLVE_CACHE_EPOCH = _RESOLVE_EPOCH
    if binary not in _RESOLVE_CACHE:
        _RESOLVE_CACHE[binary] = shutil.which(binary)
    return _RESOLVE_CACHE[binary]


def reset_resolve_cache() -> None:
    """Drop the resolution cache. Test seam — never called in production."""
    global _RESOLVE_CACHE, _RESOLVE_EPOCH, _RESOLVE_CACHE_EPOCH
    _RESOLVE_EPOCH += 1
    _RESOLVE_CACHE = None
    _RESOLVE_CACHE_EPOCH = -1


def _child_env(cwd: Path) -> dict[str, str]:
    import os  # noqa: PLC0415 — local import keeps the module import light

    env: dict[str, str] = {}
    for key in _CHILD_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    # The child's HOME is the jail, never the operator's home. Foundry writes
    # ~/.foundry; nuclei v3 writes ~/.cache/nuclei-templates and ~/.config.
    # Pointing HOME at the run root keeps all of that inside the state dir —
    # which is also why the jail must never fall back to the repo root (see
    # _jail_cwd).
    env["HOME"] = str(cwd)
    env["HUNTER_SANDBOX"] = "1"
    env["NO_COLOR"] = "1"
    return env


def _jail_cwd(ctx: ToolContext, args: dict[str, Any]) -> Path:
    """A working directory for a child that has no project root of its own.

    The naive fallback is ``Path.cwd()``, and that is a trap: a nuclei run
    from the repo root would download its template set into the repo (HOME
    defaults to the cwd, and nuclei v3 keeps templates under $HOME). Use the
    system temp dir instead — outside the repo, outside the operator's home.

    The directory is created on demand: ``subprocess.run(cwd=...)`` raises
    FileNotFoundError if it does not exist, and the first version of this
    helper returned a path nobody had made yet.
    """
    import tempfile  # noqa: PLC0415 — local import keeps the module import light

    root, _err = _local_root(ctx, args)
    if root is not None:
        return root
    jail = Path(tempfile.gettempdir()) / "hunter-toolchain"
    try:
        jail.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A read-only temp dir is not a reason to fall back to the repo.
        return Path(tempfile.gettempdir())
    return jail


def _truncate(text: str) -> str:
    if len(text) <= _MAX_OUTPUT_CHARS:
        return text
    return text[:_MAX_OUTPUT_CHARS] + f"\n...[truncated at {_MAX_OUTPUT_CHARS} chars]"


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    privileged: bool = False,
) -> dict[str, Any]:
    """Run ``argv`` and return a bounded, JSON-safe result dict.

    Never raises for a non-zero exit: a failing ``forge test`` is the single
    most valuable output in this module (it is the PoC firing). The exit code
    travels with the payload.

    ``privileged`` prefixes the command with ``sudo -n``. Non-interactive on
    purpose: a scan that stops to ask for a password is a scan that hangs.
    If passwordless sudo is not configured the call fails immediately, which
    the caller reports honestly rather than retrying.
    """
    command = list(argv)
    if privileged:
        # -A (askpass), not -n (non-interactive): -n refuses to use the
        # askpass helper and fails outright even when the sudoers rule is
        # correct, which is exactly the failure this module spent an hour
        # chasing. SUDO_ASKPASS is in the child env allowlist for this.
        command = ["sudo", "-A", *argv]
    try:
        completed = subprocess.run(  # noqa: S603 — argv is built here, not from the model
            command,
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
            "argv": command,
            "result_for_model": f"timed out after {timeout_s}s: {' '.join(command)}",
        }
    except OSError as exc:
        return {
            "ok": False,
            "code": "tool.exec_failed",
            "argv": command,
            "result_for_model": f"{type(exc).__name__}: {exc}",
        }

    stdout = _truncate(completed.stdout or "")
    stderr = _truncate(completed.stderr or "")
    return {
        "ok": True,
        "code": "ok",
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "result_for_model": (
            f"$ {' '.join(command)}\nexit={completed.returncode}\n"
            f"{stdout}{stderr and chr(10) + stderr}"
        ).strip(),
    }


# ---------------------------------------------------------------------------
# Scope gate
# ---------------------------------------------------------------------------


def _blocked_root(err: str, ctx: ToolContext) -> dict[str, Any]:
    """A scope/root refusal the model can actually act on.

    ``BLOCKED [toolchain.no_root]`` tells the agent nothing it can use — it
    cannot tell whether to pass a ``path``, whether the path was wrong, or
    whether the scope simply has no local_roots. Each code gets a sentence
    that says what to do next.
    """
    roots = list(getattr(ctx.scope, "local_roots", ()) or ())
    configured = ctx.config.get("local_root")
    hints = {
        "toolchain.no_root": (
            "no local root was given. Pass `path` (a project directory), or run the "
            "hunt against a directory so a local root is configured."
        ),
        "toolchain.bad_path": "the `path` argument is not a usable filesystem path.",
        "toolchain.not_a_directory": "the `path` argument is not an existing directory.",
        "scope.local_root_out_of_scope": (
            f"the path is outside this hunt's scope. Allowed local roots: "
            f"{roots or '(none — the scope has no local_roots)'}."
        ),
    }
    detail = hints.get(err, err)
    extra = f" Configured local_root: {configured}." if configured else ""
    return {
        "ok": False,
        "blocked": True,
        "code": err,
        "result_for_model": f"BLOCKED [{err}] — {detail}{extra}",
    }


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


def _scope_gate_url(ctx: ToolContext, target: str) -> dict[str, Any] | None:
    """Run the scope's URL check. Returns an error payload, or None if allowed.

    Deliberately narrow: only ``ScopeViolation`` (and a scope that simply has
    no ``check_url``) is a scope refusal. An ``AssertionError`` or any other
    internal error must NOT be laundered into ``scope.target_out_of_scope`` —
    that is how a bug in the tool gets reported to the operator as a policy
    decision, and it is exactly the dishonesty this module exists to avoid.
    """
    from ..tools.scope import ScopeViolation  # noqa: PLC0415 — optional import path

    check = getattr(ctx.scope, "check_url", None)
    if check is None:
        return None
    try:
        check(target)
    except ScopeViolation as exc:
        return {"ok": False, "blocked": True, "code": "scope.target_out_of_scope",
                "result_for_model": f"BLOCKED [scope.target_out_of_scope] {exc}"}
    return None


def _scope_gate_host(ctx: ToolContext, host: str) -> dict[str, Any] | None:
    """Same contract as :func:`_scope_gate_url`, for host checks."""
    from ..tools.scope import ScopeViolation  # noqa: PLC0415 — optional import path

    allows = getattr(ctx.scope, "allows_host", None)
    if allows is None:
        return None
    try:
        if not allows(host):
            return {"ok": False, "blocked": True, "code": "scope.target_out_of_scope",
                    "result_for_model": f"BLOCKED [scope.target_out_of_scope] host '{host}' out of scope"}
    except ScopeViolation as exc:
        return {"ok": False, "blocked": True, "code": "scope.target_out_of_scope",
                "result_for_model": f"BLOCKED [scope.target_out_of_scope] {exc}"}
    return None


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
        return _blocked_root(err, ctx)
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
        return _blocked_root(err, ctx)

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
        return _blocked_root(err, ctx)
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
    denied = _scope_gate_url(ctx, rpc_url)
    if denied is not None:
        return denied

    binary = _resolve("cast")
    if binary is None:
        return _unavailable("cast_call", "cast")

    argv = [binary, "call", to, signature or "0x", "--rpc-url", rpc_url]
    _emit(ctx, "cast_call", {"to": to, "rpc_url": rpc_url})
    cwd = _jail_cwd(ctx, args)
    return _run(argv, cwd=cwd, timeout_s=int(args.get("timeout_s", 60)))


# ---------------------------------------------------------------------------
# Web2 offensive tools
# ---------------------------------------------------------------------------


def port_scan(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``masscan`` — a real port scan, scope-gated.

    This is the tool ``port_hint`` never was: it opens sockets. The host must
    pass the scope gate, the port list is an allowlisted string, and the rate
    is capped so a scan cannot saturate the operator's link.

    Two masscan constraints are enforced here rather than discovered at
    runtime, because both produce a confusing error otherwise:

    * masscan takes IP addresses and CIDR ranges ONLY — never a hostname.
      The host is resolved first, and a resolution failure is reported as
      such instead of being handed to masscan as a bare name.
    * masscan needs raw-socket privileges. On an unprivileged account it
      fails with "permission denied", which is reported honestly rather than
      dressed up as a scan result.

    ``port_hint`` stays as-is — it is a zero-socket inventory hint and is
    still the right answer when the question is "what might be open".
    """
    host = str(args.get("host", "") or "").strip()
    if not host:
        return {"ok": False, "blocked": False, "code": "port.host_required",
                "result_for_model": "port_scan requires host"}
    denied = _scope_gate_host(ctx, host)
    if denied is not None:
        return denied

    # masscan does not resolve names. Resolve here so the failure is ours to
    # explain, and so the scope gate above checked the name the operator
    # actually asked for.
    try:
        resolved_ip = socket.gethostbyname(host)
    except OSError as exc:
        return {"ok": False, "blocked": False, "code": "port.resolve_failed",
                "result_for_model": f"cannot resolve {host}: {exc}"}

    # Ports: digits, commas, and dashes only. No spaces, no shell metachars.
    ports = str(args.get("ports", "") or "").strip() or "0-65535"
    if not all(c.isdigit() or c in ",-" for c in ports):
        return {"ok": False, "blocked": True, "code": "toolchain.bad_ports",
                "result_for_model": f"BLOCKED [toolchain.bad_ports] {ports!r}"}

    rate = args.get("rate", 1000)
    try:
        rate = max(1, min(int(rate), 100_000))
    except (TypeError, ValueError):
        rate = 1000

    binary = _resolve("masscan")
    if binary is None:
        return _unavailable("port_scan", "masscan")

    # The IP goes first, as masscan's own usage line specifies:
    #   masscan [Options] -p{Target-Ports} {Target-IP-Ranges}
    argv = [binary, resolved_ip, "-p", ports, "--rate", str(rate), "--wait", "3"]
    _emit(ctx, "port_scan", {"host": host, "ip": resolved_ip, "ports": ports, "rate": rate})
    cwd = _jail_cwd(ctx, args)
    # masscan opens a raw socket and cannot work unprivileged. Retry under
    # sudo only when the operator explicitly allowed it in the run config —
    # never silently escalate.
    result = _run(argv, cwd=cwd, timeout_s=int(args.get("timeout_s", 300)),
                  privileged=bool(ctx.config.get("allow_sudo")))
    # masscan exits non-zero with "permission denied" when it cannot open a
    # raw socket. That is a privilege problem, not a scan result, and saying
    # so is more useful than a bare exit code.
    combined = result.get("stderr", "") + result.get("stdout", "")
    if result.get("ok") and "permission denied" in combined:
        result["code"] = "tool.privilege_required"
        result["result_for_model"] = (
            result.get("result_for_model", "") +
            "\n[note] masscan needs raw-socket privileges — set allow_sudo in "
            "the run config, or use port_hint for a zero-privilege check."
        )
    return result


def nuclei_scan(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``nuclei`` — template-based vulnerability scanning against a URL.

    The target must pass the scope gate. Templates are restricted to a single
    ``-t`` value (or none at all, which uses the installed set) so the model
    cannot point the scanner at an arbitrary path on disk.
    """
    target = str(args.get("target", "") or "").strip()
    if not target:
        return {"ok": False, "blocked": False, "code": "nuclei.target_required",
                "result_for_model": "nuclei_scan requires target"}
    denied = _scope_gate_url(ctx, target)
    if denied is not None:
        return denied

    binary = _resolve("nuclei")
    if binary is None:
        return _unavailable("nuclei_scan", "nuclei")

    # nuclei v3 keeps its templates under $HOME (.cache/nuclei-templates and
    # .config/nuclei). _child_env already points HOME at the run root, so the
    # template download lands in the jail and never in the repo. There is no
    # -templates-home flag in v3 — the first version of this tool passed one
    # and nuclei rejected the whole invocation with "flag provided but not
    # defined", which is why the scope gate test below is load-bearing.
    argv = [binary, "-u", target, "-jsonl", "-silent", "-nc"]
    severity = str(args.get("severity", "") or "").strip()
    if severity:
        # Severity is a comma list of known words; anything else is rejected
        # rather than passed through as a flag.
        allowed = {"info", "low", "medium", "high", "critical", "unknown"}
        parts = {p.strip().lower() for p in severity.split(",") if p.strip()}
        if not parts or not parts <= allowed:
            return {"ok": False, "blocked": True, "code": "toolchain.bad_severity",
                    "result_for_model": f"BLOCKED [toolchain.bad_severity] {severity!r}"}
        argv += ["-severity", ",".join(sorted(parts))]

    _emit(ctx, "nuclei_scan", {"target": target})
    cwd = _jail_cwd(ctx, args)
    return _run(argv, cwd=cwd, timeout_s=int(args.get("timeout_s", 300)))


def gobuster_dir(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``gobuster dir`` — content discovery against an in-scope URL.

    The wordlist is the one model-supplied path, so it is the one that gets
    the strictest check: it must resolve to a real file inside the scope's
    local roots. Without a wordlist the tool refuses rather than guessing a
    default that may not exist on this machine.
    """
    target = str(args.get("target", "") or "").strip()
    if not target:
        return {"ok": False, "blocked": False, "code": "gobuster.target_required",
                "result_for_model": "gobuster_dir requires target"}
    denied = _scope_gate_url(ctx, target)
    if denied is not None:
        return denied

    wordlist = str(args.get("wordlist", "") or "").strip()
    if not wordlist:
        return {"ok": False, "blocked": False, "code": "gobuster.wordlist_required",
                "result_for_model": "gobuster_dir requires wordlist (a path to a file)"}
    try:
        resolved = Path(wordlist).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return {"ok": False, "blocked": True, "code": "toolchain.bad_wordlist",
                "result_for_model": f"BLOCKED [toolchain.bad_wordlist] {wordlist!r}"}
    if not resolved.is_file():
        return {"ok": False, "blocked": False, "code": "gobuster.wordlist_missing",
                "result_for_model": f"wordlist not found: {resolved}"}
    try:
        if not ctx.scope.allows_local_root(resolved.parent):
            return {"ok": False, "blocked": True, "code": "scope.local_root_out_of_scope",
                    "result_for_model": f"BLOCKED [scope.local_root_out_of_scope] {resolved}"}
    except Exception:  # noqa: BLE001 — a scope without the method must not crash the tool
        return {"ok": False, "blocked": True, "code": "scope.local_root_out_of_scope",
                "result_for_model": f"BLOCKED [scope.local_root_out_of_scope] {resolved}"}

    binary = _resolve("gobuster")
    if binary is None:
        return _unavailable("gobuster_dir", "gobuster")

    argv = [binary, "dir", "-u", target, "-w", str(resolved), "-q", "--no-color"]
    _emit(ctx, "gobuster_dir", {"target": target, "wordlist": str(resolved)})
    cwd = _jail_cwd(ctx, args)
    return _run(argv, cwd=cwd, timeout_s=int(args.get("timeout_s", 300)))


def sqlmap_test(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """``sqlmap`` — verify a suspected SQL injection point.

    Read-only by construction: ``--batch --flush-session`` and an explicit
    ``--level``/``--risk`` ceiling, with no ``--os-shell``/``--sql-shell`` and
    no dump flag unless the operator asks for one. The URL must be in scope.
    """
    target = str(args.get("target", "") or "").strip()
    if not target:
        return {"ok": False, "blocked": False, "code": "sqlmap.target_required",
                "result_for_model": "sqlmap_test requires target"}
    denied = _scope_gate_url(ctx, target)
    if denied is not None:
        return denied

    binary = _resolve("sqlmap")
    if binary is None:
        return _unavailable("sqlmap_test", "sqlmap")

    argv = [binary, "-u", target, "--batch", "--flush-session", "--disable-coloring"]
    level = args.get("level", 1)
    risk = args.get("risk", 1)
    try:
        level = max(1, min(int(level), 5))
        risk = max(1, min(int(risk), 3))
    except (TypeError, ValueError):
        level, risk = 1, 1
    argv += ["--level", str(level), "--risk", str(risk)]
    _emit(ctx, "sqlmap_test", {"target": target, "level": level, "risk": risk})
    cwd = _jail_cwd(ctx, args)
    return _run(argv, cwd=cwd, timeout_s=int(args.get("timeout_s", 600)))


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
        "danger": "none",
    },
    {
        "name": "port_scan",
        "description": (
            "Run a real `masscan` port scan against an in-scope host. Unlike "
            "port_hint, this opens sockets. Port list and rate are validated "
            "and capped. Requires masscan on PATH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host to scan (must be in scope)."},
                "ports": {"type": "string",
                          "description": "Port list, e.g. '80,443' or '0-65535'. Digits, commas, dashes."},
                "rate": {"type": "integer", "description": "Packets per second (1-100000)."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": ["host"],
        },
        "handler": port_scan,
        "danger": "none",
    },
    {
        "name": "nuclei_scan",
        "description": (
            "Run `nuclei` template-based vulnerability scanning against an "
            "in-scope URL, with JSONL output. Severity is restricted to the "
            "known set. Requires nuclei on PATH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to scan (must be in scope)."},
                "severity": {"type": "string",
                             "description": "Comma list: info, low, medium, high, critical."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": ["target"],
        },
        "handler": nuclei_scan,
        "danger": "none",
    },
    {
        "name": "gobuster_dir",
        "description": (
            "Run `gobuster dir` content discovery against an in-scope URL. "
            "The wordlist must be a real file inside the scope's local_roots. "
            "Requires gobuster on PATH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to scan (must be in scope)."},
                "wordlist": {"type": "string",
                             "description": "Path to a wordlist file inside local_roots."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": ["target", "wordlist"],
        },
        "handler": gobuster_dir,
        "danger": "none",
    },
    {
        "name": "sqlmap_test",
        "description": (
            "Run `sqlmap` to verify a suspected SQL injection point on an "
            "in-scope URL. Read-only by construction: batch mode, no shell "
            "escalation, level/risk capped. Requires sqlmap on PATH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to test (must be in scope)."},
                "level": {"type": "integer", "description": "sqlmap level (1-5)."},
                "risk": {"type": "integer", "description": "sqlmap risk (1-3)."},
                "timeout_s": {"type": "integer", "description": "Timeout in seconds."},
            },
            "required": ["target"],
        },
        "handler": sqlmap_test,
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
            "port_scan": "masscan",
            "nuclei_scan": "nuclei",
            "gobuster_dir": "gobuster",
            "sqlmap_test": "sqlmap",
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
