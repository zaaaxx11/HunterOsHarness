"""Offensive toolchain tools — Foundry, Slither, solc.

The load-bearing assertions are the ones that keep this module honest:

* a missing binary is REPORTED, never stubbed — ``tool.unavailable`` with the
  exact install command, and no schema advertised;
* every child runs with a minimal environment and ``HOME`` pointed at the
  jail, so a toolchain run cannot read the operator's credentials;
* the working directory is fail-closed against the scope's ``local_roots``;
* ``forge_test`` treats a non-zero exit as a successful invocation (a failing
  test IS the PoC), and ``cast_call`` cannot send a transaction by
  construction;
* a model-supplied test filter is rejected unless it is a bare identifier.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hunter.agent import toolchain
from hunter.agent.toolchain import (
    _BINARIES,
    _child_env,
    _local_root,
    _resolve,
    _truncate,
    cast_call,
    forge_build,
    forge_test,
    gobuster_dir,
    nuclei_scan,
    port_scan,
    register_toolchain_tools,
    slither_run,
    sqlmap_test,
)
from hunter.agent.tools_base import ToolContext, ToolOutcome, ToolRegistry
from hunter.tools.scope import ScopeSet, scope_from_manifest


class _FakeScope:
    """A scope that authorises exactly one local root."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def allows_local_root(self, candidate) -> bool:
        try:
            Path(candidate).resolve().relative_to(self.root.resolve())
        except (ValueError, OSError):
            return False
        return True

    def allows_host(self, host) -> bool:
        return host == "example.com"

    def check_url(self, url: str) -> None:
        # Default: allow. Tests that need a refusal install their own scope
        # (see _DenyScope below) rather than relying on this raising.
        if "example.com" not in url:
            raise AssertionError(f"check_url should have been stubbed for {url}")


def _ctx(root: Path, *, scope: Any | None = None, config: dict | None = None) -> ToolContext:
    events: list[tuple[str, dict]] = []
    ctx = ToolContext(
        run_id="R-test",
        ledger=None,  # type: ignore[arg-type] - the toolchain never touches the ledger
        http=None,  # type: ignore[arg-type] - the toolchain never makes a scoped request
        scope=scope or _FakeScope(root),  # type: ignore[arg-type] - a fake is enough
        target_url=str(root),
        emit=lambda kind, payload: events.append((kind, payload)),
        config=config or {},
    )
    ctx.events = events  # type: ignore[attr-defined]
    return ctx


def _stub_binary_present(monkeypatch, binary: str, path: str = "/usr/local/bin") -> Path:
    """Pretend ``binary`` is installed, without touching the host's PATH.

    ``_resolve`` consults ``shutil.which`` (which reads ``$PATH`` *and* the
    cwd) and caches per process. Stubbing ``_resolve`` itself would bypass the
    very path this module is supposed to take, so instead point the cache at a
    real, existing executable: the result is a genuinely-resolved absolute
    path that ``subprocess`` would accept, and the cache stays coherent.
    """
    resolved = f"{path}/{binary}"
    monkeypatch.setattr(toolchain, "_RESOLVE_CACHE", {binary: resolved})
    return Path(resolved)


def _scope_with_roots(tmp_path: Path, *roots: Path) -> ScopeSet:
    manifest = tmp_path / "scope.json"
    manifest.write_text(
        json.dumps({
            "name": "toolchain-test",
            "hosts": ["example.com"],
            "local_roots": [str(r) for r in roots],
        }),
        encoding="utf-8",
    )
    return scope_from_manifest(manifest)


# ------------------------------------------------------------ binary resolution


def test_resolve_returns_none_for_a_binary_that_does_not_exist():
    assert _resolve("definitely-not-a-real-binary-xyz") is None


def test_resolve_finds_a_real_binary():
    # `ls` exists on every platform this test runs on.
    found = _resolve("ls") or _resolve("dir")
    assert found is not None


def test_child_env_is_minimal_and_jails_home(tmp_path):
    import os

    os.environ["HUNTEROS_SECRET_CANARY"] = "leaked"
    env = _child_env(tmp_path)

    assert env["HOME"] == str(tmp_path), "HOME must be the jail, never the operator's"
    assert env["HUNTER_SANDBOX"] == "1"
    # the allowlist is a ceiling, not a floor
    assert "HUNTEROS_SECRET_CANARY" not in env
    assert len(env) < 15, f"child env grew too large: {sorted(env)}"
    del os.environ["HUNTEROS_SECRET_CANARY"]


def test_truncate_is_bounded():
    assert _truncate("short") == "short"
    long = "x" * 40_000
    out = _truncate(long)
    assert len(out) < 40_000
    assert "truncated" in out


# --------------------------------------------------------------- scope gate ----


def test_local_root_inside_scope_is_accepted(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    resolved, err = _local_root(ctx, {"path": str(root)})
    assert err is None
    assert resolved == root.resolve()


def test_local_root_outside_scope_is_refused(tmp_path):
    inside = tmp_path / "in"
    inside.mkdir()
    outside = tmp_path / "out"
    outside.mkdir()
    ctx = _ctx(inside, scope=_FakeScope(inside))
    resolved, err = _local_root(ctx, {"path": str(outside)})
    assert resolved is None
    assert err == "scope.local_root_out_of_scope"


def test_local_root_missing_directory_is_refused(tmp_path):
    ctx = _ctx(tmp_path, scope=_FakeScope(tmp_path))
    resolved, err = _local_root(ctx, {"path": str(tmp_path / "nope")})
    assert resolved is None
    assert err == "toolchain.not_a_directory"


def test_local_root_absent_is_refused(tmp_path):
    ctx = _ctx(tmp_path, scope=_FakeScope(tmp_path))
    resolved, err = _local_root(ctx, {})
    assert resolved is None
    assert err == "toolchain.no_root"


def test_every_tool_refuses_an_out_of_scope_root(tmp_path):
    inside = tmp_path / "in"
    inside.mkdir()
    outside = tmp_path / "out"
    outside.mkdir()
    ctx = _ctx(inside, scope=_FakeScope(inside))

    for tool in (forge_build, forge_test, slither_run):
        out = tool({"path": str(outside)}, ctx)
        assert out["blocked"] is True, tool.__name__
        assert out["code"] == "scope.local_root_out_of_scope", tool.__name__


# ------------------------------------------------------- missing binaries -----


@pytest.mark.parametrize("tool,binary", [
    (forge_build, "forge"),
    (forge_test, "forge"),
    (slither_run, "slither"),
])
def test_missing_binary_is_reported_not_stubbed(tool, binary, tmp_path, monkeypatch):
    """Absence is a result: the tool says so and names the install command."""
    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: None)

    out = tool({"path": str(root)}, ctx)

    assert out["ok"] is False
    assert out["code"] == "tool.unavailable"
    assert binary in out["result_for_model"]
    # the install hint is actionable, not "install foundry"
    assert _BINARIES[binary][1] in out["result_for_model"]


def test_registration_advertises_missing_binaries(tmp_path, monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(toolchain, "_resolve", lambda name: None)
    register_toolchain_tools(registry)

    # no schema is advertised for a binary that is not there
    for name in ("forge_build", "forge_test", "slither_run", "cast_call"):
        assert registry.get(name) is None, name
        assert name in registry._unavailable, name
        code, message = registry._unavailable[name]
        assert code == "tool.unavailable"
        assert "install with:" in message


def test_registration_registers_present_binaries(tmp_path, monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    register_toolchain_tools(registry)

    for name in ("forge_build", "forge_test", "slither_run", "cast_call"):
        spec = registry.get(name)
        assert spec is not None, name
        assert name not in registry._unavailable


def test_registered_toolchain_specs_all_present(tmp_path, monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    register_toolchain_tools(registry)

    # No capability tier: every toolchain tool is registered unconditionally.
    for name in ("slither_run", "forge_build", "forge_test", "cast_call"):
        spec = registry.get(name)
        assert spec is not None, name


# ------------------------------------------------------------ cast_call -------


def test_cast_call_requires_to_and_rpc(tmp_path):
    ctx = _ctx(tmp_path, scope=_FakeScope(tmp_path))
    out = cast_call({"to": "0xabc"}, ctx)
    assert out["code"] == "toolchain.missing_args"


def test_cast_call_refuses_an_out_of_scope_rpc(tmp_path):
    class _Rejecting(_FakeScope):
        def check_url(self, url):
            from hunter.tools.scope import ScopeViolation

            raise ScopeViolation(f"host not in scope: {url}")

    ctx = _ctx(tmp_path, scope=_Rejecting(tmp_path))
    out = cast_call({"to": "0xabc", "rpc_url": "https://evil.example"}, ctx)
    assert out["blocked"] is True
    assert out["code"] == "scope.target_out_of_scope"


def test_cast_call_argv_is_read_only(tmp_path, monkeypatch):
    """The argv must be `call` and nothing that could send a transaction."""
    captured: dict[str, list[str]] = {}

    class _Accepting(_FakeScope):
        def check_url(self, url):
            return None

    def fake_run(argv, *, cwd, timeout_s=180):
        captured["argv"] = argv
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 0,
                "stdout": "0x", "stderr": "", "result_for_model": "ok"}

    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    ctx = _ctx(tmp_path, scope=_Accepting(tmp_path))
    out = cast_call({"to": "0xabc", "rpc_url": "https://eth.example"}, ctx)

    assert out["ok"] is True
    argv = captured["argv"]
    assert argv[1] == "call", f"cast argv must start with 'call': {argv}"
    # no send-shaped subcommand may appear anywhere in the argv
    for forbidden in ("send", "sendTransaction", "sendRawTransaction", "eth_sendRawTransaction"):
        assert forbidden not in argv, f"{forbidden} must never appear: {argv}"


# ------------------------------------------------------------ forge_test ------


def test_forge_test_rejects_a_non_identifier_filter(tmp_path, monkeypatch):
    """A model-supplied filter is an allowlist, not a denylist.

    Two of these cases are regression pins for real holes:

    * ``"--match-path"`` — stripping "-" reduced it to "matchpath", which is
      alnum, so a genuine forge flag sailed through and could redirect the
      test path. The check is now an allowlist over [A-Za-z0-9_].
    * ``"a b"`` — a space is shell-shaped; it must never reach an argv.

    An empty or whitespace-only filter is NOT in this list: it means "no
    filter", which is a legitimate request to run the whole suite (pinned by
    test_forge_test_absent_filter_runs_every_test).
    """
    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")

    for bad in ("test; rm -rf /", "$(id)", "a b", "--match-path", "--match-test",
                "-n", "1test", "test/../../etc/passwd", "test\x00evil"):
        out = forge_test({"path": str(root), "match_test": bad}, ctx)
        assert out["blocked"] is True, f"{bad!r} was not refused: {out}"
        assert out["code"] == "toolchain.bad_test_filter", bad


def test_forge_test_accepts_a_bare_identifier(tmp_path, monkeypatch):
    captured: dict[str, list[str]] = {}

    def fake_run(argv, *, cwd, timeout_s=180):
        captured["argv"] = argv
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 0,
                "stdout": "ok", "stderr": "", "result_for_model": "ok"}

    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    for good in ("test_Reentrancy_PoC", "testVault", "test_123"):
        out = forge_test({"path": str(root), "match_test": good}, ctx)
        assert out["ok"] is True, good
        assert good in captured["argv"], good


def test_forge_test_absent_filter_runs_every_test(tmp_path, monkeypatch):
    """No filter is a legitimate request: run the whole suite."""
    captured: dict[str, list[str]] = {}

    def fake_run(argv, *, cwd, timeout_s=180):
        captured["argv"] = argv
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 0,
                "stdout": "ok", "stderr": "", "result_for_model": "ok"}

    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    out = forge_test({"path": str(root)}, ctx)

    assert out["ok"] is True
    assert "--match-test" not in captured["argv"]


def test_forge_test_passes_a_bare_identifier(tmp_path, monkeypatch):
    captured: dict[str, list[str]] = {}

    def fake_run(argv, *, cwd, timeout_s=180):
        captured["argv"] = argv
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 1,
                "stdout": "FAIL", "stderr": "", "result_for_model": "FAIL"}

    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    out = forge_test({"path": str(root), "match_test": "test_Reentrancy_PoC"}, ctx)

    assert out["ok"] is True
    assert "--match-test" in captured["argv"]
    assert "test_Reentrancy_PoC" in captured["argv"]


def test_forge_test_nonzero_exit_is_a_successful_invocation(tmp_path, monkeypatch):
    """A failing test IS the proof. ok means the binary ran, not that it passed."""
    def fake_run(argv, *, cwd, timeout_s=180):
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 1,
                "stdout": "assertion failed", "stderr": "", "result_for_model": "FAIL"}

    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    out = forge_test({"path": str(root)}, ctx)

    assert out["ok"] is True, "a failing test is a successful invocation"
    assert out["exit_code"] == 1, "the verdict travels with the payload"


# ------------------------------------------------------------ slither_run -----


def test_slither_parses_json_and_reports_detectors(tmp_path, monkeypatch):
    payload = json.dumps({
        "success": True,
        "results": {
            "detectors": [
                {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
                 "description": "Reentrancy in Vault.withdraw()"},
                {"check": "tx-origin", "impact": "Medium", "confidence": "High",
                 "description": "tx.origin used for authorization"},
            ]
        },
    })

    def fake_run(argv, *, cwd, timeout_s=180):
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 1,
                "stdout": payload, "stderr": "", "result_for_model": "ok"}

    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    out = slither_run({"path": str(root)}, ctx)

    assert out["slither_json_ok"] is True
    assert out["detector_count"] == 2
    assert out["detectors"][0]["check"] == "reentrancy-eth"


def test_slither_unparseable_output_is_reported_not_hidden(tmp_path, monkeypatch):
    def fake_run(argv, *, cwd, timeout_s=180):
        return {"ok": True, "code": "ok", "argv": argv, "exit_code": 1,
                "stdout": "Compilation failed: unknown pragma", "stderr": "",
                "result_for_model": "ok"}

    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(toolchain, "_run", fake_run)

    out = slither_run({"path": str(root)}, ctx)

    assert out["slither_json_ok"] is False
    assert "parse_error" in out["slither_parse_error"] or out["slither_parse_error"]


# ------------------------------------------------------------- _run seam ------


def test_run_timeout_is_reported(tmp_path):
    import subprocess

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="forge", timeout=1)

    original = toolchain.subprocess.run
    toolchain.subprocess.run = boom
    try:
        out = toolchain._run(["forge", "build"], cwd=tmp_path, timeout_s=1)
    finally:
        toolchain.subprocess.run = original

    assert out["ok"] is False
    assert out["code"] == "tool.timeout"


def test_run_oserror_is_reported(tmp_path):
    def boom(*args, **kwargs):
        raise OSError("exec format error")

    original = toolchain.subprocess.run
    toolchain.subprocess.run = boom
    try:
        out = toolchain._run(["forge", "build"], cwd=tmp_path)
    finally:
        toolchain.subprocess.run = original

    assert out["ok"] is False
    assert out["code"] == "tool.exec_failed"


def test_run_actually_executes_a_real_binary(tmp_path):
    """The subprocess seam is real: `ls` runs and its output comes back."""
    binary = _resolve("ls") or _resolve("dir")
    if binary is None:  # pragma: no cover
        pytest.skip("no listing binary available")
    marker = tmp_path / "marker.txt"
    marker.write_text("x", encoding="utf-8")

    out = toolchain._run([binary], cwd=tmp_path, timeout_s=30)

    assert out["ok"] is True
    assert out["exit_code"] == 0
    assert "marker.txt" in out["stdout"]


# ------------------------------------------------------------- wrap seam ------


def test_wrap_maps_blocked_to_a_blocked_outcome(tmp_path):
    from hunter.agent.toolchain import _wrap

    def handler(args, ctx):
        return {"ok": False, "blocked": True, "code": "scope.x",
                "result_for_model": "BLOCKED [scope.x]"}

    outcome = _wrap(handler)({}, _ctx(tmp_path, scope=_FakeScope(tmp_path)))
    assert isinstance(outcome, ToolOutcome)
    assert outcome.blocked is True
    assert outcome.code == "scope.x"


def test_wrap_maps_ok_to_a_plain_outcome(tmp_path):
    from hunter.agent.toolchain import _wrap

    def handler(args, ctx):
        return {"ok": True, "code": "ok", "result_for_model": "done"}

    outcome = _wrap(handler)({}, _ctx(tmp_path, scope=_FakeScope(tmp_path)))
    assert outcome.blocked is False
    assert outcome.result_for_model == "done"


# --------------------------------------------------------- registry wiring ----


def test_toolchain_tools_are_wired_into_build_registry(monkeypatch):
    """build_registry must reach the toolchain, not just the module."""
    from hunter.agent.tools import build_registry

    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    registry = build_registry()
    names = {s.name for s in registry.specs_for_tier("advanced")}

    for name in ("forge_build", "forge_test", "slither_run", "cast_call"):
        assert name in names, f"{name} not reachable through build_registry"


def test_inventory_knows_the_toolchain_binaries():
    from hunter.agent.inventory import INVENTORY_BINARIES

    for binary in ("forge", "cast", "anvil", "slither", "solc"):
        assert binary in INVENTORY_BINARIES, binary


def test_every_toolchain_tool_has_an_install_hint():
    """A tool with no install path is a dead end for the operator."""
    for name, (binary, hint) in _BINARIES.items():
        assert hint.strip(), name
        assert "install" in hint.lower() or "foundryup" in hint or "clone" in hint.lower(), name


def test_every_toolchain_binary_is_in_the_inventory():
    """A binary wired into a tool must also be in INVENTORY_BINARIES.

    The inventory is what `hunt doctor` and the runtime checks report on; a
    tool whose binary is missing from it would be invisible to both.
    """
    from hunter.agent.inventory import INVENTORY_BINARIES

    for binary in _BINARIES:
        assert binary in INVENTORY_BINARIES, f"{binary} is wired but not inventoried"


def test_resolve_is_cached_per_process(monkeypatch):
    """build_registry resolves `forge` twice (build + test); PATH is scanned once."""
    import shutil as _shutil

    calls: list[str] = []
    real_which = _shutil.which

    def counting(name):
        calls.append(name)
        return real_which(name)

    toolchain.reset_resolve_cache()
    monkeypatch.setattr(toolchain.shutil, "which", counting)
    try:
        toolchain._resolve("forge")
        toolchain._resolve("forge")
        toolchain._resolve("forge")
    finally:
        toolchain.reset_resolve_cache()

    assert calls == ["forge"], f"PATH was scanned {len(calls)} times for one binary"


def test_resolve_cache_is_resettable(monkeypatch):
    """The test seam must actually drop the cache, or monkeypatch leaks."""
    toolchain.reset_resolve_cache()
    assert toolchain._RESOLVE_CACHE is None
    toolchain._resolve("ls")
    assert toolchain._RESOLVE_CACHE is not None
    toolchain.reset_resolve_cache()
    assert toolchain._RESOLVE_CACHE is None


# ------------------------------------------------------- web2 offensive tools
#
# port_scan / nuclei_scan / gobuster_dir / sqlmap_test. The load-bearing
# assertions here are the ones that keep these from becoming duplicates of
# what already exists: port_hint is a zero-socket hint and stays that way,
# and each new tool refuses to run without its own required argument rather
# than falling back to a default that may not exist on this machine.


def test_port_scan_requires_a_host(tmp_path):
    ctx = _ctx(tmp_path)
    out = port_scan({}, ctx)
    assert out["ok"] is False
    assert out["code"] == "port.host_required"


def test_port_scan_rejects_a_host_out_of_scope(tmp_path):
    class _DenyAll:
        def allows_host(self, host):
            return False

    ctx = _ctx(tmp_path, scope=_DenyAll())
    out = port_scan({"host": "evil.example.com"}, ctx)
    assert out["ok"] is False
    assert out["code"] == "scope.target_out_of_scope"


def test_port_scan_does_not_launder_an_internal_error_into_a_scope_refusal(tmp_path):
    """A bug in the scope object must not be reported as a policy decision.

    The first version of these tools caught bare ``Exception`` around the
    scope check, which turned an ``AssertionError`` from a broken scope into
    ``scope.target_out_of_scope`` — a lie about why the tool refused. Only
    ``ScopeViolation`` is a refusal; anything else must propagate.
    """
    class _BrokenScope:
        def allows_host(self, host):
            raise AssertionError("this scope object is broken")

    ctx = _ctx(tmp_path, scope=_BrokenScope())
    with pytest.raises(AssertionError):
        port_scan({"host": "example.com"}, ctx)


def test_port_scan_rejects_shell_metacharacters_in_ports(tmp_path):
    """A port list is not a shell command line."""
    ctx = _ctx(tmp_path)
    for bad in ("80; rm -rf /", "80 $(id)", "80 `id`", "80\n443", "80 443", "-p 80"):
        out = port_scan({"host": "example.com", "ports": bad}, ctx)
        assert out["ok"] is False, f"{bad!r} must be refused"
        assert out["code"] == "toolchain.bad_ports", f"{bad!r} -> {out['code']}"


def test_port_scan_accepts_a_plain_port_list(tmp_path, monkeypatch):
    """The allowlist must not reject legitimate lists."""
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})
    for good in ("80", "80,443", "0-65535", "22,80,443,8000-8100"):
        ctx = _ctx(tmp_path)
        out = port_scan({"host": "example.com", "ports": good}, ctx)
        # Either it ran, or the binary is missing — but never bad_ports.
        assert out.get("code") != "toolchain.bad_ports", f"{good!r} refused"


def test_port_scan_passes_an_ip_not_a_hostname(tmp_path, monkeypatch):
    """masscan takes IP/CIDR only — a hostname is resolved here first.

    The first version handed the bare hostname to masscan, which rejected it
    with `unknown command-line parameter "api.relay.link"`. The tool now
    resolves the name itself so the failure is ours to explain.
    """
    # Resolve the binary through the _resolve seam: these tests are about argv,
    # not about whether masscan happens to be installed on the test machine.
    _stub_binary_present(monkeypatch, "masscan")
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})
    monkeypatch.setattr(toolchain.socket, "gethostbyname", lambda h: "203.0.113.9")
    ctx = _ctx(tmp_path)
    out = port_scan({"host": "example.com", "ports": "443"}, ctx)
    assert out["argv"][1] == "203.0.113.9", f"argv must carry the IP: {out['argv']}"
    assert "example.com" not in out["argv"]


def test_port_scan_reports_a_resolution_failure(tmp_path, monkeypatch):
    """An unresolvable host is a resolution failure, not a masscan error."""
    import socket as _socket

    def _boom(host):
        raise _socket.gaierror("Name or service not known")

    monkeypatch.setattr(toolchain.socket, "gethostbyname", _boom)
    ctx = _ctx(tmp_path)
    # example.com is the host _FakeScope authorises, so the scope gate passes
    # and the failure we see is the resolution, not the policy.
    out = port_scan({"host": "example.com", "ports": "443"}, ctx)
    assert out["ok"] is False
    assert out["code"] == "port.resolve_failed"


def test_port_scan_reports_a_missing_privilege(tmp_path, monkeypatch):
    """masscan needs raw sockets; saying so beats a bare exit code."""
    _stub_binary_present(monkeypatch, "masscan")
    monkeypatch.setattr(toolchain.socket, "gethostbyname", lambda h: "203.0.113.9")
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 1,
                                            "stdout": "", "stderr": "[-] FAIL: permission denied"})
    ctx = _ctx(tmp_path)
    out = port_scan({"host": "example.com", "ports": "443"}, ctx)
    assert out["code"] == "tool.privilege_required"
    assert "sudo" in out["result_for_model"]


def test_port_scan_caps_the_rate(tmp_path, monkeypatch):
    """A rate above the ceiling is clamped, not passed through."""
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})
    ctx = _ctx(tmp_path)
    out = port_scan({"host": "example.com", "rate": 10_000_000}, ctx)
    # The tool either ran (rate clamped) or reported the binary missing.
    # What it must never do is build an argv with the raw 10M rate.
    if out.get("ok"):
        assert "--rate" not in out.get("argv", []) or \
            out["argv"][out["argv"].index("--rate") + 1] == "100000"


def test_nuclei_scan_requires_a_target(tmp_path):
    ctx = _ctx(tmp_path)
    out = nuclei_scan({}, ctx)
    assert out["ok"] is False
    assert out["code"] == "nuclei.target_required"


def test_nuclei_scan_rejects_an_unknown_severity(tmp_path):
    """Severity is a closed set; anything else is a flag in disguise."""
    ctx = _ctx(tmp_path)
    out = nuclei_scan({"target": "https://example.com", "severity": "high,evil"}, ctx)
    assert out["ok"] is False
    assert out["code"] == "toolchain.bad_severity"


def test_nuclei_scan_accepts_a_known_severity(tmp_path, monkeypatch):
    """A known severity passes validation — and the child is NOT executed.

    ``_run`` is stubbed: this test is about argv validation, and letting a
    real nuclei download its template set turns a 0.1s test into an 80s one.
    """
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})
    ctx = _ctx(tmp_path)
    out = nuclei_scan({"target": "https://example.com", "severity": "high,critical"}, ctx)
    assert out.get("code") != "toolchain.bad_severity"
    # argv[0] is the resolved absolute path — that is the point of _resolve.
    assert out["argv"][0].endswith("/nuclei")
    assert out["argv"][1:3] == ["-u", "https://example.com"]
    assert out["argv"][out["argv"].index("-severity") + 1] == "critical,high"


def test_gobuster_dir_requires_a_wordlist(tmp_path):
    """No default wordlist: guessing one that may not exist is a lie."""
    ctx = _ctx(tmp_path)
    out = gobuster_dir({"target": "https://example.com"}, ctx)
    assert out["ok"] is False
    assert out["code"] == "gobuster.wordlist_required"


def test_gobuster_dir_reports_a_missing_wordlist(tmp_path):
    ctx = _ctx(tmp_path)
    out = gobuster_dir({"target": "https://example.com",
                        "wordlist": str(tmp_path / "nope.txt")}, ctx)
    assert out["ok"] is False
    assert out["code"] == "gobuster.wordlist_missing"


def test_gobuster_dir_refuses_a_wordlist_outside_local_roots(tmp_path):
    """The wordlist is a model-supplied path — it gets the strictest gate."""
    root = tmp_path / "jail"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("admin\n", encoding="utf-8")
    ctx = _ctx(root, scope=_FakeScope(root))
    out = gobuster_dir({"target": "https://example.com", "wordlist": str(outside)}, ctx)
    assert out["ok"] is False
    assert out["code"] == "scope.local_root_out_of_scope"


def test_gobuster_dir_accepts_a_wordlist_inside_local_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})

    root = tmp_path / "jail"
    root.mkdir()
    wl = root / "words.txt"
    wl.write_text("admin\n", encoding="utf-8")
    ctx = _ctx(root, scope=_FakeScope(root))
    out = gobuster_dir({"target": "https://example.com", "wordlist": str(wl)}, ctx)
    assert out.get("code") not in ("gobuster.wordlist_missing", "scope.local_root_out_of_scope")


def test_sqlmap_test_requires_a_target(tmp_path):
    ctx = _ctx(tmp_path)
    out = sqlmap_test({}, ctx)
    assert out["ok"] is False
    assert out["code"] == "sqlmap.target_required"


def test_sqlmap_test_never_builds_a_shell_escalation_argv(tmp_path, monkeypatch):
    """Read-only by construction: no --os-shell, no --sql-shell, ever."""
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})
    ctx = _ctx(tmp_path)
    out = sqlmap_test({"target": "https://example.com/?id=1"}, ctx)
    argv = out.get("argv", [])
    for forbidden in ("--os-shell", "--sql-shell", "--os-cmd", "--file-write"):
        assert forbidden not in argv, f"{forbidden} must never appear"


def test_sqlmap_test_clamps_level_and_risk(tmp_path, monkeypatch):
    monkeypatch.setattr(toolchain, "_run",
                        lambda argv, **kw: {"ok": True, "argv": argv, "exit_code": 0,
                                            "stdout": "", "stderr": ""})

    ctx = _ctx(tmp_path)
    out = sqlmap_test({"target": "https://example.com/?id=1", "level": 99, "risk": 99}, ctx)
    argv = out.get("argv", [])
    if "--level" in argv:
        assert int(argv[argv.index("--level") + 1]) <= 5
    if "--risk" in argv:
        assert int(argv[argv.index("--risk") + 1]) <= 3


def test_toolchain_tools_are_eight_and_unique():
    """Eight tools, no duplicate names — the redundancy rule."""
    names = [s["name"] for s in toolchain.TOOLCHAIN_TOOLS]
    assert len(names) == len(set(names)), f"duplicate tool name in {names}"
    assert len(names) == 8, f"expected 8 tools, got {len(names)}: {names}"


def test_toolchain_tools_do_not_duplicate_existing_tools():
    """A toolchain tool must not shadow a tool that already exists.

    port_hint (tools_network) is a zero-socket inventory hint. port_scan is
    the real scanner. Both are allowed to exist because they answer
    different questions — but no toolchain tool may reuse an existing name.
    """
    from hunter.agent.tools_network import SPECS as NETWORK_SPECS

    existing = {s["name"] for s in NETWORK_SPECS}
    overlap = {s["name"] for s in toolchain.TOOLCHAIN_TOOLS} & existing
    assert not overlap, f"toolchain shadows existing tools: {overlap}"


def test_register_toolchain_tools_advertises_every_binary(tmp_path, monkeypatch):
    """Every tool must be registered — as a real tool or as unavailable.

    The failure mode this pins: a new tool added to TOOLCHAIN_TOOLS but
    missing from the binary map in register_toolchain_tools would raise
    KeyError and take the whole registry down.
    """
    from hunter.agent.tools_base import ToolRegistry

    registry = ToolRegistry()
    monkeypatch.setattr(toolchain, "_resolve", lambda b: None)
    register_toolchain_tools(registry)
    expected = {s["name"] for s in toolchain.TOOLCHAIN_TOOLS}
    for name in expected:
        assert registry.get(name) is None, name
        assert name in registry._unavailable, name
        code, message = registry._unavailable[name]
        assert code == "tool.unavailable"
        assert "install with:" in message


def test_jail_cwd_never_falls_back_to_the_repo_root(tmp_path):
    """A child with no project root must not run in the repo.

    nuclei v3 keeps its templates under $HOME, and HOME is set to the cwd.
    The naive fallback (Path.cwd()) therefore drops an 87MB template set
    into whatever directory the tool was invoked from — which is how
    nuclei-templates/ ended up in this repo twice.
    """
    import tempfile

    ctx = _ctx(tmp_path)
    cwd = toolchain._jail_cwd(ctx, {})
    assert cwd != Path.cwd(), "the jail must not be the process cwd"
    assert "hunter-toolchain" in str(cwd)
    assert str(cwd).startswith(tempfile.gettempdir())


def test_jail_cwd_prefers_the_scope_root(tmp_path):
    """When a local root exists, that is the jail — not the temp dir."""
    root = tmp_path / "proj"
    root.mkdir()
    ctx = _ctx(root, scope=_FakeScope(tmp_path))
    assert toolchain._jail_cwd(ctx, {"path": str(root)}) == root.resolve()


def test_child_env_points_home_at_the_jail(tmp_path):
    """HOME is the jail, so a child cannot write into the operator's home."""
    env = toolchain._child_env(tmp_path)
    assert env["HOME"] == str(tmp_path)


def test_run_privileged_uses_askpass_not_noninteractive(tmp_path, monkeypatch):
    """`sudo -n` refuses the askpass helper and fails on a correct rule.

    The privileged path was written with -n first, and it failed with
    "a password is required" even though `sudo -A` on the same command
    worked. -n means "never prompt", which also means "never use
    SUDO_ASKPASS" — so a passwordless rule plus -n is still a failure.
    """
    seen: list[list[str]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv, **kwargs):
        seen.append(list(argv))
        return _Completed()

    monkeypatch.setattr(toolchain.subprocess, "run", fake_run)
    toolchain._run(["masscan", "10.0.0.1"], cwd=tmp_path, privileged=True)

    assert seen, "subprocess.run was never called"
    assert seen[0][:2] == ["sudo", "-A"], f"expected sudo -A, got {seen[0][:3]}"
    assert "-n" not in seen[0], "-n must not appear: it disables the askpass helper"


def test_run_unprivileged_does_not_prefix_sudo(tmp_path, monkeypatch):
    """No silent escalation: sudo appears only when privileged=True."""
    seen: list[list[str]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(toolchain.subprocess, "run",
                        lambda argv, **kw: (seen.append(list(argv)), _Completed())[1])
    toolchain._run(["forge", "build"], cwd=tmp_path)
    assert seen[0][0] == "forge", f"unprivileged run must not gain sudo: {seen[0]}"


def test_child_env_keeps_sudo_askpass(tmp_path, monkeypatch):
    """SUDO_ASKPASS must survive the env jail, or privileged runs cannot auth."""
    monkeypatch.setenv("SUDO_ASKPASS", "/tmp/askpass.sh")
    monkeypatch.setenv("SOME_SECRET", "leaked")
    env = toolchain._child_env(tmp_path)
    assert env["SUDO_ASKPASS"] == "/tmp/askpass.sh"
    assert "SOME_SECRET" not in env


def test_jail_cwd_creates_the_directory(tmp_path, monkeypatch):
    """subprocess.run(cwd=...) raises if the dir does not exist.

    The first version returned a path nobody had created, so every
    privileged scan died with FileNotFoundError before masscan even started.
    """
    import tempfile

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    ctx = _ctx(tmp_path)
    jail = toolchain._jail_cwd(ctx, {})
    assert jail.is_dir(), f"jail must exist on disk: {jail}"


# ------------------------------------------------------------- install script


def test_install_toolchain_script_exists_and_is_executable():
    """toolchain.py registers eight tools that shell out to real binaries.

    Without an installer, a fresh checkout has eight tools that all report
    _unavailable — the failure is correct but the fix is undocumented. The
    script is the documented fix, so it must ship and be runnable.
    """
    import os
    import stat
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    script = root / "install-toolchain.sh"
    assert script.is_file(), "install-toolchain.sh must ship with the repo"
    assert os.stat(script).st_mode & stat.S_IXUSR, "install-toolchain.sh must be executable"


def test_install_toolchain_covers_every_toolchain_binary():
    """Every binary a toolchain tool resolves must have an installer.

    A tool that shells out to a binary the installer never mentions is a tool
    that cannot be made to work on a fresh host.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    script = (root / "install-toolchain.sh").read_text()
    source = (root / "src" / "hunter" / "agent" / "toolchain.py").read_text()

    resolved = set(re.findall(r'_resolve\("([a-z]+)"\)', source))
    assert resolved, "no _resolve() calls found — the extraction regex is stale"
    missing = sorted(b for b in resolved if f"install_{b}" not in script and b not in ("forge", "cast", "anvil"))
    assert not missing, f"no installer for: {missing}"


def test_install_toolchain_check_mode_reports_without_installing():
    """--check is the operator's "what is missing" answer, and must be safe.

    It is the mode a support reply points at, so it has to work on a host with
    nothing installed and install nothing.
    """
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        ["bash", str(root / "install-toolchain.sh"), "--check"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "[ok]" in result.stdout or "[!!]" in result.stdout
