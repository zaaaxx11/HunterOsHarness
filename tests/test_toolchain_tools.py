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
    register_toolchain_tools,
    slither_run,
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

    def check_url(self, url: str) -> None:  # pragma: no cover - overridden per test
        raise AssertionError("check_url should have been stubbed")


def _ctx(root: Path, *, scope: _FakeScope | None = None, config: dict | None = None) -> ToolContext:
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


def test_registered_specs_have_sane_tiers(tmp_path, monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(toolchain, "_resolve", lambda name: f"/usr/bin/{name}")
    register_toolchain_tools(registry)

    # slither is advanced-only: it is the heavy analyser.
    slither_spec = registry.get("slither_run")
    assert slither_spec is not None and slither_spec.min_tier == "advanced"
    # the rest are basic — a compile step is not a privilege.
    for name in ("forge_build", "forge_test", "cast_call"):
        spec = registry.get(name)
        assert spec is not None and spec.min_tier == "basic", name


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
    registry = build_registry("advanced")
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
        assert "install" in hint.lower() or "foundryup" in hint, name


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
