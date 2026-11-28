"""The operator's --scope manifest is authoritative for EVERY target and every
downstream RagConfig — no LLM guessing when a manifest is given.

Regression pins for the multi-target bug (runs R-78795bd6a350 and friends):
`hunt` reset tgt_scope to None when len(targets) > 1 and called
`recognize_scope()`, whose LLM/deterministic guess encoded
``allow_subdomains: False`` and dropped ``exclude_hosts`` — so a 3-host manifest
with ``allow_subdomains: true`` was recorded in the ledger as a 1-host,
no-subdomain scope per target, and hosts nobody authorized could be invented.

Offline only: no network, no live hunt. Every RagLoop is either driven with
``dry_run=True`` or its ``_enqueue`` is inspected through the queue directory
under ``run_inline`` via a stubbed child path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from hunter.tools.scope import ScopeSet, scope_from_manifest, scope_from_summary
from hunter.workflow import multi_target as mt
from hunter.workflow.rag import RagConfig, RagLoop

# The operator's manifest: three hosts, subdomains ON, one explicit exclusion.
MANIFEST = {
    "name": "airvpn-vdp-2026-11",
    "hosts": ["airvpn.org", "eddie.website", "ipleak.net"],
    "allow_subdomains": True,
    "exclude_hosts": ["out.airvpn.org"],
}
TARGETS = ["https://airvpn.org/", "https://eddie.website/", "https://ipleak.net/"]


def _manifest_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope-airvpn.json"
    path.write_text(json.dumps(MANIFEST), encoding="utf-8")
    return path


# -- 1. the manifest round-trips: nothing is lost in serialization -------------


def test_scope_from_manifest_preserves_every_field(tmp_path):
    scope = scope_from_manifest(_manifest_file(tmp_path))
    assert scope.allowed_hosts == frozenset(MANIFEST["hosts"])
    assert scope.allow_subdomains is True
    assert scope.exclude_hosts == frozenset({"out.airvpn.org"})

    # summary() -> scope_from_summary() must be an exact round trip: this is
    # the pair that carries the scope into queued tasks and ledger events.
    rebuilt = scope_from_summary(scope.summary())
    assert rebuilt.allowed_hosts == scope.allowed_hosts
    assert rebuilt.allow_subdomains is True
    assert rebuilt.exclude_hosts == scope.exclude_hosts
    assert rebuilt.local_roots == scope.local_roots
    assert rebuilt.allow_private_ips == scope.allow_private_ips


# -- 2. the CLI hands the manifest to every target spec -----------------------


def _run_cli_hunt(monkeypatch, tmp_path, argv):
    from typer.testing import CliRunner

    from hunter.cli.main import app

    return CliRunner().invoke(app, argv)


def test_multi_target_hunt_uses_manifest_scope_for_every_target(monkeypatch, tmp_path):
    """Three URL targets, one --scope manifest: all three specs carry it.

    A stubbed provider keeps `recognize_scope` from ever being consulted for a
    *guessed* scope; what matters is that the scope each TargetSpec receives is
    the manifest's, byte for byte — with allow_subdomains and exclude_hosts
    intact. The RAG loop itself is stubbed out so nothing is hunted.
    """
    seen: list[tuple[str, object]] = []

    class _FakeLoop:
        def __init__(self, config):
            self.config = config

        def run(self):
            seen.append((self.config.target, self.config.scope))
            return 0

    monkeypatch.setattr(mt, "RagLoop", _FakeLoop)
    # no brain configured -> deterministic engine, no LLM dials at all
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "missing.yaml"))

    manifest = _manifest_file(tmp_path)
    result = _run_cli_hunt(
        monkeypatch,
        tmp_path,
        [
            "hunt",
            *TARGETS,
            "--scope",
            str(manifest),
            "--engine",
            "deterministic",
            "--time",
            "1",
            "--state",
            str(tmp_path / "state"),
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)

    # every target ran ...
    assert {t for t, _ in seen} == set(TARGETS)
    # ... and every one of them got the manifest scope, not a per-host guess.
    assert len(seen) == len(TARGETS)
    for _target, scope in seen:
        assert isinstance(scope, ScopeSet)
        assert scope.allowed_hosts == frozenset(MANIFEST["hosts"])
        assert scope.allow_subdomains is True
        assert scope.exclude_hosts == frozenset({"out.airvpn.org"})
        assert scope.name == MANIFEST["name"]


def test_manifest_wins_even_when_llm_recognition_is_available(monkeypatch, tmp_path):
    """With no --scope, recognize_scope is consulted; WITH one, it must not be.

    Pin the precedence rule itself: the manifest branch never calls the
    recognizer (which would return a single-host scope per target).
    """
    calls: list[str] = []

    def _boom(_provider, target):
        calls.append(target)  # pragma: no cover — must never run
        raise AssertionError("recognize_scope must not be consulted when --scope is given")

    monkeypatch.setattr("hunter.workflow.scope_recognize.recognize_scope", _boom)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "missing.yaml"))

    manifest = _manifest_file(tmp_path)
    result = _run_cli_hunt(
        monkeypatch,
        tmp_path,
        [
            "hunt",
            *TARGETS,
            "--scope",
            str(manifest),
            "--engine",
            "deterministic",
            "--time",
            "1",
            "--state",
            str(tmp_path / "state"),
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == []


# -- 3. the scope survives into the RAG queue / ledger ------------------------


def test_rag_task_carries_full_scope_summary(tmp_path, monkeypatch):
    """RagLoop._enqueue must serialize the WHOLE scope, not three keys.

    The old hand-rolled dict (name/hosts/allow_subdomains) lost
    exclude_hosts, local_roots and allow_private_ips, so a child hunt rebuilt
    from it forgot the operator's exclusions.

    The queue is intercepted at ``enqueue_task`` (the shim seam) so the tasks
    are captured WITHOUT running any child hunt — offline by construction.
    """
    tasks: list[dict] = []
    # rag.py binds ``enqueue_task`` from the shim at import time, so the
    # patch must target the bound name in ``hunter.workflow.rag``.
    monkeypatch.setattr(
        "hunter.workflow.rag.enqueue_task",
        lambda _state, task: tasks.append(task),
    )

    sd = tmp_path / "state"
    sd.mkdir()
    scope = scope_from_summary({**MANIFEST, "local_roots": []})

    cfg = RagConfig(
        state_dir=sd,
        target="https://airvpn.org/",
        scope=scope,
        engine="deterministic",
        time_budget_s=1,
        interval_s=1,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    enqueued = RagLoop(cfg)._cycle()
    assert enqueued, "the seed cycle must enqueue at least the scope hosts"
    assert tasks

    for task in tasks:
        assert task["scope"] == scope.summary()
        # the exact fields the bug dropped
        assert task["scope"]["allow_subdomains"] is True
        assert task["scope"]["exclude_hosts"] == ["out.airvpn.org"]
        # the payload rebuilds into an equivalent fail-closed gate
        rebuilt = scope_from_summary(task["scope"])
        assert rebuilt.allows_host("out.airvpn.org") is False
        assert rebuilt.allows_host("api.airvpn.org") is True


def test_rag_task_scope_round_trips_through_scope_from_summary(tmp_path, monkeypatch):
    tasks: list[dict] = []
    # rag.py binds ``enqueue_task`` from the shim at import time, so the
    # patch must target the bound name in ``hunter.workflow.rag``.
    monkeypatch.setattr(
        "hunter.workflow.rag.enqueue_task",
        lambda _state, task: tasks.append(task),
    )

    sd = tmp_path / "state"
    sd.mkdir()
    scope = scope_from_manifest(_manifest_file(tmp_path))
    cfg = RagConfig(
        state_dir=sd,
        target="https://airvpn.org/",
        scope=scope,
        engine="deterministic",
        time_budget_s=1,
        interval_s=1,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    RagLoop(cfg)._cycle()
    assert tasks
    for task in tasks:
        assert set(MANIFEST["hosts"]) <= set(task["scope"]["hosts"])
        assert task["scope"]["allow_subdomains"] is True
        assert task["scope"]["exclude_hosts"] == ["out.airvpn.org"]


def test_duck_typed_scope_without_summary_still_serializes(tmp_path, monkeypatch):
    """A scope object lacking summary() must not lose the four key fields."""
    tasks: list[dict] = []
    # rag.py binds ``enqueue_task`` from the shim at import time, so the
    # patch must target the bound name in ``hunter.workflow.rag``.
    monkeypatch.setattr(
        "hunter.workflow.rag.enqueue_task",
        lambda _state, task: tasks.append(task),
    )

    class _Bare:
        allowed_hosts = frozenset({"airvpn.org"})
        allow_subdomains = True
        name = "bare"
        local_roots = ("/tmp/root",)
        exclude_hosts = frozenset({"out.airvpn.org"})
        allow_private_ips = False

        def check_url(self, url: str) -> str:
            from urllib.parse import urlparse

            host = (urlparse(url).hostname or "").lower()
            if host in self.exclude_hosts:
                raise ValueError(f"excluded: {host}")
            if host in self.allowed_hosts:
                return host
            if self.allow_subdomains and host.endswith(
                tuple(f".{a}" for a in self.allowed_hosts)
            ):
                return host
            raise ValueError(f"out of scope: {host}")

    sd = tmp_path / "state"
    sd.mkdir()
    cfg = RagConfig(
        state_dir=sd,
        target="https://airvpn.org/",
        scope=cast(ScopeSet, _Bare()),
        engine="deterministic",
        time_budget_s=1,
        interval_s=1,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    RagLoop(cfg)._cycle()
    assert tasks
    payload = tasks[0]["scope"]
    assert payload["name"] == "bare"
    assert payload["allow_subdomains"] is True
    assert payload["exclude_hosts"] == ["out.airvpn.org"]
    assert payload["local_roots"] == ["/tmp/root"]
    assert payload["allow_private_ips"] is False


# -- 4. every downstream RagConfig gets the same scope object -----------------


def test_run_targets_passes_one_manifest_scope_to_every_config(tmp_path):
    specs = [mt.TargetSpec(t, ScopeSet(frozenset(MANIFEST["hosts"]), True,
                                      name=MANIFEST["name"],
                                      exclude_hosts=frozenset({"out.airvpn.org"})))
             for t in TARGETS]
    got: list[tuple[str, ScopeSet]] = []

    class _FakeLoop:
        def __init__(self, config):
            self.config = config

        def run(self):
            got.append((self.config.target, self.config.scope))
            return 0

    original = mt.RagLoop
    mt.RagLoop = _FakeLoop
    try:
        ok, failed, errors = mt.run_targets(
            specs,
            state_dir=tmp_path,
            engine="deterministic",
            time_budget_s=1.0,
            provider=None,
            parallel=True,
        )
    finally:
        mt.RagLoop = original

    assert (ok, failed, errors) == (3, 0, [])
    assert len(got) == 3
    assert len({s for _, s in got}) == 1, "all specs must share the ONE manifest scope"
    scope = got[0][1]
    assert scope.allowed_hosts == frozenset(MANIFEST["hosts"])
    assert scope.allow_subdomains is True
    assert scope.exclude_hosts == frozenset({"out.airvpn.org"})
