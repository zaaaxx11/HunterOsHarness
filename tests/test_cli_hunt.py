"""`hunter hunt` one-shot CLI tests (M3 H1-H10) — the Strix exit-code contract.

0 clean / 1 error / 2 findings / 3 refused-usage. Every test is hermetic: the
`vault` fixture and the local-dir mount are loopback-only, the manifest
confirm is a monkeypatched `hunter.hunt.confirm_prompt` (never real stdin),
and H2/H4/H8 spy `hunter.hunt.run_scan` (module-level binding) instead of
touching the pipeline. `$HUNTER_STATE_DIR` is deleted in every test via
`_cli_env` so nothing leaks into the repo checkout.

Note: rich soft-wraps long lines at ~80 columns under CliRunner, so long-line
asserts match against whitespace-flattened output.
"""

from __future__ import annotations

import json
import os
import re
import socket

import pytest
from typer.testing import CliRunner

from hunter.cli.main import app
from hunter.kernel.ledger import Ledger
from hunter.workflow.pipeline import RunSummary

runner = CliRunner()

FAKE_SCOPE_SUMMARY = {
    "name": "staging.client-x.com",
    "hosts": ["staging.client-x.com"],
    "allow_subdomains": False,
    "localhost": True,
}
PROPOSED_JSON = (
    '{"name": "staging.client-x.com", "hosts": ["staging.client-x.com"], '
    '"allow_subdomains": false}'
)


def _cli_env(monkeypatch, tmp_path) -> None:
    # Sandbox from tests/test_cli_init.py + the M3 state-dir scrub: the hunt
    # must never touch a real HOME or a leaked $HUNTER_STATE_DIR.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)


def _flat(text: str) -> str:
    """Undo rich's soft word-wrap: one space between all tokens."""
    return " ".join(text.split())


def _fake_summary(
    target: str, engine: str, *, status: str = "completed", findings=(), verified=0, candidates=0
) -> RunSummary:
    return RunSummary(
        run_id="R-FAKEHUNT",
        target=target,
        engine=engine,
        status=status,
        findings=list(findings),
        verified=verified,
        candidates=candidates,
        stats={"requests": 0},
        report_markdown="# fake report\n",
    )


# -- shared loopback fixtures (vault conventions from tests/test_pipeline.py) --

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture()
def no_proxy(monkeypatch):
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


@pytest.fixture()
def vault(no_proxy):
    from hunter.vault.server import start_server

    handle, _port = start_server()
    try:
        yield handle
    finally:
        handle.shutdown()


# -- H1 -----------------------------------------------------------------------


def test_hunt_localhost_vault_findings_exit_2(monkeypatch, tmp_path, vault):
    _cli_env(monkeypatch, tmp_path)
    result = runner.invoke(app, ["hunt", vault.url, "--yes", "--state", str(tmp_path)])
    assert result.exit_code == 2, (result.output, result.exception)
    out = _flat(result.stdout)
    assert "target check:" in out  # pre-hunt lines (§4.3 step 4)
    assert "skills mounted:" in out
    assert "report:" in out  # the report line
    assert "verified" in out  # summary table columns like `hunter scan`
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        runs = ledger.runs()
        assert len(runs) == 1 and runs[0]["status"] == "completed"
    finally:
        ledger.close()


# -- H2 -----------------------------------------------------------------------


def test_hunt_manifest_declined_refuses_cleanly(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr("hunter.hunt.confirm_prompt", lambda _prompt: False)
    spied: list = []

    def spy(*_args, **_kwargs):
        spied.append(1)  # pragma: no cover — must never run
        return _fake_summary("http://staging.client-x.com", "deterministic")

    monkeypatch.setattr("hunter.hunt.run_scan", spy)

    result = runner.invoke(app, ["hunt", "http://staging.client-x.com", "--state", str(tmp_path)])
    assert result.exit_code == 3, (result.output, result.exception)
    # The proposed manifest block is printed with the EXACT JSON...
    assert PROPOSED_JSON in _flat(result.stdout)
    # ...then the honest refusal.
    assert "refused — nothing ran." in _flat(result.output)
    assert spied == []  # the spied pipeline was NEVER called


# -- H3 -----------------------------------------------------------------------


def test_propose_manifest_shape_and_target_normalization(tmp_path, monkeypatch):
    _cli_env(monkeypatch, tmp_path)
    from hunter.hunt import normalize_hunt_target, propose_manifest

    from hunter.tools.scope import ScopeSet

    proposed = propose_manifest("staging.client-x.com")
    assert proposed == {
        "name": "staging.client-x.com",
        "hosts": ["staging.client-x.com"],
        "allow_subdomains": False,
    }
    # The proposed dict fits the gate EXACTLY: that host, nothing wider.
    scope = ScopeSet(
        frozenset(proposed["hosts"]), proposed["allow_subdomains"], name=proposed["name"]
    )
    assert scope.allows_host("staging.client-x.com") is True
    assert scope.allows_host("api.staging.client-x.com") is False  # subdomain BLOCKED
    assert scope.allows_host("evil.com") is False

    assert normalize_hunt_target("http://127.0.0.1:8941/") == ("http://127.0.0.1:8941/", "url")
    assert normalize_hunt_target("https://target.example.com/admin") == (
        "https://target.example.com/admin",
        "url",
    )
    assert normalize_hunt_target("foo.com:8941")[0] == "http://foo.com:8941"
    assert normalize_hunt_target("127.0.0.1:8941")[0] == "http://127.0.0.1:8941"

    site = tmp_path / "site"
    site.mkdir()
    normalized = normalize_hunt_target(str(site))
    assert normalized == (os.path.abspath(str(site)), "dir")

    assert normalize_hunt_target("definitely not a target") == ("", "invalid")


# -- H4 -----------------------------------------------------------------------


def test_hunt_confirmed_manifest_authorizes_run_scan_scope(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr("hunter.hunt.confirm_prompt", lambda _prompt: True)
    seen: list[dict] = []

    def spy(target_url, *_args, scope=None, **_kwargs):
        seen.append({"target": target_url, "scope": scope})
        return _fake_summary(target_url, "deterministic")  # completed, 0 findings

    monkeypatch.setattr("hunter.hunt.run_scan", spy)

    result = runner.invoke(app, ["hunt", "http://staging.client-x.com", "--state", str(tmp_path)])
    assert result.exit_code == 0, (result.output, result.exception)  # 0 findings → 0
    assert len(seen) == 1  # run_scan called ONCE
    assert seen[0]["target"] == "http://staging.client-x.com"
    assert seen[0]["scope"] is not None
    assert seen[0]["scope"].summary() == FAKE_SCOPE_SUMMARY


# -- H5 -----------------------------------------------------------------------


def test_hunt_local_dir_mounts_loopback_and_runs(monkeypatch, tmp_path, no_proxy):
    _cli_env(monkeypatch, tmp_path)
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.html").write_text(
        "<html><body><h1>local site</h1></body></html>", encoding="utf-8"
    )

    def _must_not_prompt(_prompt: str) -> bool:
        raise AssertionError("a local-dir mount never asks for a manifest")

    monkeypatch.setattr("hunter.hunt.confirm_prompt", _must_not_prompt)

    result = runner.invoke(app, ["hunt", str(site), "--state", str(tmp_path)])
    assert result.exit_code == 2, (result.output, result.exception)  # findings ≥ 1
    out = _flat(result.stdout)
    # The exact mount-warning line (port is ephemeral — regex the number).
    assert re.search(
        r"mounting local directory .+ on http://127\.0\.0\.1:\d+/ "
        r"\(temporary, localhost-only\) — everything inside is reachable by the audit\.",
        out,
    )
    assert os.path.abspath(str(site)) in out
    match = re.search(r"127\.0\.0\.1:(\d+)", out)
    assert match is not None
    port = int(match.group(1))
    # The mount's server is shut down after the command returns.
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)


# -- H6 -----------------------------------------------------------------------


def test_hunt_exit_code_mapping_table(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    from hunter.hunt import HuntOutcome, run_hunt

    from hunter.tools.scope import localhost_scope

    target = "http://127.0.0.1:8941/"

    def _patch(summary: RunSummary) -> None:
        monkeypatch.setattr("hunter.hunt.run_scan", lambda *_a, **_k: summary)

    _patch(_fake_summary(target, "deterministic", status="failed"))
    failed = run_hunt(target, scope=localhost_scope(), engine_name="deterministic",
                      state_dir=str(tmp_path))
    assert isinstance(failed, HuntOutcome)
    assert (failed.status, failed.exit_code, failed.findings) == ("failed", 1, 0)

    _patch(_fake_summary(target, "deterministic", status="completed"))
    clean = run_hunt(target, scope=localhost_scope(), engine_name="deterministic",
                     state_dir=str(tmp_path))
    assert clean.exit_code == 0 and clean.status == "completed" and clean.run_id == "R-FAKEHUNT"

    three = [object(), object(), object()]
    _patch(_fake_summary(target, "deterministic", findings=three, verified=1, candidates=2))
    found = run_hunt(target, scope=localhost_scope(), engine_name="deterministic",
                     state_dir=str(tmp_path))
    assert (found.exit_code, found.findings, found.verified, found.candidates) == (2, 3, 1, 2)

    def crash(*_args, **_kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr("hunter.hunt.run_scan", crash)
    crashed = run_hunt(target, scope=localhost_scope(), engine_name="deterministic",
                       state_dir=str(tmp_path))
    assert crashed.status == "failed" and crashed.exit_code == 1  # never propagates


# -- H7 -----------------------------------------------------------------------


def test_hunt_json_payload_and_refusal_silence(monkeypatch, tmp_path, vault):
    _cli_env(monkeypatch, tmp_path)
    result = runner.invoke(app, ["hunt", vault.url, "--json", "--yes", "--state", str(tmp_path)])
    assert result.exit_code == 2, (result.output, result.exception)
    payload = json.loads(result.stdout)  # stdout parses as JSON, nothing else
    assert set(payload) == {
        "run_id", "status", "verified", "candidates", "findings", "stats", "report",
    }
    assert payload["status"] == "completed"
    assert len(payload["findings"]) >= 1
    assert isinstance(payload["report"], str) and payload["report"]

    # A refusal prints NO stdout JSON: refusal lines live on stderr, exit 3.
    monkeypatch.setattr("hunter.hunt.confirm_prompt", lambda _prompt: False)
    refused = runner.invoke(
        app, ["hunt", "http://staging.client-x.com", "--json", "--state", str(tmp_path)]
    )
    assert refused.exit_code == 3, (refused.output, refused.exception)
    with pytest.raises(ValueError):
        json.loads(refused.stdout)
    assert "refused" in refused.stderr


# -- H8 -----------------------------------------------------------------------


def test_hunt_yes_skips_confirm_with_generated_scope(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)

    def _must_not_ask(_prompt: str) -> bool:
        raise AssertionError("--yes must skip the confirm prompt")

    for flag in ("--yes", "-y"):
        seen: list = []

        def spy(target_url, *_args, scope=None, _seen=seen, **_kwargs):
            _seen.append(scope)
            return _fake_summary(target_url, "deterministic")

        monkeypatch.setattr("hunter.hunt.confirm_prompt", _must_not_ask)
        monkeypatch.setattr("hunter.hunt.run_scan", spy)
        result = runner.invoke(
            app, ["hunt", "http://staging.client-x.com", flag, "--state", str(tmp_path)]
        )
        assert result.exit_code == 0, (result.output, result.exception)
        assert len(seen) == 1
        assert seen[0] is not None
        assert seen[0].summary() == FAKE_SCOPE_SUMMARY


# -- H9 -----------------------------------------------------------------------


def test_hunt_deterministic_fallback_and_llm_failure(monkeypatch, tmp_path, vault):
    _cli_env(monkeypatch, tmp_path)
    # No config in the sandbox → deterministic engine + the stderr note.
    result = runner.invoke(app, ["hunt", vault.url, "--yes", "--state", str(tmp_path)])
    assert result.exit_code == 2, (result.output, result.exception)
    assert "no brain configured — using the deterministic engine." in _flat(result.stderr)

    # --engine llm with no brain: the run closes failed, exit 1, no traceback.
    failed = runner.invoke(app, ["hunt", vault.url, "--engine", "llm", "--yes", "--state", str(tmp_path)])
    assert failed.exit_code == 1, (failed.output, failed.exception)
    combined = _flat(failed.output)
    assert "failed" in combined
    assert "Traceback" not in combined


# -- H10 ----------------------------------------------------------------------


def test_hunt_usage_refusals_open_no_run(monkeypatch, tmp_path):
    _cli_env(monkeypatch, tmp_path)
    cases = [
        (
            ["hunt", "http://127.0.0.1:8941/", "--engine", "nope", "--state", str(tmp_path)],
            ["deterministic", "mock", "llm"],  # the engines list
        ),
        (
            ["hunt", str(tmp_path / "missing-dir"), "--state", str(tmp_path)],
            ["BLOCKED"],  # nonexistent path target
        ),
        (
            ["hunt", "not a target at all", "--state", str(tmp_path)],
            ["BLOCKED"],  # normalize_hunt_target garbage
        ),
    ]
    for argv, needles in cases:
        result = runner.invoke(app, argv)
        assert result.exit_code == 3, (argv, result.output, result.exception)
        for needle in needles:
            assert needle in result.output, (argv, result.output)

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        assert ledger.runs() == []  # no run in ANY refusal case
    finally:
        ledger.close()
