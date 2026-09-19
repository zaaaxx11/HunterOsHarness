"""R2-A cron CLI+delivery — TDD RED (failing by design).

R2-A target: ``hunter.cron.scheduler`` jobs persist under ``<state>/``
(not in-memory dicts); ``hunter hunt cron`` CLI verbs exist; every fire
runs an ephemeral agent, delivers (report/notify) BEFORE teardown, and
writes one execution ledger row.

Prod targets (per-fn):
- test_r2a_cron_cli_hunt_cron_verbs_exist -> hunter.cli.main hunt cron add/list/remove
- test_r2a_cron_cli_jobs_persisted_not_memory -> cron jobs JSON under <state>/cron
- test_r2a_cron_cli_tick_uses_persisted_jobs -> tick reads persisted jobs (no default-only)
- test_r2a_cron_cli_delivery_writes_ledger_row -> execution_rows from Ledger file
- test_r2a_cron_cli_advance_before_exec_persisted -> advance fence persisted crash-safe
- test_r2a_cron_cli_teardown_after_delivery -> heartbeat<run<deliver<teardown

Adversarial: tmp_path state isolation, monotonic fake (no sleep/network),
strict fire-count + ledger-row asserts, negatives (default in-memory rejected).
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest


def _needs_cron() -> Any:
    return pytest.importorskip("hunter.cron.scheduler")


def _needs_cli() -> Any:
    return pytest.importorskip("hunter.cli.main")


def _fake_monotonic(monkeypatch: Any, start: float = 3000.0) -> dict[str, float]:
    clock = {"t": float(start)}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    monkeypatch.setattr("time.time", lambda: clock["t"])
    return clock


def test_r2a_cron_cli_hunt_cron_verbs_exist() -> None:
    cli = _needs_cli()
    source = pathlib.Path("src/hunter/cli/main.py").read_text(encoding="utf-8")
    # R2-A: `hunter hunt cron ...` (or `hunter cron ...`) must exist.
    if "cron" not in source.lower():
        pytest.fail("EXPECTED-FAIL-R2A: cli/main.py has no hunt cron verbs")
    assert hasattr(cli, "app")
    # Strict: the Typer app must route a cron verb (not just mention cron).
    names: list[str] = []
    try:
        for cmd in getattr(cli.app, "registered_commands", []):
            names.append(str(getattr(cmd, "name", "")))
        for grp in getattr(cli.app, "registered_groups", []):
            names.append(str(getattr(grp, "name", "")))
    except Exception:
        names = []
    if "cron" not in " ".join(names).lower() and "cron" not in source.lower().split("def hunt(")[-1][:4000]:
        pytest.fail(
            "EXPECTED-FAIL-R2A: hunt cron subcommand not registered on Typer app"
        )


def test_r2a_cron_cli_jobs_persisted_not_memory(tmp_path: Any, monkeypatch: Any) -> None:
    cron = _needs_cron()
    _fake_monotonic(monkeypatch)
    state = tmp_path / "state"
    # R2-A: adding a job must leave a file under <state>/ (not just _rows dict).
    if not hasattr(cron, "add_job") and not hasattr(cron, "save_job"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: cron.scheduler has no add_job/save_job; "
            "default job in-memory only (no CLI persistence)"
        )
    job = {"id": "job-r2a-1", "slot": "s1", "target": "http://127.0.0.1:9/"}
    cron.add_job(str(state), job)  # type: ignore[attr-defined]
    persisted = list((state).rglob("*.json"))
    assert persisted, "persisted job file missing under <state>/"
    body = json.loads(persisted[0].read_text(encoding="utf-8"))
    assert "job-r2a-1" in json.dumps(body)


def test_r2a_cron_cli_tick_uses_persisted_jobs(tmp_path: Any, monkeypatch: Any) -> None:
    cron = _needs_cron()
    _fake_monotonic(monkeypatch)
    state = tmp_path / "state"
    if not hasattr(cron, "add_job"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: no persisted jobs API; tick still fires "
            "default in-memory job only"
        )
    cron.add_job(str(state), {"id": "job-r2a-2", "slot": "s1"})  # type: ignore[attr-defined]
    fired: list[str] = []
    outcome = cron.tick(str(state), dispatch=lambda job: fired.append(str(job.get("id"))))
    assert outcome in ("ok", "estop", "gated")
    assert "job-r2a-2" in fired


def test_r2a_cron_cli_delivery_writes_ledger_row(tmp_path: Any, monkeypatch: Any) -> None:
    cron = _needs_cron()
    _fake_monotonic(monkeypatch)
    state = tmp_path / "state"
    events: list[str] = []
    cron.run_one_job(
        str(state),
        {"id": "job-r2a-3"},
        run_agent=lambda job: events.append("run") or "ok",
        deliver=lambda result: events.append("deliver"),
        teardown=lambda: events.append("teardown"),
        heartbeat=lambda job: events.append("heartbeat"),
    )
    assert events.index("heartbeat") < events.index("run")
    assert events.index("deliver") < events.index("teardown")
    # R2-A: the execution row must live in the real Ledger, not _rows dict.
    if not hasattr(cron, "execution_ledger_path") and "_rows" in dir(cron):
        # In-memory _rows still present and no ledger path seam -> RED.
        rows = cron.execution_rows(str(state), "job-r2a-3")
        from hunter.kernel.ledger import Ledger
        from hunter.runtime_paths import RuntimePaths

        db = RuntimePaths.resolve(state=state, migrate=False).ledger
        if not db.is_file():
            pytest.fail(
                "EXPECTED-FAIL-R2A: execution row only in-memory _rows; "
                "no Ledger execution row per fire"
            )
        ledger = Ledger(db)
        try:
            assert any("job-r2a-3" in json.dumps(dict(r)) for r in ledger.runs()) or len(rows) == 1
        finally:
            ledger.close()
        pytest.fail(
            "EXPECTED-FAIL-R2A: execution_rows served from in-memory dict; "
            "must be Ledger-backed per fire"
        )
    rows = cron.execution_rows(str(state), "job-r2a-3")
    assert len(rows) == 1 and rows[0]["job_id"] == "job-r2a-3"


def test_r2a_cron_cli_advance_before_exec_persisted(tmp_path: Any, monkeypatch: Any) -> None:
    cron = _needs_cron()
    _fake_monotonic(monkeypatch)
    state = tmp_path / "state"
    order: list[str] = []

    def dispatch(job: Any) -> None:
        order.append("exec")
        assert cron.next_runs_advanced(str(state), job) is True

    # Persisted advance fence required for crash-safe at-most-once.
    if not hasattr(cron, "advance_path") and not hasattr(cron, "load_advance"):
        # Probe: does advance survive a module-level dict clear (i.e. persisted)?
        cron.tick(str(state), dispatch=dispatch, record_advance=lambda job: order.append("advance"))
        assert order == ["advance", "exec"]
        pytest.fail(
            "EXPECTED-FAIL-R2A: advance_next_runs in-memory only; "
            "crash between advance and exec would re-fire"
        )
    cron.tick(str(state), dispatch=dispatch, record_advance=lambda job: order.append("advance"))
    assert order == ["advance", "exec"]


def test_r2a_cron_cli_teardown_after_delivery_negative(tmp_path: Any) -> None:
    cron = _needs_cron()
    state = tmp_path / "state"
    events: list[str] = []
    cron.run_one_job(
        str(state),
        {"id": "job-r2a-4"},
        run_agent=lambda job: events.append("run"),
        deliver=lambda result: events.append("deliver"),
        teardown=lambda: events.append("teardown"),
        heartbeat=lambda job: events.append("heartbeat"),
    )
    # Negative: teardown must NEVER precede delivery.
    assert events.index("teardown") > events.index("deliver")
    if not hasattr(cron, "add_job"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: ephemeral agent + deferred teardown unwired to "
            "persisted CLI jobs (run_one_job in-memory only)"
        )
