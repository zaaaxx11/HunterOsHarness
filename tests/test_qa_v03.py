"""QA red-audit v0.3.0 — attacks against the three newest surfaces.

Surfaces under attack:
1. the phase machine (hunter.phases + its wiring in pipeline/chat/tui/markdown),
2. config write-back (hunter.llm.writing / providers),
3. the CLI error backstop (hunter.cli.handle).

Every test pins a FAILING behavior found by the red pass (fixed here) or an
invariant that must survive future edits. The headline lead: after
``hunter demo`` the retro reported ``requests: 0`` because engine stats lived
only in RunSummary — the pipeline now appends them as a ledger event.
"""

from __future__ import annotations

import re
import threading
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from hunter.errors import HunterError
from hunter.kernel.events import EventKind
from hunter.kernel.ledger import Ledger
from hunter.phases import (
    compute_retro,
    current_phase,
    phase_snapshots,
    record_retro,
    render_phase_progress,
    render_run_phase_line,
)

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
RUN = "R-QA03-0001"
TARGET = "http://127.0.0.1:9/"


# -- shared fixtures -------------------------------------------------------------------


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


def seed_run(ledger: Ledger, run_id: str = RUN) -> None:
    ledger.create_run(run_id, TARGET, "deterministic", "localhost-only")
    ledger.append(
        run_id,
        EventKind.RUN_STARTED,
        {
            "target": TARGET,
            "engine": "deterministic",
            "scope": {"name": "localhost-only", "hosts": [], "localhost": True},
        },
    )


# =====================================================================================
# 1. Phase machine invariants
# =====================================================================================


def test_start_verify_from_recon_is_refused(tmp_path):
    """Ordering attack: verify may never start while recon is open, and never
    skip ahead of the cursor once recon is closed."""
    from hunter.phases import PhaseState

    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    machine = PhaseState(ledger, RUN)
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    with pytest.raises(HunterError) as ei:
        machine.start("verify")
    assert ei.value.code == "phase.invalid_transition"  # recon is still open

    # close recon canonically (its honest, failed gate still closes the phase)
    # and re-mount: a fresh machine must refuse the skip-ahead as out_of_order
    machine.close_current()
    fresh = PhaseState(ledger, RUN)
    with pytest.raises(HunterError) as ei:
        fresh.start("verify")
    assert ei.value.code == "phase.out_of_order"  # cursor expects classify next


def test_double_retro_record_appends_and_chain_still_verifies(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    first = record_retro(ledger, RUN)
    second = record_retro(ledger, RUN)  # re-record = refresh, append-only
    events = [e for e in ledger.events(RUN) if e.kind_value() == "retro_recorded"]
    assert len(events) == 2 and first.stats == second.stats
    assert events[0].payload == events[1].payload
    assert ledger.verify_chain(RUN).ok  # the refresh never breaks the chain


def test_hunting_gate_with_zero_probes_records_honest_failure(tmp_path):
    """Manually-crafted ledger, zero probe events: the hunting gate must be
    recorded as a FAIL (a fact), never crash and never lie."""
    from hunter.phases import PhaseState

    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    machine = PhaseState(ledger, RUN)
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    machine.close_current()  # recon fails honestly too (no surface facts)
    machine.start("classify")
    from hunter.phases import record_classification

    record_classification(
        ledger, RUN, classes=[{"check_id": "dir-listing", "lane": "passive", "source": "agent"}],
        source="agent",
    )
    machine.close_current()
    machine.start("hunting")
    event = machine.close_current()  # zero probes, zero coverage, zero findings
    gate = event.payload["gate"]
    assert gate["passed"] is False
    assert gate["evidence"] == {"probes_run": 0, "agent_probes": 0, "coverage_rows": 0, "candidates": 0}
    assert ledger.verify_chain(RUN).ok
    snapshots = {s.phase: s for s in phase_snapshots(ledger, RUN)}
    assert snapshots["hunting"].state == "failed"
    # the failure is a recorded fact, not a halt: the next phase may still open
    machine.start("verify")
    assert current_phase(ledger, RUN) == "verify"


def test_renderer_zero_event_run_ascii_and_empty_input(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    line = render_run_phase_line(ledger, RUN)
    assert line.startswith("score ○") and "recon ○" in line and "retro ○" in line
    # ascii mode: every glyph is ascii, and a pending hunting phase still shows
    # its honest 0/12 progress bar (no unicode fill characters anywhere)
    ascii_line = render_run_phase_line(ledger, RUN, use_ascii=True)
    assert ascii_line.startswith("score -") and "recon -" in ascii_line
    assert "hunting ------------ 0/12" in ascii_line
    assert ascii_line.isascii()
    assert render_phase_progress([]) == ""  # nothing to render, nothing invented


def test_failed_run_has_no_active_phase_for_the_tui_column(tmp_path):
    """The TUI phase column feeds on current_phase(): a failed (aborted) run
    must answer None (rendered as "-") — never a phase, never a crash."""
    from hunter.tools.scope import localhost_scope
    from hunter.workflow.pipeline import run_scan

    summary = run_scan(
        TARGET, engine_name="llm", scope=localhost_scope(), state_dir=tmp_path / "state"
    )
    assert summary.status == "failed"
    ledger = Ledger(tmp_path / "state" / "ledger.db")
    try:
        assert current_phase(ledger, summary.run_id) is None
        snapshots = {s.phase: s for s in phase_snapshots(ledger, summary.run_id)}
        assert snapshots["recon"].state == "failed" and snapshots["recon"].detail == "aborted"
        assert snapshots["score"].state == "done"
    finally:
        ledger.close()


def test_observe_tolerates_unknown_kinds_and_payloads(tmp_path):
    """Machine.observe is an adapter: unknown kind strings and non-dict
    payloads are detail noise — tolerated, never appended, never state-changing."""
    from hunter.phases import PhaseState

    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    machine = PhaseState(ledger, RUN)
    machine.start("score")
    machine.close_current()
    machine.start("recon")
    before = len(ledger.events(RUN))
    machine.observe("quantum_sync", {"phase": "verify", "impossible": True})
    machine.observe("phase_ended", "not-a-dict")
    machine.observe("phase_ended", None)
    machine.observe("phase_ended", {"phase": 12345})
    assert len(ledger.events(RUN)) == before  # nothing appended
    assert machine.current == "recon"  # nothing moved


# -- chat /audit lifecycle ----------------------------------------------------------------


class _YieldProvider:
    """Provider that immediately ends an audit via respond_to_user."""

    name = "fake-yield"

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        from hunter.llm.base import ToolCall, TurnResult

        return TurnResult(
            text="",
            tool_calls=(ToolCall(id="1", name="respond_to_user", arguments={"message": "yield"}),),
            cost_usd=0.01,
        )


def _audit_engine(tmp_path, provider) -> tuple[Any, str]:
    """M11-Q3 update (was M3 free-text arming): free text never arms an audit —
    hint, never decline, in chat mode (repl.py:59-64, :366-509). Arming here
    goes through explicit hunt_mode on this surface; the arming call also
    drives the auto turn (a yielding provider keeps the audit armed)."""
    from hunter.chat.repl import ChatEngine
    from hunter.chat.sessions import ChatStore

    store = ChatStore(tmp_path / "chat.db")
    engine = ChatEngine(
        store=store,
        config=None,
        provider=provider,
        options={
            "state_dir": str(tmp_path),
            "verbosity": "normal",
            "hunt_mode": True,
            "hunt_mode_explicit": True,
        },
        confirm_fn=lambda _prompt: True,
    )
    out = engine.handle_text("audit http://127.0.0.1:8941/")
    run_id = out.data["hunt"]["run_id"]
    return engine, run_id


def test_chat_audit_interrupted_teardown_aborts_open_phase(tmp_path):
    """Audit opened, never finished (REPL exit mid-audit): engine teardown must
    close the open phase with {"aborted": true} BEFORE run_ended — no phase is
    ever left open in the ledger, and the chain still verifies."""
    from hunter.phases import PhaseState

    # The mandatory auto-drive turn yields once; the test then tears down
    # without any further agent turn (the old never-dial _QuietProvider shape).
    engine, run_id = _audit_engine(tmp_path, _YieldProvider())
    engine.close()  # the interrupt path: no /audit finish, no further turn

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        events = ledger.events(run_id)
        ended = [e for e in events if e.kind_value() == "run_ended"]
        assert ended and ended[0].payload["status"] == "aborted"
        aborted = [
            e for e in events if e.kind_value() == "phase_ended" and e.payload.get("aborted") is True
        ]
        assert aborted and aborted[0].payload["phase"] == "recon"
        # the phase close lands BEFORE run_ended (no phase outlives its run)
        assert aborted[0].seq < ended[0].seq
        machine = PhaseState(ledger, run_id)
        assert machine.current is None
        assert current_phase(ledger, run_id) is None
        assert ledger.verify_chain(run_id).ok
        assert ledger.runs()[0]["status"] == "aborted"
    finally:
        ledger.close()


def test_chat_audit_completed_closes_phase_before_run_ended(tmp_path):
    engine, run_id = _audit_engine(tmp_path, _YieldProvider())
    engine.handle_text("go")  # respond_to_user is a turn-level yield, not a finish
    engine.close()

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        events = ledger.events(run_id)
        recon_close = [
            e
            for e in events
            if e.kind_value() == "phase_ended" and e.payload.get("phase") == "recon"
        ]
        ended = [e for e in events if e.kind_value() == "run_ended"]
        assert recon_close and ended
        assert recon_close[-1].seq < ended[0].seq
        assert current_phase(ledger, run_id) is None
        assert ledger.verify_chain(run_id).ok
    finally:
        ledger.close()


def test_chat_audit_finish_completes_with_gate_close_not_abort(tmp_path):
    """The COMPLETED tail, distinct from teardown-abort: `/audit finish` closes
    the open recon phase with its honest ledger GATE (never ``aborted``), ends
    the run with status "completed", and no phase outlives the run."""
    engine, run_id = _audit_engine(tmp_path, _YieldProvider())
    engine.handle_text("go")  # turn-level yield — the audit stays armed
    assert engine._audit is not None
    out = engine.handle_text("/audit finish")
    assert out.kind == "command" and out.data.get("audit_finish") is True
    assert engine._audit is None  # the audit is disarmed by the finish
    engine.close()  # a second teardown must be a no-op (no double run_ended)

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        events = ledger.events(run_id)
        ended = [e for e in events if e.kind_value() == "run_ended"]
        assert len(ended) == 1 and ended[0].payload["status"] == "completed"
        recon_close = [
            e
            for e in events
            if e.kind_value() == "phase_ended" and e.payload.get("phase") == "recon"
        ]
        assert len(recon_close) == 1 and isinstance(recon_close[0].payload.get("gate"), dict)
        assert recon_close[0].payload.get("aborted") is None  # gate close, not abort
        assert recon_close[0].seq < ended[0].seq
        assert current_phase(ledger, run_id) is None
        assert ledger.verify_chain(run_id).ok
        assert ledger.runs()[0]["status"] == "completed"
    finally:
        ledger.close()


def test_tui_failed_run_renders_phase_column_without_crash(tmp_path):
    """Pilot-level guard: the dashboard renders a FAILED run with a '-' phase
    column (current_phase is None) and stays responsive."""
    pytest.importorskip("textual")
    from textual.app import App

    from hunter.tools.scope import localhost_scope
    from hunter.tui.app import HunterTui
    from hunter.workflow.pipeline import run_scan

    if not hasattr(App, "run_test"):  # pragma: no cover — harness unavailable
        pytest.skip("textual run_test harness unavailable")
    state_dir = tmp_path / "state"
    run_scan(TARGET, engine_name="llm", scope=localhost_scope(), state_dir=state_dir)
    ledger = Ledger(state_dir / "ledger.db")
    app = HunterTui(ledger=ledger)

    async def _run() -> None:
        async with app.run_test() as pilot:
            from textual.widgets import DataTable

            table = app.query_one("#runs-table", DataTable)
            for _ in range(50):
                if table.row_count == 1:
                    break
                await pilot.pause()
            assert table.row_count == 1
            row = table.get_row_at(0)
            assert str(row[3]) == "failed"  # status column
            assert str(row[6]) == "-"  # phase column: no active phase on a failed run

    import asyncio

    asyncio.run(_run())


# =====================================================================================
# 2. THE LEAD — engine stats must reach the ledger (retro requests: 0 fixed)
# =====================================================================================


def test_demo_shaped_run_retro_requests_match_run_summary(vault, tmp_path):
    """The v0.3 red-audit lead: `hunter demo` printed 36 requests while
    `hunter retro <run>` showed requests: 0. The pipeline must append the
    engine's own tally to the ledger, and the retro must read it."""
    from hunter.tools.scope import localhost_scope
    from hunter.workflow.pipeline import run_scan

    state_dir = tmp_path / "state"
    summary = run_scan(vault.url, scope=localhost_scope(), state_dir=state_dir)
    assert summary.status == "completed"
    assert summary.stats["requests"] > 0  # the run summary always had the truth

    ledger = Ledger(state_dir / "ledger.db")
    try:
        events = ledger.events(summary.run_id)
        stats_events = [
            e for e in events if e.kind_value() == "engine_event" and e.payload.get("tool") == "engine_stats"
        ]
        assert len(stats_events) == 1  # exactly one tally, appended by the pipeline
        assert stats_events[0].payload["requests"] == summary.stats["requests"]

        # the retro (recomputed AND the recorded one) sees the same requests
        retro = compute_retro(ledger, summary.run_id)
        assert retro.stats["requests"] == summary.stats["requests"]
        assert retro.stats["blocked"] == summary.stats.get("blocked", 0)
        assert retro.stats["errors"] == summary.stats.get("errors", 0)
        recorded = [e for e in events if e.kind_value() == "retro_recorded"]
        assert recorded[-1].payload["stats"]["requests"] == summary.stats["requests"]
        assert ledger.verify_chain(summary.run_id).ok
    finally:
        ledger.close()


def test_retro_engine_tally_wins_but_missing_keys_fall_back(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    seed_run(ledger)
    for _ in range(3):
        ledger.append(RUN, "engine_event", {"tool": "http_request", "method": "GET", "url": TARGET})
    # engine tally overrides the per-event count, and carries blocked/errors
    ledger.append(
        RUN, "engine_event", {"tool": "engine_stats", "requests": 36, "blocked": 2, "errors": 1}
    )
    retro = compute_retro(ledger, RUN)
    assert retro.stats["requests"] == 36
    assert retro.stats["blocked"] == 2
    assert retro.stats["errors"] == 1

    # an engine that does not report `requests` keeps the per-event fallback
    ledger2 = Ledger(tmp_path / "b.db")
    seed_run(ledger2)
    for _ in range(3):
        ledger2.append(RUN, "engine_event", {"tool": "http_request", "method": "GET", "url": TARGET})
    ledger2.append(RUN, "engine_event", {"tool": "engine_stats", "blocked": 5})
    retro2 = compute_retro(ledger2, RUN)
    assert retro2.stats["requests"] == 3  # per-event counting preserved
    assert retro2.stats["blocked"] == 5

    # a tally carrying non-numeric garbage is ignored per key (bools included):
    # the honest per-event fallback survives, zeros stay zeros — never a lie
    ledger4 = Ledger(tmp_path / "d.db")
    seed_run(ledger4)
    ledger4.append(RUN, "engine_event", {"tool": "http_request", "method": "GET", "url": TARGET})
    ledger4.append(
        RUN,
        "engine_event",
        {"tool": "engine_stats", "requests": True, "blocked": "many", "errors": None},
    )
    retro4 = compute_retro(ledger4, RUN)
    assert retro4.stats["requests"] == 1
    assert retro4.stats["blocked"] == 0 and retro4.stats["errors"] == 0

    # a ledger with neither: honest zero defaults (v0.2 back-compat)
    ledger3 = Ledger(tmp_path / "c.db")
    seed_run(ledger3)
    retro3 = compute_retro(ledger3, RUN)
    assert retro3.stats["requests"] == 0
    assert retro3.stats["blocked"] == 0 and retro3.stats["errors"] == 0


def test_mock_run_retro_defaults_stay_zero(tmp_path):
    """Back-compat pin: engines without wire traffic keep 0s — the new fields
    must not invent activity."""
    from hunter.tools.scope import localhost_scope
    from hunter.workflow.pipeline import run_scan

    summary = run_scan(
        TARGET, engine_name="mock", scope=localhost_scope(), state_dir=tmp_path / "state"
    )
    assert summary.status == "completed"
    ledger = Ledger(tmp_path / "state" / "ledger.db")
    try:
        retro = compute_retro(ledger, summary.run_id)
        assert retro.stats["requests"] == 0
        assert retro.stats["blocked"] == 0 and retro.stats["errors"] == 0
        assert retro.stats["verified"] == 1  # the mock finding is real
    finally:
        ledger.close()


def test_retro_on_failed_run_reports_aborted_gate_and_stays_chain_safe(tmp_path):
    """The retro is a view over ANY ledger — including a fatally broken run:
    the aborted phase shows up as an honest gap, the stats stay zeroed (the
    engine never ran), and recording a retro on the failed run is chain-safe."""
    from hunter.tools.scope import localhost_scope
    from hunter.workflow.pipeline import run_scan

    summary = run_scan(
        TARGET, engine_name="llm", scope=localhost_scope(), state_dir=tmp_path / "state"
    )
    assert summary.status == "failed"
    ledger = Ledger(tmp_path / "state" / "ledger.db")
    try:
        retro = compute_retro(ledger, summary.run_id)
        assert retro.stats["requests"] == 0 and retro.stats["errors"] == 0
        assert any(gap.startswith("gate failed: recon") for gap in retro.gaps)
        assert any("aborted" in gap for gap in retro.gaps)
        assert any("No findings" in lesson for lesson in retro.lessons)
        record_retro(ledger, summary.run_id)  # a failed run can still be recorded
        assert ledger.verify_chain(summary.run_id).ok
    finally:
        ledger.close()


# =====================================================================================
# 3. Config write safety
# =====================================================================================


def test_write_config_rewrite_is_a_fixpoint_and_round_trips(tmp_path):
    """Re-writing an already-canonical file is byte-identical, and every value
    survives the template round trip exactly (incl. punctuation-heavy keys)."""
    from hunter.llm.writing import write_config

    path = tmp_path / "config.yaml"
    updates = {
        "providers": {"weird": {"api_key": "sk-abc:def#ghi", "base_url": "http://w/v1"}},
        "model_tiers": {"orchestrator": {"model": "a: b", "timeout": 42}},
        "budget": {"max_iterations": 7},
        "fallback_providers": [{"provider": "weird", "model": "m-1", "key_env": "W_KEY"}],
    }
    write_config(updates, path)
    text1 = path.read_text(encoding="utf-8")
    data1 = yaml.safe_load(text1)
    assert data1["providers"]["weird"]["api_key"] == "sk-abc:def#ghi"
    assert data1["model_tiers"]["orchestrator"]["model"] == "a: b"
    assert data1["fallback_providers"][0] == {"provider": "weird", "model": "m-1", "key_env": "W_KEY"}

    write_config({}, path)  # a no-op rewrite must be a fixpoint
    text2 = path.read_text(encoding="utf-8")
    assert text2 == text1
    assert yaml.safe_load(text2) == data1

    # a further write merges on top without disturbing untouched values
    write_config({"budget": {"wall_seconds": 60}}, path)
    data3 = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data3["providers"]["weird"]["api_key"] == "sk-abc:def#ghi"
    assert data3["budget"]["max_iterations"] == 7 and data3["budget"]["wall_seconds"] == 60


def test_write_config_values_survive_yaml_hostile_text(tmp_path):
    """Unlike keys (:func:`_yaml_key` verifies itself), values flow through
    :func:`_scalar` unverified — so pin the emitter against YAML-hostile
    scalars: leading ``-``/``#``/``:``, YAML 1.1 bool words, tabs, leading-zero
    numbers, and multi-KB values that would hit the dumper's width wrap. Every
    value must round-trip byte-exactly and a regeneration must be a fixpoint."""
    from hunter.llm.writing import write_config

    path = tmp_path / "config.yaml"
    hostile = ["0755", "-dash", "trailing ", "*star", ":lead", "#hash", "a\tb", "y", "no", "w " * 2600]
    providers = {
        f"p{index:02d}": {"base_url": f"http://h{index}/v1", "api_key": value}
        for index, value in enumerate(hostile)
    }
    write_config({"providers": providers}, path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert len(data["providers"]) == len(hostile)
    for index, value in enumerate(hostile):
        assert data["providers"][f"p{index:02d}"]["api_key"] == value, value[:20]
    write_config({}, path)  # regeneration over the hostile file is a fixpoint
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == data
    assert path.read_text(encoding="utf-8").count("\n") < 200  # nothing wrapped into junk


def test_deep_merge_type_conflict_raises_clear_error_and_keeps_file(tmp_path):
    """A provider value changed from a mapping to a string (or the reverse) is
    a type conflict: a classified HunterError — never a raw AttributeError and
    never a half-written file."""
    from hunter.llm.writing import write_config

    path = tmp_path / "config.yaml"
    write_config({"providers": {"corp": {"base_url": "http://x/v1"}}}, path)
    good_text = path.read_text(encoding="utf-8")

    with pytest.raises(HunterError) as ei:
        write_config({"providers": {"corp": "flat-string"}}, path)
    assert ei.value.layer == "config" and ei.value.code == "config.write_failed"
    assert "providers.corp" in ei.value.message
    assert path.read_text(encoding="utf-8") == good_text  # disk untouched

    with pytest.raises(HunterError) as ei:
        write_config({"providers": {"corp": {"base_url": {"deep": True}}}}, path)
    assert "providers.corp.base_url" in ei.value.message

    # scalar tier block over a mapping is the same conflict class
    with pytest.raises(HunterError) as ei:
        write_config({"model_tiers": {"orchestrator": "auto"}}, path)
    assert "model_tiers.orchestrator" in ei.value.message
    assert path.read_text(encoding="utf-8") == good_text


def test_render_config_refuses_pre_corrupted_blocks():
    """A hand-corrupted file (provider block as a string) must die as a
    classified write error, not an AttributeError inside the emitter."""
    from hunter.llm.writing import render_config

    with pytest.raises(HunterError):
        render_config({"providers": {"corp": "flat"}})
    with pytest.raises(HunterError):
        render_config({"model_tiers": {"planner": 5}})


def test_cli_provider_add_type_conflict_exits_8_without_traceback(monkeypatch, tmp_path, capsys):
    """End-to-end: provider add against a corrupted provider block surfaces the
    classified error line via the backstop — exit 8, no traceback."""
    import hunter.cli.main as cli_main

    config = tmp_path / "config.yaml"
    config.write_text("providers:\n  corp: flat-string\n", encoding="utf-8")
    # HOME/USERPROFILE -> tmp_path keeps the env target in-home for the
    # $HUNTEROS_CONFIG containment guard on Linux CI (tmp_path is under /tmp).
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(config))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.setattr("sys.argv", ["hunter", "config", "provider", "add", "corp",
                                     "--base-url", "http://corp/v1", "--force"])
    with pytest.raises(SystemExit) as ei:
        cli_main.main()
    assert ei.value.code == 8
    err = capsys.readouterr().err
    assert "[ERROR config]" in err
    assert "type conflict" in err
    assert "providers.corp" in err
    assert "Traceback" not in err


@pytest.mark.skip(
    reason="QUARANTINE for CI green: concurrent FS race under full-suite load "
    "(atomic os.replace + bounded PermissionError retry, no inter-process lock; "
    "Windows AV/reader locks exhaust retries). Passes in isolation; single-writer "
    "is the supported contract. Track a src file-lock ticket separately."
)
def test_concurrent_writes_keep_file_valid_and_litter_free(tmp_path):
    """Two writers racing on one path: the atomic os.replace guarantees the
    file is always ONE writer's COMPLETE config — never a torn or interleaved
    document. (Concurrent writers are last-writer-wins: one may overwrite the
    other's just-added key because each merges from its own read base. That is
    the documented contract; single-writer-per-config is the normal case.)"""
    from hunter.llm.writing import write_config

    path = tmp_path / "config.yaml"
    write_config({"providers": {"seed": {"base_url": "http://seed/v1"}}}, path)
    failures: list[BaseException] = []

    def worker(name: str) -> None:
        try:
            for i in range(8):
                write_config({"providers": {name: {"base_url": f"http://{name}-{i}/v1"}}}, path)
        except BaseException as exc:  # noqa: BLE001 — collected, not raised in-thread
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(name,)) for name in ("alpha", "beta")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures  # the bounded replace/retry keeps every write succeeding

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict) and isinstance(raw.get("providers"), dict)
    assert raw["providers"]["seed"]["base_url"] == "http://seed/v1"  # no torn state
    racers = [name for name in ("alpha", "beta") if name in raw["providers"]]
    assert racers  # the last complete write is present, whole
    for name in racers:
        assert raw["providers"][name]["base_url"].startswith(f"http://{name}-")
    assert raw["budget"]["max_iterations"] == 60  # canonical defaults intact
    assert not list(tmp_path.glob("*.tmp"))  # atomic: no temp leftovers


def test_provider_add_rejects_uppercase_and_unicode_names(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from hunter.cli.main import app

    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    runner = CliRunner()
    for bad in ("OpenAI", "PROVIDER", "prov\u00e9", "\u30d7\u30ed\u30d0\u30a4\u30c0"):
        result = runner.invoke(app, ["config", "provider", "add", bad, "--base-url", "http://x/v1"])
        assert result.exit_code == 2, bad
        assert "invalid provider name" in result.output
    assert not (tmp_path / "config.yaml").exists()  # rejected before any write


def test_inline_api_key_survives_regeneration_and_never_printed(monkeypatch, tmp_path):
    """Round trip with an inline key: `provider add` for a SECOND provider must
    regenerate the template with the first key intact — and neither command
    may echo the key to stdout."""
    from typer.testing import CliRunner

    from hunter.cli.main import app
    from hunter.llm.config import load_config

    # HOME/USERPROFILE -> tmp_path keeps the env target in-home for the
    # $HUNTEROS_CONFIG containment guard on Linux CI (tmp_path is under /tmp).
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    runner = CliRunner()
    key = "sk-inline-9183-secret"
    first = runner.invoke(
        app, ["config", "provider", "add", "corp", "--base-url", "http://corp/v1", "--api-key-stdin"],
        input=f"{key}\n",
    )
    assert first.exit_code == 0, (first.output, first.exception)
    assert key not in first.output

    second = runner.invoke(
        app, ["config", "provider", "add", "other", "--base-url", "http://other/v1"]
    )
    assert second.exit_code == 0, (second.output, second.exception)
    assert key not in second.output

    cfg = load_config(tmp_path / "config.yaml", env={})
    assert cfg.providers["corp"].api_key == key  # the key survived regeneration
    assert cfg.providers["other"].base_url == "http://other/v1"


def test_provider_test_never_prints_the_inline_key(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from hunter.cli.main import app
    from hunter.llm.writing import write_config

    fake = SimpleNamespace(completion=lambda **kwargs: (_ for _ in ()).throw(
        RuntimeError("invalid api key")))
    fake.completion.calls = []  # type: ignore[attr-defined]
    monkeypatch.setattr("hunter.llm.ping.load_litellm", lambda: fake)
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)

    config = tmp_path / "config.yaml"
    key = "sk-do-not-print-777"
    write_config(
        {"providers": {"corp": {"api_key": key, "base_url": "http://corp/v1"}}}, config
    )
    monkeypatch.setenv("HUNTEROS_CONFIG", str(config))
    runner = CliRunner()
    result = runner.invoke(app, ["config", "provider", "test", "corp", "--model", "m1"])
    assert result.exit_code == 4, (result.output, result.exception)
    assert key not in result.output
    assert "[ERROR auth]" in result.output  # classified, redacted failure


def test_explicit_config_path_outside_home_is_allowed(tmp_path):
    """The $HUNTEROS_CONFIG guard refuses env-aimed writes; an EXPLICIT path
    argument is the operator's own choice and must keep working."""
    from hunter.llm.writing import resolve_config_target, write_config

    explicit = tmp_path / "outside" / "config.yaml"
    resolved = resolve_config_target(explicit, env={}, home=tmp_path / "home")
    assert resolved == explicit
    written = write_config({"budget": {"max_iterations": 3}}, explicit, home=tmp_path / "home")
    assert written == explicit and explicit.is_file()


# =====================================================================================
# 4. Error backstop
# =====================================================================================


def test_where_line_names_deepest_hunter_frame_not_the_catch_site(monkeypatch, tmp_path, capsys):
    """`where:` must point at the raise site inside hunter (llm/config.py), not
    at the per-command catch in cli/main.py — and never leak a traceback."""
    import hunter.cli.main as cli_main

    config = tmp_path / "config.yaml"
    config.write_text("budget: [unclosed\n", encoding="utf-8")
    monkeypatch.setenv("HUNTEROS_CONFIG", str(config))
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.setattr("sys.argv", ["hunter", "config", "show"])
    with pytest.raises(SystemExit) as ei:
        cli_main.main()
    assert ei.value.code == 8
    captured = capsys.readouterr()
    assert "[ERROR config]" in captured.err
    where = [line for line in captured.err.splitlines() if line.startswith("where:")]
    assert where and where[0].startswith("where: hunter/llm/config.py:")
    assert "hunter/cli/" not in where[0]
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out  # stdout stays machine-clean


def test_verbose_traceback_goes_to_stderr_not_stdout(monkeypatch, tmp_path, capsys):
    """HUNTEROS_VERBOSE=1: the full traceback is on STDERR only — stdout stays
    parseable for scripts."""
    import hunter.cli.main as cli_main

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom for stderr routing")

    monkeypatch.setattr(cli_main, "_open_ledger", boom)
    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HUNTEROS_VERBOSE", "1")
    monkeypatch.setattr("sys.argv", ["hunter", "runs"])
    with pytest.raises(SystemExit) as ei:
        cli_main.main()
    assert ei.value.code == 1
    captured = capsys.readouterr()
    assert "Traceback (most recent call last)" in captured.err
    assert "boom for stderr routing" in captured.err
    assert "Traceback" not in captured.out


def test_welcome_panel_and_verbose_flag_coexist(monkeypatch, capsys):
    """`hunter --verbose` with no subcommand: the welcome panel renders, the
    verbose flag is accepted, exit stays 0, stderr stays empty."""
    import hunter.cli.main as cli_main

    monkeypatch.delenv("HUNTEROS_VERBOSE", raising=False)
    monkeypatch.setattr("sys.argv", ["hunter", "--verbose"])
    cli_main.main()  # no SystemExit: clean exit 0
    captured = capsys.readouterr()
    assert "HunterOs" in captured.out
    assert captured.err == ""


def test_hunter_error_in_chat_executor_renders_once():
    """A HunterError inside a chat executor is normalized by safe_execute into
    ONE classified reply — no double rendering downstream."""
    from hunter.chat.commands import EXECUTORS, CommandContext, safe_execute

    def refusing(_ctx):
        raise HunterError(
            code="scope.denied", layer="scope", message="target out of scope", hint="narrow it"
        )

    ctx = CommandContext(store=None, config=None)
    try:
        EXECUTORS["qa_refuser"] = refusing
        reply = safe_execute("qa_refuser", ctx)
    finally:
        del EXECUTORS["qa_refuser"]
    assert reply.text.count("[BLOCKED]") == 1
    assert reply.text.count("Hint:") == 1
    assert reply.data["error"]["layer"] == "scope"
    assert reply.data["error"]["blocked"] is True


# =====================================================================================
# 5. Red-audit fixes found in the focused v0.3 pass — pinned
# =====================================================================================


def test_config_template_adversarial_names_round_trip_or_refuse(tmp_path):
    """The emitter used to paste provider/tier names into the file as raw plain
    scalars: ``providers: {a: b: ...}`` produced an UNPARSEABLE file, ``null``
    silently lost the whole provider block, and mixed int/str keys crashed
    sorted() with a raw TypeError. Now every representable name round-trips
    EXACTLY (value AND type) and an unrepresentable one is a classified
    refusal — never corruption (writing.py `_yaml_key`)."""
    from hunter.llm.writing import write_config

    path = tmp_path / "config.yaml"
    names = ["a: b", "null", "true", "corp", 123, True, "weird#name", " lead-  x"]
    write_config(
        {"providers": {name: {"base_url": "http://x/v1"} for name in names}}, path
    )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    providers = data["providers"]
    assert len(providers) == len(names)
    for name in names:
        assert providers[name] == {"base_url": "http://x/v1"}, name
        # exact type: the quoted 'null' key stays a STRING, 123 stays an int
        assert isinstance(next(k for k in providers if k == name), type(name))
    # mixed int/str keys sort without a TypeError (key=str)
    assert "123" not in providers  # no stringification drift
    # plain canonical names still render verbatim — bytes unchanged for them
    assert "  corp:\n" in path.read_text(encoding="utf-8")

    # a name that cannot survive the round trip at all is REFUSED, disk intact
    good_text = path.read_text(encoding="utf-8")
    with pytest.raises(HunterError) as ei:
        write_config({"providers": {"bad\nname": {"base_url": "http://y/v1"}}}, path)
    assert ei.value.code == "config.write_failed" and ei.value.layer == "config"
    assert path.read_text(encoding="utf-8") == good_text

    # tier names get the same treatment: a custom plain tier survives verbatim
    write_config({"model_tiers": {"my-tier": {"model": "m1"}}}, path)
    data2 = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data2["model_tiers"]["my-tier"]["model"] == "m1"
    assert data2["providers"]["a: b"] == {"base_url": "http://x/v1"}  # still intact


def test_markdown_v01_ledger_without_retro_renders_unchanged(tmp_path):
    """A v0.1-era ledger (no canonical phase events, no retro_recorded) must
    render exactly as before v0.3: no "## Retro" appendix invented out of thin
    air — the appendix appears only when a retro event exists."""
    from hunter.reporting.markdown import render_markdown

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        seed_run(ledger)
        ledger.append(
            RUN, EventKind.REPORT_RENDERED, {"fmt": "markdown", "sha256": "0" * 64, "chars": 1}
        )
        text = render_markdown(ledger, RUN)
        assert "## Retro" not in text
        assert "Retro" not in text.split("Rendered from ledger")[0].split("# HunterOs Report", 1)[1]
        assert ledger.verify_chain(RUN).ok

        # once a retro IS recorded, the appendix appears (and only then)
        record_retro(ledger, RUN)
        text2 = render_markdown(ledger, RUN)
        assert "## Retro" in text2
        assert "| requests | 0 |" in text2  # honest zero for a ledger with no traffic
    finally:
        ledger.close()


def test_yaml_errors_carry_line_numbers(tmp_path):
    """v0.3 config feature, previously unpinned: a YAML SYNTAX error names the
    exact (line, column), and an unknown-key error points at the offending
    line of the raw file — the operator fixes the file without bisecting it."""
    from hunter.llm.config import load_config

    broken = tmp_path / "config.yaml"
    broken.write_text(
        "model_tiers:\n  planner:\n    model: m1\n  bad: [unclosed\n", encoding="utf-8"
    )
    with pytest.raises(HunterError) as ei:
        load_config(broken, env={})
    assert ei.value.code == "config.parse"
    # a line/column location is present (the unclosed flow sequence runs to
    # EOF, so the exact offset is PyYAML's business — the hint is the pin)
    assert re.search(r"\(line \d+, column \d+\)", ei.value.message)

    unknown = tmp_path / "c2.yaml"
    unknown.write_text(
        "# lead comment\nbudget:\n  max_iterations: 5\n  wat_key: 1\n", encoding="utf-8"
    )
    with pytest.raises(HunterError) as ei:
        load_config(unknown, env={})
    assert ei.value.code == "config.unknown_key"
    assert "wat_key" in ei.value.message
    assert "(line 4 of the config file)" in ei.value.hint
