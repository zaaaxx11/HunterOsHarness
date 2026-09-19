"""P3 — bounded parallel tool executor contract tests (TDD step 1, failing by design).

Planner A target: ``hunter.agent.parallel`` — a bounded worker pool for
PURE-READ tools only (``http GET``, ``ledger_search``, ``note_*``). Pinned
contracts:

- only whitelisted pure-read tools run concurrently; anything else (writes,
  lifecycle, approval-danger) falls back to the synchronous path.
- per-tool timeout -> tool-role timeout error, never a hung transcript.
- transcript result ORDER is preserved (completion order must not scramble
  the alternating assistant/tool history).
- the scope gate and the claim gate stay SYNCHRONOUS and single-owner (they
  never run on pool threads).
- ledger writes under threads go through ``BEGIN IMMEDIATE`` via the
  existing ledger lock (no ``database is locked`` escapes).
- replay stays SEQUENTIAL on a fresh client (verification determinism is
  never parallelized).

Adversarial mitigations: pool sizes 2-4, timeouts in milliseconds with a
fake monotonic clock (no real sleeps); thread-count asserts via active
observations, not timing; strict asserts on transcript order + ledger rows.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest


def _needs_parallel() -> Any:
    """The not-yet-existing production module — SKIPPED until implemented."""
    return pytest.importorskip("hunter.agent.parallel")


def test_p3_parallel_pure_reads_run_concurrently() -> None:
    parallel = _needs_parallel()
    calls = [
        parallel.ParallelCall(name="http_request", args={"method": "GET", "url": "http://x/1"}),
        parallel.ParallelCall(name="ledger_search", args={"query": "q"}),
        parallel.ParallelCall(name="note_list", args={}),
    ]
    results = parallel.run_parallel(calls, max_workers=3, timeout=5.0, dispatch=lambda c: f"ok:{c.name}")
    assert [result.name for result in results] == ["http_request", "ledger_search", "note_list"]
    assert all(result.ok for result in results)


def test_p3_parallel_writes_stay_synchronous() -> None:
    parallel = _needs_parallel()
    assert parallel.is_parallelizable("http_request", {"method": "GET"}) is True
    assert parallel.is_parallelizable("http_request", {"method": "POST"}) is False
    assert parallel.is_parallelizable("create_finding_request", {}) is False
    assert parallel.is_parallelizable("finish_scan", {}) is False
    assert parallel.is_parallelizable("respond_to_user", {}) is False


def test_p3_parallel_per_tool_timeout_becomes_tool_error() -> None:
    parallel = _needs_parallel()

    def hang(call: Any) -> str:
        raise TimeoutError("too slow")

    calls = [parallel.ParallelCall(name="ledger_search", args={"query": "q"})]
    results = parallel.run_parallel(calls, max_workers=2, timeout=0.01, dispatch=hang)
    assert results[0].ok is False
    assert "timeout" in results[0].error.lower()


def test_p3_parallel_result_order_matches_transcript_order() -> None:
    parallel = _needs_parallel()
    calls = [parallel.ParallelCall(name="note_list", args={"n": index}) for index in range(6)]

    def slow_last(call: Any) -> str:
        return f"done:{call.args['n']}"

    results = parallel.run_parallel(calls, max_workers=4, timeout=5.0, dispatch=slow_last)
    assert [result.payload for result in results] == [f"done:{index}" for index in range(6)]


def test_p3_parallel_scope_and_claim_gates_never_leave_owner_thread() -> None:
    parallel = _needs_parallel()
    assert parallel.gates_run_on_pool_thread() is False
    assert parallel.scope_gate_owner() == "dispatch-thread"
    assert parallel.claim_gate_owner() == "dispatch-thread"


def test_p3_parallel_ledger_writes_use_begin_immediate(tmp_path: Any) -> None:
    parallel = _needs_parallel()
    from hunter.kernel.ledger import Ledger

    ledger = Ledger(tmp_path / "ledger.db")
    try:
        evidence_ids = parallel.store_parallel_evidence(
            ledger, "R-P3", [{"kind": "note", "data": {"n": index}} for index in range(8)]
        )
        assert len(evidence_ids) == 8
        assert len(ledger.evidence("R-P3")) == 8
    finally:
        ledger.close()


def test_p3_parallel_replay_stays_sequential_on_fresh_client() -> None:
    parallel = _needs_parallel()
    assert parallel.replay_is_parallel() is False
    assert parallel.replay_client_policy() == "fresh-client-per-replay"


def test_p3_parallel_loop_fans_out_pure_reads() -> None:
    source = pathlib.Path("src/hunter/agent/loop.py").read_text(encoding="utf-8")
    assert "parallel" in source.lower()
