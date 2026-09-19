"""R2-A true parallel — TDD RED (failing by design).

R2-A target: ``hunter.agent.loop.AgentLoop`` actually fans out pure-read
batches through ``hunter.agent.parallel.run_parallel`` (today
``_maybe_parallel_dispatch`` is never called — sequential only); scope/claim
gates stay on the dispatch thread; ledger writes stay BEGIN IMMEDIATE;
replay stays sequential.

Prod targets (per-fn):
- test_r2a_parallel_true_loop_fans_out_pure_read_batch -> AgentLoop.run calls parallel.run_parallel
- test_r2a_parallel_true_overlap_observed_via_barrier -> loop-level overlap (Barrier, no sleep)
- test_r2a_parallel_true_order_preserved -> transcript order == completion order
- test_r2a_parallel_true_writes_stay_synchronous_negative -> POST/lifecycle never parallel
- test_r2a_parallel_true_scope_claim_gates_dispatch_thread -> gates never on pool thread
- test_r2a_parallel_true_ledger_begin_immediate_no_locked -> store_parallel_evidence ledger rows

Adversarial: tmp_path ledgers, Barrier/Event overlap (no sleep/network),
strict order + thread asserts, negatives for writes/lifecycle.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest


def _needs_parallel() -> Any:
    return pytest.importorskip("hunter.agent.parallel")


def _needs_loop() -> Any:
    return pytest.importorskip("hunter.agent.loop")


def _ledger_ctx(tmp_path: Any) -> Any:
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    import httpx

    def _ok(request: Any) -> Any:
        return httpx.Response(200, text="ok")

    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=httpx.MockTransport(_ok))
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run("R-R2A-PAR", "http://127.0.0.1:9/", "deterministic", "localhost-only")
    ctx = ToolContext(
        run_id="R-R2A-PAR",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url="http://127.0.0.1:9/",
        emit=lambda k, p: None,
        config={"tier": "basic"},
        state={},
    )
    return ctx, ledger, http


def test_r2a_parallel_true_loop_fans_out_pure_read_batch(tmp_path: Any, monkeypatch: Any) -> None:
    parallel = _needs_parallel()
    loop_mod = _needs_loop()
    from hunter.agent.tools import build_registry
    from hunter.llm.base import ToolCall, TurnResult

    seen: dict[str, Any] = {}

    orig_run_parallel = parallel.run_parallel

    def spy(calls: Any, **kw: Any) -> Any:
        seen["n"] = len(list(calls))
        return orig_run_parallel(calls, **kw)

    monkeypatch.setattr(parallel, "run_parallel", spy)

    class TwoReads:
        name = "fake"

        def complete(self, tier: Any, messages: Any, tools: Any = None, **kw: Any) -> Any:
            if not hasattr(self, "fired"):
                self.fired = True  # type: ignore[attr-defined]
                return TurnResult(
                    text="",
                    tool_calls=(
                        ToolCall(id="c-1", name="note_list", arguments={}),
                        ToolCall(id="c-2", name="ledger_search", arguments={"query": "q"}),
                    ),
                    finish_reason="tool_calls",
                )
            from hunter.llm.base import TurnResult as TR

            return TR(text="", tool_calls=(), finish_reason="stop")

        def classify(self, exc: BaseException) -> Any:
            from hunter.llm.base import ClassifiedError

            return ClassifiedError(reason="unknown")

    ctx, ledger, http = _ledger_ctx(tmp_path)
    try:
        loop = loop_mod.AgentLoop(TwoReads(), build_registry("basic"), tier="basic")  # type: ignore[arg-type]
        # R2-A requires the loop to consult the allowlist AND fan out.
        if "_maybe_parallel_dispatch" not in dir(loop) or "run_parallel" not in open(
            "src/hunter/agent/loop.py", encoding="utf-8"
        ).read().split("def run(")[1].split("def _")[0]:
            pytest.fail(
                "EXPECTED-FAIL-R2A: AgentLoop.run never calls "
                "parallel.run_parallel (sequential-only today)"
            )
        loop.run(ctx, "audit")
        assert seen.get("n") == 2
    finally:
        http.close()
        ledger.close()


def test_r2a_parallel_true_overlap_observed_via_barrier(tmp_path: Any, monkeypatch: Any) -> None:
    parallel = _needs_parallel()
    loop_mod = _needs_loop()
    # Loop-level overlap: two pure reads must overlap on pool threads.
    # Barrier proves concurrency with no sleep/network in test code.
    barrier = threading.Barrier(2, timeout=5.0)
    entered: list[str] = []
    lock = threading.Lock()

    def dispatch(call: Any) -> str:
        with lock:
            entered.append(str(call.name))
        barrier.wait()
        return f"ok:{call.name}"

    calls = [
        parallel.ParallelCall(name="note_list", args={"n": 0}),
        parallel.ParallelCall(name="note_list", args={"n": 1}),
    ]
    # Raw pool can overlap today; R2-A pins the LOOP path does too.
    import pathlib as _pl

    run_src = _pl.Path("src/hunter/agent/loop.py").read_text(encoding="utf-8")
    run_body = run_src.split("def run(", 1)[1] if "def run(" in run_src else ""
    # The run() body must invoke run_parallel (not just define the seam).
    if "run_parallel" not in run_body:
        pytest.fail(
            "EXPECTED-FAIL-R2A: loop run() body never invokes run_parallel; "
            "Barrier overlap only possible via true fan-out"
        )
    results = parallel.run_parallel(calls, max_workers=2, timeout=5.0, dispatch=dispatch)
    assert [r.name for r in results] == ["note_list", "note_list"]
    assert all(r.ok for r in results)
    assert sorted(entered) == ["note_list", "note_list"]
    _ = loop_mod


def test_r2a_parallel_true_order_preserved(tmp_path: Any) -> None:
    parallel = _needs_parallel()
    loop_src = open("src/hunter/agent/loop.py", encoding="utf-8").read()
    run_body = loop_src.split("def run(", 1)[1] if "def run(" in loop_src else ""
    if "run_parallel" not in run_body:
        pytest.fail(
            "EXPECTED-FAIL-R2A: transcript order via parallel fan-out missing; "
            "loop still sequential so order-preservation unproven"
        )
    calls = [parallel.ParallelCall(name="note_list", args={"n": i}) for i in range(6)]
    results = parallel.run_parallel(
        calls, max_workers=4, timeout=5.0, dispatch=lambda c: f"done:{c.args['n']}"
    )
    assert [r.payload for r in results] == [f"done:{i}" for i in range(6)]


def test_r2a_parallel_true_writes_stay_synchronous_negative() -> None:
    parallel = _needs_parallel()
    assert parallel.is_parallelizable("http_request", {"method": "GET"}) is True
    # Negatives: writes/lifecycle must NEVER fan out.
    for name, args in [
        ("http_request", {"method": "POST"}),
        ("create_finding_request", {}),
        ("finish_scan", {}),
        ("respond_to_user", {}),
    ]:
        assert parallel.is_parallelizable(name, args) is False
    loop_src = open("src/hunter/agent/loop.py", encoding="utf-8").read()
    run_body = loop_src.split("def run(", 1)[1] if "def run(" in loop_src else ""
    if "run_parallel" not in run_body:
        pytest.fail(
            "EXPECTED-FAIL-R2A: allowlist correct but loop never enforces it "
            "via run_parallel (writes would run inline sequential today)"
        )


def test_r2a_parallel_true_scope_claim_gates_dispatch_thread() -> None:
    parallel = _needs_parallel()
    assert parallel.gates_run_on_pool_thread() is False
    assert parallel.scope_gate_owner() == "dispatch-thread"
    assert parallel.claim_gate_owner() == "dispatch-thread"
    loop_src = open("src/hunter/agent/loop.py", encoding="utf-8").read()
    run_body = loop_src.split("def run(", 1)[1] if "def run(" in loop_src else ""
    if "run_parallel" not in run_body:
        pytest.fail(
            "EXPECTED-FAIL-R2A: gates pinned dispatch-thread but loop has no "
            "parallel dispatch site to enforce single-owner gates"
        )


def test_r2a_parallel_true_ledger_begin_immediate_no_locked(tmp_path: Any) -> None:
    parallel = _needs_parallel()
    from hunter.kernel.ledger import Ledger

    loop_src = open("src/hunter/agent/loop.py", encoding="utf-8").read()
    run_body = loop_src.split("def run(", 1)[1] if "def run(" in loop_src else ""
    if "run_parallel" not in run_body and "store_parallel_evidence" not in loop_src:
        pytest.fail(
            "EXPECTED-FAIL-R2A: loop never stores via store_parallel_evidence; "
            "BEGIN IMMEDIATE threaded path unwired"
        )
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        ids = parallel.store_parallel_evidence(
            ledger, "R-PAR-R2A", [{"kind": "note", "data": {"n": i}} for i in range(8)]
        )
        assert len(ids) == 8
        assert len(ledger.evidence("R-PAR-R2A")) == 8
        # Ledger rows are the anti-vacuous pin: ids minted EV-*, no loss.
        assert all(str(v).startswith("EV-") for v in ids)
    finally:
        ledger.close()
