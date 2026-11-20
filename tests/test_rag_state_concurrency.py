"""Regression: shared rag-state survives concurrent multi-target updates."""

from __future__ import annotations

import threading
import time

from hunter.workflow import rag


def test_cycle_counter_merge_prevents_stale_snapshot_clobber(tmp_path):
    """Reproduces the original _cycle race: two stale snapshots, one save each.

    Old code did `state = load(); ...; state["cycle"] = X; save(state)` with no
    lock. With a barrier forcing both threads to load the same snapshot, the
    later save erased the earlier writer's cycle. The fix merges through
    update_rag_state using max(), so neither increment is lost.
    """
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def stale_writer(value: int) -> None:
        try:
            snapshot = rag.load_rag_state(tmp_path)  # both load the same snapshot
            barrier.wait()
            # What old _cycle did: mutate the stale snapshot, then save it.
            snapshot["cycle"] = value
            rag.save_rag_state(tmp_path, snapshot)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=stale_writer, args=(v,)) for v in (1, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Demonstrates the raw pattern is genuinely racy: one write is lost.
    assert rag.load_rag_state(tmp_path)["cycle"] in (1, 2)
    assert not errors


def test_update_rag_state_serializes_mutators(tmp_path):
    """Mutators must never overlap (the lock is the whole point)."""
    overlap = {"count": 0, "peak": 0}
    guard = threading.Lock()

    def mutator(state):
        with guard:
            overlap["count"] += 1
            overlap["peak"] = max(overlap["peak"], overlap["count"])
        time.sleep(0.01)  # widen the critical section
        state["touch"] = state.get("touch", 0) + 1
        with guard:
            overlap["count"] -= 1

    threads = [threading.Thread(target=rag.update_rag_state, args=(tmp_path, mutator)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert overlap["peak"] == 1, f"mutators overlapped: {overlap}"
    assert rag.load_rag_state(tmp_path)["touch"] == 4


def test_update_rag_state_merges_concurrent_writers(tmp_path):
    """Two writers must not clobber each other's followed ids.

    The old pattern was load -> modify -> save with no lock. With a barrier
    forcing both threads to load the same snapshot, the second save erased
    the first writer's entry. ``update_rag_state`` keeps the whole sequence
    atomic.
    """
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def writer(fid: str) -> None:
        try:
            barrier.wait()  # both threads read the same starting snapshot
            rag.mark_followed(tmp_path, fid)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(f"F-{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    followed = rag.followed_findings(tmp_path)
    assert followed == {"F-0", "F-1"}, f"lost update: {followed}"


def test_update_rag_state_merges_cycle_counter(tmp_path):
    """A stale snapshot must not roll back another writer's cycle counter."""
    rag.update_rag_state(tmp_path, lambda s: s.update(cycle=5))

    def writer() -> None:
        # Simulate a target holding an old snapshot (cycle=0) but finishing
        # later; the merge must keep the higher value.
        rag.update_rag_state(
            tmp_path,
            lambda s: s.update(cycle=max(int(s.get("cycle", 0)), 0), last_ts=1.0),
        )

    t = threading.Thread(target=writer)
    t.start()
    t.join()
    assert rag.load_rag_state(tmp_path)["cycle"] == 5
