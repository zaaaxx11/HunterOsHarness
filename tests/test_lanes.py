from __future__ import annotations

from hunter.agent.lanes import Lane, LaneRunner, default_lanes, merge


def test_lane_consume_and_remaining():
    lane = Lane("recon", 3, [], {})
    assert lane.remaining() == 3
    assert lane.consume() is True
    assert lane.remaining() == 2
    assert lane.consume(2) is True
    assert lane.remaining() == 0
    assert lane.consume() is False
    assert lane.remaining() == 0
    # consuming more than remaining fails without mutation
    lane2 = Lane("x", 2, [], {})
    assert lane2.consume(5) is False
    assert lane2.remaining() == 2


def test_default_lanes_budgets():
    lanes = default_lanes()
    assert [lane.name for lane in lanes] == [
        "recon", "web2", "web3", "network", "chainer", "verifier", "curator",
    ]
    budgets = {lane.name: lane.budget for lane in lanes}
    assert budgets == {
        "recon": 20, "web2": 50, "web3": 50, "network": 30,
        "chainer": 40, "verifier": 30, "curator": 10,
    }


def test_fan_out_collects_per_lane_results():
    lanes = default_lanes()[:2]

    def work_fn(lane):
        lane.findings.append(f"finding-{lane.name}")
        return list(lane.findings)

    runner = LaneRunner()
    results = runner.fan_out(lanes, work_fn)
    assert results == [["finding-recon"], ["finding-web2"]]
    # lanes independent: findings not shared
    assert lanes[0].findings == ["finding-recon"]
    assert lanes[1].findings == ["finding-web2"]


def test_budget_exhaustion_stops_lane():
    lane = Lane("worker", 2, [], {})

    def work_fn(lane):
        out = []
        while lane.consume():
            out.append(lane.name)
        return out

    runner = LaneRunner()
    results = runner.fan_out([lane], work_fn)
    assert results == [["worker", "worker"]]
    assert lane.remaining() == 0
    assert lane.consume() is False


def test_merge_flattens():
    lanes = default_lanes()[:2]
    for lane in lanes:
        lane.findings.append(lane.name)
        lane.findings.append(lane.name + "-2")

    runner = LaneRunner()
    results = runner.fan_out(lanes, lambda lane: list(lane.findings))
    merged = runner.merge(results)
    assert merged == ["recon", "recon-2", "web2", "web2-2"]
    # module-level helper works too
    assert merge(results) == merged


def test_merge_nested_and_objects():
    class Obj:
        def __init__(self, findings):
            self.findings = findings

    results = [[1, 2], (3,), {"findings": [4, 5]}, Obj([6])]
    assert LaneRunner.merge(results) == [1, 2, 3, 4, 5, 6]


def test_global_cap_stops_lanes():
    lanes = [Lane("a", 5, [], {}), Lane("b", 5, [], {})]

    def work_fn(lane):
        n = 0
        while lane.consume():
            n += 1
        return n

    runner = LaneRunner(global_cap=3)
    # cap lane budgets so total <= 3
    results = runner.fan_out(lanes, work_fn)
    # first lane consumes up to 3 (capped), second sees 0 global -> None
    assert results[0] == 3
    assert results[1] is None
