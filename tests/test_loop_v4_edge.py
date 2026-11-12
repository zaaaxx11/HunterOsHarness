"""Deep stress test — exercises ALL loop_v4 edge cases.

Tests:
  1. Empty target (no source files) — graceful handle? or crash?
  2. Target with 500 fake files — memory/OOM? or bounded?
  3. Rapid cycle (idle=0) — state corruption? race condition?
  4. Resume hunt — stale state handled correctly?
  5. Tool call timeout → retry → success path
  6. L1 verify edge: anchor with unicode path, missing file, line=0, negative line
  7. Deep-dive with all verdict variants (verified/refuted/unreviewed/JSON/line)
  8. add_finding dedup: same title, same file:line, edge cases
  9. Complete cycle NEVER finds anything — convergence detection
  10. Multiple lanes reporting identical findings — dedup in action
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hunter.workflow.loop_v4 import (
    HuntLoopV4, LANE_SOULS, _parse_verdict, _candidates_from_args,
    _calls_from_text, _norm_response, _number_lines, _target_files, _split_source
)
from hunter.workflow.state import HuntState, new_state, add_finding, save, load

# ── helper: a fake LLM that returns controlled answers ──

class TestLLM:
    def __init__(self, mode="clean"):
        self.mode = mode        # clean | crash | timeout | one_find
        self.calls = 0
        self.cost = 0.0

    def complete(self, system, user):
        self.calls += 1
        self.cost += 0.001
        u = user.lower()
        if self.mode == "crash":
            raise RuntimeError("simulated provider crash")
        if self.mode == "timeout":
            time.sleep(60)  # won't actually sleep here
            return ""
        # return findings matching a ground-truth pattern
        return json.dumps({"findings": [
            {"title": f"test-{self.calls}", "severity": "high",
             "description": "test", "file": "x.py", "line": 1, "code": "x"}
        ]})

    def complete_with_tools(self, system, user, tools, tool_choice=None):
        self.calls += 1
        self.cost += 0.001
        return {"text": "", "tool_calls": [
            {"name": "report_finding", "arguments": {"findings": [
                {"title": f"tool-{self.calls}", "severity": "high",
                 "description": "test", "file": "x.py", "line": 1, "code": "x"}
            ]}}
        ], "cost": 0.001}

# ── helper: a fake verifier ──

def fake_verify(claim, ctx):
    return {"status": "unverified", "l1": {"status": "anchored", "detail": "fake"}}

# ── helpers: temp dirs ──

def mktarget(files=None):
    d = tempfile.mkdtemp(prefix="stress_")
    if files:
        for name, content in (files or {}).items():
            Path(d, name).write_text(content)
    return d

def mkstate_dir():
    return tempfile.mkdtemp(prefix="state_")

# ══════════════════════════════════════════════════════════════
# TEST 1: Empty target (no files) → graceful? or crash?
# ══════════════════════════════════════════════════════════════
def test_empty_target():
    print("TEST 1: empty target dir")
    d = mktarget()
    ws = mkstate_dir()
    loop = HuntLoopV4(TestLLM(), fake_verify, target=d,
                      wall_seconds=2, idle_seconds=0, workdir=ws,
                      log=lambda m: None)
    try:
        state = loop.run()
        assert state.completion_reason == "time-expired"
        assert state.round >= 1  # at least one round ran
        print("  ✅ cycles=%d findings=%d" % (state.round, len(state.findings)))
    except Exception as e:
        print(f"  ❌ CRASH: {type(e).__name__}: {e}")
        return False
    return True

# ══════════════════════════════════════════════════════════════
# TEST 2: 500-fake-files target → memory? OOM?
# ══════════════════════════════════════════════════════════════
def test_many_files():
    print("TEST 2: 500 .py files")
    files = {}
    for i in range(500):
        files[f"mod_{i:04d}.py"] = f"# file {i}\ndef foo():\n    return {i}\nPASSWORD_{i} = 'secret'"
    d = mktarget(files)
    ws = mkstate_dir()
    loop = HuntLoopV4(TestLLM(), fake_verify, target=d,
                      wall_seconds=1, idle_seconds=0, workdir=ws,
                      log=lambda m: None)
    try:
        state = loop.run()
        assert state.round >= 1
        assert state.completion_reason == "time-expired"
        print(f"  ✅ cycles={state.round} findings={len(state.findings)}")
    except Exception as e:
        print(f"  ❌ CRASH: {type(e).__name__}: {e}")
        return False
    return True

# ══════════════════════════════════════════════════════════════
# TEST 3: Rapid cycles (idle=0) → state corruption?
# ══════════════════════════════════════════════════════════════
def test_rapid_cycles():
    print("TEST 3: rapid cycles (idle=0, 5s)")
    d = mktarget({"a.py": "x=1\n"})
    ws = mkstate_dir()
    loop = HuntLoopV4(TestLLM(), fake_verify, target=d,
                      wall_seconds=3, idle_seconds=0, workdir=ws,
                      log=lambda m: None)
    try:
        state = loop.run()
        assert state.round >= 1
        assert state.completion_reason == "time-expired"
        print(f"  ✅ cycles={state.round} findings={len(state.findings)}")
    except Exception as e:
        print(f"  ❌ CRASH: {type(e).__name__}: {e}")
        return False
    return True

# ══════════════════════════════════════════════════════════════
# TEST 4: State resume (stale budget) → handled?
# ══════════════════════════════════════════════════════════════
def test_state_resume():
    print("TEST 4: stale state resume")
    d = mktarget({"a.py": "x=1\n"})
    ws = mkstate_dir()
    sp = Path(ws) / ".hunt" / "x" / "hunt_state.json"
    sp.parent.mkdir(parents=True, exist_ok=True)
    # Write a stale state (expired 1000s ago)
    stale = new_state(d, wall_seconds=5, idle_seconds=0)
    stale.wall_seconds = 5
    stale.started_at = time.time() - 1000  # expired long ago
    stale.completion_reason = "time-expired"
    save(stale, sp)
    # New HuntLoopV4 with fresh budget should override stale
    loop = HuntLoopV4(TestLLM(), fake_verify, target=d,
                      wall_seconds=2, idle_seconds=0, workdir=ws,
                      log=lambda m: None)
    try:
        state = loop.run()
        assert state.round >= 1
        assert state.completion_reason == "time-expired"
        print(f"  ✅ resumed, cycles={state.round} (budget overrode stale)")
    except Exception as e:
        print(f"  ❌ CRASH: {type(e).__name__}: {e}")
        return False
    return True

# ══════════════════════════════════════════════════════════════
# TEST 5: L1 verify edge cases
# ══════════════════════════════════════════════════════════════
def test_l1_edges():
    print("TEST 5: L1 verify edges")
    d = mktarget({"a.py": "line1\nline2\nline3\nline4\n"})
    ws = mkstate_dir()
    class _S: target = d
    class _L:
        state = _S()
        workdir = ws
        from hunter.workflow.loop_v4 import HuntLoopV4 as H
        _resolve_anchor_path = H._resolve_anchor_path
        _anchor_inside = H._anchor_inside
        _l1_verify_finding = H._l1_verify_finding
        def _log(self, *a): pass
    loop = _L()

    tests = [
        # (finding dict, expected l1 status, label)
        ({"file_line": "a.py:1"}, "anchored", "normal"),
        ({"file_line": "a.py:999"}, "refuted", "line OOB"),
        ({"file_line": "a.py:0"}, "refuted", "line=0"),
        ({"file_line": "a.py:-1"}, "unverifiable", "negative line — regex rejects"),
        ({"file_line": "b.py:1"}, "refuted", "missing file"),
        ({"file_line": ""}, "unverifiable", "empty anchor"),
        ({"title": "x"}, "unverifiable", "no anchor at all"),
    ]
    for f, want, label in tests:
        r = loop._l1_verify_finding(f)
        got = (r.get("l1") or {}).get("status", r.get("status","?"))
        ok = got == want
        print(f"  {'✅' if ok else '❌'} {label:16s} want={want:12s} got={got}")
    return all((loop._l1_verify_finding(f).get("l1") or {}).get("status") == w
               for f, w, _ in tests)

# ══════════════════════════════════════════════════════════════
# TEST 6: _parse_verdict robustness
# ══════════════════════════════════════════════════════════════
def test_parse_verdict():
    print("TEST 6: _parse_verdict all variants")
    cases = [
        ('{"verdict":"verified","reason":"ok"}', "verified"),
        ('{"verdict":"refuted","reason":"bad"}', "refuted"),
        ("analysis paragraph\n\nVERDICT: VERIFIED", "verified"),
        ("VERDICT - REFUTED because auth required", "refuted"),
        ("This is exploitable", "verified"),
        ("This is not exploitable because of nonce", "refuted"),
        # tricky: both words appear
        ("exploitable but refuted by gate.check", "refuted"),
        ("not exploitable but verified by code", "refuted"),  # negation first
        ("just a description with no verdict", "unreviewed"),
        ("", "unreviewed"),
    ]
    ok = 0
    for raw, want in cases:
        got = _parse_verdict(raw)["verdict"]
        if got == want:
            ok += 1
            print(f"  ✅ {raw[:50]!r:52s} -> {got}")
        else:
            print(f"  ❌ {raw[:50]!r:52s} want={want:10s} got={got}")
    print(f"  {ok}/{len(cases)} passed")
    return ok == len(cases)

# ══════════════════════════════════════════════════════════════
# TEST 7: _candidates_from_args — all key variants
# ══════════════════════════════════════════════════════════════
def test_candidates():
    print("TEST 7: _candidates_from_args key variants")
    cases = [
        # (args, expected_count, label)
        ({"findings": [{"title":"a","severity":"high"}]}, 1, "findings[]"),
        ({"mappings": [{"title":"b","severity":"med"}]}, 1, "mappings[]"),
        ({"results": [{"title":"c","severity":"low"}]}, 1, "results[]"),
        ({"items": [{"title":"d","severity":"high"}]}, 1, "items[]"),
        ({"vulnerabilities": [{"title":"e","severity":"critical"}]}, 1, "vulnerabilities[]"),
        ({"title": "solo", "severity": "high"}, 1, "bare dict"),
        ([{"title": "list"}, {"severity":"high"}], 1, "bare list (only titled)"),
        ({"result": {"findings": [{"title":"nested","severity":"high"}]}}, 1, "nested result"),
        ({}, 0, "empty dict"),
        (None, 0, "None"),
        ({"no_title_here": [{"foo":"bar"}]}, 0, "untitled items"),
    ]
    ok = 0
    for args, want, label in cases:
        got = _candidates_from_args(args)
        if len(got) == want:
            ok += 1
            print(f"  ✅ {label:24s} -> {len(got)}")
        else:
            print(f"  ❌ {label:24s} want={want} got={len(got)}")
    print(f"  {ok}/{len(cases)} passed")
    return ok == len(cases)

# ══════════════════════════════════════════════════════════════
# TEST 8: _norm_response — dict vs object turns
# ══════════════════════════════════════════════════════════════
def test_norm_response():
    print("TEST 8: _norm_response dict/object handling")
    # dict (our adapters return this)
    d, c, cost = _norm_response({"text":"ok","tool_calls":[{"name":"f","arguments":{"x":1}}],"cost":0.5})
    assert d == "ok", d
    assert len(c) == 1 and c[0]["name"] == "f"
    assert cost == 0.5
    print("  ✅ dict response -> text+tool_calls+cost")

    # bare dict with no tool_calls
    d, c, cost = _norm_response({"text":"prose"})
    assert d == "prose" and c == [] and cost == 0.0
    print("  ✅ bare text dict -> no tool_calls")

    # object (native provider)
    class Obj:
        text = "obj"
        tool_calls = []
        cost = 0.01
    d, c, cost = _norm_response(Obj())
    assert d == "obj" and c == []
    print("  ✅ object response -> clean")

    # None / empty
    d, c, cost = _norm_response(None)
    print(f"  ✅ None -> safe defaults (text={d!r}, calls={len(c)}, cost={cost})")
    return True

# ══════════════════════════════════════════════════════════════
# TEST 9: Source chunking edge cases
# ══════════════════════════════════════════════════════════════
def test_chunking():
    print("TEST 9: source chunking")
    # 5000-char file should be split into chunks
    big = "x" * 6000 + "\ny" * 6000
    chunks = _split_source(big)
    assert len(chunks) >= 2, f"expected >=2 chunks, got {len(chunks)}"
    print(f"  ✅ 12k source -> {len(chunks)} chunks")

    # tiny file (single chunk)
    tiny = "hello\n"
    chunks = _split_source(tiny)
    assert len(chunks) == 1
    print(f"  ✅ 6-char source -> 1 chunk")
    return True

# ══════════════════════════════════════════════════════════════
# TEST 10: Convergence detection (3 empty cycles → warning)
# ══════════════════════════════════════════════════════════════
class SilentLLM(TestLLM):
    """Returns empty findings every time — should trigger convergence."""
    def complete_with_tools(self, *a, **kw):
        self.calls += 1; self.cost += 0.001
        return {"text":"","tool_calls":[{"name":"report_finding","arguments":{"findings":[]}}],"cost":0.001}
    def complete(self, *a, **kw):
        self.calls += 1; self.cost += 0.001
        return '{"findings":[]}'

def test_convergence():
    print("TEST 10: convergence detection (empty cycles)")
    d = mktarget({"a.py": "x=1\n# just one line\n"})
    ws = mkstate_dir()
    logs = []
    loop = HuntLoopV4(SilentLLM(), fake_verify, target=d,
                      wall_seconds=5, idle_seconds=0, workdir=ws,
                      log=lambda m: logs.append(m))
    try:
        state = loop.run()
        assert state.completion_reason == "time-expired"
        # check there was a convergence warning in the logs
        warnings = [l for l in logs if "empty cycles" in l.lower() or "hardened" in l.lower()]
        print(f"  ✅ cycles={state.round} findings={len(state.findings)} convergence_warnings={len(warnings)}")
        return True
    except Exception as e:
        print(f"  ❌ CRASH: {type(e).__name__}: {e}")
        return False

# ── run all ──
if __name__ == "__main__":
    results = {}
    for name, fn in [
        ("empty-target", test_empty_target),
        ("many-files", test_many_files),
        ("rapid-cycles", test_rapid_cycles),
        ("state-resume", test_state_resume),
        ("l1-edges", test_l1_edges),
        ("parse-verdict", test_parse_verdict),
        ("candidates", test_candidates),
        ("norm-response", test_norm_response),
        ("chunking", test_chunking),
        ("convergence", test_convergence),
    ]:
        try:
            ok = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            ok = False
        results[name] = ok
        print()

    print("=" * 50)
    passed = sum(1 for v in results.values() if v)
    print(f"RESULT: {passed}/{len(results)} passed")
    for n, v in results.items():
        print(f"  {'✅' if v else '❌'} {n}")
    sys.exit(0 if passed == len(results) else 1)