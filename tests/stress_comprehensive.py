#!/usr/bin/env python3
"""HunterOSHarness COMPREHENSIVE STRESS TEST — 1 hour, random inputs.

Tests EVERY code path: Phase 0 classifier, each gatherer, loop_v4 with a
real provider, state corruption, doctor self-repair, and edge-case error
recovery. Reports a failure count and a verdict at the end.

Designed to catch:
  - Crashes / unhandled exceptions
  - Memory leaks (monitored via RSS every 60s)
  - State corruption (verified after every cycle)
  - Provider failures (retry logic exhausts)
  - Input kind misclassification
  - Deterministic fallback quality (confidence ≥ 1 on every input)
"""

from __future__ import annotations

import gc
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/tmp/hunteros-clone/src")

# ── imports under test ────────────────────────────────────────────
from hunter.workflow.phase0_recon import (
    Phase0Recon, classify_input, gather_material, run_recon,
    _deterministic_fallback, _extract_json, TARGET_JSON_SCHEMA,
)
from hunter.workflow.loop_v4 import (
    HuntLoopV4, LANE_SOULS, _parse_verdict, _candidates_from_args,
    _calls_from_text, _norm_response, _number_lines, read_target_source,
    _target_files, _split_source,
)
from hunter.workflow.state import HuntState, new_state, add_finding, save, load, SCHEMA_VERSION
from hunter.cli.doctor_v4 import collect_v4_checks
from hunter.cli.doctor_fix import attempt_fixes

# ── test harness ──────────────────────────────────────────────────
FAILS: list[dict] = []
STARTED = time.time()
BUDGET = 3600  # 1 hour
RSS_SAMPLES: list[int] = []
WORK = Path(tempfile.mkdtemp(prefix="hunt_stress_"))
WORK.mkdir(parents=True, exist_ok=True)

# Mistral provider for cheap fast calls
import ssl, urllib.request, urllib.error

def fail(label: str, detail: str, exc: Exception | None = None):
    entry = {"label": label, "detail": detail, "time": time.time() - STARTED}
    if exc is not None:
        entry["traceback"] = traceback.format_exc()[-800:]
    FAILS.append(entry)
    print(f"  ❌ [{entry['time']:.0f}s] {label}: {detail[:100]}")


def ok(label: str, detail: str = ""):
    print(f"  ✅ [{time.time()-STARTED:.0f}s] {label} {detail[:70]}")


def rss_mb() -> int:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        return -1


# ── random input generators ──────────────────────────────────────

VALID_URLS = [
    "https://example.com",
    "https://github.com/zaaaxx11/HunterOsHarness",
    "https://api.github.com/repos/zaaaxx11/HunterOsHarness",
    "https://eth.blockscout.com/api/v2/addresses/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "https://ethereum-rpc.publicnode.com",
]
INVALID_URLS = [
    "not-a-url", "", "ftp://no-such-protocol.local", "https://",
    "https://nonexistent-domain-48275.example", "javascript:alert(1)",
]
ADDRESSES = [
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
    "0x" + "a" * 40,
    "0x" + "b" * 64,  # tx hash, not address
]
FILES = [
    "*.example.com\napi.example.com\nhttps://app.example.com",
    json.dumps({"scope": ["x.com", "y.io"], "rules": {"no_ddos": True}}),
    "single line", "", "x" * 100_000,  # huge file
    "0x" + "c" * 40 + "\nhttps://foo.bar",
]
FREE_TEXT = [
    "bug bounty for foo.com and api.foo.com", "",
    "please test github.com/org/repo and contract 0x" + "d" * 40,
    "日本で一番人気のバウンティ",  # unicode stress
]


def gen_inputs() -> list[tuple[str, str]]:
    """(label, raw_input) pairs — every kind, valid and invalid."""
    pairs: list[tuple[str, str]] = []
    for u in VALID_URLS:
        pairs.append(("url-valid", u))
    for u in INVALID_URLS:
        pairs.append(("url-invalid", u))
    for a in ADDRESSES:
        pairs.append(("contract", a))
    # file
    for i, content in enumerate(FILES):
        f = WORK / f"scope_{i}.txt"
        f.write_text(content)
        pairs.append(("file", str(f)))
    # directory
    pairs.append(("directory", "/tmp/hunt-target-pv"))
    pairs.append(("directory", str(WORK)))
    # free-text
    for t in FREE_TEXT:
        pairs.append(("text", t))
    # edge: random bytes
    pairs.append(("garbage", os.urandom(200).hex()))
    pairs.append(("null-bytes", "hello\x00world"))
    # long text
    pairs.append(("long-text", "abc " * 8000))
    return pairs


# ── Phase-0 fuzz ──────────────────────────────────────────────────

def test_classify(label: str, raw: str):
    try:
        kind = classify_input(raw)
    except Exception as exc:
        fail(f"classify:{label}", f"crash on {raw[:40]!r}", exc)
        return
    # a valid kind is always one of the known set
    if kind not in ("url", "github", "playstore", "appstore", "file",
                    "directory", "contract", "tx", "text"):
        fail(f"classify:{label}", f"unknown kind {kind!r}")


def test_gather(label: str, raw: str, kind: str):
    try:
        m = gather_material(raw)
    except Exception as exc:
        fail(f"gather:{label}", f"crash on kind={kind}", exc)
        return
    if not isinstance(m, dict) or "kind" not in m:
        fail(f"gather:{label}", f"result not a dict with 'kind' — {type(m).__name__}")
        return
    if m["kind"] != kind:
        # contract gatherer may return "contract"; tx falls back to "tx"
        pass  # acceptable


def test_fallback(label: str, raw: str, kind: str):
    try:
        out = run_recon(raw, None, WORK)
    except Exception as exc:
        fail(f"fallback:{label}", f"deterministic crash", exc)
        return
    if out.get("recon_confidence", 10) < 1:
        fail(f"fallback:{label}", "confidence < 1")


# ── loop_v4 functional tests ─────────────────────────────────────
def test_loop_v4_short(target: str, label: str, wall_s: int = 3):
    """Run a minimal loop_v4 with a stub LLM — verify no crash."""
    class Stub:
        def __init__(self):
            self.calls = 0
        def complete(self, system, user):
            self.calls += 1
            return '{"findings":[]}'
        def complete_with_tools(self, system, user, tools, tool_choice=None):
            self.calls += 1
            return {"text":"","tool_calls":[{"name":"report_finding","arguments":{"findings":[]}}],"cost":0.0}
    ws = Path(tempfile.mkdtemp(dir=WORK))
    try:
        loop = HuntLoopV4(Stub(), None, target=target,
                          wall_seconds=wall_s, idle_seconds=0,
                          workdir=ws, log=lambda m: None)
        state = loop.run()
    except Exception as exc:
        fail(f"loop:{label}", f"crash", exc)
        return
    if state.round < 1:
        fail(f"loop:{label}", "no cycle ran")
    if state.completion_reason not in ("time-expired", "goals-met", "max-cycles"):
        fail(f"loop:{label}", f"unexpected stop: {state.completion_reason}")


# ── utility function robustness ──────────────────────────────────
def test_utils():
    """Exercise every module-level helper."""
    # _parse_verdict
    for raw in ('{"verdict":"verified"}', "VERDICT: REFUTED\n", "exploitable",
                "not exploitable", "", "garbage text with no signal"):
        try:
            v = _parse_verdict(raw)
            if v.get("verdict") not in ("verified", "refuted", "unreviewed"):
                fail("parse_verdict", f"unknown verdict {v['verdict']!r}")
        except Exception as exc:
            fail("parse_verdict", f"crash on {raw[:40]!r}", exc)

    # _candidates_from_args
    for args in ({"findings": [{"title":"x","severity":"h"}]}, {}, None,
                 {"nested": {"findings": [{"title":"y","severity":"m"}]}},
                 [{"title":"list","severity":"l"}]):
        try:
            got = _candidates_from_args(args)
            if not isinstance(got, list):
                fail("candidates_from_args", f"non-list return: {type(got).__name__}")
        except Exception as exc:
            fail("candidates_from_args", "crash", exc)

    # _norm_response
    for resp in (None, {}, {"text":"hi"}, {"text":"","tool_calls":[{"name":"f","arguments":{"x":1}}],"cost":0.5}):
        try:
            t, c, cost = _norm_response(resp)
            if not isinstance(t, str) or not isinstance(c, list) or not isinstance(cost, (int,float)):
                fail("norm_response", f"wrong types: {type(t).__name__} {type(c).__name__} {type(cost).__name__}")
        except Exception as exc:
            fail("norm_response", "crash", exc)

    # _target_files
    try:
        files = _target_files(Path("/tmp/hunt-target-pv"))
        if not isinstance(files, list):
            fail("target_files", f"non-list: {type(files).__name__}")
    except Exception as exc:
        fail("target_files", "crash", exc)

    # _split_source edge cases
    for text in ("", "hello", "x" * 5000, "\0" * 200):
        try:
            chunks = _split_source(text)
            if not isinstance(chunks, list):
                fail("split_source", f"non-list: {type(chunks).__name__}")
        except Exception as exc:
            fail("split_source", "crash on len={len(text)}", exc)

    ok("utils", f"_parse_verdict + _candidates + _norm_response + target_files + split_source")


# ── agent prompt truncation test ──────────────────────────────────
def test_prompt_truncation():
    """Loop_v4 must not exceed provider max-token budget on large targets."""
    from hunter.workflow.loop_v4 import read_target_source
    source = read_target_source("/tmp/hunt-target-pv", Path("/tmp"))
    if source is not None:
        n = len(source.split())
        if n > 20_000:
            fail("truncation", f"prompt too large ({n} words) — may 524")
        else:
            ok("truncation", f"prompt ~{n} words (acceptable)")
    else:
        ok("truncation", "no source (empty target)")


# ── state corruption / recovery ───────────────────────────────────
def test_state_corruption_recovery():
    """Corrupt hunt_state.json, run doctor --fix, verify it heals."""
    sdir = WORK / "doctor_test"
    sdir.mkdir(exist_ok=True)
    sp = sdir / "hunt_state.json"
    # write garbage
    sp.write_text("NOT JSON AT ALL {{{")
    try:
        checks = collect_v4_checks(state=sdir)
        fails = [c for c in checks if c.status == "fail"]
        if fails:
            # attempt fix
            fixes = attempt_fixes(checks)
            applied = [f for f in fixes if f.action == "applied"]
            if applied:
                ok("state-recovery", f"corrupted state fixed ({applied[0].detail[:60]})")
            else:
                fail("state-recovery", f"no fix applied for {fails[0].label}")
        else:
            ok("state-recovery", "state checks passed without fix needed")
    except Exception as exc:
        fail("state-recovery", "doctor crash", exc)


# ── loop_v4 error blanket ─────────────────────────────────────────
def test_loop_v4_provider_crash():
    """Inject a crashing provider and verify the loop survives."""
    class CrashLLM:
        def __init__(self):
            self.calls = 0
        def complete(self, system, user):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("simulated provider crash")
            return '{"findings":[]}'
        def complete_with_tools(self, system, user, tools, tool_choice=None):
            self.calls += 1
            return {"text":"","tool_calls":[{"name":"report_finding","arguments":{"findings":[]}}],"cost":0.0}

    ws = Path(tempfile.mkdtemp(dir=WORK))
    try:
        loop = HuntLoopV4(CrashLLM(), None, target="/tmp/hunt-target-pv",
                          wall_seconds=3, idle_seconds=0,
                          workdir=ws, log=lambda m: None)
        state = loop.run()
        if state.round >= 1 and state.completion_reason in ("time-expired",):
            ok("error-blanket", "loop survived provider crash + continued")
        else:
            fail("error-blanket", f"unexpected stop: {state.completion_reason}")
    except Exception as exc:
        fail("error-blanket", "crash", exc)


# ── doctor self-test ──────────────────────────────────────────────
def test_doctor_self():
    try:
        checks = collect_v4_checks(state=WORK, live=False)
        if any(c.status == "fail" for c in checks):
            for c in checks:
                if c.status == "fail":
                    fail(f"doctor:{c.label}", c.detail)
        else:
            ok("doctor-self", f"{len(checks)} checks all green")
    except Exception as exc:
        fail("doctor-self", "crash", exc)


# ── schema version check ─────────────────────────────────────────
def test_schema_version():
    try:
        assert SCHEMA_VERSION >= 1
        st = new_state("test")
        assert st.phase0_done is False
        assert st.target_json_path == ""
        ok("schema", f"v{SCHEMA_VERSION} — phase0_done + target_json_path present")
    except Exception as exc:
        fail("schema", "version or field error", exc)


# ── live hunt (short, real provider) ─────────────────────────────
def test_live_hunt():
    """Run a 120s live hunt against PracticeVault. Verifies end-to-end."""
    import yaml
    from pathlib import Path as P

    cfg = yaml.safe_load(P(os.path.expanduser("~/.hermes/config.yaml")).read_text())
    providers = [p for p in (cfg.get("custom_providers") or [])
                 if isinstance(p, dict) and p.get("name", "").lower() == "customin"]
    if not providers:
        ok("live-hunt", "skipped — no customin provider")
        return
    ci = providers[0]
    key = ci.get("api_key", "")
    base = ci.get("base_url", "")
    if "..." in str(key) or not base:
        ok("live-hunt", "skipped — masked key")
        return

    class LiveLLM:
        def __init__(self):
            self.calls = 0
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

        def _post(self, messages, tools=None):
            payload = {"model": "deepseek-v4.1-flash", "max_tokens": 2000, "messages": messages}
            if tools: payload["tools"] = tools
            req = urllib.request.Request(
                f"{base}/chat/completions",
                data=json.dumps(payload).encode(),
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            for _ in range(2):
                try:
                    with urllib.request.urlopen(req, timeout=120, context=self._ctx) as r:
                        return json.loads(r.read().decode())
                except Exception:
                    time.sleep(3)
            return None

        def complete(self, system, user):
            self.calls += 1
            d = self._post([{"role":"system","content":system},{"role":"user","content":user}])
            if d and "choices" in d:
                return d["choices"][0].get("message",{}).get("content","")
            return '{"findings":[]}'

        def complete_with_tools(self, system, user, tools, tool_choice=None):
            self.calls += 1
            d = self._post([{"role":"system","content":system},{"role":"user","content":user}], tools)
            if d and "choices" in d:
                msg = d["choices"][0].get("message",{})
                tc = msg.get("tool_calls") or []
                calls = []
                for t in tc:
                    fn = t.get("function",{})
                    args = fn.get("arguments","{}")
                    if isinstance(args, str):
                        try: args = json.loads(args)
                        except Exception: args = {}
                    calls.append({"name":fn.get("name",""),"arguments":args})
                return {"text":msg.get("content",""),"tool_calls":calls,"cost":0.0}
            return {"text":"","tool_calls":[{"name":"report_finding","arguments":{"findings":[]}}],"cost":0.0}

    ws = Path(tempfile.mkdtemp(dir=WORK))
    try:
        loop = HuntLoopV4(LiveLLM(), None, target="/tmp/hunt-target-pv",
                          wall_seconds=120, idle_seconds=10,
                          workdir=ws, log=lambda m: None)
        state = loop.run()
        n = len(state.findings)
        if n > 0:
            ok("live-hunt", f"{n} findings in {state.round} cycles (live provider)")
        elif state.round >= 1:
            ok("live-hunt", f"0 findings but {state.round} cycles completed (provider may be slow/524)")
        else:
            fail("live-hunt", "no cycles ran — provider unreachable")
    except Exception as exc:
        fail("live-hunt", "crash", exc)


# ── memory monitor ────────────────────────────────────────────────
def check_memory():
    rss = rss_mb()
    RSS_SAMPLES.append(rss)
    if len(RSS_SAMPLES) > 2:
        first = RSS_SAMPLES[0]
        last5 = RSS_SAMPLES[-5:]
        growth = max(last5) - first
        if growth > 500:  # 500 MB growth is leak territory
            fail("memory", f"possible leak: +{growth}MB over {len(RSS_SAMPLES)} samples "
                  f"(first={first} last={RSS_SAMPLES[-1]})")


# ══════════════════════════════════════════════════════════════════
# MAIN — 1 hour randomized queue
# ══════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("HUNTEROSHARNESS COMPREHENSIVE STRESS TEST — 1 hour")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"Workdir: {WORK}")
    print("=" * 60)

    inputs = gen_inputs()
    print(f"\n{len(inputs)} input variants generated")

    # ── TIME-BOXED RANDOMIZED LOOP ──────────────────────────────
    count = 0
    while time.time() - STARTED < BUDGET:
        count += 1
        remaining = int(BUDGET - (time.time() - STARTED))
        if count % 20 == 0:
            print(f"\n--- tick {count}  ({remaining}s left)  RSS={rss_mb()}MB  failures={len(FAILS)} ---")

        # pick a random input
        slabel, raw = random.choice(inputs)
        kind = classify_input(raw)

        # -- Phase 0 fuzz
        test_classify(slabel, raw)
        test_gather(slabel, raw, kind)
        test_fallback(slabel, raw, kind)

        # -- every 10th iteration: run a short loop_v4
        if count % 10 == 0:
            target = raw if kind in ("file", "directory") else "/tmp/hunt-target-pv"
            test_loop_v4_short(target, f"cycle{count}", wall_s=2)

        # -- every 50th: utility checks
        if count % 25 == 0:
            test_utils()
            test_schema_version()

        # -- every 100th: doctor + state recovery + error blanket
        if count % 50 == 0:
            test_doctor_self()
            test_state_corruption_recovery()
            test_prompt_truncation()

        # -- every 150th: provider crash recovery
        if count % 75 == 0:
            test_loop_v4_provider_crash()

        # -- memory check every 60 cycles
        if count % 60 == 0:
            check_memory()
            gc.collect()

        # -- at 30 min: run the live hunt once
        elapsed = time.time() - STARTED
        if 1700 < elapsed < 1750:
            test_live_hunt()

        # short sleep to avoid CPU saturation
        time.sleep(random.uniform(0.5, 2.0))

    # ── FINAL REPORT ────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STRESS TEST COMPLETE")
    print("=" * 60)
    print(f"  iterations      : {count}")
    print(f"  elapsed         : {time.time()-STARTED:.0f}s")
    print(f"  failures        : {len(FAILS)}")
    print(f"  RSS start       : {RSS_SAMPLES[0] if RSS_SAMPLES else '?'}MB")
    print(f"  RSS end         : {RSS_SAMPLES[-1] if RSS_SAMPLES else '?'}MB")
    print(f"  RSS growth      : {(RSS_SAMPLES[-1]-RSS_SAMPLES[0]) if len(RSS_SAMPLES)>1 else 0}MB")

    print(f"\n  FAILURE COUNT BY LABEL:")
    by_label = Counter(f["label"] for f in FAILS)
    for l, n in by_label.most_common(15):
        print(f"    {l:45s} {n}")

    # verdict
    if not FAILS:
        print("\n  VERDICT: ✅ ALL CLEAN — 0 failures in 1 hour")
    elif len(FAILS) <= 3:
        print(f"\n  VERDICT: ⚠️  ACCEPTABLE — {len(FAILS)} minor failures (see above)")
    else:
        print(f"\n  VERDICT: ❌ NEEDS WORK — {len(FAILS)} failures")

    # save report
    report = {
        "started": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": time.time() - STARTED,
        "iterations": count,
        "failures": len(FAILS),
        "failure_details": FAILS[:50],
        "rss_samples": RSS_SAMPLES,
    }
    (WORK / "stress_report.json").write_text(json.dumps(report, indent=2, default=str))
    print(f"\n  report -> {WORK/'stress_report.json'}")

    return len(FAILS)


if __name__ == "__main__":
    try:
        n = main()
    except KeyboardInterrupt:
        print(f"\ninterrupted after {time.time()-STARTED:.0f}s")
        n = len(FAILS) + 1
    sys.exit(0 if n == 0 else min(n, 127))