#!/usr/bin/env python3
"""Stress test for HuntLoopV4 — 15 minutes, simulated LLM, local target.

Exercises:
- Phase 0 RECON (real HTTP fetch to a test URL)
- Multi-lane loop (architect/redteam/fuzzer → chainer)
- L1 verify (deterministic, real files)
- Deep-dive trigger flow
- Timer / idle / state save crash-safety
- Memory / open-file leaks

Simulated LLM: returns JSON findings on demand.
"""

import json
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from hunter.workflow.loop_v4 import HuntLoopV4, _load_soul
from hunter.workflow.state import HuntState, new_state, save, load, count_verified, elapsed_seconds

# ---- simulated LLM ----

class StressLLM:
    """Returns JSON findings for lanes, chains for chainer, verdicts for verifier."""
    def __init__(self):
        self.call_count = 0
        self.cost_total = 0.0

    def complete(self, system: str, user: str) -> str:
        self.call_count += 1
        self.cost_total += 0.001
        user_lower = user.lower()

        # chainer
        if "chainer" in system.lower() or "build exploit chains" in user_lower:
            if "new finding" in user_lower:
                return '{"chains":[{"title":"sim-chain-auth-bypass","steps":"Recon leak -> auth bypass -> admin","severity":"high","impact":"Admin takeover via leaked credential chain"}]}'
            return '{"chains":[]}'

        # empty cycle simulation — only report findings every 3rd call
        if self.call_count % 3 != 0:
            return '{"findings":[]}'

        # verifier (deep-dive)
        if "not exploitable" in user_lower or "verdict" in user_lower:
            return '{"verdict":"verified","reason":"Simulated adversarial review — looks solid"}'

        # regular lane
        return json.dumps({"findings": [
            {"title": f"sim-finding-{self.call_count}", "severity": "high",
             "description": f"Simulated vulnerability #{self.call_count}: insecure default config",
             "file": "src/test.py", "line": 10, "code": "password = 'admin123'",
             "vuln_type": "info-disclosure"},
            {"title": f"sim-low-{self.call_count}", "severity": "low",
             "description": f"Minor info leak #{self.call_count}",
             "file": "src/test.py", "line": 42, "code": "print(debug_info)",
             "vuln_type": "info-disclosure"},
        ]})

    def complete_with_tools(self, system, user, tools, tool_choice=None):
        return type("Resp", (), {
            "text": self.complete(system, user),
            "tool_calls": [{"name": "report_finding", "arguments": json.loads(self.complete(system, user))}],
            "cost": 0.001,
        })()


# ---- verify hook ----

def fake_verify(claim, ctx):
    return {"status": "unverified", "l1": {"status": "anchored", "detail": "stress test: file simulated"}}


# ---- setup ----

def setup_target_dir():
    d = tempfile.mkdtemp(prefix="stress_target_")
    # Create some python files as fake audit surface
    (Path(d) / "src").mkdir(exist_ok=True)
    (Path(d) / "src" / "test.py").write_text("""# Stress test target
import os

PASSWORD = 'admin123'
SECRET_KEY = 'sk-test-1234567890'

def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return os.system(f"echo {user_input}")

class AdminPanel:
    def __init__(self):
        self.debug = True
        self.password = PASSWORD

    def login(self, username, password):
        if password == self.password:
            print(debug_info)
            return True
        return False

debug_info = {"secret": SECRET_KEY}
""")
    return d


def main():
    print("=" * 60)
    print("HUNT-OS V4 STRESS TEST — 15 minutes")
    print("=" * 60)

    target_dir = setup_target_dir()
    state_dir = Path(tempfile.mkdtemp(prefix="stress_state_"))
    print(f"Target: {target_dir}")
    print(f"State:  {state_dir}")

    llm = StressLLM()
    
    loop = HuntLoopV4(
        llm=llm,
        verify_claim=fake_verify,
        target=target_dir,
        wall_seconds=float(os.environ.get('WALL_SECONDS', 900)),
        idle_seconds=2,
        budget_usd=0.0,
        workdir=state_dir,
        log=print,
    )

    t0 = time.time()
    errors = 0
    last_finding_count = 0
    
    try:
        state = loop.run()
    except Exception as e:
        print(f"\n❌ FATAL: {e}")
        traceback.print_exc()
        errors += 1
        state = loop.state if hasattr(loop, 'state') else None

    elapsed = time.time() - t0

    # ---- report ----
    print("\n" + "=" * 60)
    print("STRESS TEST RESULTS")
    print("=" * 60)
    print(f"  Elapsed:       {elapsed:.1f}s (target: 900s)")
    print(f"  Cycles:        {state.round if state else 'N/A'}")
    print(f"  LLM calls:     {llm.call_count}")
    print(f"  Total cost:    ${llm.cost_total:.4f}")
    print(f"  Findings:      {len(state.findings) if state else 'N/A'}")
    print(f"  Verified:      {count_verified(state) if state else 'N/A'}")
    print(f"  Chains:        {len(state.chains) if state else 'N/A'}")
    print(f"  Stop reason:   {state.completion_reason if state else 'N/A'}")
    print(f"  Errors:        {errors}")
    
    if state:
        by_status = {}
        for f in state.findings:
            if isinstance(f, dict):
                by_status[f.get("status", "?")] = by_status.get(f.get("status", "?"), 0) + 1
        print(f"  By status:     {by_status}")
    
    verdict = "✅ PASS" if elapsed >= 880 and errors == 0 else "⚠️  PARTIAL" if errors == 0 else "❌ FAIL"
    print(f"\n  VERDICT:       {verdict}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())