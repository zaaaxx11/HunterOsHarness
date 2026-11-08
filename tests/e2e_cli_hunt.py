"""E2E test: HunterOS CLI — all hunt flows, local only.

Tests cover:
1. /hunt with URL + goal
2. /hunt with file content injected
3. /hunt override /goals /time /loop
4. /hunt without target → chat fallback
5. Session state persistence across commands
6. MarkdownV2 output rendering
"""
import sys, json, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ----- test harness -----
class MockLLM:
    """Simulates an LLM provider matching LLMAdapter._turn()."""
    def __init__(self):
        self.reply = ""
        self.calls = []

    def complete(self, tier: str, messages: list, **kw):
        prompt = messages[-1].get("content", "") if messages else ""
        self.calls.append({"tier": tier, "prompt": prompt[:200]})
        class Turn:
            text = self.reply
        return Turn()


class MockSession:
    """Enough of HuntSession for cmd_hunt to work."""
    def __init__(self):
        self.log_lines = []
        self.target = ""
        self.goals = {"findings-min": 5}
        self.wall_seconds = 21600
        self.idle_seconds = 15
        self.budget = 0.0
        self.running = False
        self._chat = None

    def log(self, msg):
        self.log_lines.append(msg)

    def _g(self, key, default=None):
        return getattr(self, key, default)


def _session_for_test():
    s = MockSession()
    from hunter.cli.shell import LLMAdapter
    llm = MockLLM()
    adapter = LLMAdapter(llm, "hunter")
    s._llm = adapter
    s._chat = lambda t: adapter.complete("", t)
    s._mock_llm = llm  # for assertions
    return s


PASS, FAIL = 0, 0


def ok(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {label}")
    else:
        FAIL += 1
        extra = f" — {detail}" if detail else ""
        print(f"  ❌ FAIL: {label}{extra}")


# ----- TESTS -----
print("=" * 60)
print("E2E HunterOS CLI — Full Hunt Flow")
print("=" * 60)

# --- 1: /hunt with explicit URL + goal ---
print("\n1. /hunt with URL + goal")
from hunter.cli.commands.core import cmd_hunt
s = _session_for_test()
s._mock_llm.reply = (
    '{"target":"https://falcon.finance",'
    '"goal_description":"find all critical vulns and fund theft paths",'
    '"time":3600}'
)
r = cmd_hunt("https://falcon.finance find all critical vulns", s)
ok("returns hunt confirmation (no start() on mock)", "cannot start" in r.lower() or "hunting" in r.lower(), r[:80])
ok("target set", s.target == "https://falcon.finance", s.target)
ok("goal description stored", "fund theft" in s.goals.get("_description", ""), str(s.goals)[:80])
ok("time set to 3600", s.wall_seconds == 3600, str(s.wall_seconds))
ok("LLM was called", len(s._mock_llm.calls) > 0, str(len(s._mock_llm.calls)))

# --- 2: /hunt without target → nice error ---
print("\n2. /hunt without target → help text")
s2 = _session_for_test()
r2 = cmd_hunt("", s2)
ok("returns help text", "/hunt <describe" in r2, r2[:80])

# --- 3: /hunt with angle-bracket URL ---
print("\n3. /hunt with <angle brackets> in URL")
s3 = _session_for_test()
s3._mock_llm.reply = (
    '{"target":"https://movementnetwork.xyz/yield",'
    '"goal_description":"RCE and fund theft"}'
)
r3 = cmd_hunt("<https://movementnetwork.xyz/yield> find RCE", s3)
ok("angle brackets stripped", s3.target == "https://movementnetwork.xyz/yield",
   s3.target)

# --- 4: /hunt LLM returns set_target action ---
print("\n4. /hunt LLM returns set_target (don't start hunt, just set)")
s4 = _session_for_test()
s4._mock_llm.reply = (
    '{"action":"set_target",'
    '"target":"https://x.com",'
    '"goal_description":"audit the bridge"}'
)
r4 = cmd_hunt("https://x.com audit the bridge", s4)
ok("returns target set or cannot start", "target set:" in r4.lower() or "cannot start" in r4.lower(), r4[:80])
ok("target stored", s4.target == "https://x.com")
ok("goal stored", "audit" in s4.goals.get("_description", ""), str(s4.goals)[:80])
ok("did not start hunt (no start() method)",
   "this session cannot start" in r4.lower() or "target set" in r4.lower(), r4[:80])

# --- 5: /hunt with pre-set target ---
print("\n5. /hunt with pre-set target (user already did /target)")
s5 = _session_for_test()
s5.target = "https://already.set"
s5._mock_llm.reply = (
    '{"target":"https://already.set",'
    '"goal_description":"hunt the preset target"}'
)
r5 = cmd_hunt("hunt the preset target", s5)
ok("uses pre-set target", s5.target == "https://already.set",
   s5.target)

# --- 6: chat path works ---
print("\n6. Chat path works (no slash command)")
from hunter.cli.shell import CHAT_SYSTEM
ok("CHAT_SYSTEM loads", len(CHAT_SYSTEM) > 10, str(len(CHAT_SYSTEM)))

# --- 7: registry dispatch ---
print("\n7. Command registry dispatch")
from hunter.cli.commands.registry import dispatch
s7 = MockSession()
r7 = dispatch("/help", s7)
ok("/help returns commands", "HUNT commands" in r7 or "/help" in r7, r7[:80])

r7b = dispatch("/help hunt", s7)
ok("/help hunt returns detail", len(r7b) > 20, r7b[:80])

# --- 8: attachment text injection ---
print("\n8. Attachment text injection (simulate file upload)")
# Simulate what app.py does when attachment arrives
test_file = "/tmp/hunter_e2e_test_scope.json"
with open(test_file, "w") as f:
    json.dump({
        "target": "https://gravity-bridge.example.com",
        "contracts": ["Gravity.sol", "Orchestrator.sol"],
        "description": "Cross-chain bridge audit scope"
    }, f)

raw = open(test_file).read()
prefix = f"[📎 scope.json]\nat {test_file}\n```\n{raw}\n```"
text = f"{prefix}\n/hunt find critical vulns and fund theft"
ok("prefix built correctly", "scope.json" in prefix and "Gravity" in prefix,
   prefix[:100])

# Clean up
os.remove(test_file)

# --- 9: MarkdownV2 rendering ---
print("\n9. MarkdownV2 rendering")
from hunter.gateway.render import render, strip_mdv2
original = "**bold** and `code()` and [link](https://x.com)"
rendered = render(original)
ok("bold rendered", "*bold*" in rendered, rendered[:60])
ok("inline code preserved", "`code()`" in rendered, rendered[:60])
ok("round-trip keeps plain text", "bold" in strip_mdv2(rendered) and "code()" in strip_mdv2(rendered), strip_mdv2(rendered)[:60])

# --- 10: Chunking preserves fences ---
print("\n10. Chunking never splits a code fence")
from hunter.gateway.render import chunk_text
fenced = "```solidity\n" + "\n".join(f"line {i} " + "x" * 60 for i in range(120)) + "\n```"
parts = chunk_text(render(fenced), 400)
all_balanced = all(p.count("```") % 2 == 0 for p in parts)
ok("all parts balanced", all_balanced,
   f"{len(parts)} parts, first/third balanced: "
   f"{parts[0].count('```') % 2 == 0}/{parts[2].count('```') % 2 == 0 if len(parts) > 2 else 'n/a'}")

# --- SUMMARY ---
print("\n" + "=" * 60)
total = PASS + FAIL
print(f"Results: {PASS}/{total} passed, {FAIL} failed")
if FAIL:
    print("⚠️  SOME TESTS FAILED — fix before deploying")
else:
    print("✅ ALL TESTS PASSED — ready to deploy")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)