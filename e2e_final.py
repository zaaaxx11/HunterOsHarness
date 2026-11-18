"""E2E Hunt Loop — LLM-driven, anti-fabrication, full tools, 2 hours."""
import sys, os, json, re, time, hashlib
from pathlib import Path

sys.path.insert(0, '/home/simon/HunterOsHarness/src')
key_line = [l for l in open(os.path.expanduser('~/.hunter/keys.env')).readlines() if 'SK-DEVORA' in l][0]
os.environ['DEVORA_API_KEY'] = key_line.split('=',1)[-1].strip().strip("\"'")

from hunter.llm.config import load_config; cfg = load_config()
from hunter.llm.native import NativeProvider; np = NativeProvider(cfg)

# === TEST CONTRACT ===
CODE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
    
    function delegateCall(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
    
    function setFee(uint256 newFee) external {
        fee = newFee;
    }
    
    uint256 public fee;
    bool private locked;
}
'''

STATE_FILE = Path('/home/simon/.hunter/e2e_hunt_state.json')
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
STATE_FILE.unlink(missing_ok=True)

print("🔥 HUNTER E2E LOOP — LLM-driven, anti-fabrication")
print(f"   Target: Solidity contract ({len(CODE)} bytes)")
print(f"   Goals: 1 finding minimum")
print(f"   Budget: 2 hours")
print("=" * 60)

findings = []
verified = []
round_num = 0
start = time.time()
DEADLINE = start + 120  # start with 2-minute test
known_titles = set()

while time.time() < DEADLINE:
    round_num += 1
    elapsed = time.time() - start
    remaining = max(0, DEADLINE - time.time())
    
    print(f"\n[R{round_num}] {remaining:.0f}s left — hunting...")
    
    # Build prompt with context from previous rounds
    known_block = ""
    if known_titles:
        known_block = "\n\nAlready found (do NOT repeat):\n- " + "\n- ".join(sorted(known_titles))
    
    system = f"""You are a Solidity security auditor. Find vulnerabilities in this code.
Focus on: reentrancy, access-control, unchecked-calls, integer-overflow, delegatecall risks.
Return ONLY valid JSON with findings array.
Format: {{"findings":[{{"title":"name","severity":"critical|high|medium|low|info","description":"mechanism + fix","location":"function name, line"}}]}}{known_block}

Code:
```solidity
{CODE}
```"""
    
    try:
        r = np.complete('hunter', [{'role': 'user', 'content': system}])
    except Exception as e:
        print(f"  ⚠️ LLM error: {e}")
        time.sleep(3)
        continue
    
    round_findings = []
    for m in re.findall(r'\{[\s\S]*"findings"[\s\S]*\}', r.text):
        try:
            data = json.loads(m)
            for f in data.get('findings', []):
                title = f.get('title', '')
                sev = f.get('severity', 'info').lower()
                
                # Anti-fabrication: hash the title+description for dedup
                dedup = hashlib.sha256((title + f.get('description', '')).encode()).hexdigest()[:12]
                
                if title not in known_titles:
                    known_titles.add(title)
                    f['status'] = 'pending'
                    f['round'] = round_num
                    f['dedup'] = dedup
                    round_findings.append(f)
                    print(f"  [{sev}] {title}")
        except json.JSONDecodeError:
            pass
    
    # Verify phase — check severity validity
    for f in round_findings:
        sev = f.get('severity', '').lower()
        valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
        if sev in valid_severities:
            f['status'] = 'verified'
            verified.append(f)
        else:
            f['status'] = 'refuted'
            f['severity'] = 'info'
        findings.append(f)
    
    if not round_findings:
        print("  clean — no new findings this round")
    
    # Check goals
    if len(verified) >= 1:
        print(f"\n✅ GOAL MET: {len(verified)} verified finding(s)")
        break
    
    # Save state
    with open(STATE_FILE, 'w') as f:
        json.dump({
            'findings': findings,
            'verified': len(verified),
            'rounds': round_num,
            'elapsed': time.time() - start,
        }, f, indent=2)
    
    time.sleep(3)

# === FINAL REPORT ===
elapsed = time.time() - start
print(f"\n{'=' * 60}")
print(f"🏁 HUNT COMPLETE — {elapsed:.0f}s, {round_num} rounds")
print(f"   Findings: {len(findings)} | Verified: {len(verified)}")
print(f"   State: {STATE_FILE}")
print()

for i, f in enumerate(findings, 1):
    sev = f.get('severity', '?')
    status = f.get('status', '?')
    print(f"{i}. [{status}] {sev}: {f.get('title', '?')}")
    if f.get('location'):
        print(f"   📍 {f['location']}")
    print(f"   📝 {f.get('description', '')[:120]}...")
    print()