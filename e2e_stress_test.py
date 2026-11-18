"""E2E Stress Test: LLM reads scope → target.json → 2-hour hunt → findings."""
import sys, os, json, re, time
from pathlib import Path

sys.path.insert(0, '/home/simon/HunterOsHarness/src')
os.environ['DEVORA_API_KEY'] = open(os.path.expanduser('~/.hunter/keys.env')).read().strip().split('=')[-1].strip().strip("'\"")

from hunter.llm.config import load_config
from hunter.cli.shell import build_provider, LLMAdapter
from hunter.llm.native import NativeProvider

cfg = load_config()
np = NativeProvider(cfg)

SCOPE_FILE = "/home/simon/.hermes/cache/scratch/scope_abema.json"
TARGET_FILE = "/home/simon/.hunter/target.json"
STATE_FILE = "/home/simon/.hunter/hunt_state.json"

print("=" * 60)
print("HUNTER OS — 2-HOUR STRESS TEST")
print("=" * 60)

# === PHASE 1: LLM extracts targets ===
print("\n[PHASE 1] LLM reading scope...")
raw_scope = open(SCOPE_FILE).read()

system = """You are a target extractor for a bug bounty security scanner.
Read the scope below. Extract every domain, URL, and API endpoint into structured JSON.

Return ONLY valid JSON in this exact format:
{"targets":[{"url":"https://...","type":"web|api|mobile","priority":"high|medium|low"}],"summary":"one line"}

Rules:
- Every domain gets its own entry
- *.wildcard.com → https://wildcard.com
- App store links → base domain
- Priority: web services with authentication → high, static marketing sites → low
- Return ONLY the JSON. No other text."""

reply = np.complete('hunter', [
    {'role': 'system', 'content': system},
    {'role': 'user', 'content': f"Extract all targets from this bug bounty scope:\n\n```json\n{raw_scope}\n```"}
])
print(f"   LLM reply: {reply.text[:200]}...")

targets = []
for match in re.findall(r'\{[\s\S]*"targets"[\s\S]*\}', reply.text):
    try:
        data = json.loads(match)
        if "targets" in data and isinstance(data["targets"], list):
            targets = data["targets"]
            break
    except json.JSONDecodeError:
        continue

if not targets:
    scope = json.loads(raw_scope)
    for t in scope.get("targets", []):
        for domain in t.get("domains", []):
            clean = domain.replace("*", "www")
            targets.append({"url": f"https://{clean}", "type": "web", "priority": "high"})

Path(TARGET_FILE).parent.mkdir(parents=True, exist_ok=True)
with open(TARGET_FILE, 'w') as f:
    json.dump({"targets": targets, "scope_file": SCOPE_FILE}, f, indent=2)

print(f"   ✅ {len(targets)} targets extracted → {TARGET_FILE}")
for t in targets:
    print(f"      {t['url']} ({t.get('priority', '?')})")

# === PHASE 2: Hunt each target (2 hours) ===
print(f"\n[PHASE 2] Hunting {len(targets)} targets — 2 hour budget...")
findings = []
start_time = time.time()
DEADLINE = start_time + 7200  # 2 hours

target_idx = 0
round_num = 0

while time.time() < DEADLINE:
    round_num += 1
    target = targets[target_idx % len(targets)]
    url = target['url']
    elapsed = time.time() - start_time
    remaining = max(0, DEADLINE - time.time())
    
    print(f"\n[R{round_num}] {url} ({elapsed:.0f}s elapsed, {remaining:.0f}s left)")
    
    # Probe target
    try:
        probe_reply = np.complete('hunter', [
            {'role': 'system', 'content': 'You are a web security probe. Based on the URL, identify the likely tech stack. Return JSON: {"tech":"unknown|react|vue|rails|django|node|go","risks":["list of likely vuln classes"]}. Return ONLY JSON.'},
            {'role': 'user', 'content': f"Probe: {url}\n\nWhat tech stack is this likely running? What are the top 3 security risks?"}
        ])
        probe_text = probe_reply.text[:300]
    except Exception as e:
        print(f"   ⚠️ probe failed: {e}")
        target_idx += 1
        continue
    
    # Hunt for vulns
    try:
        vuln_reply = np.complete('hunter', [
            {'role': 'system', 'content': f"""You are a vulnerability hunter. Based on the target info, identify specific vulnerabilities.
Return JSON with findings array: {{"findings":[{{"title":"vuln name","severity":"critical|high|medium|low|info","description":"mechanism + impact + exploitation","evidence":"URL or reasoning","confidence":"theoretical|probable|high"}}]}}
Focus on: RCE, SSRF, SQLi, IDOR, auth-bypass, info-leak.
Return ONLY JSON."""},
            {'role': 'user', 'content': f"Target: {url}\nTech probe: {probe_text}\n\nScope: {raw_scope[:500]}\n\nIdentify the most likely vulnerabilities. Be specific."}
        ])
    except Exception as e:
        print(f"   ⚠️ vuln scan failed: {e}")
        target_idx += 1
        continue
    
    # Parse findings
    for match in re.findall(r'\{[\s\S]*"findings"[\s\S]*\}', vuln_reply.text):
        try:
            data = json.loads(match)
            for f in data.get("findings", []):
                f["target"] = url
                f["status"] = "pending"
                f["round"] = round_num
                findings.append(f)
                print(f"   🔍 [{f.get('severity','?')}] {f.get('title','?')}")
        except json.JSONDecodeError:
            pass
    
    target_idx += 1
    
    # Save progress
    with open(STATE_FILE, 'w') as f:
        json.dump({
            "findings": findings,
            "rounds": round_num,
            "targets_scanned": target_idx,
            "total_targets": len(targets),
            "elapsed": elapsed,
            "remaining": remaining,
        }, f, indent=2)
    
    # Pause between rounds
    time.sleep(3)

# === RESULTS ===
elapsed = time.time() - start_time
print(f"\n{'=' * 60}")
print(f"HUNT COMPLETE — {elapsed:.0f}s elapsed, {round_num} rounds, {len(findings)} findings")
print(f"{'=' * 60}")
for i, f in enumerate(findings[:20]):
    print(f"  {i+1}. [{f.get('severity','?')}] {f.get('title','?')} → {f.get('target','?')}")

# Summary
severity_counts = {}
for f in findings:
    sev = f.get('severity', 'unknown')
    severity_counts[sev] = severity_counts.get(sev, 0) + 1
print(f"\n📊 By severity: {severity_counts}")
print(f"📄 State saved: {STATE_FILE}")
print(f"🎯 Target file: {TARGET_FILE}")