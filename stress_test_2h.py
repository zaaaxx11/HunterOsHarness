"""E2E Stress Test — 2 hour hunt, real probes, findings saved."""
import sys, os, json, re, time, urllib.request
from pathlib import Path

sys.path.insert(0, '/home/simon/HunterOsHarness/src')
key_line = [l for l in open(os.path.expanduser('~/.hunter/keys.env')).readlines() if 'SK-DEVORA' in l][0]
os.environ['DEVORA_API_KEY'] = key_line.split('=',1)[-1].strip().strip("\"'")

from hunter.llm.config import load_config; cfg = load_config()
from hunter.llm.native import NativeProvider; np = NativeProvider(cfg)

scope = json.load(open('/home/simon/.hermes/cache/scratch/scope_abema.json'))
targets = []
for t in scope.get('targets', []):
    for d in t.get('domains', []):
        clean = d.replace('*', 'www')
        targets.append(f'https://{clean}')

STATE_FILE = Path('/home/simon/.hunter/hunt_state.json')
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

print(f"🔥 HUNTER STRESS TEST — {len(targets)} targets — 2 HOURS")
start = time.time()
DEADLINE = start + 120  # 2 minutes for initial test, will extend to 7200
findings = []
round_num = 0
errors = 0

COMMON_PATHS = ['/api', '/api/v1', '/login', '/admin', '/.git/config', '/robots.txt', '/sitemap.xml', '/graphql', '/swagger.json', '/health', '/metrics', '/actuator/health']

def probe_url(url, path=''):
    full = url.rstrip('/') + path
    try:
        req = urllib.request.Request(full, method='HEAD', headers={'User-Agent': 'HunterOS/1.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return f'{resp.status}'
    except urllib.error.HTTPError as e:
        return f'{e.code}'
    except Exception as e:
        return f'ERR:{type(e).__name__}'

while time.time() < DEADLINE:
    round_num += 1
    url = targets[round_num % len(targets)]
    elapsed = time.time() - start
    
    # Probe multiple paths
    probes = {path: probe_url(url, path) for path in [''] + COMMON_PATHS[:3]}
    alive_paths = {k:v for k,v in probes.items() if v not in ('ERR:URLError', 'ERR:timeout') and not v.startswith('ERR:')}
    
    if not alive_paths:
        print(f'[R{round_num}] {url} — dead, skipping')
        time.sleep(2)
        continue
    
    probe_text = '\n'.join(f'{url}{k}: {v}' for k,v in alive_paths.items())
    print(f'[R{round_num}] {url} ({elapsed:.0f}s) — {len(alive_paths)} paths alive')
    
    try:
        r = np.complete('hunter', [
            {'role': 'system', 'content': f"""Find REAL vulnerabilities for this target.
HTTP probe results:
{probe_text}

Scope: {json.dumps(scope)[:400]}

Focus on HIGH and CRITICAL: RCE, SSRF, SQLi, IDOR, auth bypass, leaked secrets.
Be specific — name the exact endpoint, parameter, or header.
Return ONLY valid JSON: {{"findings":[{{"title":"vuln name","severity":"critical|high|medium|low|info","description":"mechanism + exploitation steps","evidence":"specific endpoint/header/response","confidence":"high|medium|low"}}]}}"""},
            {'role': 'user', 'content': f'Hunt: {url}. Probe: {probe_text}. Find vulnerabilities.'}
        ])
        
        found_this_round = 0
        for m in re.findall(r'\{[\s\S]*"findings"[\s\S]*\}', r.text):
            try:
                data = json.loads(m)
                for f in data.get('findings', []):
                    f['target'] = url
                    f['round'] = round_num
                    findings.append(f)
                    found_this_round += 1
                    print(f"  [{f.get('severity','?')}] {f.get('title','?')}")
            except json.JSONDecodeError:
                pass
        
        if not found_this_round:
            print(f'  clean — no findings')
    except Exception as e:
        errors += 1
        print(f'  ⚠️ error: {type(e).__name__}')
        if errors > 3:
            print(f'  too many errors ({errors}), sleeping before retry')
            time.sleep(5)
    
    # Save state
    with open(STATE_FILE, 'w') as f:
        json.dump({
            'findings': findings,
            'rounds': round_num,
            'errors': errors,
            'elapsed': time.time() - start,
            'targets': targets,
        }, f, indent=2)
    
    time.sleep(2)

elapsed = time.time() - start
print(f'\n{"="*60}')
print(f'🏁 STRESS TEST COMPLETE — {elapsed:.0f}s, {round_num} rounds, {len(findings)} findings, {errors} errors')
severity_counts = {}
for f in findings:
    sev = f.get('severity', 'unknown')
    severity_counts[sev] = severity_counts.get(sev, 0) + 1
print(f'📊 Severity: {severity_counts}')
print(f'📄 State: {STATE_FILE}')
for f in findings[:10]:
    print(f"  [{f.get('severity','?')}] {f.get('title','?')} → {f.get('target','?')}")