"""E2E validation of the auto_extract pipeline against relay-settlement — no LLM."""
import sys
import json
import os
sys.path.insert(0, '/home/simon/HunterOsHarness/src')
os.chdir('/home/simon/HunterOsHarness')

from hunter.kernel.ledger import Ledger
from hunter.agent.tools_base import ToolContext
from hunter.tools.scope import scope_from_manifest
from hunter.engine.auto_extract import run_auto_extract

LEDGER_PATH = '/tmp/e2e_val_ledger.db'
if os.path.exists(LEDGER_PATH):
    os.unlink(LEDGER_PATH)

ledger = Ledger(LEDGER_PATH)
run_id = 'e2e-val-relay-settlement'

from hunter.tools.http_client import ScopedHttpClient
scope = scope_from_manifest('/tmp/e2e_scope.json')
http = ScopedHttpClient(scope, user_agent='hunteros-e2e-validation/0.1')
ctx = ToolContext(
    run_id=run_id,
    ledger=ledger,
    http=http,
    scope=scope,
    target_url='file:///home/simon/relay-settlement/smart-contracts',
    emit=lambda ev: ledger.append(run_id, 'engine_event', ev) if ev else None,
    config={},
)

# Load the real slither output (168 findings from the live run)
with open('/tmp/slither_relay.json') as f:
    slither = json.load(f)
dets = slither['results']['detectors']
print(f"slither detectors loaded: {len(dets)}")

# Emit as engine event so scan_slither_evidence finds it naturally
event_id = ledger.append(run_id, "slither_audit", {
    "detector_count": len(dets),
    "detectors": dets,
})

summary = run_auto_extract(ledger, ctx, run_id)
print("\n=== SUMMARY ===")
print(json.dumps(summary, indent=2))

# Breakdown by status + klass
import sqlite3
conn = sqlite3.connect(LEDGER_PATH)
rows = conn.execute("SELECT status, COUNT(*) FROM findings GROUP BY status").fetchall()
print("\nfindings by status:", dict(rows))
rows = conn.execute("SELECT klass, status, COUNT(*) FROM findings GROUP BY klass, status ORDER BY COUNT(*) DESC LIMIT 15").fetchall()
for r in rows:
    print(f"  {r[2]:4d}  [{r[1]}] {r[0]}")
print(f"\nledger db: {LEDGER_PATH}")
