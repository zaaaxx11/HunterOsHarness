# Ladder: PROVEN_LIVE

You are at the PROVEN_LIVE stage — the highest confidence. Your claim has
survived independent verification, adversary challenge, and a second
confirmation. You now have:

- A compilable POC on disk
- A logs.txt with execution traces
- Evidence that withstands scrutiny

## Your deliverable

- Final verification via verify_finding with prove=true
- POC + logs already on disk from previous stages
- Finding at PROVEN_LIVE status — the terminal state

## What to do

1. Call verify_finding with prove=true
2. The harness will independently:
   - Verify POC compiles (forge build)
   - Verify logs.txt exists and contains output
   - Confirm >=2 evidence still resolves on disk
3. If all checks pass → PROVEN_LIVE

## Guard

You ARE the final guard. Before calling prove=true:
- Re-read the POC one last time
- Confirm the logs are accurate
- Ask yourself: "If I were trying to disprove this, could I?"
- If the answer is NO → PROVEN_LIVE

PROVEN_LIVE is the end. There is no ladder above this.