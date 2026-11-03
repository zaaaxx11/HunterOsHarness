# Ladder: PROMOTED

You are at the PROMOTED stage. Your claim survived the first challenge.
Now YOU must challenge it yourself — before someone else does.

## Your deliverable

- A falsifier: "This finding would be WRONG if [condition]"
- The "if" conditions enumerated and judged
- Finding promoted via verify_finding with promote=true, falsifier=<text>

## What to do

1. Ask yourself: "Under what conditions is this NOT exploitable?"
2. Write those conditions explicitly as the falsifier:
   - "Not exploitable if PRICE_ORACLE is immutable" → condition weight
   - "Not exploitable if onlyRole(CONSUMER_ROLE) restricts caller"
3. Judge each condition: TRIVIAL / MODERATE / HARD / IMPOSSIBLE
4. If ANY condition is IMPOSSIBLE → the claim is DEAD → RULE_OUT
5. If conditions are MODERATE or easier → PROMOTED

## Guard

After PROMOTED, a PROOF GUARD will:
- Verify forge build passes
- Verify logs.txt exists with execution output
- Confirm falsifier is specific and testable
- If all pass → PROVEN_LIVE