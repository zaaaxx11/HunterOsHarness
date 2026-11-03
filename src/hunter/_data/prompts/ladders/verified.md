# Ladder: VERIFIED

You are at the VERIFIED stage. The code pattern has been confirmed by an
independent re-read. Now you must test it.

## Your deliverable

A POC (proof of concept) and plain-text logs showing:
- The vulnerable code lines
- How exploitation works
- forge build output confirming the POC compiles

## What to do

1. Write a Solidity POC contract that demonstrates the exploit
2. Save it via verify_finding with poc=<contract code>
3. Write logs.txt with step-by-step verification log
4. Call verify_finding with verdict="confirmed"

## Guard

At this stage, a PROMOTION GUARD will:
- Run forge build on your POC
- Check if it actually compiles
- List every condition required for exploitation
- Weigh: TRIVIAL / MODERATE / HARD / IMPOSSIBLE
- If HARD or IMPOSSIBLE → RULE_OUT. Otherwise → PROMOTED.

Compilation failure = RULE_OUT. No exceptions.