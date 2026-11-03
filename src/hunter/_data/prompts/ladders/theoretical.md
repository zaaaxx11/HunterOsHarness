# Ladder: THEORETICAL

You are at the THEORETICAL stage. This is the cheapest stage — hypotheses
cost nothing. Be bold.

## Your deliverable

A list of suspected vulnerabilities. One per line. Wrong guesses are free.
You do NOT need evidence yet.

## What to do

1. Read contracts, run slither, search for patterns
2. For every interesting function or pattern, write a note: "X might be
   vulnerable to Y because Z"
3. If slither found detectors, list the relevant ones
4. Ship the best hypothesis as a CANDIDATE finding

## Guard

After you ship, a VERIFIER GUARD will challenge your claim. The guard will:
- Check if your hypothesis matches the code
- Reject impossible claims (immutable oracle, etc.)
- Accept plausible claims for promotion to VERIFIED

You are NOT expected to be right. You ARE expected to ship.
A bad hypothesis that gets ruled out is better than silence.