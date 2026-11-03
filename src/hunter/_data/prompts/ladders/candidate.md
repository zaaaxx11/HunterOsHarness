# Ladder: CANDIDATE

You are at the CANDIDATE stage. This is the first real claim — you must
bind evidence. But you do NOT need to be proven yet.

## Your deliverable

A finding shipped through create_finding_request with:
- title, description, impact
- at least 1 local_read evidence id
- check_id describing the vulnerability class

## What to do

1. Pick ONE finding from slither detectors that looks real
2. Read the vulnerable contract with read_file
3. Call create_finding_request with:
   - check_id="reentrancy" or "access-control" or the slither detector name
   - endpoint="."
   - evidence_ids=[EV-xxxx from read_file output]
   - klass="reentrancy-no-eth" or appropriate class

## Guard

After you ship a CANDIDATE, it enters the queue for VERIFIED. A verifier
will independently:
- Re-read your evidence from disk
- Check if the code actually does what you claim
- If real → VERIFIED. If wrong → RULED_OUT.

A RULED_OUT finding is NOT a failure. It is a closed investigation.