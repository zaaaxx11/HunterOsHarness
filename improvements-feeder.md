# improvements.md — the hunt feeder

> **Status: SHIPPED and RUNNING (2026-11-01).** `~/relay_feeder.py` is live,
> feeding the HunterOs daemon against the Relay bug-bounty scope. This file
> records what it does, what it deliberately does not do, and what is still
> open. The live hunt state is `~/.hunter/`; the scope manifest is
> `~/relay-scope-full.json`.

---

## 1. Why the feeder exists

The daemon only **consumes** its queue. `daemon.py` claims the oldest task,
runs it, and when the queue is empty it `return`s — `daemon_main` re-arms it
after `poll_seconds`. Nothing inside the daemon creates a task.

So `hunt start --time 6h` is a **wall-clock ceiling, not a work guarantee**.
Observed before the feeder: 17 minutes of daemon uptime produced roughly
5 minutes of actual run time. Six of those minutes were idle polling.

The feeder closes that gap. It is an external loop that keeps the queue at a
high-water mark and, more importantly, makes findings **generate work**
instead of just being recorded.

## 2. What it does

Every cycle (default 45s), in this order:

1. **Finding-driven work first.** Reads the ledger read-only
   (`file:...?mode=ro`) and selects findings whose status is `candidate`,
   `theoretical`, or `in-code`. Each becomes a NEW hunt task whose target is
   that finding's recorded endpoint. A finding therefore immediately becomes
   the next thing hunted, deeper — the `finding → task → finding` chain.
2. **On-chain fleet second.** Enqueues any not-yet-queued target from the
   Relay Chain contract set, the Aurora pair, the three source repos, and
   the 53 depository chains (dialed at their RPC endpoint, which is a
   probeable JSON-RPC surface where an explorer page is not).
3. **High-water guard.** Stops enqueueing at 8 pending. Without it the
   feeder would flood the queue faster than the daemon drains it and the
   "oldest first" claim order would starve the newest work.

Deduplication is against every task file in the queue directory — `task-`,
`claimed-`, and `done-` alike — so a target is never hunted twice.

Task files are written to a `.tmp` sibling and `os.replace`d into place, so
the daemon's glob never sees a partial JSON document.

## 3. What it deliberately does NOT do

- **It does not decide validity.** The feeder picks targets; the claim gate
  decides what becomes a finding. A feeder-enqueued task that produces
  nothing produces nothing.
- **It does not widen scope.** Every task carries the same scope payload the
  daemon already validates. The feeder cannot authorize a host the manifest
  does not list.
- **It does not retry failures.** A task that exits non-zero is left in
  `done-` and its target stays in the dedupe set, so it is not re-queued
  automatically. See open item 5.1.
- **It does not touch the ledger.** Read-only connection, always. The only
  writer is the daemon through the CLI.

## 4. Configuration

| Knob | Default | Meaning |
|---|---|---|
| `--interval` | 60s | Seconds between cycles |
| `--high-water` | 8 | Max pending tasks before the feeder backs off |
| `--once` | off | One cycle then exit (used for dry runs and testing) |
| `--dry-run` | off | Print what would be enqueue, write nothing |

Run it detached:

```sh
python3 ~/relay_feeder.py --interval 45 --high-water 8
```

## 5. Open items

### 5.1 Failed tasks are never retried

A run that exits 1 (provider blip, timeout, transient network) is marked
`done` with `status: failed` and its target enters the dedupe set, so the
feeder will not re-queue it. Early runs showed exactly this: `R-f4050e29af0d`
failed before the budget fix and was never retried.

*Proposed:* track `(target, attempt_count)` in a sidecar file and allow up to
N attempts, with the count reset when a run for that target completes.

### 5.2 The finding→task chain is one level deep

The feeder turns a finding into a task, but it does not read what that task
*produced*. If the follow-up run records a new candidate, the next feeder
cycle will pick it up — so the chain does continue — but only because the
ledger is re-scanned wholesale each cycle, not because the feeder knows
about parentage.

*Proposed:* record `parent_finding_id` on the task so the chain is explicit
and the retro can show which finding led where.

### 5.3 On-chain targets are observation surfaces

Explorer pages and RPC endpoints tell you what a contract *is*, not what it
*does wrong*. The productive target is static review of
`relay-settlement` (266 Solidity files, ~44k lines), which is in the queue as
a repo target but is not being driven systematically.

*Proposed:* a review-mode feeder that walks `smart-contracts/contracts/`
file by file, one task per contract, so the corpus is covered rather than
sampled.

### 5.4 No finding-severity prioritization

The feeder enqueues in ledger order, not by severity. An `info` finding and a
`critical` one get the same treatment.

*Proposed:* order finding-driven tasks by severity, and stop enqueueing
low-severity follow-ups while a high-severity one is still open.

### 5.5 The feeder is not supervised

It runs as a bare background process. If it dies, the queue drains and the
daemon goes idle again — silently.

*Proposed:* heartbeat file alongside the daemon's, plus a check in
`hunt status` that reports `feeder: stale` when the feeder has not written
recently.

## 6. Verified behaviour

- Queue holds 8 pending across cycles; daemon claims oldest-first.
- Finding F-0011 produced a follow-up task targeting its own endpoint.
- 80 distinct targets available (17 Relay Chain + 2 Aurora + 3 repos +
  53 depository + finding-derived).
- 68 hosts in the scope manifest, so no in-scope target is gate-blocked.
- Task writes are atomic (`os.replace`); no partial task was ever observed
  by the daemon.
