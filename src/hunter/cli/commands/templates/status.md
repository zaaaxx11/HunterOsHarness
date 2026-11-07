---
name: status
description: Show the live hunt status — target, round, time, budget, findings, goals.
argument-hint:
---

# /status

A one-screen snapshot of the hunt: whether it is running, the target and
round, elapsed versus wall time, the idle interval, the budget, the finding
count, and progress against each goal.

## Usage

```
/status
```

## Arguments

None. Any `$ARGUMENTS` supplied are ignored.

## Examples

```
/status
```

Goal lines read `have/need [OK]` when met and `have/need [..]` when not.
Related: `/goals`, `/time`, `/cost`.
