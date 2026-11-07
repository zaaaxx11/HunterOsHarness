---
name: config
description: Show the effective session configuration in one view.
argument-hint:
---

# /config

A read-only view of everything the session is working with: target, run
state, round, wall time and idle interval, budget, goals, and the model-tier
map.

## Usage

```
/config
```

## Arguments

None. Any `$ARGUMENTS` supplied are ignored.

## Examples

```
/config
```

Change any value with `/set` (`model`, `time`, `loop`, `budget`, `target`,
`goals`) or the dedicated command (`/model`, `/time`, `/loop`, `/target`,
`/goals`).
