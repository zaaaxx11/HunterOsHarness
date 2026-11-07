---
name: hunt
description: Start a goal-driven hunt of a target and run it in the session loop.
argument-hint: <target> [goal] [time] [loop] [budget]
---

# /hunt

Arm a target and start the hunt loop. The session loads the target, the goal
set, and the time/loop/budget limits, then drives cycles until every goal is
met or the wall clock expires.

## Usage

```
/hunt $ARGUMENTS
```

Positional arguments, in order. Anything past `budget` is ignored.

## Arguments

| # | Name    | Required | Default           | Notes                                                            |
|---|---------|----------|-------------------|-----------------------------------------------------------------|
| 1 | target  | yes      | —                 | URL, host, or local path you are authorized to test.            |
| 2 | goal    | no       | `findings-min:5`  | `kind:count`, comma-separated. Kinds: `findings-min`, `verified-min`, `exploitable-min`, `rce-min`. |
| 3 | time    | no       | `6h`              | Wall budget as `[Nh][Nm][Ns]`; `0` = unlimited.                 |
| 4 | loop    | no       | `15`              | Seconds idle between cycles.                                    |
| 5 | budget  | no       | `0`               | Max USD spend; `0` = unlimited.                                 |

The hunt refuses to start while another hunt is running — `/stop` first.

## Examples

```
/hunt https://target.example.com
/hunt https://target.example.com findings-min:20 4h 30 5
/hunt 10.0.0.5 rce-min:1,findings-min:50 12h 15 50
/hunt ./local/repo exploitable-min:1 2h
```

Watch progress with `/status`; hold it with `/pause`; end it with `/stop`.
