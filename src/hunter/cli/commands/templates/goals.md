---
name: goals
description: Show hunt goals, or set/add/clear them.
argument-hint: [set|add|clear] <kind:count,...>
---

# /goals

Inspect or change what the hunt is trying to achieve. The loop stops only when
**every** declared goal is met or the wall clock runs out.

## Usage

```
/goals $ARGUMENTS
```

## Arguments

| Sub-command | Effect                                              |
|-------------|-----------------------------------------------------|
| *(none)*    | Show each goal with its progress.                   |
| `set <spec>`| Replace all goals with the spec.                    |
| `add <spec>`| Merge the spec into the current goals.              |
| `clear`     | Remove every goal.                                  |
| `<spec>`    | Same as `set`.                                      |

A `<spec>` is `kind:count`, comma-separated. Kinds: `findings-min`,
`verified-min`, `exploitable-min`, `rce-min`.

## Examples

```
/goals
/goals set findings-min:20,rce-min:1
/goals add verified-min:5
/goals clear
```
