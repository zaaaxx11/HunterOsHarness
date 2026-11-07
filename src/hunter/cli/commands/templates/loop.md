---
name: loop
description: Show or set the idle interval between hunt cycles, in seconds.
argument-hint: [seconds]
---

# /loop

Control how long the loop rests between cycles. A shorter loop hunts harder
and spends more; a longer one is gentler on a small box.

## Usage

```
/loop $ARGUMENTS
```

## Arguments

| Name    | Required | Notes                                                        |
|---------|----------|--------------------------------------------------------------|
| seconds | no       | A non-negative number. With no value, the current idle shows. |

The idle value **cannot** be changed while a hunt is running — the loop owns
it mid-flight. `/pause` or `/stop` first, then set it. This refusal is by
design: silently retuning a live loop makes the timing impossible to reason
about.

## Examples

```
/loop
/loop 15
/loop 60
```

Related: `/time` sets the wall budget; `/set loop <seconds>` is equivalent to
`/loop <seconds>`.
