---
name: btw
description: Drop a side note that does not affect the hunt or any session state.
argument-hint: <note>
---

# /btw

A side channel. Use it to jot a remark, a hunch, or a reminder without
changing the run. It touches **no** session state — not the queue, the goals,
the findings, or the log.

## Usage

```
/btw $ARGUMENTS
```

## Arguments

| Name | Required | Notes                                  |
|------|----------|----------------------------------------|
| note | yes      | Free text.                             |

## Examples

```
/btw the staging host also runs the old API on :8081
/btw revisit the JWT kid header after the IDs are enumerated
```

Because it is side-band, `/btw` never counts toward a goal and never starts or
stops anything. If you want a note to influence the hunt, put it in a real
command (`/goals`, `/target`) instead.
