---
name: resume
description: Resume a saved session by id, or the most recent one with 'latest'.
argument-hint: <id|latest>
---

# /resume

Attach to a saved session, restoring its queue, ledger, and followed findings.
Nothing is re-derived.

## Usage

```
/resume $ARGUMENTS
```

## Arguments

| Name | Required | Notes                                                          |
|------|----------|----------------------------------------------------------------|
| id   | yes      | A session id from `/sessions`, or `latest` for the newest one. |

## Examples

```
/sessions
/resume latest
/resume s-1731043200
```

Use `/sessions` first when you are not sure which id to pick.
