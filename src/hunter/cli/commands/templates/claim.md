---
name: claim
description: Claim a finding for this session so it is not picked up by another.
argument-hint: <finding-id>
---

# /claim

Mark a finding as owned by this session. Claiming is a lightweight lock: the
status moves to `claimed` and later cycles leave it alone until you verify or
release it.

## Usage

```
/claim $ARGUMENTS
```

## Arguments

| Name       | Required | Notes                                                   |
|------------|----------|--------------------------------------------------------|
| finding-id | yes      | The id shown by `/findings` (e.g. `3` or `F-0003`).      |

With no id, the command prints the ids you can claim.

## Examples

```
/claim 3
/claim F-0003
```

After claiming, confirm it with `/verify <id>` (add `rejected` or `exploited`
to override the default `verified`).
