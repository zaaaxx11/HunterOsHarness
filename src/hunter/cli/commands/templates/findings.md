---
name: findings
description: List the findings recorded so far, optionally filtered by severity or status.
argument-hint: [severity|status]
---

# /findings

Print the hunt's findings, one row per finding: id, severity, status, round,
and title. With no argument, everything is listed.

## Usage

```
/findings $ARGUMENTS
```

## Arguments

| Name     | Required | Notes                                                                 |
|----------|----------|----------------------------------------------------------------------|
| filter   | no       | A severity (`critical` `high` `medium` `low` `info`) or a status (`new` `claimed` `verifying` `verified` `rejected` `exploited`). |

Rows sort by severity, most severe first.

## Examples

```
/findings
/findings critical
/findings verified
/findings claimed
```

Then act on an id: `/claim <id>`, `/verify <id>`, or `/report`.
