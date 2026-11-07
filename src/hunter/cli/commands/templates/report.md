---
name: report
description: Render a report of the current findings as markdown, text, or a summary.
argument-hint: [markdown|text|summary]
---

# /report

Turn the session's findings into a report. The default is markdown, suitable
for pasting into a write-up or a tracker.

## Usage

```
/report $ARGUMENTS
```

## Arguments

| Name | Required | Default    | Notes                                                  |
|------|----------|------------|--------------------------------------------------------|
| fmt  | no       | `markdown` | One of `markdown`, `text`, or `summary`.              |

- `markdown` / `text` — header, severity breakdown, and a finding list.
- `summary` — a one-line count only.

## Examples

```
/report
/report summary
/report markdown
```

Verified findings are counted in the header; run `/findings verified` to check
which ones qualify.
