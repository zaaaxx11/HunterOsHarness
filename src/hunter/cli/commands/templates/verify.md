---
name: verify
description: Mark a finding verified, rejected, exploited, or back to verifying.
argument-hint: <finding-id> [verified|rejected|exploited|verifying]
---

# /verify

Record the outcome of checking a finding. Verification is what separates a
candidate from a result, and it feeds `verified-min` goals and the report
counts.

## Usage

```
/verify $ARGUMENTS
```

## Arguments

| Name       | Required | Default    | Notes                                                        |
|------------|----------|------------|--------------------------------------------------------------|
| finding-id | yes      | —          | The id shown by `/findings`.                                 |
| status     | no       | `verified` | One of `verified`, `rejected`, `exploited`, `verifying`.     |

## Examples

```
/verify 3
/verify 3 exploited
/verify 7 rejected
/verify 7 verifying
```

Evidence or nothing: mark `verified` only when the reproduction actually held.
