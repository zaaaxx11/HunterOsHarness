---
name: target
description: Show or set the hunt target.
argument-hint: [value]
---

# /target

Read or change the target. With no argument the current target is printed;
with a value it is set. The target is locked while a hunt is running.

## Usage

```
/target $ARGUMENTS
```

## Arguments

| Name  | Required | Notes                                                |
|-------|----------|------------------------------------------------------|
| value | no       | A URL, host, or path you are authorized to test.     |

## Examples

```
/target
/target https://target.example.com
/target ./local/repo
```

Then start the hunt with `/run`, or configure everything at once with `/hunt`.
