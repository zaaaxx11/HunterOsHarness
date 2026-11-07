---
name: model
description: Show or set one model tier's model.
argument-hint: [tier] [model]
---

# /model

Point a single tier at a model. With no argument, the four-tier map is shown.

## Usage

```
/model $ARGUMENTS
```

## Arguments

| Name  | Required | Notes                                                          |
|-------|----------|----------------------------------------------------------------|
| tier  | no       | `orchestrator`, `hunter`, `chainer`, or `verifier`.            |
| model | no       | The model id to assign to that tier.                            |

- `/model` — show every tier and current model.
- `/model <tier>` — show one tier.
- `/model <tier> <model>` — set it (session-scoped).

## Examples

```
/model
/model orchestrator
/model verifier claude-haiku
/model hunter deepseek-chat
```

To set several tiers at once — or apply a preset — use `/set model`.
