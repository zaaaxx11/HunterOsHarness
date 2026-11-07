---
name: set
description: Configure the session — model tiers, time, loop, budget, target, goals.
argument-hint: model <preset> | <key> <value>
---

# /set

One place to adjust the session. The most common use is pointing every model
tier at a brain with a preset.

## Usage

```
/set $ARGUMENTS
```

## Arguments

### model (the multi-tier picker)

`/set model` with no value prints the picker: the four tiers, their roles, the
available models, and the presets. Tiers: `orchestrator`, `hunter`, `chainer`,
`verifier`.

Presets:

| Preset       | orchestrator | hunter | chainer | verifier |
|--------------|--------------|--------|---------|----------|
| `balanced`   | strong       | mid    | mid     | cheap    |
| `aggressive` | strong       | strong | strong  | mid      |
| `cheap`      | mid          | cheap  | cheap   | cheap    |

Assign tiers by hand with `tier=model` pairs, or use `/model <tier> <model>`.

### other keys

| Key      | Value        | Notes                                            |
|----------|--------------|--------------------------------------------------|
| `time`   | `[Nh][Nm][Ns]` | Wall budget.                                   |
| `loop`   | seconds      | Idle between cycles (blocked while running).     |
| `budget` | USD          | `0` = unlimited.                                 |
| `target` | value        | Locked while running.                            |
| `goals`  | `kind:count` | Comma-separated.                                 |

## Examples

```
/set model
/set model balanced
/set model aggressive
/set model cheap
/set model orchestrator=deepseek-chat,verifier=claude-haiku
/set time 4h
/set loop 30
/set budget 25
```
