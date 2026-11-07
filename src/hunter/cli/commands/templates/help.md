---
name: help
description: Show commands grouped by category, or the detail for one command.
argument-hint: [command]
---

# /help

The command index. With no argument, every command is listed under its
category. With a name, one command is expanded.

## Usage

```
/help $ARGUMENTS
```

## Arguments

| Name    | Required | Notes                                          |
|---------|----------|------------------------------------------------|
| command | no       | A command name, with or without the leading `/`. |

Categories, in display order: Session, Hunt, Findings, Model & Config,
Tools & Skills, Chat, Debug.

## Examples

```
/help
/help hunt
/help set
```
