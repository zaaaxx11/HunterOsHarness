"""Patch cmd_hunt in core.py: LLM parses the free-form /hunt line.

Builds a new function body and splices it in, replacing the old cmd_hunt.
"""

import re

PATH = "src/hunter/cli/commands/core.py"

with open(PATH) as fh:
    source = fh.read()

# Locate the old cmd_hunt function (from the @command decorator).
start = source.index('@command(\n    "hunt",')
# Find the NEXT function via the next @command decorator.
rest = source[start:]
next_cmd = rest.find("\n@command(", 50)
if next_cmd > 0:
    old_block = rest[:next_cmd]
else:
    old_block = rest

def_start = old_block.index("def cmd_hunt")
old_fn = old_block[def_start:]

new_fn = '''
def cmd_hunt(args: str, session: Any) -> str:
    """Start a hunt from free-form text — the model extracts target/goals/time.

    /hunt <anything human> is sent to the LLM and every field (target, goal
    description, time, loop, budget) is extracted from natural language. Falls
    back to the old positional parser when no model is available.
    """
    raw = (args or "").strip()
    if not raw:
        return (
            "/hunt <target and instructions>\\n"
            "  Describe the target plus what to look for.  Examples:\\n"
            "  /hunt https://x.com find all critical vulns\\n"
            "  /hunt app.falcon.finance findings-min:5 21600"
        )

    if _g(session, "running", False):
        return "a hunt is already running — /status to watch it, /stop to end it first"

    chat = _g(session, "_chat", None)
    if not callable(chat):
        return _cmd_hunt_positional(raw, session)

    import json as _json

    system = (
        "You are a hunt parser. Return a JSON object with these keys "
        "(ALL optional except target):\\n"
        '{"target":"<url or path>","goal_description":"<what to find>",'
        '"time":<seconds>,"loop":<seconds>,"budget":<USD>}\\n\\n'
        "Rules:\\n"
        "- Time is always seconds (21600 = 6 hours).\\n"
        "- If the user writes \\"<https://x>\\" strip the angle brackets.\\n"
        "- Never invent a URL; set target to null if none given.\\n"
        "- Return ONLY the JSON, no other text."
    )
    prompt = f"Parse this hunt request into JSON:\\n{raw}"
    try:
        reply = chat(system, prompt)
    except Exception as exc:
        return f"model parse failed: {type(exc).__name__} — {raw[:120]}"

    payload: dict = {}
    for candidate in re.findall(r"(?s)\\{.*?\\}", reply):
        try:
            payload = _json.loads(candidate)
            if isinstance(payload, dict) and "target" in payload:
                break
        except _json.JSONDecodeError:
            continue
    if not isinstance(payload, dict) or not payload.get("target"):
        return (
            "[parse] no target found.  Try again with an explicit URL.\\n\\n"
            f"model said:\\n{reply[:300]}"
        )

    target = str(payload.get("target") or "").strip()
    target = target.removeprefix("<").removesuffix(">")
    if not target:
        return f"[parse] empty target extracted from: {str(payload)[:200]}"

    desc = str(payload.get("goal_description") or "").strip()
    goals: dict = {"findings-min": 5}
    if desc:
        goals["_description"] = desc

    wall = 21600.0
    if "time" in payload:
        try:
            wall = max(0.0, float(payload["time"]))
        except (ValueError, TypeError):
            pass

    idle = 15.0
    if "loop" in payload:
        try:
            idle = max(1.0, float(payload["loop"]))
        except (ValueError, TypeError):
            pass

    budget = 0.0
    if "budget" in payload:
        try:
            budget = max(0.0, float(payload["budget"]))
        except (ValueError, TypeError):
            pass

    _set(session, "target", target)
    _set(session, "goals", goals)
    _set(session, "wall_seconds", wall)
    _set(session, "idle_seconds", idle)
    _set(session, "budget", budget)

    err = _start_hunt(session, goals)
    if err:
        return err

    budget_note = "unlimited" if budget == 0 else f"${budget:.2f}"
    mins, secs = divmod(int(wall), 60)
    nice = f"{mins // 60}h{mins % 60:02d}m" if mins >= 60 else f"{mins}m{secs:02d}s"
    return (
        f"hunting {target}\\n"
        f"  goals:  {desc or ', '.join(f'{k}:{v}' for k, v in goals.items() if k != '_description')}\\n"
        f"  time:   {nice} ({int(wall)}s)  ·  loop: {int(idle)}s\\n"
        f"  budget: {budget_note}\\n"
        "  /status · /pause · /stop"
    )


def _cmd_hunt_positional(raw: str, session: Any) -> str:
    """Fallback parser — no model, parse by position (the old cmd_hunt)."""
    toks = _tokens(raw)
    usage = (
        "usage: /hunt <target> [goal] [time] [loop] [budget]\\n"
        f"  defaults: goal={DEFAULT_GOAL}  time={DEFAULT_TIME}  loop={int(DEFAULT_LOOP)}  budget=0 (unlimited)"
    )
    if not toks:
        return usage
    target = toks[0]
    if target.startswith("-"):
        return usage
    if _g(session, "running", False):
        return "a hunt is already running — /status to watch it, /stop to end it first"
    goal_text = toks[1] if len(toks) > 1 else DEFAULT_GOAL
    time_text = toks[2] if len(toks) > 2 else DEFAULT_TIME
    loop_text = toks[3] if len(toks) > 3 else str(int(DEFAULT_LOOP))
    budget_text = toks[4] if len(toks) > 4 else "0"
    try:
        goals = _goal_spec(goal_text)
    except ValueError as exc:
        return f"bad goal: {exc}"
    try:
        wall = _parse_dur(time_text)
    except ValueError:
        return f"bad time '{time_text}': {_DUR_HINT}"
    try:
        idle = float(loop_text)
        if idle < 0:
            raise ValueError
    except ValueError:
        return f"bad loop '{loop_text}': loop is seconds between cycles (e.g. 15)"
    try:
        budget = float(budget_text)
        if budget < 0:
            raise ValueError
    except ValueError:
        return f"bad budget '{budget_text}': a non-negative USD amount (0 = unlimited)"
    _set(session, "target", target)
    _set(session, "goals", goals)
    _set(session, "wall_seconds", wall)
    _set(session, "idle_seconds", idle)
    _set(session, "budget", budget)
    err = _start_hunt(session, goals)
    if err:
        return err
    budget_note = "unlimited" if budget == 0 else f"${budget:.2f}"
    return (
        f"hunting {target}\\n"
        f"  goals:  {', '.join(f'{k}:{v}' for k, v in goals.items())}\\n"
        f"  time:   {_fmt_dur(wall)} wall  ·  loop: {idle:g}s\\n"
        f"  budget: {budget_note}\\n"
        "  /status · /pause · /stop"
    )

'''

source = source.replace(old_fn, new_fn, 1)
with open(PATH, "w") as fh:
    fh.write(source)
print("cmd_hunt: LLM parser + fallback written")