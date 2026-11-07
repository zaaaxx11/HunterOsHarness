"""Core slash-command implementations for the HUNT terminal CLI.

Every command here is registered with :mod:`registry` and has the shape
``handler(args: str, session) -> str``. The return value is the text the chat
prints; a handler never raises and never returns non-str — a misbehaving
command must not end the hunt.

The ``session`` object is duck-typed and never imported. Everything is read
through :func:`_g` (``getattr`` with a default) so a session that is missing an
attribute — an older build, a test double, a half-initialised run — yields a
helpful message instead of an ``AttributeError``. Writes go through
:func:`_set`, which swallows the failure of a read-only attribute and lets the
caller report it.

Two contract details worth stating up front:

* ``/btw`` is a side channel. It returns a note and touches **no** session
  state — not the log, not the findings, not the goals. The hunt is unaffected.
* ``/loop`` only changes the idle interval while the hunt is *not* running;
  during a hunt it refuses, because the loop owns that value mid-flight.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

try:  # package layout (cli/commands/) or flat dir (selftest)
    from .registry import REGISTRY, command, help_text as _registry_help_text
except ImportError:  # pragma: no cover - flat import path
    from registry import REGISTRY, command, help_text as _registry_help_text  # type: ignore[no-redef]

__all__ = ["VERSION"]

VERSION = "1.0.0"

# --- canonical vocabularies -------------------------------------------------

TIERS: tuple[str, ...] = ("orchestrator", "hunter", "chainer", "verifier")

TIER_ROLES: dict[str, str] = {
    "orchestrator": "strong reasoning — plans the hunt, adjudicates chains",
    "hunter": "fast — drives recon and exploit attempts",
    "chainer": "mid — links findings into exploit chains",
    "verifier": "cheap, careful — re-checks evidence",
}

# preset -> tier -> rank; rank is resolved to a concrete model id at apply time.
PRESETS: dict[str, dict[str, str]] = {
    "balanced": {"orchestrator": "strong", "hunter": "mid", "chainer": "mid", "verifier": "cheap"},
    "aggressive": {"orchestrator": "strong", "hunter": "strong", "chainer": "strong", "verifier": "mid"},
    "cheap": {"orchestrator": "mid", "hunter": "cheap", "chainer": "cheap", "verifier": "cheap"},
}

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
STATUS_ORDER: tuple[str, ...] = ("new", "claimed", "verifying", "verified", "rejected", "exploited")

# /hunt defaults — see templates/hunt.md.
DEFAULT_GOAL = "findings-min:5"
DEFAULT_TIME = "6h"
DEFAULT_LOOP = 15.0
DEFAULT_BUDGET = 0.0


# --- defensive session access ----------------------------------------------


def _g(session: Any, name: str, default: Any = None) -> Any:
    """``getattr`` that never raises, so a thin session degrades gracefully."""
    try:
        return getattr(session, name, default)
    except Exception:  # noqa: BLE001 — a property that throws is still "missing"
        return default


def _set(session: Any, name: str, value: Any) -> bool:
    """Best-effort attribute write. Returns True when it stuck."""
    try:
        setattr(session, name, value)
        return True
    except Exception:  # noqa: BLE001 — read-only / property without setter
        return False


def _tokens(args: str) -> list[str]:
    """Split an argument string, tolerating quotes; never raises.

    ``shlex`` treats ``<`` / ``>`` as shell redirections, so a bare URL
    ``<https://x>`` was split into three tokens and read as a time value.
    Fall back to a simple space-split first when the text looks like a
    URL — it always starts with a scheme — and let quotes control grouping
    for everything else.
    """
    text = (args or "").strip()
    if not text:
        return []
    # A URL is a single token. Guard it before it reaches a shell tokeniser.
    if text.startswith(("http://", "https://", "git://", "ssh://")):
        idx = text.index(" ") if " " in text else len(text)
        url = text[:idx]
        rest = text[idx:].strip()
        return [url] + _tokens(rest) if rest else [url]
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _text(args: str) -> str:
    """Free-text argument: strip whitespace and drop quotes around a single value.

    ``/btw "the API runs on :8081"`` should read as ``the API runs on :8081``,
    not keep the quotes. Only a value that is exactly one quoted token is
    dequoted, so an apostrophe mid-sentence is left alone.
    """
    text = (args or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        try:
            parts = shlex.split(text)
        except ValueError:
            return text
        if len(parts) == 1:
            return parts[0]
    return text


def _num(value: Any, default: float = 0.0) -> float:
    """Coerce a session value to float, falling back instead of raising."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _findings(session: Any) -> list[dict]:
    """The session's findings, coerced to a list of dicts."""
    raw = _g(session, "findings", []) or []
    if not isinstance(raw, (list, tuple)):
        return []
    return [f if isinstance(f, dict) else {"id": str(f), "title": str(f)} for f in raw]


def _models(session: Any) -> list[str]:
    raw = _g(session, "available_models", []) or []
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(m) for m in raw]


def _goals(session: Any) -> dict:
    """Goals as a ``{kind: count}`` dict, however the session stores them."""
    raw = _g(session, "goals", {}) or {}
    if isinstance(raw, dict):
        out: dict[str, int] = {}
        for key, value in raw.items():
            try:
                out[str(key)] = int(value)
            except (TypeError, ValueError):
                out[str(key)] = 0
        return out
    if isinstance(raw, (list, tuple)):  # tolerate the list form from state.json
        out = {}
        for item in raw:
            if isinstance(item, dict) and "kind" in item:
                try:
                    out[str(item["kind"])] = int(item.get("count", 1))
                except (TypeError, ValueError):
                    out[str(item["kind"])] = 1
        return out
    return {}


def _tier_model(session: Any, tier: str) -> str:
    tiers = _g(session, "model_tiers", {}) or {}
    if not isinstance(tiers, dict):
        return "(unset)"
    value = tiers.get(tier)
    if isinstance(value, dict):
        value = value.get("model")
    return str(value) if value else "(unset)"


# --- duration grammar [Nh][Nm][Ns] (local copy: this module stays stdlib-only) ----

_DUR_RE = re.compile(r"^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s?)?$")
_DUR_HINT = "durations use [Nh][Nm][Ns] — 90, 90s, 90m, 2h, 1h30m, 1.5h (bare = seconds; 0 = unlimited)"


def _parse_dur(text: str | int | float | None) -> float:
    """Parse a hunt duration: seconds only, no h/m/s suffixes.

    ``0`` and empty mean unlimited. Everything else must be a positive integer
    or float of seconds — ``21600``, ``3600``, ``900``. A trailing ``s`` is
    tolerated (``3600s``).

    Other paths (config CLI, TUI) use ``parse_duration`` which still accepts
    ``1h30m``; this is deliberately stricter so ``/hunt`` has one unambiguous
    unit.
    """
    if text is None:
        return 0.0
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        value = float(text)
        if value < 0 or value != value:
            raise ValueError(f"duration must be a positive number, not {text!r}")
        return value
    token = str(text).strip()
    if not token:
        return 0.0
    clean = token.rstrip("sS")
    try:
        value = float(clean)
    except ValueError:
        raise ValueError(
            f"time must be seconds, not {token!r} — e.g. 21600 (= 6h), 3600, 900"
        )
    if value < 0 or value != value:
        raise ValueError(f"duration must be positive, not {token!r}")
    return value


def _fmt_dur(seconds: float) -> str:
    """Format seconds as a compact ``1h30m`` / ``45s`` string."""
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "n/a"
    if seconds <= 0:
        return "0 (unlimited)"
    hours, rem = divmod(int(seconds), 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return "".join(parts)


# --- goals ------------------------------------------------------------------


def _goal_spec(text: str) -> dict:
    """Parse a goal spec: ``kind:count,...`` or free-form description.

    ``"findings-min:5,rce-min:1"`` -> counts.
    ``"find all critical vulns"`` -> default target with the raw text
    stored under ``_description`` so every output scanner can see it.
    """
    out: dict[str, int] = {}
    desc: str | None = None
    token = (text or "").strip()
    if not token:
        raise ValueError("no goals given — e.g. findings-min:5,rce-min:2")
    if not any(ch in token for ch in (":", "=")):
        desc = token
    else:
        for item in token.split(","):
            item = item.strip()
            if not item:
                continue
            sep = ":" if ":" in item else "="
            if sep not in item:
                desc = token
                break
            kind, _, count = item.partition(sep)
            kind = kind.strip()
            try:
                out[kind] = int(count.strip())
            except ValueError as exc:
                raise ValueError(
                    f"goal '{kind}' needs a whole number, got {count.strip()!r}"
                ) from exc
    if desc and not out:
        out["findings-min"] = 5
        out["_description"] = desc
    if not out:
        raise ValueError("no goals given — e.g. findings-min:5,rce-min:2")
    return out


def _goal_summary_text(session: Any) -> str | None:
    """Return the goal's free-form description if one was stored."""
    goals = _g(session, "goals", None)
    if isinstance(goals, dict):
        return goals.get("_description")
    return None


def _goal_have(session: Any, kind: str) -> int:
    """How many of ``kind`` the session already has."""
    findings = _findings(session)
    if kind == "findings-min":
        return len(findings)
    if kind == "verified-min":
        return sum(1 for f in findings if str(f.get("status")) == "verified")
    if kind == "exploitable-min":
        return sum(
            1
            for f in findings
            if str(f.get("status")) in ("verified", "exploited")
            and str(f.get("severity")) in ("critical", "high")
        )
    if kind == "rce-min":
        return sum(
            1
            for f in findings
            if "rce" in str(f.get("title", "")).lower()
            or "command injection" in str(f.get("title", "")).lower()
        )
    return 0


def _start_hunt(session: Any, goals: dict) -> str | None:
    """Call ``session.start(goals)`` defensively; return an error string or None."""
    starter = _g(session, "start", None)
    if not callable(starter):
        return "this session cannot start a hunt (no start() method) — /help for the command list"
    try:
        starter(goals)
    except Exception as exc:  # noqa: BLE001 — surface the reason, do not crash
        return f"could not start the hunt: {type(exc).__name__}: {exc}"
    _set(session, "running", True)
    return None


# ==========================================================================
# Session
# ==========================================================================


@command("new", "Start a fresh session (optionally titled)", "[title]", "Session")
def cmd_new(args: str, session: Any) -> str:
    if _g(session, "running", False):
        return "a hunt is running — /stop or /pause it before starting a new session"
    title = _text(args)
    starter = _g(session, "new", None)
    if callable(starter):
        try:
            starter(title)
            return f"new session" + (f" — {title}" if title else "")
        except Exception as exc:  # noqa: BLE001
            return f"could not start a new session: {type(exc).__name__}: {exc}"
    # No dedicated method: reset the documented mutable state in place.
    reset = _set(session, "log_lines", []) and _set(session, "findings", [])
    _set(session, "target", "")
    _set(session, "goals", {})
    _set(session, "round", 0)
    _set(session, "running", False)
    tail = "" if reset else " (session did not expose resettable state — started fresh anyway)"
    return f"new session" + (f" — {title}" if title else "") + tail


@command("sessions", "List saved sessions", "", "Session")
def cmd_sessions(args: str, session: Any) -> str:
    records = _g(session, "sessions", None)
    if records is None:
        records = _g(session, "available_sessions", None)
    current = _g(session, "session_id", None) or _g(session, "id", "current")
    if not records:
        return f"only this session is visible here — current: {current}"
    lines = ["sessions (most recent first):"]
    for record in records:
        if isinstance(record, dict):
            sid = record.get("id") or record.get("session_id", "?")
            title = record.get("title") or record.get("target") or "(untitled)"
            status = record.get("status", "")
        else:
            sid = str(_g(record, "id", "?"))
            title = str(_g(record, "target", "") or "(untitled)")
            status = str(_g(record, "status", ""))
        mark = "->" if str(sid) == str(current) else "  "
        suffix = f" [{status}]" if status else ""
        lines.append(f"{mark} {sid}  {title}{suffix}")
    return "\n".join(lines)


@command("resume", "Resume a session by id or 'latest'", "<id|latest>", "Session")
def cmd_resume(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        return "usage: /resume <id|latest> — /sessions lists saved ids"
    sid = toks[0]
    if sid == "latest":
        records = _g(session, "sessions", None) or _g(session, "available_sessions", None)
        if not records:
            return "no saved sessions to resume"
        first = records[0]
        sid = str(first.get("id") or first.get("session_id")) if isinstance(first, dict) else str(_g(first, "id", ""))
        if not sid:
            return "could not resolve 'latest' — /sessions lists saved ids"
    resumer = _g(session, "resume", None)
    if callable(resumer):
        try:
            resumer(sid)
            _set(session, "session_id", sid)
            return f"resumed {sid}"
        except Exception as exc:  # noqa: BLE001
            return f"could not resume {sid}: {type(exc).__name__}: {exc}"
    _set(session, "session_id", sid)
    return f"attached to {sid} (resume is engine-side; queue and ledger are restored there)"


@command("rename", "Set the current session title", "<title>", "Session")
def cmd_rename(args: str, session: Any) -> str:
    title = _text(args)
    if not title:
        current = _g(session, "title", "") or _g(session, "target", "") or "(untitled)"
        return f"title: {current} — /rename <title> to change it"
    if not _set(session, "title", title):
        return "this session has no settable title attribute"
    _g(session, "save", lambda: None)()
    return f"renamed: {title}"


@command("compact", "Compact the session view, keeping the durable state", "", "Session")
def cmd_compact(args: str, session: Any) -> str:
    compactor = _g(session, "compact", None)
    if callable(compactor):
        try:
            result = compactor()
            return result if isinstance(result, str) else "session compacted"
        except Exception as exc:  # noqa: BLE001
            return f"could not compact: {type(exc).__name__}: {exc}"
    logs = _g(session, "log_lines", []) or []
    findings = _findings(session)
    return (
        f"nothing to compact here — {len(logs)} log line(s) and {len(findings)} finding(s) held; "
        "compaction is engine-side (/clear trims the visible log)"
    )


@command("clear", "Clear the visible chat log (findings and state are kept)", "", "Session")
def cmd_clear(args: str, session: Any) -> str:
    clearer = _g(session, "clear_log", None)
    if callable(clearer):
        try:
            clearer()
            return "chat log cleared — findings and hunt state untouched"
        except Exception as exc:  # noqa: BLE001
            return f"could not clear: {type(exc).__name__}: {exc}"
    logs = _g(session, "log_lines", None)
    count = len(logs) if isinstance(logs, list) else 0
    if _set(session, "log_lines", []):
        return f"chat log cleared ({count} line(s)) — findings and hunt state untouched"
    return "this session does not expose a clearable log"


@command("exit", "Leave the session (state is saved)", "", "Session")
def cmd_exit(args: str, session: Any) -> str:
    saver = _g(session, "save", None)
    if callable(saver):
        try:
            saver()
        except Exception:  # noqa: BLE001 — a failed save must not block the exit
            pass
    findings = len(_findings(session))
    return f"session saved — {findings} finding(s) kept. Evidence or nothing."


# ==========================================================================
# Hunt
# ==========================================================================


@command(
    "hunt",
    "Start a goal-driven hunt of a target",
    "<target> [goal] [time] [loop] [budget]",
    "Hunt",
)

def cmd_hunt(args: str, session: Any) -> str:
    """Start a hunt from free-form text — the model extracts target/goals/time.

    /hunt <anything human> is sent to the LLM and every field (target, goal
    description, time, loop, budget) is extracted from natural language. Falls
    back to the old positional parser when no model is available.
    """
    raw = (args or "").strip()
    if not raw:
        return (
            "/hunt <target and instructions>\n"
            "  Describe the target plus what to look for.  Examples:\n"
            "  /hunt https://x.com find all critical vulns\n"
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
        "(ALL optional except target):\n"
        '{"target":"<url or path>","goal_description":"<what to find>",'
        '"time":<seconds>,"loop":<seconds>,"budget":<USD>}\n\n'
        "Rules:\n"
        "- Time is always seconds (21600 = 6 hours).\n"
        "- If the user writes \"<https://x>\" strip the angle brackets.\n"
        "- Never invent a URL; set target to null if none given.\n"
        "- Return ONLY the JSON, no other text."
    )
    prompt = f"Parse this hunt request into JSON:\n{raw}"
    try:
        reply = chat(system, prompt)
    except Exception as exc:
        return f"model parse failed: {type(exc).__name__} — {raw[:120]}"

    payload: dict = {}
    for candidate in re.findall(r"(?s)\{.*?\}", reply):
        try:
            payload = _json.loads(candidate)
            if isinstance(payload, dict) and "target" in payload:
                break
        except _json.JSONDecodeError:
            continue
    if not isinstance(payload, dict) or not payload.get("target"):
        return (
            "[parse] no target found.  Try again with an explicit URL.\n\n"
            f"model said:\n{reply[:300]}"
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
        f"hunting {target}\n"
        f"  goals:  {desc or ', '.join(f'{k}:{v}' for k, v in goals.items() if k != '_description')}\n"
        f"  time:   {nice} ({int(wall)}s)  ·  loop: {int(idle)}s\n"
        f"  budget: {budget_note}\n"
        "  /status · /pause · /stop"
    )


def _cmd_hunt_positional(raw: str, session: Any) -> str:
    """Fallback parser — no model, parse by position (the old cmd_hunt)."""
    toks = _tokens(raw)
    usage = (
        "usage: /hunt <target> [goal] [time] [loop] [budget]\n"
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
        f"hunting {target}\n"
        f"  goals:  {', '.join(f'{k}:{v}' for k, v in goals.items())}\n"
        f"  time:   {_fmt_dur(wall)} wall  ·  loop: {idle:g}s\n"
        f"  budget: {budget_note}\n"
        "  /status · /pause · /stop"
    )


@command("run", "Run (or resume) the configured hunt", "", "Hunt")
def cmd_run(args: str, session: Any) -> str:
    target = _g(session, "target", "") or ""
    if not target:
        return "no target set — /target <value> or /hunt <target> [goal] [time] [loop] [budget]"
    if _g(session, "running", False):
        return f"already hunting {target} — /status to watch, /stop to end"
    goals = _goals(session) or _goal_spec(DEFAULT_GOAL)
    err = _start_hunt(session, goals)
    if err:
        return err
    return f"running — hunting {target} ({', '.join(f'{k}:{v}' for k, v in goals.items())})"


@command("stop", "Stop the running hunt (state is saved)", "", "Hunt")
def cmd_stop(args: str, session: Any) -> str:
    if not _g(session, "running", False):
        return "no hunt is running — /hunt <target> to start one"
    stopper = _g(session, "stop", None)
    if callable(stopper):
        try:
            stopper()
        except Exception as exc:  # noqa: BLE001
            return f"stop failed: {type(exc).__name__}: {exc}"
    _set(session, "running", False)
    _g(session, "save", lambda: None)()
    rounds = _g(session, "round", 0)
    findings = len(_findings(session))
    return f"hunt stopped after round {rounds} — {findings} finding(s) kept. Saved."


@command("pause", "Pause the running hunt, keeping all state", "", "Hunt")
def cmd_pause(args: str, session: Any) -> str:
    if not _g(session, "running", False):
        return "nothing to pause — the hunt is not running"
    pauser = _g(session, "pause", None)
    if callable(pauser):
        try:
            pauser()
            return "hunt paused — state kept; /run or /resume to continue"
        except Exception as exc:  # noqa: BLE001
            return f"pause failed: {type(exc).__name__}: {exc}"
    _set(session, "running", False)
    return "hunt paused (running=False) — /run to continue"


@command("status", "Show the live hunt status", "", "Hunt")
def cmd_status(args: str, session: Any) -> str:
    target = _g(session, "target", "") or "(none)"
    running = _g(session, "running", False)
    round_no = _g(session, "round", 0)
    wall = _g(session, "wall_seconds", 0) or 0
    idle = _num(_g(session, "idle_seconds", 0))
    budget = _num(_g(session, "budget", 0))
    elapsed = _g(session, "elapsed_seconds", None)
    findings = _findings(session)
    goals = _goals(session)
    lines = [
        f"status: {'running' if running else 'idle'}",
        f"  target: round {round_no} — {target}",
        f"  time:   {_fmt_dur(elapsed) if elapsed else '—'} elapsed / {_fmt_dur(wall)} wall  ·  loop {idle:g}s",
        f"  budget: {'unlimited' if not budget else f'${budget:.2f}'}",
        f"  findings: {len(findings)} ({sum(1 for f in findings if str(f.get('status')) == 'verified')} verified)",
    ]
    if goals:
        for kind, need in goals.items():
            have = _goal_have(session, kind)
            mark = "OK" if have >= need else ".."
            lines.append(f"  goal {kind}: {have}/{need} [{mark}]")
    else:
        lines.append("  goals: none — /goals to set one")
    return "\n".join(lines)


@command("goals", "Show or set hunt goals", "[set|add|clear] <kind:count,...>", "Hunt")
def cmd_goals(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        goals = _goals(session)
        if not goals:
            return f"no goals set — /goals set {DEFAULT_GOAL} (e.g. rce-min:1,findings-min:100)"
        lines = ["goals:"]
        for kind, need in goals.items():
            have = _goal_have(session, kind)
            lines.append(f"  {kind}: {have}/{need} {'(met)' if have >= need else ''}".rstrip())
        return "\n".join(lines)

    sub = toks[0].lower()
    if sub == "clear":
        _set(session, "goals", {})
        return "goals cleared"
    if sub in ("set", "add"):
        spec_text = " ".join(toks[1:])
        if not spec_text:
            return f"usage: /goals {sub} {DEFAULT_GOAL}"
        try:
            spec = _goal_spec(spec_text)
        except ValueError as exc:
            return f"bad goal: {exc}"
        if sub == "add":
            merged = _goals(session)
            merged.update(spec)
            _set(session, "goals", merged)
            return f"goals: {', '.join(f'{k}:{v}' for k, v in merged.items())}"
        _set(session, "goals", spec)
        return f"goals set: {', '.join(f'{k}:{v}' for k, v in spec.items())}"
    # Bare spec: treat as a replace.
    try:
        spec = _goal_spec(args)
    except ValueError as exc:
        return f"bad goal: {exc}"
    _set(session, "goals", spec)
    return f"goals set: {', '.join(f'{k}:{v}' for k, v in spec.items())}"


@command("time", "Show or set the wall-clock budget", "[duration]", "Hunt")
def cmd_time(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        wall = _num(_g(session, "wall_seconds", 0))
        elapsed = _g(session, "elapsed_seconds", None)
        base = f"wall budget: {_fmt_dur(wall)} ({wall:.0f}s)"
        if elapsed:
            base += f"  ·  elapsed: {_fmt_dur(elapsed)}"
        return base
    try:
        wall = _parse_dur(toks[0])
    except ValueError:
        return f"bad duration '{toks[0]}': {_DUR_HINT}"
    _set(session, "wall_seconds", wall)
    note = " (applies next cycle)" if _g(session, "running", False) else ""
    return f"wall budget set: {_fmt_dur(wall)}{note}"


@command("loop", "Show or set the idle interval between cycles (seconds)", "[seconds]", "Hunt")
def cmd_loop(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        idle = _num(_g(session, "idle_seconds", 0))
        return f"loop idle: {idle:g}s between cycles"
    if _g(session, "running", False):
        return "cannot change loop idle while the hunt is active — /pause or /stop first, then /loop <seconds>"
    try:
        idle = float(toks[0])
        if idle < 0:
            raise ValueError
    except ValueError:
        return f"bad loop value '{toks[0]}': seconds between cycles (e.g. 15)"
    _set(session, "idle_seconds", idle)
    return f"loop idle set: {idle:g}s"


@command("target", "Show or set the hunt target", "[value]", "Hunt")
def cmd_target(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        target = _g(session, "target", "") or "(none)"
        return f"target: {target}"
    if _g(session, "running", False):
        return "target is locked while the hunt is active — /pause or /stop first"
    new_target = " ".join(toks)
    _set(session, "target", new_target)
    return f"target set: {new_target}"


# ==========================================================================
# Findings
# ==========================================================================


def _finding_row(finding: dict) -> str:
    fid = str(finding.get("id", "?"))
    severity = str(finding.get("severity", "?"))
    status = str(finding.get("status", "?"))
    round_no = finding.get("round", "?")
    title = str(finding.get("title", "")).replace("\n", " ")
    return f"  [{fid}] {severity:<8} {status:<9} r{round_no}  {title}"


def _find_finding(session: Any, fid: str) -> dict | None:
    for finding in _findings(session):
        if str(finding.get("id")) == fid:
            return finding
    return None


@command("findings", "List findings, optionally filtered by severity or status", "[severity|status]", "Findings")
def cmd_findings(args: str, session: Any) -> str:
    rows = _findings(session)
    if not rows:
        return "no findings yet — /hunt <target> to start hunting"
    toks = _tokens(args)
    filt = toks[0].lower() if toks else ""
    if filt:
        if filt in SEVERITY_ORDER:
            rows = [f for f in rows if str(f.get("severity", "")).lower() == filt]
        elif filt in STATUS_ORDER:
            rows = [f for f in rows if str(f.get("status", "")).lower() == filt]
        else:
            return f"unknown filter '{filt}' — severity {('/'.join(SEVERITY_ORDER))} or status {('/'.join(STATUS_ORDER))}"
    if not rows:
        return f"no findings match '{filt}'"
    rows.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]) if str(f.get("severity")) in SEVERITY_ORDER else 99))
    header = f"findings ({len(rows)}):"
    body = [_finding_row(f) for f in rows]
    return "\n".join([header, *body, "  /claim <id> · /verify <id> · /report"])


@command("claim", "Inspect one finding: evidence, verifier notes, layer checks", "<id>", "Findings")
def cmd_claim(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        ids = ", ".join(str(f.get("id", "?")) for f in _findings(session)) or "(none)"
        return f"usage: /claim <id> — ids: {ids}"
    fid = toks[0]
    finding = _find_finding(session, fid)
    if finding is None:
        ids = ", ".join(str(f.get("id", "?")) for f in _findings(session)) or "(none)"
        return f"no finding '{fid}' — ids: {ids}"

    lines = [f"claim {fid}"]
    lines.append(f"  title:    {finding.get('title', '')}")
    lines.append(f"  severity: {finding.get('severity', '')}")
    lines.append(f"  status:   {finding.get('status', '')}")
    if finding.get("round") is not None:
        lines.append(f"  round:    {finding.get('round')}")
    for key in ("file", "line", "evidence_kind"):
        if finding.get(key) not in (None, ""):
            lines.append(f"  {key + ':':<9} {finding.get(key)}")
    if finding.get("description"):
        lines.append(f"  desc:     {finding['description']}")
    if finding.get("evidence"):
        lines.append(f"  evidence: {finding['evidence']}")
    # the four anti-fabrication layers, when the verifier has run
    for layer, label in (("l1", "L1 deterministic"), ("l2", "L2 adversarial"),
                         ("l3", "L3 cross-ref"), ("l4", "L4 evidence")):
        payload = finding.get(layer)
        if payload:
            lines.append(f"  {label}: {str(payload)[:240]}")
    if finding.get("verifier_note"):
        lines.append(f"  note:     {finding['verifier_note']}")
    if finding.get("chain_from"):
        lines.append(f"  chain:    {finding['chain_from']}")
    return "\n".join(lines)


@command("verify", "Mark a finding verified, rejected, or exploited", "<id> [verified|rejected|exploited]", "Findings")
def cmd_verify(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        ids = ", ".join(str(f.get("id", "?")) for f in _findings(session)) or "(none)"
        return f"usage: /verify <id> [verified|rejected|exploited] — ids: {ids}"
    fid = toks[0]
    target_status = toks[1].lower() if len(toks) > 1 else "verified"
    if target_status not in ("verified", "rejected", "exploited", "verifying"):
        return "status must be one of: verified, rejected, exploited, verifying"
    finding = _find_finding(session, fid)
    if finding is None:
        return f"no finding '{fid}' — /findings lists ids"
    prev = str(finding.get("status", "new"))
    finding["status"] = target_status
    _g(session, "save", lambda: None)()
    return f"[{fid}] {prev} -> {target_status}: {finding.get('title', '')}"


@command("report", "Render a report of the current findings", "[markdown|text|summary]", "Findings")
def cmd_report(args: str, session: Any) -> str:
    toks = _tokens(args)
    fmt = toks[0].lower() if toks else "markdown"
    if fmt not in ("markdown", "text", "summary"):
        return "usage: /report [markdown|text|summary]"
    rows = _findings(session)
    target = _g(session, "target", "") or "(no target)"
    rounds = _g(session, "round", 0)
    verified = sum(1 for f in rows if str(f.get("status")) == "verified")
    by_sev: dict[str, int] = {}
    for finding in rows:
        sev = str(finding.get("severity", "unknown"))
        by_sev[sev] = by_sev.get(sev, 0) + 1
    lines = [
        f"# Hunt report — {target}",
        f"_round {rounds} · {len(rows)} findings · {verified} verified_",
        "",
    ]
    if by_sev:
        lines.append("## Severity")
        for sev in SEVERITY_ORDER:
            if sev in by_sev:
                lines.append(f"- {sev}: {by_sev[sev]}")
        lines.append("")
    if fmt != "summary":
        lines.append("## Findings")
        if not rows:
            lines.append("- (none)")
        for finding in rows:
            lines.append(
                f"- **[{finding.get('id', '?')}] {finding.get('title', '')}** "
                f"— {finding.get('severity', '?')} / {finding.get('status', '?')}"
            )
    else:
        lines.append(f"summary: {len(rows)} findings, {verified} verified")
    return "\n".join(lines)


# ==========================================================================
# Model & Config
# ==========================================================================


def _model_map_lines(session: Any) -> list[str]:
    return [f"  {tier:<13} {_tier_model(session, tier):<22} {TIER_ROLES[tier]}" for tier in TIERS]


def _picker_spec(session: Any) -> str:
    """The multi-tier picker: tier menu, available models, presets."""
    lines = ["set model — multi-tier picker", ""]
    for index, tier in enumerate(TIERS, 1):
        lines.append(f"  {index}. {tier:<13} {TIER_ROLES[tier]}")
        lines.append(f"     now: {_tier_model(session, tier)}")
    models = _models(session)
    lines.append("")
    if models:
        lines.append(f"available models ({len(models)}):")
        for index, model in enumerate(models[:40], 1):
            lines.append(f"  {index}. {model}")
        if len(models) > 40:
            lines.append(f"  ... and {len(models) - 40} more")
    else:
        lines.append("available models: (none discovered — /model --list or set tiers by hand)")
    lines.append("")
    lines.append("presets:  /set model balanced | aggressive | cheap")
    lines.append("per tier: /set model orchestrator=deepseek-chat,verifier=claude-haiku")
    lines.append("          or /model <tier> <model>")
    return "\n".join(lines)


def _apply_preset(session: Any, preset: str) -> str:
    # Prefer the session's own preset table (concrete model ids) when it has one,
    # so the shell and the CLI never drift apart.
    native = _g(session, "set_preset", None)
    if callable(native):
        try:
            if native(preset):
                tiers = _g(session, "model_tiers", {}) or {}
                lines = [f"preset applied: {preset}"]
                for tier in TIERS:
                    lines.append(f"  {tier:<13} -> {tiers.get(tier, '(unset)')}")
                return "\n".join(lines)
        except Exception:  # noqa: BLE001 - fall through to the rank resolver
            pass

    models = _models(session)
    if not models:
        return (
            f"preset '{preset}' needs a model list this session does not expose — "
            "/set model <tier>=<model>,... or /model <tier> <model>"
        )
    ranks = {"strong": models[0], "cheap": models[-1], "mid": models[len(models) // 2]}
    mapping = PRESETS[preset]
    tiers = _g(session, "model_tiers", {}) or {}
    if not isinstance(tiers, dict):
        return "session.model_tiers is not a dict — cannot apply a preset"
    tiers = dict(tiers)
    for tier, rank in mapping.items():
        tiers[tier] = ranks[rank]
    _set(session, "model_tiers", tiers)
    lines = [f"preset applied: {preset}"]
    for tier in TIERS:
        lines.append(f"  {tier:<13} -> {tiers.get(tier, '(unset)')}")
    return "\n".join(lines)


def _apply_assignments(session: Any, pairs: list[str]) -> str:
    tiers = _g(session, "model_tiers", {}) or {}
    if not isinstance(tiers, dict):
        return "session.model_tiers is not a dict — cannot set tiers"
    tiers = dict(tiers)
    applied: list[str] = []
    for pair in pairs:
        if "=" not in pair:
            return f"bad assignment '{pair}' — use tier=model, e.g. hunter=deepseek-chat"
        tier, _, model = pair.partition("=")
        tier = tier.strip().lower()
        model = model.strip()
        if tier not in TIERS:
            return f"unknown tier '{tier}' — valid: {', '.join(TIERS)}"
        if not model:
            return f"no model given for tier '{tier}'"
        tiers[tier] = model
        applied.append(f"{tier} -> {model}")
    _set(session, "model_tiers", tiers)
    return "model tiers set: " + ", ".join(applied)


@command("model", "Show or set a tier's model", "[tier] [model]", "Model & Config")
def cmd_model(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        lines = ["model tiers:", *_model_map_lines(session)]
        models = _models(session)
        if models:
            lines += ["", f"available models ({len(models)}):"]
            lines += [f"  {m}" for m in models[:20]]
            if len(models) > 20:
                lines.append(f"  ... +{len(models) - 20} more")
        lines += ["", "  /model <tier> <model>   e.g. /model hunter devora-01/stepfun/stepfun-5-preview",
                  "  /set model balanced|aggressive|cheap"]
        return "\n".join(lines)
    if len(toks) == 1:
        tier = toks[0].lower()
        if tier not in TIERS:
            return f"unknown tier '{tier}' — valid: {', '.join(TIERS)}"
        return f"{tier}: {_tier_model(session, tier)}  ({TIER_ROLES[tier]})"
    tier = toks[0].lower()
    model = toks[1]
    if tier not in TIERS:
        return f"unknown tier '{tier}' — valid: {', '.join(TIERS)}"
    tiers = _g(session, "model_tiers", {}) or {}
    if not isinstance(tiers, dict):
        return "session.model_tiers is not a dict — cannot set a model"
    tiers = dict(tiers)
    tiers[tier] = model
    _set(session, "model_tiers", tiers)
    return f"{tier} -> {model} (session-scoped)"


@command("set", "Set config: models, time, loop, budget, target, goals", "model <preset> | <key> <value>", "Model & Config")
def cmd_set(args: str, session: Any) -> str:
    toks = _tokens(args)
    if not toks:
        return _picker_spec(session)
    key = toks[0].lower()
    rest = toks[1:]

    if key == "model":
        if not rest:
            return _picker_spec(session)
        first = rest[0].lower()
        if first in PRESETS:
            return _apply_preset(session, first)
        if any("=" in token for token in rest):
            return _apply_assignments(session, rest)
        return f"unknown preset '{rest[0]}' — choose balanced | aggressive | cheap, or tier=model,..."

    if not rest:
        return f"usage: /set {key} <value>"
    value = " ".join(rest)

    if key in ("time", "wall"):
        try:
            wall = _parse_dur(value)
        except ValueError:
            return f"bad duration '{value}': {_DUR_HINT}"
        _set(session, "wall_seconds", wall)
        return f"wall budget set: {_fmt_dur(wall)}"
    if key in ("loop", "idle"):
        if _g(session, "running", False):
            return "cannot change loop idle while the hunt is active — /pause or /stop first"
        try:
            idle = float(value)
            if idle < 0:
                raise ValueError
        except ValueError:
            return f"bad loop value '{value}': seconds between cycles"
        _set(session, "idle_seconds", idle)
        return f"loop idle set: {idle:g}s"
    if key == "budget":
        try:
            budget = float(value)
            if budget < 0:
                raise ValueError
        except ValueError:
            return f"bad budget '{value}': non-negative USD (0 = unlimited)"
        _set(session, "budget", budget)
        return f"budget set: {'unlimited' if budget == 0 else f'${budget:.2f}'}"
    if key == "target":
        if _g(session, "running", False):
            return "target is locked while the hunt is active — /pause or /stop first"
        _set(session, "target", value)
        return f"target set: {value}"
    if key == "goals":
        try:
            spec = _goal_spec(value)
        except ValueError as exc:
            return f"bad goal: {exc}"
        _set(session, "goals", spec)
        return f"goals set: {', '.join(f'{k}:{v}' for k, v in spec.items())}"
    return f"unknown setting '{key}' — model | time | loop | budget | target | goals"


@command("config", "Show the effective configuration", "", "Model & Config")
def cmd_config(args: str, session: Any) -> str:
    goals = _goals(session)
    wall = _num(_g(session, "wall_seconds", 0))
    idle = _num(_g(session, "idle_seconds", 0))
    budget = _num(_g(session, "budget", 0))
    lines = [
        "config",
        f"  target:  {_g(session, 'target', '') or '(none)'}",
        f"  running: {bool(_g(session, 'running', False))}",
        f"  round:   {_g(session, 'round', 0)}",
        f"  time:    {_fmt_dur(wall)} wall  ·  loop {idle:g}s",
        f"  budget:  {'unlimited' if not budget else f'${budget:.2f}'}",
        f"  goals:   {', '.join(f'{k}:{v}' for k, v in goals.items()) or '(none)'}",
        "  models:",
        *_model_map_lines(session),
    ]
    return "\n".join(lines)


@command("cost", "Show spend against the budget", "", "Model & Config")
def cmd_cost(args: str, session: Any) -> str:
    budget = _num(_g(session, "budget", 0))
    spent = _g(session, "cost_usd", None)
    lines = []
    if spent is None:
        lines.append("spend: not tracked on this session")
    else:
        try:
            spent_f = float(spent)
            lines.append(f"spend: ${spent_f:.4f}")
        except (TypeError, ValueError):
            lines.append(f"spend: {spent}")
    lines.append(f"budget: {'unlimited' if not budget else f'${budget:.2f}'}")
    if budget and spent is not None:
        try:
            remaining = budget - float(spent)
            lines.append(f"remaining: ${remaining:.4f}")
        except (TypeError, ValueError):
            pass
    return "\n".join(lines)


# ==========================================================================
# Tools & Skills
# ==========================================================================


def _render_items(items: list, label: str) -> str:
    if not items:
        return f"no {label} available"
    lines = [f"{label} ({len(items)}):"]
    for item in items:
        if isinstance(item, dict):
            name = item.get("name", "?")
            desc = item.get("description", "")
            lines.append(f"  {name}" + (f" — {desc}" if desc else ""))
        else:
            lines.append(f"  {item}")
    return "\n".join(lines)


@command("tools", "List the tools available to this session", "", "Tools & Skills")
def cmd_tools(args: str, session: Any) -> str:
    return _render_items(list(_g(session, "tools", []) or []), "tools")


@command("skills", "List the methodology skills available to this session", "", "Tools & Skills")
def cmd_skills(args: str, session: Any) -> str:
    return _render_items(list(_g(session, "skills", []) or []), "skills")


@command("add", "Add a tool or skill to the session", "<tool|skill> <name>", "Tools & Skills")
def cmd_add(args: str, session: Any) -> str:
    toks = _tokens(args)
    if len(toks) < 2:
        return "usage: /add <tool|skill> <name>"
    kind = toks[0].lower()
    name = " ".join(toks[1:])
    attr = {"tool": "tools", "skill": "skills"}.get(kind)
    if attr is None:
        return f"unknown kind '{kind}' — use 'tool' or 'skill'"
    current = _g(session, attr, None)
    if current is None:
        current = []
    if not isinstance(current, list):
        return f"session.{attr} is not a list — cannot add"
    if name in current:
        return f"{kind} '{name}' is already present"
    updated = list(current)
    updated.append(name)
    if not _set(session, attr, updated):
        return f"session.{attr} is read-only — cannot add"
    return f"added {kind}: {name} ({len(updated)} total)"


# ==========================================================================
# Chat
# ==========================================================================


@command("help", "Show commands, or detail for one command", "[command]", "Chat")
def cmd_help(args: str, session: Any) -> str:
    name = args.strip().lstrip("/").split(" ")[0].lower()
    if not name:
        return _registry_help_text()
    cmd = REGISTRY.get(name)
    if cmd is None:
        return f"no command '{name}' — /help lists all"
    lines = [cmd.usage, f"  {cmd.description}", f"  category: {cmd.category}"]
    if cmd.aliases:
        lines.append(f"  aliases: {', '.join('/' + a for a in cmd.aliases)}")
    return "\n".join(lines)


@command("btw", "A side note to the hunt — does not touch any session state", "<note>", "Chat")
def cmd_btw(args: str, session: Any) -> str:
    # Side channel by contract: this handler reads nothing and writes NOTHING.
    # No _set, no _g on mutable state, no save. The hunt is unaffected.
    note = _text(args)
    if not note:
        return "usage: /btw <note> — a side note that does not affect the hunt"
    return (
        "btw — noted to the side. The hunt is unaffected; no session state was changed.\n"
        f"  > {note}"
    )


# ==========================================================================
# Debug
# ==========================================================================


@command("logs", "Show the most recent session log lines", "[n]", "Debug")
def cmd_logs(args: str, session: Any) -> str:
    toks = _tokens(args)
    limit = 20
    if toks:
        try:
            limit = max(1, int(toks[0]))
        except ValueError:
            return f"usage: /logs [n] — n is a whole number of lines (got '{toks[0]}')"
    lines = _g(session, "log_lines", []) or []
    if not isinstance(lines, (list, tuple)):
        return "session.log_lines is not a list"
    if not lines:
        return "no log lines yet"
    tail = list(lines)[-limit:]
    header = f"last {len(tail)} of {len(lines)} log line(s):"
    return "\n".join([header, *[f"  {line}" for line in tail]])


@command("version", "Show the command-layer version", "", "Debug")
def cmd_version(args: str, session: Any) -> str:
    return f"HUNT commands v{VERSION} — {len(REGISTRY)} registered command(s)"


@command("stats", "Show aggregate hunt statistics", "", "Debug")
def cmd_stats(args: str, session: Any) -> str:
    findings = _findings(session)
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "unknown"))
        status = str(finding.get("status", "unknown"))
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
    verified = by_status.get("verified", 0)
    pct = (verified / len(findings) * 100.0) if findings else 0.0
    lines = [
        "stats",
        f"  rounds:   {_g(session, 'round', 0)}",
        f"  findings: {len(findings)} ({verified} verified, {pct:.0f}%)",
        f"  by severity: {', '.join(f'{k}={v}' for k, v in sorted(by_sev.items())) or '(none)'}",
        f"  by status:   {', '.join(f'{k}={v}' for k, v in sorted(by_status.items())) or '(none)'}",
        f"  wall: {_fmt_dur(_g(session, 'wall_seconds', 0) or 0)}  ·  loop {_num(_g(session, 'idle_seconds', 0)):g}s",
    ]
    return "\n".join(lines)