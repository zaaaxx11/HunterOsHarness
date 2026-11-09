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
DEFAULT_TIME = "21600"  # seconds (= 6 hours)
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
    # was empty
    manual="Start a hunt from natural language. Describe the target and what to find in plain text — the model extracts the URL, goals, time, loop interval and budget. Example: /hunt https://falcon.finance find critical vulns in 3 hours"
)

def cmd_hunt(args: str, session: Any) -> str:
    """/hunt <anything natural> — the model reasons, then acts.

    Plain language, no positional syntax, no JSON parser. The LLM extracts
    target, goals and time from whatever the user wrote and starts the hunt.
    """
    raw = (args or "").strip()
    if not raw:
        return (
            "/hunt <describe your hunt>\n"
            "  Examples:\n"
            "  /hunt https://x.com find all critical vulns in 3 hours\n"
            "  /hunt audit contracts at github.com/org/repo 21600s\n"
            "  /hunt (attach a file + say) find reentrancy and access-control"
        )

    if _g(session, "running", False):
        return "a hunt is already running — /status, /stop"

    chat = _g(session, "_chat", None)
    if not callable(chat):
        return "/hunt needs a model — this session has no chat pipeline yet"

    # Gather what the user already set
    existing_target = _g(session, "target", "")
    existing_wall = _g(session, "wall_seconds", 0) or 0
    existing_goals = _g(session, "goals", {}) or {}
    existing_desc = existing_goals.get("_description", "") if isinstance(existing_goals, dict) else ""
    ctx_bits = []
    if existing_target:
        ctx_bits.append("target: " + existing_target)
    if existing_wall:
        ctx_bits.append("time: " + str(int(existing_wall)) + "s")
    if existing_desc:
        ctx_bits.append("goals: " + existing_desc)
    ctx_line = "  |  ".join(ctx_bits) if ctx_bits else "no prior settings"

    system = (
        "You are the hunt controller for HunterOS. Read the user instruction.\n\n"
        "Current session: " + ctx_line + "\n\n"
        "Return ONLY a JSON object with these optional keys:\n"
        '{"action":"start_hunt","target":"url_or_path","goal_description":"what to find",'
        '"time":seconds,"loop":seconds,"budget":USD}\n\n'
        "Rules:\n"
        "- If the user is describing a hunt, set action to start_hunt.\n"
        "- Always fill target — extract URL, file path, or repo from the text.\n"
        "- Strip angle brackets from URLs.\n"
        "- goal_description is the objective in natural language.\n"
        "- If the user mentions a duration, convert to seconds. Default: 21600 (6h).\n"
        "- loop is seconds between rounds. Default: 15s.\n"
        "- budget is USD. Default: 0 (unlimited).\n"
        "- Return ONLY the JSON, no other text."
    )
    prompt = "User hunt request:\n" + raw
    try:
        # Bypass the chat tone (CHAT_SYSTEM sensual) — the model must return
        # JSON, not flirt. Use the raw LLM adapter when the session carries one.
        reply = chat(system + "\n\n" + prompt)
    except Exception as exc:
        return "model unreachable: " + type(exc).__name__ + " — " + raw[:120]

    import json as _json

    payload: dict = {}
    for candidate in re.findall(r"(?s)\{.*?\}", reply):
        try:
            payload = _json.loads(candidate)
            if isinstance(payload, dict) and payload.get("target"):
                break
        except _json.JSONDecodeError:
            continue

    target = str(payload.get("target") or "").strip()
    target = target.removeprefix("<").removesuffix(">")
    if not target:
        if existing_target:
            target = existing_target
        else:
            return (
                "[hunt] no target found in your message.\n\n"
                "Try:\n"
                "/hunt https://x.com find vulns\n"
                "/target https://x.com  (then /hunt find vulns)"
            )

    action = str(payload.get("action", "start_hunt"))
    if action == "set_target":
        _set(session, "target", target)
        desc = str(payload.get("goal_description") or "").strip()
        if desc:
            _set(session, "goals", {"_description": desc, "findings-min": 5})
        return "target set: " + target + "\n  " + (desc or "no goal yet") + "\nready — /hunt to start"

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

    budget_note = "unlimited" if budget == 0 else "$" + "{:.2f}".format(budget)
    mins_total, secs = divmod(int(wall), 60)
    if mins_total >= 60:
        h, m = divmod(mins_total, 60)
        nice = str(h) + "h" + "{:02d}".format(m) + "m"
    else:
        nice = str(mins_total) + "m" + "{:02d}".format(secs) + "s"
    return (
        "hunting " + target + "\n"
        "  goals:  " + (desc or ", ".join(k + ":" + str(v) for k, v in goals.items() if k != "_description")) + "\n"
        "  time:   " + nice + " (" + str(int(wall)) + "s)  \u00b7  loop: " + str(int(idle)) + "s\n"
        "  budget: " + budget_note + "\n"
        "  /status \u00b7 /pause \u00b7 /stop"
    )

