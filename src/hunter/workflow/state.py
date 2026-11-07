"""Hunt state — the ``hunt_state.json`` schema and its crash-safe persistence.

State on disk is the SINGLE SOURCE OF TRUTH for a hunt.  Every writer goes
through :func:`save`, which is atomic (temp file in the same directory +
``os.fsync`` + ``os.replace``), so a crash in the middle of a round can never
leave a half-written mission file behind: the file on disk is always either
the previous round or the new one.

Nothing in this module performs I/O beyond the state file itself, and nothing
imports a third-party package — it is importable standalone and testable fully
offline.

Public surface
--------------
    HuntState                     dataclass, one JSON document
    new_state(...)                fresh state for a new hunt
    save(state, path)             atomic write, creates parent dirs
    load(path)                    read + normalise an existing state
    add_finding(state, finding)   de-duplicated append, returns True if added
    add_chain(state, chain)       de-duplicated chain append
    count_verified(state)         number of verified findings
    goals_met(state)              (bool, reason)
    time_left(state)              seconds of the total wall budget left
    goal_counts(state)            every goal metric in one dict

Finding records are stored RAW — the dict returned by the verifier layer::

    {id, title, severity, description, evidence, status,
     l1, l2, l3, l4, round}

``add_finding`` only fills in keys the verifier omitted (``id``, ``round``,
``status``, ``l1..l4``); it never rewrites a value the verifier supplied.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import posixpath
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "SCHEMA_VERSION",
    "STATE_FILENAME",
    "GOAL_KEYS",
    "HuntState",
    "add_chain",
    "add_finding",
    "count_verified",
    "elapsed_seconds",
    "finding_location",
    "goal_counts",
    "goals_met",
    "is_refuted",
    "is_verified",
    "load",
    "new_state",
    "normalize_goals",
    "normalize_title",
    "save",
    "slugify",
    "state_path_for",
    "time_left",
]

#: Bumped only when a field is removed or changes meaning.  Readers tolerate
#: unknown extra keys and missing optional keys, so a bump never blocks a
#: resume of an older file.
SCHEMA_VERSION = 1

STATE_FILENAME = "hunt_state.json"

#: Canonical goal vocabulary.  A goal value is the minimum count required.
GOAL_FINDINGS_MIN = "findings-min"        # total non-refuted findings
GOAL_VERIFIED_MIN = "verified-min"        # findings the verifier confirmed
GOAL_CRITICAL_MIN = "critical-min"        # reported critical-severity findings
GOAL_EXPLOITABLE_MIN = "exploitable-min"  # VERIFIED + live-exploitable class
GOAL_RCE_MIN = "rce-min"                  # VERIFIED + code-execution class

GOAL_KEYS: tuple[str, ...] = (
    GOAL_FINDINGS_MIN,
    GOAL_VERIFIED_MIN,
    GOAL_CRITICAL_MIN,
    GOAL_EXPLOITABLE_MIN,
    GOAL_RCE_MIN,
)

# Accept the spellings humans (and old state files) actually type.
_GOAL_ALIASES: dict[str, str] = {
    "findings": GOAL_FINDINGS_MIN,
    "finding-min": GOAL_FINDINGS_MIN,
    "all-vulns": GOAL_FINDINGS_MIN,
    "all-vulns-min": GOAL_FINDINGS_MIN,
    "verified": GOAL_VERIFIED_MIN,
    "proof-min": GOAL_VERIFIED_MIN,
    "critical": GOAL_CRITICAL_MIN,
    "crit-min": GOAL_CRITICAL_MIN,
    "exploitable": GOAL_EXPLOITABLE_MIN,
    "rce-proven-live": GOAL_EXPLOITABLE_MIN,
    "rce": GOAL_RCE_MIN,
}

#: Status values that mean "the verifier confirmed this claim".
VERIFIED_STATUSES: frozenset[str] = frozenset(
    {
        "verified",
        "proven",
        "proven-live",
        "confirmed",
        "promoted",
        "exploitable",
        "poc-verified",
    }
)

#: Status values that mean "this claim is dead" — excluded from every count.
REFUTED_STATUSES: frozenset[str] = frozenset(
    {
        "refuted",
        "overturned",
        "false-positive",
        "rejected",
        "invalid",
        "duplicate",
    }
)

_CRITICAL_SEVERITIES = frozenset({"critical", "crit", "blocker", "sev0", "s0"})

#: Keyword sets for class detection.  Ordered: first match wins.
_EXPLOITABLE_KEYWORDS: tuple[str, ...] = (
    "rce",
    "remote code",
    "code-execution",
    "code execution",
    "command-injection",
    "command injection",
    "deserialization",
    "template-injection",
    "reentrancy",
    "re-entrancy",
    "access-control",
    "access control",
    "missing-auth",
    "authorization-bypass",
    "auth-bypass",
    "privilege-escalation",
    "arbitrary-call",
    "unsafe-delegatecall",
    "delegatecall",
    "oracle-manipulation",
    "price-manipulation",
    "flash-loan",
    "signature-replay",
    "unchecked-call",
    "arbitrary-write",
)

_RCE_KEYWORDS: tuple[str, ...] = (
    "rce",
    "remote code",
    "code-execution",
    "code execution",
    "command-injection",
    "command injection",
    "deserialization",
    "template-injection",
    "ssti",
    "arbitrary-code",
    "arbitrary code",
    "shell-exec",
)

_WS = re.compile(r"[^a-z0-9]+")
_LOC_TAIL = re.compile(r"^(?P<file>.+?):(?P<line>\d+(?:\s*[-:]\s*\d+)?)$")

#: Distinguishes "key absent from the JSON" from "key present and null".
_MISSING = object()


# --------------------------------------------------------------------------- #
# HuntState
# --------------------------------------------------------------------------- #
@dataclass
class HuntState:
    """One hunt, serialised to ``hunt_state.json``.

    ``wall_seconds`` is a TOTAL budget for the hunt, not per round: the loop
    computes ``elapsed = now - started_at``.  ``wall_seconds = 0`` therefore
    means "no time budget left", which the loop honours by running the single
    mandatory round and stopping.  ``None`` means unlimited.

    ``budget_usd = 0`` means unlimited spend.  ``idle_seconds = 0`` means no
    pause between rounds.
    """

    target: str = ""
    goals: dict[str, int] = field(default_factory=dict)
    started_at: float = 0.0
    wall_seconds: float | None = 0.0
    idle_seconds: float = 0.0
    budget_usd: float = 0.0
    round: int = 0
    findings: list[dict] = field(default_factory=list)
    completion_reason: str | None = None
    model_tiers: dict = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    # --- optional extras (defaulted, so old files and old callers still load)
    spent_usd: float = 0.0
    chains: list[dict] = field(default_factory=list)
    #: round-robin cursor over the target's audit units (chunked hunting)
    chunk_cursor: int = 0

    # -- serialisation ---------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": int(self.schema_version or SCHEMA_VERSION),
            "target": str(self.target),
            "goals": {str(k): int(v) for k, v in (self.goals or {}).items()},
            "started_at": float(self.started_at or 0.0),
            "wall_seconds": None if self.wall_seconds is None else float(self.wall_seconds),
            "idle_seconds": float(self.idle_seconds or 0.0),
            "budget_usd": float(self.budget_usd or 0.0),
            "spent_usd": float(self.spent_usd or 0.0),
            "round": int(self.round or 0),
            "findings": [dict(f) for f in self.findings if isinstance(f, dict)],
            "chains": [dict(c) for c in self.chains if isinstance(c, dict)],
            "chunk_cursor": int(self.chunk_cursor or 0),
            "completion_reason": self.completion_reason,
            "model_tiers": dict(self.model_tiers or {}),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HuntState":
        """Build from a decoded JSON object, tolerating missing/extra keys.

        ``wall_seconds`` distinguishes ABSENT (no budget recorded -> 0.0, the
        dataclass default, so a legacy file cannot hang a loop) from an explicit
        JSON ``null`` (deliberately unlimited).
        """
        if not isinstance(data, dict):
            raise ValueError(f"state must be a JSON object, got {type(data).__name__}")
        raw_wall = data.get("wall_seconds", _MISSING)
        if raw_wall is _MISSING:
            wall: float | None = 0.0
        elif raw_wall is None:
            wall = None
        else:
            wall = _as_float(raw_wall, 0.0)
        return cls(
            target=str(data.get("target") or ""),
            goals=normalize_goals(data.get("goals")),
            started_at=_as_float(data.get("started_at"), 0.0),
            wall_seconds=wall,
            idle_seconds=_as_float(data.get("idle_seconds"), 0.0),
            budget_usd=_as_float(data.get("budget_usd"), 0.0),
            round=_as_int(data.get("round"), 0),
            findings=[dict(f) for f in (data.get("findings") or []) if isinstance(f, dict)],
            completion_reason=(None if data.get("completion_reason") in (None, "")
                               else str(data.get("completion_reason"))),
            model_tiers=dict(data.get("model_tiers") or {})
            if isinstance(data.get("model_tiers"), dict) else {},
            schema_version=_as_int(data.get("schema_version"), SCHEMA_VERSION),
            spent_usd=_as_float(data.get("spent_usd"), 0.0),
            chains=[dict(c) for c in (data.get("chains") or []) if isinstance(c, dict)],
            chunk_cursor=_as_int(data.get("chunk_cursor"), 0),
        )


# --------------------------------------------------------------------------- #
# construction / persistence
# --------------------------------------------------------------------------- #
def new_state(
    target: str,
    goals: dict[str, int] | list | None = None,
    wall_seconds: float | None = 0.0,
    idle_seconds: float = 0.0,
    budget_usd: float = 0.0,
    *,
    model_tiers: dict | None = None,
    started_at: float | None = None,
) -> HuntState:
    """A fresh hunt state.  ``started_at`` defaults to now (epoch seconds)."""
    return HuntState(
        target=str(target or ""),
        goals=normalize_goals(goals),
        started_at=float(started_at if started_at is not None else time.time()),
        wall_seconds=None if wall_seconds is None else _as_float(wall_seconds, 0.0),
        idle_seconds=max(0.0, _as_float(idle_seconds, 0.0)),
        budget_usd=max(0.0, _as_float(budget_usd, 0.0)),
        round=0,
        findings=[],
        completion_reason=None,
        model_tiers=dict(model_tiers or {}),
        schema_version=SCHEMA_VERSION,
        spent_usd=0.0,
        chains=[],
    )


def save(state: HuntState, path: str | os.PathLike = STATE_FILENAME) -> Path:
    """Write ``state`` atomically.  Returns the path written.

    Atomicity contract: the JSON is fully written and fsynced to a temp file in
    the *same directory* (so ``os.replace`` is a same-filesystem rename, which
    POSIX guarantees is atomic), then renamed over the target.  A reader either
    sees the complete old file or the complete new one — never a truncated one.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = state.to_dict()
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{p.name}.", suffix=".tmp", dir=str(p.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=_json_default)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, p)
        tmp_name = ""  # consumed by the rename
        _fsync_dir(p.parent)
    finally:
        if tmp_name and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
    return p


def load(path: str | os.PathLike) -> HuntState:
    """Read a state file.

    Raises :class:`FileNotFoundError` when absent and :class:`ValueError` when
    the JSON is unreadable — callers that want "resume or create" should test
    ``Path(path).exists()`` first (that is exactly what ``loop_v3`` does).
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except OSError as exc:  # permissions, a directory in the way, ...
        raise ValueError(f"cannot read hunt state {p}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"corrupt hunt state {p}: {exc}") from exc
    state = HuntState.from_dict(data)
    if not state.started_at:
        state.started_at = time.time()
    if not state.schema_version:
        state.schema_version = SCHEMA_VERSION
    return state


def slugify(target: str) -> str:
    """Filesystem-safe name for a target path or URL."""
    safe = "".join(c if (c.isalnum() or c in "_-.") else "-" for c in str(target or ""))
    safe = safe.strip("-").lower()
    return safe[:64] or "hunt"


def state_path_for(target: str, base_dir: str | os.PathLike = ".") -> Path:
    """``<base_dir>/.hunt/<slug>/hunt_state.json`` — never pollutes the target."""
    return Path(base_dir) / ".hunt" / slugify(target) / STATE_FILENAME


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
def normalize_title(title: Any) -> str:
    """Case/punctuation/whitespace-insensitive title key used for de-dup."""
    return _WS.sub(" ", str(title or "").lower()).strip()


def is_verified(finding: Any) -> bool:
    """True when the finding's status means the verifier confirmed it."""
    return _status(finding) in VERIFIED_STATUSES


def is_refuted(finding: Any) -> bool:
    """True when the finding was disproved / withdrawn."""
    return _status(finding) in REFUTED_STATUSES


def finding_location(finding: dict) -> tuple[str | None, str | None]:
    """Best-effort ``(file, line)`` for a raw finding dict.

    Accepts the shapes the verify layers actually emit: top-level
    ``file``/``line``, an ``evidence`` dict carrying them, an ``evidence``
    string like ``"src/Vault.sol:42"``, or a ``location`` string.
    """
    if not isinstance(finding, dict):
        return (None, None)
    ev = finding.get("evidence")
    fpath: Any = None
    line: Any = None

    if isinstance(ev, dict):
        fpath = ev.get("file") or ev.get("path") or ev.get("filename")
        line = (ev.get("line") or ev.get("start_line") or ev.get("lineno")
                or ev.get("lines"))
        if not fpath:
            loc = ev.get("location") or ev.get("loc")
            if isinstance(loc, str):
                fpath, line = _split_location(loc, line)
    elif isinstance(ev, str):
        fpath, line = _split_location(ev, line)

    if not fpath:
        fpath = finding.get("file") or finding.get("path") or finding.get("filename")
    if line is None:
        line = finding.get("line") or finding.get("start_line")
    if not fpath:
        loc = finding.get("location") or finding.get("loc")
        if isinstance(loc, str):
            fpath, line = _split_location(loc, line)

    if not fpath:
        return (None, None)
    norm_line = None if line is None else str(line).strip() or None
    return (_norm_path(fpath), norm_line)


def add_finding(state: HuntState, finding: dict) -> bool:
    """Append ``finding`` unless it duplicates one already recorded.

    De-duplication keys, in order: ``id``, normalised title, ``(file, line)``.
    The record itself is stored raw (a copy, so later caller mutations cannot
    rewrite history); only absent boilerplate keys are filled in.

    Returns True when the finding was appended.
    """
    if not isinstance(finding, dict):
        raise TypeError(f"finding must be a dict, got {type(finding).__name__}")

    rec = dict(finding)
    rec.setdefault("status", "unverified")
    rec.setdefault("round", int(state.round or 0))
    for key in ("l1", "l2", "l3", "l4"):
        rec.setdefault(key, None)
    if not rec.get("id"):
        rec["id"] = _make_id("F", rec.get("title"), finding_location(rec))

    if _is_duplicate_finding(state, rec):
        return False
    state.findings.append(rec)
    return True


def add_chain(state: HuntState, chain: dict) -> bool:
    """Append an attack chain unless one with the same id/title exists."""
    if not isinstance(chain, dict):
        raise TypeError(f"chain must be a dict, got {type(chain).__name__}")
    rec = dict(chain)
    if not rec.get("id"):
        rec["id"] = _make_id("C", rec.get("title"), None)
    rid = str(rec.get("id") or "")
    ntitle = normalize_title(rec.get("title"))
    for existing in state.chains:
        if rid and str(existing.get("id") or "") == rid:
            return False
        if ntitle and normalize_title(existing.get("title")) == ntitle:
            return False
    state.chains.append(rec)
    return True


# --------------------------------------------------------------------------- #
# goal evaluation
# --------------------------------------------------------------------------- #
def count_verified(state: HuntState) -> int:
    """Findings whose status the verifier promoted."""
    return sum(1 for f in state.findings if is_verified(f))


def goal_counts(state: HuntState) -> dict[str, int]:
    """Every goal metric, computed once.

    * ``findings-min``    — all non-refuted findings (volume)
    * ``verified-min``    — verifier-confirmed findings (quality gate)
    * ``critical-min``    — non-refuted critical-severity findings (severity volume)
    * ``exploitable-min`` — VERIFIED findings in a live-exploitable class
    * ``rce-min``         — VERIFIED findings in a code-execution class
    """
    live = [f for f in state.findings if isinstance(f, dict) and not is_refuted(f)]
    verified = [f for f in live if is_verified(f)]
    return {
        GOAL_FINDINGS_MIN: len(live),
        GOAL_VERIFIED_MIN: len(verified),
        GOAL_CRITICAL_MIN: sum(1 for f in live if _is_critical(f)),
        GOAL_EXPLOITABLE_MIN: sum(1 for f in verified if _is_exploitable(f)),
        GOAL_RCE_MIN: sum(1 for f in verified if _is_rce(f)),
    }


def goals_met(state: HuntState) -> tuple[bool, str]:
    """``(True, "goals-met")`` when EVERY declared goal is satisfied.

    Goals outrank time: the loop stops the moment this returns True even with
    wall budget to spare.  With no goals declared this returns
    ``(False, "no-goals")`` so the loop falls through to its time/round caps.

    Unknown goal keys are ignored (a typo must not make a hunt unstoppable).
    """
    declared = normalize_goals(state.goals)
    if not declared:
        return (False, "no-goals")

    counts = goal_counts(state)
    short: list[str] = []
    for key, need in declared.items():
        if key not in counts:
            continue
        have = counts[key]
        if have < need:
            short.append(f"{key} {have}/{need}")
    if short:
        return (False, "unmet: " + ", ".join(short))
    return (True, "goals-met")


def normalize_goals(goals: Any) -> dict[str, int]:
    """Coerce any accepted goal shape into ``{canonical-key: int}``.

    Accepted: ``{"findings-min": 5}``, ``{"findings_min": "5"}``,
    ``{"verified-min": {"count": 2}}``, and the legacy list form
    ``[{"kind": "verified-min", "count": 2}]``.
    """
    out: dict[str, int] = {}
    if not goals:
        return out
    if isinstance(goals, dict):
        items = goals.items()
    elif isinstance(goals, (list, tuple)):
        pairs = []
        for item in goals:
            if isinstance(item, dict):
                key = item.get("kind") or item.get("key") or item.get("goal")
                val = item.get("count", item.get("value", item.get("min", 1)))
                if key:
                    pairs.append((key, val))
            elif isinstance(item, str):
                pairs.append((item, 1))
        items = pairs
    elif isinstance(goals, str):
        items = [(goals, 1)]
    else:
        return out

    for raw_key, raw_val in items:
        key = _canon_goal_key(raw_key)
        if not key:
            continue
        if isinstance(raw_val, dict):
            raw_val = raw_val.get("count", raw_val.get("min", raw_val.get("value", 1)))
        out[key] = max(0, _as_int(raw_val, 1 if raw_val is None else 0))
    return out


# --------------------------------------------------------------------------- #
# time
# --------------------------------------------------------------------------- #
def elapsed_seconds(state: HuntState, now: float | None = None) -> float:
    """Seconds since the hunt started (never negative)."""
    started = _as_float(state.started_at, 0.0)
    if not started:
        return 0.0
    return max(0.0, _as_float(now if now is not None else time.time(), 0.0) - started)


def time_left(state: HuntState, now: float | None = None) -> float:
    """Seconds of the TOTAL wall budget still available.

    ``wall_seconds is None`` -> ``inf`` (unlimited).  ``wall_seconds == 0`` ->
    ``0.0`` (no budget: the loop runs its one mandatory round and stops).
    """
    if state.wall_seconds is None:
        return float("inf")
    return max(0.0, _as_float(state.wall_seconds, 0.0) - elapsed_seconds(state, now))


# --------------------------------------------------------------------------- #
# internals
# --------------------------------------------------------------------------- #
def _status(finding: Any) -> str:
    if isinstance(finding, dict):
        raw = finding.get("status")
    else:
        raw = getattr(finding, "status", None)
    return str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")


def _severity(finding: dict) -> str:
    raw = finding.get("severity") or finding.get("sev") or ""
    return str(raw).strip().lower()


def _is_critical(finding: dict) -> bool:
    return _severity(finding) in _CRITICAL_SEVERITIES


def _class_text(finding: dict) -> str:
    """Explicit class fields first; the title is the fallback (never the body)."""
    explicit = " ".join(
        str(finding.get(k) or "")
        for k in ("vuln_type", "vuln_class", "klass", "category", "type", "bug_class", "kind")
    ).strip().lower()
    if explicit:
        return explicit
    tags = finding.get("tags")
    if isinstance(tags, (list, tuple)) and tags:
        return " ".join(str(t) for t in tags).lower()
    return str(finding.get("title") or "").lower()


def _is_exploitable(finding: dict) -> bool:
    text = _class_text(finding)
    return any(word in text for word in _EXPLOITABLE_KEYWORDS)


def _is_rce(finding: dict) -> bool:
    text = _class_text(finding)
    return any(word in text for word in _RCE_KEYWORDS)


def _canon_goal_key(key: Any) -> str:
    k = str(key or "").strip().lower().replace("_", "-").replace(" ", "-")
    k = re.sub(r"-+", "-", k).strip("-")
    if k in GOAL_KEYS:
        return k
    if k in _GOAL_ALIASES:
        return _GOAL_ALIASES[k]
    if not k.endswith("-min"):
        k2 = k + "-min"
        if k2 in GOAL_KEYS:
            return k2
        if k2 in _GOAL_ALIASES:
            return _GOAL_ALIASES[k2]
    return ""  # unknown goal: ignored, never blocks completion


def _is_duplicate_finding(state: HuntState, rec: dict) -> bool:
    rid = str(rec.get("id") or "")
    ntitle = normalize_title(rec.get("title"))
    loc = finding_location(rec)
    has_loc = bool(loc[0] and loc[1])
    for existing in state.findings:
        if not isinstance(existing, dict):
            continue
        if rid and str(existing.get("id") or "") == rid:
            return True
        if ntitle and normalize_title(existing.get("title")) == ntitle:
            return True
        if has_loc and finding_location(existing) == loc:
            return True
    return False


def _make_id(prefix: str, title: Any, loc: tuple[str | None, str | None] | None) -> str:
    basis = "|".join(
        [normalize_title(title), (loc[0] or "") if loc else "",
         (loc[1] or "") if loc else ""]
    )
    return prefix + hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]


def _split_location(text: str, line: Any = None) -> tuple[str | None, Any]:
    """``"src/Vault.sol:42"`` -> ``("src/Vault.sol", "42")``."""
    s = str(text or "").strip()
    m = _LOC_TAIL.match(s)
    if not m:
        return (None, line)
    return (m.group("file").strip(), line if line is not None else m.group("line").strip())


def _norm_path(path: Any) -> str:
    s = str(path or "").strip().replace("\\", "/")
    if not s:
        return ""
    s = posixpath.normpath(s)
    while s.startswith("./"):
        s = s[2:]
    return s.lower()


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return int(value)
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    return str(obj)


def _fsync_dir(directory: Path) -> None:
    """Best-effort directory fsync so the rename itself is durable."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)