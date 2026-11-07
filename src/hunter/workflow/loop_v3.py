"""Three-phase hunt loop (v3): HUNTER -> VERIFIER -> CHAINER, state-driven.

Design contract
---------------
* Everything that could touch the outside world is INJECTED::

      llm.complete(system, user) -> str
      llm.complete_with_tools(system, user, tools) -> dict

      verify_claim(claim, ctx) -> dict      # the 4-layer verify (l1..l4 + status)
      chainer(verified_findings, ctx) -> list[dict]

  so the entire loop runs offline in ``selftest.py`` with a FakeLLM.

* State on disk is the single source of truth.  A resume loads
  ``hunt_state.json``, keeps the original ``started_at`` (``wall_seconds`` is a
  budget for the WHOLE hunt, not per round) and every round ends with an atomic
  :func:`state.save`.

* Goals outrank time: if every declared goal is met we stop with time to spare.
  Time, then budget, then ``max_rounds`` bound the loop.  Two guards keep a
  goal-only hunt (no clock budget) from spinning: ``no_progress_rounds``
  consecutive rounds that add nothing stop with ``no-progress``, and three
  consecutive failed rounds stop with ``error``.

* At least one round always runs per invocation (do-while), so
  ``wall_seconds=0`` means "run one round, then stop" rather than "never start".

* Force-retry: a hunter turn that returns TEXT but makes zero
  ``report_finding`` calls is retried exactly once with an explicit
  "now call report_finding" nudge.  Repeated talking is not a finding.

Progress lines are printed with a ``[R<round>]`` prefix through the injected
``log`` callable (``print`` by default).
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

try:  # imported as ``hunter.workflow.loop_v3``
    from .state import (
        HuntState,
        add_chain,
        add_finding,
        count_verified,
        elapsed_seconds,
        goals_met,
        is_verified,
        load,
        new_state,
        normalize_goals,
        save,
        state_path_for,
        time_left,
    )
except ImportError:  # pragma: no cover - standalone / integration import paths
    try:
        from hunter.workflow.state import (  # type: ignore
            HuntState,
            add_chain,
            add_finding,
            count_verified,
            elapsed_seconds,
            goals_met,
            is_verified,
            load,
            new_state,
            normalize_goals,
            save,
            state_path_for,
            time_left,
        )
    except ImportError:
        from state import (  # type: ignore
            HuntState,
            add_chain,
            add_finding,
            count_verified,
            elapsed_seconds,
            goals_met,
            is_verified,
            load,
            new_state,
            normalize_goals,
            save,
            state_path_for,
            time_left,
        )

__all__ = [
    "HUNTER_SYSTEM",
    "HUNTER_TOOLS",
    "HuntLoop",
    "MAX_HUNTER_RETRIES",
    "build_hunter_prompt",
    "run",
    "run_hunt",
    "run_loop",
]

#: How many times a text-only hunter turn is re-asked (spec: exactly one).
MAX_HUNTER_RETRIES = 1

#: Safety valve for the pathological "no time, no goals, no max_rounds" call.
_SAFETY_ROUNDS = 100

#: Consecutive failed rounds after which the run stops with reason "error".
_MAX_ROUND_ERRORS = 3

#: Consecutive rounds adding nothing (no findings, no chains) before a hunt with
#: no time budget stops with reason "no-progress".  Without this a
#: goals-only + unlimited-time hunt whose hunter finds nothing spins forever.
_NO_PROGRESS_ROUNDS = 5

_LOG_LIMIT = 400


# --------------------------------------------------------------------------- #
# prompts / tools
# --------------------------------------------------------------------------- #
HUNTER_SYSTEM = """\
You are a security auditor. Audit the code in this message and report every
vulnerability you find by calling the report_finding tool — one call per finding.

Do not explain, summarise or think out loud in text: the only acceptable reply is
one or more report_finding calls.

- file: the path shown after "FILE:" / in the UNIT header. line: a real line number in it.
- severity: critical | high | medium | low | info.
  critical = direct loss of funds or unauthenticated code execution.
- description: the mechanism, the attacker's steps, the impact. Under 400 characters.
- Report one finding per distinct root cause. Never repeat a title already recorded.
- Only report code that is actually present above. If the code is clean, call
  report_finding with {"findings": []}.
"""

#: Tool schema for the HUNTER turn (OpenAI function-calling shape).
HUNTER_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": (
                "Report one NEW candidate security finding for verification. "
                "Call once per distinct root cause."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, specific title."},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "description": {
                        "type": "string",
                        "description": "Mechanism + attacker steps + impact.",
                    },
                    "file": {"type": "string", "description": "Path as it appears in the target."},
                    "line": {"type": "integer", "description": "Line number of the flawed code."},
                    "vuln_type": {
                        "type": "string",
                        "description": "e.g. reentrancy, access-control, oracle, overflow",
                    },
                    "evidence": {
                        "type": "object",
                        "description": "Concrete proof: snippet, request, transaction, output.",
                    },
                },
                "required": ["title", "severity", "description"],
            },
        },
    }
]

_NUDGE = """
STOP. You returned text but made no report_finding call.
Now call report_finding once per candidate finding — do not explain, do not summarise,
just call the tool with title, severity, description, file and line.
If the target genuinely yielded nothing new, call report_finding with {"findings": []}.
"""

_JSON_FALLBACK_INSTRUCTION = (
    '\n\nNo tools are available in this session. Reply with ONLY a JSON object:\n'
    '{"findings": [{"title": "...", "severity": "high", "description": "...", '
    '"file": "...", "line": 1, "vuln_type": "..."}]}\n'
    'An empty list means "nothing new".'
)

#: Stronger variant used when the tool call never arrives (reasoning models burn
#: the whole output budget on reasoning_content and stop before the tool call).
_JSON_STRICT = """

OUTPUT FORMAT — OVERRIDE (your tool call did not arrive):
You have NO tools in this turn. Your ENTIRE reply must be exactly one JSON object,
with no prose before or after it:

{"findings": [{"title": "...", "severity": "critical|high|medium|low|info",
  "description": "...", "file": "exact path from the --- header ---", "line": 123,
  "vuln_type": "..."}]}

Rules:
- Keep every description under 400 characters.
- file MUST be one of the paths shown in the --- <path> --- headers, and line the
  real line number inside it.
- If you found nothing new, reply exactly {"findings": []}.
- Do NOT write an introduction, an analysis, a summary, or any thinking out loud —
  only the JSON object."""


_HUNTER_EXTS = {
    ".sol", ".vy", ".cairo", ".move", ".rs", ".go", ".py", ".js", ".ts",
    ".java", ".rb", ".php", ".c", ".h", ".cpp", ".cs", ".sh", ".yaml", ".json",
}

#: Directories that are dependencies, build output, or test scaffolding —
#: auditing these wastes the whole prompt budget on OpenZeppelin/Node modules
#: instead of the target's own code.
_SKIP_DIRS = {
    "lib", "node_modules", ".git", "test", "tests", "script", "scripts",
    "mock", "mocks", "vendor", "build", "out", "cache", "artifacts",
    "dependencies", ".deps", "coverage", "typechain", "typechain-types",
}

#: Path fragments that mark the target's OWN code (ranked first).
_OWN_HINTS = ("src/", "contracts/", "sources/", "programs/", "core/", "app/")


def _rel_parts(path: Path, base: Path) -> set[str]:
    """Lower-cased path parts RELATIVE to base.

    Using absolute parts would make a target under e.g. ``~/.hermes/cache/...``
    invisible, because ``cache`` is in ``_SKIP_DIRS``.
    """
    try:
        return {p.lower() for p in path.relative_to(base).parts}
    except Exception:  # noqa: BLE001
        return {p.lower() for p in path.parts}


def _source_rank(path: Path, base: Path) -> tuple[int, int, str]:
    """Sort key: own code first, dependencies last, shallow before deep."""
    try:
        rel = path.relative_to(base).as_posix()
    except Exception:  # noqa: BLE001
        rel = path.name
    rel_l = rel.lower()
    score = 0
    if _rel_parts(path, base) & _SKIP_DIRS:
        score -= 100
    if "/node_modules/" in rel_l or rel_l.startswith("node_modules/"):
        score -= 100
    if any(h in rel_l for h in _OWN_HINTS):
        score += 50
    if rel_l.startswith("src/") or "/src/" in rel_l:
        score += 30
    if path.suffix.lower() == ".sol":
        score += 10
    depth = rel_l.count("/")
    return (-score, depth, rel)


def read_target_source(
    target: str,
    workdir: str | os.PathLike = ".",
    *,
    max_files: int = 10,
    max_chars_per_file: int = 8000,
    max_total: int = 48000,
) -> str:
    """Inline the target's source so the hunter is not blind.

    The HUNTER turn has no file-reading tool (by design — fewer tools, fewer
    ways to stall). Without this the model is asked to audit code it cannot
    see, which is the single largest source of invented findings. Paths are
    emitted relative to the target root so a cited ``file:line`` matches what
    the deterministic verifier will look up on disk.
    """
    root = Path(target) if target else Path(workdir)
    try:
        if root.is_file():
            files = [root]
            base = root.parent
        elif root.is_dir():
            candidates = [
                p for p in root.rglob("*")
                if p.is_file()
                and p.suffix.lower() in _HUNTER_EXTS
                and not (_rel_parts(p, root) & _SKIP_DIRS)
            ]
            files = sorted(candidates, key=lambda p: _source_rank(p, root))
            base = root
        else:
            return ""
    except Exception:  # noqa: BLE001 - an unreadable target is not a crash
        return ""

    chunks: list[str] = []
    total = 0
    for f in files[:max_files]:
        try:
            text = f.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
        room = max_total - total
        if room <= 0:
            break
        text = text[: min(max_chars_per_file, room)]
        try:
            rel = f.relative_to(base)
        except Exception:  # noqa: BLE001
            rel = f.name
        chunks.append(f"--- {rel} ---\n{text}")
        total += len(text)
        if total >= max_total:
            break
    return "\n\n".join(chunks)


def _target_files(root: Path) -> list[tuple[Path, str]]:
    """Ranked ``(path, relpath)`` for the target's own source files."""
    try:
        if root.is_file():
            return [(root, root.name)]
        if not root.is_dir():
            return []
    except Exception:  # noqa: BLE001
        return []
    candidates = [
        p for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in _HUNTER_EXTS
        and not (_rel_parts(p, root) & _SKIP_DIRS)
    ]
    out: list[tuple[Path, str]] = []
    for p in sorted(candidates, key=lambda q: _source_rank(q, root)):
        try:
            rel = p.relative_to(root).as_posix()
        except Exception:  # noqa: BLE001
            rel = p.name
        out.append((p, rel))
    return out


#: Lines that start a self-contained unit of code in the languages we audit.
_BLOCK_START = re.compile(
    r"^(?P<indent>[ \t]*)"
    r"(?:"
    r"(?:abstract\s+)?(?:contract|library|interface)\s+\w+"
    r"|function\s+\w+"
    r"|constructor\s*\("
    r"|modifier\s+\w+"
    r"|receive\s*\("
    r"|fallback\s*\("
    r"|(?:pub(?:lic)?\s+)?(?:async\s+)?fn\s+\w+"
    r"|def\s+\w+"
    r"|class\s+\w+"
    r"|(?:export\s+)?(?:async\s+)?function\s+\w+"
    r")"
)


def _split_blocks(text: str) -> list[tuple[int, str]]:
    """Split source into blocks, keeping each block's 0-based start line.

    The start line is kept so a chunk can be padded back to its original line
    numbering: a finding that cites ``line 42`` of part 2 must resolve to line 42
    of the file, not line 42 of the excerpt.
    """
    lines = text.splitlines(keepends=True)
    starts = [i for i, ln in enumerate(lines) if _BLOCK_START.match(ln)]
    if not starts:
        return [(0, text)]
    if starts[0] != 0:
        starts.insert(0, 0)
    blocks: list[tuple[int, str]] = []
    for a, b in zip(starts, starts[1:] + [len(lines)]):
        chunk = "".join(lines[a:b])
        if chunk.strip():
            blocks.append((a, chunk))
    return blocks or [(0, text)]


def _merge_blocks(blocks: list[tuple[int, str]], max_chars: int) -> list[tuple[int, str]]:
    """Greedily pack blocks up to ``max_chars``, preserving the first start line."""
    out: list[tuple[int, str]] = []
    cur_start = 0
    cur = ""
    for start, b in blocks:
        if cur and len(cur) + len(b) > max_chars:
            out.append((cur_start, cur))
            cur_start, cur = start, b
        else:
            if not cur:
                cur_start = start
            cur += b
    if cur:
        out.append((cur_start, cur))
    return out or [(0, "")]


def _number_lines(lines: list[str], offset: int) -> str:
    """Prefix every line with its real (1-based) line number in the source file.

    Blank-line padding was ambiguous: a model counts the lines it can see, not the
    leading newlines, so a cited "line 8" pointed at the wrong code. An explicit
    gutter removes the guesswork — the number the model reads is the number the
    verifier looks up.
    """
    return "\n".join(
        f"{offset + i:>5} | {ln}" for i, ln in enumerate(lines, 1)
    )


def iter_target_chunks(
    target: str,
    workdir: str | os.PathLike = ".",
    *,
    max_chars: int | None = None,
) -> list[tuple[str, str]]:
    """Chunk the target so each unit fits the model's reliable tool-call window.

    Live evidence: with a ~6.8k-char prompt the provider truncates the turn
    (``finish_reason=length``) before the tool call is emitted, while a small
    unit-sized prompt calls ``report_finding`` natively on the default output
    budget. Chunking is therefore the fix that needs no token-budget change.

    Returns ``[(label, code), ...]`` with labels that are safe to cite back as
    ``file`` in a finding (``path`` or ``path#partN``).
    """
    if max_chars is None:
        try:
            max_chars = int(os.environ.get("HUNTEROS_CHUNK_CHARS", "2000") or 2000)
        except ValueError:
            max_chars = 2000
    root = Path(target) if target else Path(workdir)
    out: list[tuple[str, str]] = []
    for path, rel in _target_files(root):
        try:
            text = path.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if len(text) <= max_chars:
            out.append((rel, _number_lines(text.splitlines(), 0)))
            continue
        parts = _merge_blocks(_split_blocks(text), max_chars)
        if len(parts) == 1:
            out.append((rel, _number_lines(text.splitlines(), 0)))
            continue
        for i, (start_line, part) in enumerate(parts, 1):
            out.append((f"{rel}#part{i}", _number_lines(part.splitlines(), start_line)))
    return out


def build_chunk_prompt(
    state: HuntState,
    known_titles: list[str] | None,
    label: str,
    code: str,
    *,
    index: int = 0,
    total: int = 1,
    nudge: bool = False,
) -> str:
    """A unit-sized HUNTER turn: exactly one chunk of the target source."""
    known = [str(t) for t in (known_titles or []) if str(t).strip()]
    left = time_left(state)
    left_s = "unlimited" if left == float("inf") else f"{left:.0f}s"
    lines = [
        f"TARGET: {state.target or '(unspecified)'}",
        f"UNIT {index}/{total}: {label}  (this is the ONLY code in scope for this turn)",
        f"ROUND: {state.round}   TIME LEFT: {left_s}",
        "PHASE: HUNTER — report NEW candidate findings for THIS UNIT only.",
        "",
    ]
    if known:
        lines.append(f"ALREADY RECORDED ({len(known)}) — do NOT repeat any of these:")
        for i, title in enumerate(known, 1):
            lines.append(f"  {i}. {title}")
    else:
        lines.append("ALREADY RECORDED: none — this is the first turn.")
    lines += [
        "",
        f"Report each vulnerability in the code below with report_finding. "
        f"Use file={label!r} and the line number shown in the gutter "
        f"(the `NNNN |` prefix of the offending line). "
        'If the unit is clean, call report_finding with {"findings": []}. '
        'Never report a finding titled "no vulnerabilities" or "clean".',
        "",
        "UNIT SOURCE (left gutter = real line numbers in the file):",
        code,
    ]
    prompt = "\n".join(lines)
    if nudge:
        prompt += "\n" + _NUDGE
    return prompt


def build_hunter_prompt(
    state: HuntState,
    known_titles: list[str] | None,
    *,
    workdir: str | os.PathLike = ".",
    nudge: bool = False,
) -> str:
    """The HUNTER user turn: target, budget, known titles, instructions."""
    known = [str(t) for t in (known_titles or []) if str(t).strip()]
    left = time_left(state)
    left_s = "unlimited" if left == float("inf") else f"{left:.0f}s"
    budget = (
        "unlimited"
        if not state.budget_usd
        else f"${float(state.spent_usd or 0.0):.4f} of ${float(state.budget_usd):.4f}"
    )

    lines = [
        f"TARGET: {state.target or '(unspecified)'}",
        "(the full source of this target is included at the END of this message —",
        " you do NOT need to read, list or explore anything)",
        f"ROUND: {state.round}",
        f"TIME LEFT: {left_s}   BUDGET: {budget}",
        "PHASE: HUNTER — report NEW candidate findings only.",
        "",
    ]
    if known:
        lines.append(
            f"ALREADY RECORDED ({len(known)}) — do NOT report any of these again:"
        )
        for i, title in enumerate(known, 1):
            lines.append(f"  {i}. {title}")
    else:
        lines.append("ALREADY RECORDED: none — this is the first round.")
    lines += [
        "",
        "INSTRUCTIONS:",
        "1. Audit the TARGET SOURCE included below. It is the real code — do not",
        "   describe code that is not in it.",
        "2. Find vulnerabilities that are NOT in the list above.",
        "3. For each one call report_finding with title, severity, description, file,",
        "   line and the concrete evidence you saw.",
        "4. `file` must be the exact path shown in the --- <path> --- headers, and",
        "   `line` the real line number in that file. A claim without a true",
        "   file:line is rejected by the verifier.",
        "5. When there are no more new candidates, stop.",
    ]
    source = read_target_source(state.target, workdir)
    if source:
        lines += ["", "TARGET SOURCE:", source]
    else:
        lines += [
            "",
            "TARGET SOURCE: (not readable from the shell — report only what you can",
            "cite concretely; an uncited claim will be rejected).",
        ]
    prompt = "\n".join(lines)
    if nudge:
        prompt += "\n" + _NUDGE
    return prompt


# --------------------------------------------------------------------------- #
# response normalisation (dict / TurnResult / str / OpenAI message)
# --------------------------------------------------------------------------- #
def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _norm_response(resp: Any) -> tuple[str, list[dict], float]:
    """``(text, [{"name","arguments"}], cost_usd)`` from any provider shape."""
    if resp is None:
        return ("", [], 0.0)
    if isinstance(resp, str):
        return (resp, [], 0.0)

    message = _get(resp, "message")
    choices = _get(resp, "choices")
    if message is None and isinstance(choices, list) and choices:
        # Raw OpenAI-style response: unwrap choices[0].message.
        message = _get(choices[0], "message") or choices[0]
    text = _get(resp, "text")
    if text is None:
        text = _get(resp, "content")
    if text is None and isinstance(message, dict):
        text = message.get("content")
    if text is None and message is not None and not isinstance(message, dict):
        text = getattr(message, "content", None)
    if not isinstance(text, str):
        text = "" if text is None else str(text)

    calls = _get(resp, "tool_calls")
    if calls is None:
        calls = _get(resp, "calls")
    if not calls and isinstance(message, dict):
        calls = message.get("tool_calls") or message.get("calls")
    if not calls and message is not None and not isinstance(message, dict):
        calls = getattr(message, "tool_calls", None)
    if isinstance(calls, dict):
        calls = [calls]
    if not isinstance(calls, (list, tuple)):
        calls = []

    out: list[dict] = []
    for call in calls:
        name = _get(call, "name")
        args = _get(call, "arguments")
        fn = _get(call, "function")
        if isinstance(fn, dict):
            name = name or fn.get("name")
            args = args if args is not None else fn.get("arguments")
        if args is None:
            args = _get(call, "args")
        if args is None:
            args = _get(call, "input")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"_raw": args}
        out.append(
            {"name": str(name or ""), "arguments": args if isinstance(args, dict) else {}}
        )

    cost = _num(_get(resp, "cost_usd"), 0.0)
    if not cost:
        usage = _get(resp, "usage") or {}
        cost = _num(
            _get(usage, "cost_usd", None)
            or _get(usage, "total_cost_usd", None)
            or _get(usage, "cost", None),
            0.0,
        )
    return (text, out, cost)


_FENCE_RE = re.compile(r"```(?:json)?\s*(.+?)```", re.DOTALL)


def _first_json(text: str) -> Any:
    """First JSON value in ``text``: a fenced block, else a balanced span."""
    body = text or ""
    for block in _FENCE_RE.findall(body):
        try:
            return json.loads(block.strip())
        except json.JSONDecodeError:
            pass
    for idx, ch in enumerate(body):
        if ch not in "{[":
            continue
        span = _balanced_span(body, idx)
        if span is None:
            continue
        try:
            return json.loads(span)
        except json.JSONDecodeError:
            continue
    return None


def _balanced_span(text: str, start: int) -> str | None:
    opener = text[start]
    closer = "}" if opener == "{" else "]"
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _json_calls_from_text(text: str) -> list[dict]:
    """Treat a text-only LLM answer as a fake ``report_finding`` call list."""
    data = _first_json(text)
    items = data.get("findings") if isinstance(data, dict) else data
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return []
    calls = []
    for item in items:
        if isinstance(item, dict) and (item.get("title") or item.get("description")):
            calls.append({"name": "report_finding", "arguments": dict(item)})
    return calls


_NON_FINDING_RE = re.compile(
    r"\b(?:no\s+(?:new\s+)?(?:vulnerabilit\w*|issue\w*|finding\w*|bug\w*)"
    r"|clean\b|nothing\s+(?:found|to\s+report)|none\s+found|no\s+problems?\b)",
    re.IGNORECASE,
)


def _is_non_finding(title: Any, description: Any = "") -> bool:
    """A "we found nothing" note is a status, not a finding — never store it."""
    text = f"{title or ''} {description or ''}".strip()
    if not text:
        return True
    return bool(_NON_FINDING_RE.search(str(title or "")))


def _is_report_call(name: Any) -> bool:
    key = re.sub(r"[\s-]+", "_", str(name or "").strip().lower())
    return key in {"report_finding", "report_findings", "add_finding", "reportfinding"}


def _candidates_from_args(args: dict) -> list[dict]:
    """One tool call may carry one finding or a ``{"findings": [...]}`` batch.

    "Nothing found" notes are dropped: a clean/empty report is a status signal,
    not a finding, and storing it pollutes the ledger and the dedup keys.
    """
    if not isinstance(args, dict):
        return []
    raw: list[dict] = []
    batch = args.get("findings")
    if isinstance(batch, list):
        raw = [dict(x) for x in batch if isinstance(x, dict)]
    elif isinstance(args.get("finding"), dict):
        raw = [dict(args["finding"])]
    elif any(k in args for k in ("title", "description", "vuln_type")):
        raw = [dict(args)]
    return [
        c for c in raw
        if not _is_non_finding(c.get("title"), c.get("description"))
    ]


def _claim_from_candidate(cand: dict, state: HuntState) -> dict:
    """Normalise a hunter candidate into the claim handed to ``verify_claim``."""
    claim = dict(cand)
    claim["title"] = str(cand.get("title") or "").strip()
    claim["severity"] = str(cand.get("severity") or "").strip().lower() or "info"
    claim["description"] = str(cand.get("description") or "")
    claim["vuln_type"] = str(
        cand.get("vuln_type") or cand.get("klass") or cand.get("type") or ""
    )

    ev = cand.get("evidence")
    if isinstance(ev, dict):
        ev = dict(ev)
    elif ev is None:
        ev = {}
    else:
        ev = {"note": str(ev)}
    # Mirror the explicit location into evidence: verify layers consistently read
    # evidence["file"]/["line"], and a candidate must not lose its citation here.
    if cand.get("file") is not None:
        ev.setdefault("file", cand.get("file"))
    if cand.get("line") is not None:
        ev.setdefault("line", cand.get("line"))
    claim["evidence"] = ev

    claim["status"] = "candidate"
    claim["round"] = int(state.round or 0)
    if not isinstance(claim.get("id"), str):
        claim["id"] = str(claim.get("id") or "")
    return claim


def _call2(fn: Callable, first: Any, second: Any) -> Any:
    """Call ``fn(first, second)``, degrading gracefully to one/zero args."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(first, second)
    params = list(sig.parameters.values())
    positional = [
        p
        for p in params
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    if any(p.kind is p.VAR_POSITIONAL for p in params):
        return fn(first, second)
    if len(positional) >= 2:
        return fn(first, second)
    if len(positional) == 1:
        return fn(first)
    return fn()


# --------------------------------------------------------------------------- #
# the loop
# --------------------------------------------------------------------------- #
class HuntLoop:
    """State-driven HUNTER -> VERIFIER -> CHAINER loop with injected IO.

    ``llm`` and ``verify_claim`` are required.  ``chainer`` is optional: without
    it the CHAINER phase logs that it was skipped.

    ``wall_seconds`` / ``idle_seconds`` / ``budget_usd`` accept ``None`` meaning
    "inherit from the state file" (for a resumed hunt) or "the safe default"
    (for a fresh one: 0s wall -> one round, 0s idle, unlimited budget).  Pass
    ``float("inf")`` for a genuinely unlimited wall budget.
    """

    def __init__(
        self,
        llm: Any,
        verify_claim: Callable | None,
        *,
        target: str = "",
        goals: dict[str, int] | list | None = None,
        wall_seconds: float | None = None,
        idle_seconds: float | None = None,
        budget_usd: float | None = None,
        state_path: str | os.PathLike | None = None,
        workdir: str | os.PathLike | None = None,
        chainer: Callable | None = None,
        model_tiers: dict | None = None,
        max_rounds: int = 0,
        no_progress_rounds: int = _NO_PROGRESS_ROUNDS,
        force: bool = False,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
        log: Callable[[str], None] | None = None,
    ) -> None:
        if llm is None:
            raise ValueError("HuntLoop requires an injected llm object")
        if not callable(getattr(llm, "complete", None)) and not callable(
            getattr(llm, "complete_with_tools", None)
        ):
            raise TypeError(
                "llm must expose complete(system,user) and/or "
                "complete_with_tools(system,user,tools)"
            )

        self.llm = llm
        self.verify_claim = verify_claim
        self.chainer = chainer
        self.target = str(target or "")
        self._goals_arg = goals
        self._wall_arg = wall_seconds
        self._idle_arg = idle_seconds
        self._budget_arg = budget_usd
        self._state_arg_path = state_path
        self._model_tiers = model_tiers
        self.max_rounds = max(0, int(max_rounds or 0))
        self.no_progress_rounds = max(0, int(no_progress_rounds or 0))
        self.force = bool(force)
        self.clock = clock
        self.sleeper = sleeper
        self.log = log or _print_flush

        self.workdir = Path(workdir) if workdir is not None else (
            Path(self.target) if self.target and os.path.isdir(self.target) else Path.cwd()
        )

        if state_path is None:
            state_path = state_path_for(self.target or "hunt", ".")
        self.state_path = Path(state_path)
        self._ran = 0
        self._round_errors = 0
        self._idle_streak = 0
        #: set False after the first tool turn that yields no call, so later rounds
        #: go straight to the JSON turn instead of re-paying for a dead path
        self._tools_work = True
        self._verifier_llm_failed = False

    # -- public ----------------------------------------------------------- #
    def run(self, state: HuntState | None = None) -> HuntState:
        """Run until a stop condition; always returns the persisted state.

        ``state`` may be supplied directly (an in-memory mission); otherwise the
        hunt resumes from ``state_path`` when it exists, or starts fresh.
        """
        if state is None:
            state = self._load_or_init()
        else:
            state = self._apply_overrides(state)
            if self.force:
                state.completion_reason = None
            if not state.started_at:
                state.started_at = self.clock()

        self._maybe_cap(state)
        self._log(
            f"[R{state.round}] hunt: target={state.target or '(unspecified)'} "
            f"goals={state.goals or '{}'} wall="
            f"{'unlimited' if state.wall_seconds is None else f'{float(state.wall_seconds):g}s'} "
            f"idle={float(state.idle_seconds or 0):g}s "
            f"budget={'unlimited' if not state.budget_usd else f'${float(state.budget_usd):g}'} "
            f"findings={len(state.findings)}"
        )
        if self.verify_claim is None:
            self._log(
                f"[R{state.round}] verify: NO verify_claim injected — "
                f"candidates cannot be verified"
            )

        while True:
            reason = self._pre_stop(state)
            if reason:
                state.completion_reason = reason
                break

            state.round = int(state.round or 0) + 1
            try:
                stats = self._round(state)
            except Exception as exc:
                # An unexpected failure must not lose the round's state or kill
                # the hunt: persist what we have and let the stop conditions
                # decide.  Three consecutive bad rounds end the run.
                self._round_errors += 1
                self._log(
                    f"[R{state.round}] round failed: {type(exc).__name__}: "
                    f"{_clip(str(exc))}"
                )
            else:
                self._round_errors = 0
                produced = int(stats.get("added", 0) or 0) + int(stats.get("chains", 0) or 0)
                self._idle_streak = 0 if produced else self._idle_streak + 1
            save(state, self.state_path)  # persist BEFORE any idle wait
            self._ran += 1

            reason = self._post_stop(state)
            if reason:
                state.completion_reason = reason
                break
            if state.idle_seconds and float(state.idle_seconds) > 0:
                self._log(f"[R{state.round}] idle: sleeping {float(state.idle_seconds):g}s")
                try:
                    self.sleeper(float(state.idle_seconds))
                except Exception as exc:  # a broken sleeper must not kill the hunt
                    self._log(f"[R{state.round}] idle: sleep failed ({exc}) — continuing")

        save(state, self.state_path)
        self._print_stop(state)
        return state

    # -- setup ------------------------------------------------------------ #
    def _load_or_init(self) -> HuntState:
        exists = self.state_path.exists()
        if exists:
            state = load(self.state_path)
            self._log(
                f"[R{state.round}] resume: {self.state_path} "
                f"(findings={len(state.findings)}, reason={state.completion_reason})"
            )
            if self.force:
                state.completion_reason = None
            self._apply_overrides(state)
        else:
            goals = normalize_goals(self._goals_arg)
            wall: float | None
            if self._wall_arg is not None:
                wall = float(self._wall_arg)
            elif goals:
                # Goals will stop the loop; no need to invent a clock budget.
                wall = None
            else:
                # Nothing bounds the hunt, so bound it: one round.
                wall = 0.0
            state = new_state(
                self.target,
                goals,
                wall,
                float(self._idle_arg or 0.0),
                float(self._budget_arg or 0.0),
                model_tiers=self._model_tiers or {},
                started_at=self.clock(),
            )
        if not state.started_at:
            state.started_at = self.clock()
        return state

    def _apply_overrides(self, state: HuntState) -> HuntState:
        """Apply only the config the caller explicitly passed (None = keep)."""
        if self.target:
            state.target = self.target
        if self._goals_arg is not None:
            state.goals = normalize_goals(self._goals_arg)
        if self._wall_arg is not None:
            state.wall_seconds = float(self._wall_arg)
        if self._idle_arg is not None:
            state.idle_seconds = max(0.0, float(self._idle_arg))
        if self._budget_arg is not None:
            state.budget_usd = max(0.0, float(self._budget_arg))
        if self._model_tiers:
            state.model_tiers = dict(self._model_tiers)
        return state

    def _maybe_cap(self, state: HuntState) -> None:
        """Bound the pathological "no time, no goals, no max_rounds" call."""
        if (
            not self.max_rounds
            and state.wall_seconds is None
            and not normalize_goals(state.goals)
        ):
            self.max_rounds = _SAFETY_ROUNDS
            self._log(
                f"[R{state.round}] safety: no time budget, no goals and no max_rounds "
                f"— capping this run at {_SAFETY_ROUNDS} rounds"
            )

    # -- phases ----------------------------------------------------------- #
    def _round(self, state: HuntState) -> dict[str, Any]:
        r = int(state.round)
        stats: dict[str, Any] = {}

        candidates, tool_calls = self._hunter_phase(state)
        stats["tool_calls"] = tool_calls
        stats["candidates"] = len(candidates)
        self._log(
            f"[R{r}] hunter: {tool_calls} tool call(s), {len(candidates)} candidate(s)"
        )

        if candidates:
            stats.update(self._verifier_phase(state, candidates))
        else:
            stats.update({"checked": 0, "added": 0, "dupes": 0, "verified": 0})
            self._log(f"[R{r}] verify: nothing to check")

        stats["chains"] = self._chainer_phase(state)

        left = time_left(state, self.clock())
        left_s = "unlimited" if left == float("inf") else f"{left:.1f}s"
        self._log(
            f"[R{r}] round: findings={len(state.findings)} "
            f"verified={count_verified(state)} chains={len(state.chains)} "
            f"new={int(stats.get('added', 0) or 0) + int(stats.get('chains', 0) or 0)} "
            f"spent=${float(state.spent_usd or 0.0):.4f} "
            f"elapsed={elapsed_seconds(state, self.clock()):.1f}s left={left_s}"
        )
        return stats

    def _hunter_phase(self, state: HuntState) -> tuple[list[dict], int]:
        """HUNTER turn(s): returns (candidates, tool_call_count).

        The target is audited UNIT BY UNIT. A chunk small enough for the model's
        reliable tool-call window is the only configuration we have measured
        where ``report_finding`` is actually emitted on the default output
        budget; a whole-target prompt gets truncated before the call.
        """
        r = int(state.round)
        known = _known_titles(state)
        calls_total = 0
        candidates: list[dict] = []

        try:
            per_round = max(1, int(os.environ.get("HUNTEROS_CHUNKS_PER_ROUND", "3") or 3))
        except ValueError:
            per_round = 3

        chunks = iter_target_chunks(state.target, self.workdir)
        if chunks:
            n = len(chunks)
            start = int(getattr(state, "chunk_cursor", 0) or 0) % n
            picks = [(start + i) % n for i in range(min(per_round, n))]
            try:
                state.chunk_cursor = (start + len(picks)) % n
            except Exception:  # noqa: BLE001 - a frozen state must not stop the hunt
                pass
            units = [(i + 1, chunks[j][0], chunks[j][1]) for i, j in enumerate(picks)]
            if n > per_round:
                self._log(f"[R{r}] hunter: units {start + 1}..{start + len(picks)} of {n}")
        else:
            units = [(1, "", "")]

        for index, label, code in units:
            # A round cannot be interrupted, and unit-by-unit auditing can take
            # much longer than one whole-target turn. Stop mid-round once the wall
            # budget is gone, as long as this round already did some work (so a
            # zero-budget hunt still runs its single mandatory turn).
            has_wall = state.wall_seconds is not None and float(state.wall_seconds) > 0
            if calls_total and has_wall and self._time_exhausted(state):
                self._log(f"[R{r}] hunter: wall budget reached — stopping unit loop")
                break
            found, calls = self._audit_unit(state, known, label, code, index, len(units), r)
            candidates.extend(found)
            calls_total += calls

            # A unit can still be truncated (finish_reason=length) when the model
            # reasons unusually long for it — reasoning length is not proportional
            # to prompt size. One deterministic recovery: split the unit in half
            # and retry the halves, rather than guessing a smaller fixed size.
            if not found and not calls and code and len(code) > 700:
                # The unit text already carries its line-number gutter, so split
                # it by lines: every half keeps the original numbers verbatim.
                _lines = code.splitlines()
                if len(_lines) > 40:
                    _mid = len(_lines) // 2
                    halves = ["\n".join(_lines[:_mid]), "\n".join(_lines[_mid:])]
                else:
                    halves = []
                if len(halves) > 1:
                    self._log(
                        f"[R{r}] hunter: unit {index} yielded nothing — retrying as "
                        f"{len(halves)} smaller halves"
                    )
                    for h_i, half in enumerate(halves, 1):
                        f2, c2 = self._audit_unit(
                            state, known, f"{label}#h{h_i}", half, index, len(units), r
                        )
                        candidates.extend(f2)
                        calls_total += c2

        return candidates, calls_total

    def _audit_unit(
        self,
        state: HuntState,
        known: list[str],
        label: str,
        code: str,
        index: int,
        total: int,
        r: int,
    ) -> tuple[list[dict], int]:
        """One unit's HUNTER turn(s): returns (candidates, tool_call_count)."""
        calls_total = 0
        candidates: list[dict] = []
        user = (
            build_chunk_prompt(state, known, label, code, index=index, total=total)
            if code else
            build_hunter_prompt(state, known, workdir=self.workdir)
        )
        attempt = 0
        while True:
            try:
                text, calls, cost = self._ask_hunter(user)
            except Exception as exc:  # provider hiccup: keep the round
                self._log(
                    f"[R{r}] hunter: llm error {type(exc).__name__}: "
                    f"{_clip(str(exc))} — unit skipped"
                )
                break

            self._charge(state, cost)
            calls_total += len(calls)
            report_calls = [c for c in calls if _is_report_call(c.get("name"))]

            batch: list[dict] = []
            for call in report_calls:
                batch.extend(_candidates_from_args(call.get("arguments") or {}))

            if batch:
                candidates.extend(batch)
                break
            if report_calls:
                # The model DID call report_finding and had nothing to add.
                self._log(f"[R{r}] hunter: unit {index} clean (no new findings)")
                break
            if attempt >= MAX_HUNTER_RETRIES:
                break
            if not text.strip():
                self._log(f"[R{r}] hunter: unit {index} empty response — no retry")
                break

            attempt += 1
            self._log(
                f"[R{r}] hunter: unit {index} returned text but 0 report_finding "
                f"calls — retrying once with an explicit nudge"
            )
            user = (
                build_chunk_prompt(state, known, label, code, index=index,
                                   total=total, nudge=True)
                if code else
                build_hunter_prompt(state, known, workdir=self.workdir, nudge=True)
            )

        return candidates, calls_total

    def _ask_hunter(self, user: str) -> tuple[str, list[dict], float]:
        """One hunter turn: tool-calling when it works, JSON text when it does not.

        Reasoning models on this provider spend the entire output budget on
        ``reasoning_content`` and finish with ``finish_reason=length`` before the
        tool call is emitted, so a tools-only path silently yields nothing. When
        the tool turn produces no call we make ONE more attempt asking for a bare
        JSON object; the deterministic verifier gates whatever comes back.
        """
        mode = (os.environ.get("HUNTEROS_HUNTER_MODE") or "auto").strip().lower()
        complete_with_tools = getattr(self.llm, "complete_with_tools", None)

        text, calls, cost = "", [], 0.0
        # Adaptive: once a tool turn comes back empty we stop paying for it. Some
        # providers/reasoning models never reach the tool call and only answer in
        # JSON text, so round 2 onward goes straight to the JSON turn.
        if mode in ("auto", "tools") and callable(complete_with_tools) and self._tools_work:
            resp = complete_with_tools(HUNTER_SYSTEM, user, [dict(t) for t in HUNTER_TOOLS])
            text, calls, cost = _norm_response(resp)
            if not calls and text.strip():
                calls = _json_calls_from_text(text)
            if not calls:
                # Deterministic enforcement: with tool_choice=required the API
                # cannot return a text-only turn, so the model must call the tool.
                # This is what makes tool-calling reliable on this provider.
                try:
                    resp2 = complete_with_tools(
                        HUNTER_SYSTEM, user, [dict(t) for t in HUNTER_TOOLS],
                        tool_choice="required",
                    )
                except TypeError:
                    resp2 = None
                if resp2 is not None:
                    text2, calls2, cost2 = _norm_response(resp2)
                    cost += cost2
                    if calls2:
                        calls = calls2
                        text = text2 or text
            if not calls:
                self._tools_work = False

        if not calls and mode in ("auto", "json"):
            raw = str(self.llm.complete(HUNTER_SYSTEM + _JSON_STRICT, user) or "")
            if raw.strip():
                text = text or raw
                calls = _json_calls_from_text(raw)
        return (text, calls, cost)

    def _verifier_phase(self, state: HuntState, candidates: list[dict]) -> dict[str, int]:
        r = int(state.round)
        ctx = self._ctx(state, "verifier")
        checked = added = dupes = verified = rejected = errored = 0

        for cand in candidates:
            claim = _claim_from_candidate(cand, state)
            if not claim["title"]:
                rejected += 1
                continue
            checked += 1
            try:
                verdict = (
                    _call2(self.verify_claim, claim, ctx)
                    if self.verify_claim is not None
                    else {"status": "unverified", "note": "no verify_claim injected"}
                )
            except Exception as exc:
                errored += 1
                verdict = {
                    "status": "unverified",
                    "error": f"{type(exc).__name__}: {exc}"[:_LOG_LIMIT],
                }
            rec, was_added = _apply_verdict(state, claim, verdict)
            if not was_added:
                dupes += 1
                continue
            added += 1
            if is_verified(rec):
                verified += 1
            else:
                rejected += 1

        tail = f", {errored} error(s)" if errored else ""
        self._log(
            f"[R{r}] verify: {checked} checked -> {verified} verified, "
            f"{rejected} rejected, {added} new, {dupes} dup{tail}"
        )
        return {
            "checked": checked,
            "added": added,
            "dupes": dupes,
            "verified": verified,
            "rejected": rejected,
            "errors": errored,
        }

    def _chainer_phase(self, state: HuntState) -> int:
        r = int(state.round)
        if self.chainer is None:
            self._log(f"[R{r}] chain: skipped (no chainer injected)")
            return 0
        verified_findings = [
            dict(f) for f in state.findings if isinstance(f, dict) and is_verified(f)
        ]
        if not verified_findings:
            self._log(f"[R{r}] chain: skipped (0 verified findings)")
            return 0
        ctx = self._ctx(state, "chainer")
        try:
            built = _call2(self.chainer, verified_findings, ctx)
        except Exception as exc:
            self._log(
                f"[R{r}] chain: chainer error {type(exc).__name__}: {_clip(str(exc))}"
            )
            return 0
        if isinstance(built, dict):
            built = [built]
        if not isinstance(built, (list, tuple)):
            self._log(f"[R{r}] chain: chainer returned {type(built).__name__}, ignored")
            return 0

        added = 0
        for chain in built:
            if isinstance(chain, dict) and add_chain(state, chain):
                added += 1
        self._log(
            f"[R{r}] chain: {added} new chain(s) from {len(verified_findings)} "
            f"verified finding(s), {len(state.chains)} total"
        )
        return added

    # -- stop conditions --------------------------------------------------- #
    def _pre_stop(self, state: HuntState) -> str | None:
        if state.completion_reason and not self.force:
            return str(state.completion_reason)
        ok, _why = goals_met(state)
        if ok:
            return "goals-met"
        if self._round_errors >= _MAX_ROUND_ERRORS:
            return "error"
        if self._ran <= 0:
            # Do-while: every invocation runs at least one round.
            return None
        if self.no_progress_rounds and self._idle_streak >= self.no_progress_rounds:
            return "no-progress"
        if self._budget_exhausted(state):
            return "budget-exhausted"
        if self._time_exhausted(state):
            return "time-expired"
        if self.max_rounds and self._ran >= self.max_rounds:
            return "max-rounds"
        return None

    def _post_stop(self, state: HuntState) -> str | None:
        ok, _why = goals_met(state)
        if ok:  # goals outrank time
            return "goals-met"
        if self._round_errors >= _MAX_ROUND_ERRORS:
            return "error"
        if self.no_progress_rounds and self._idle_streak >= self.no_progress_rounds:
            return "no-progress"
        if self._budget_exhausted(state):
            return "budget-exhausted"
        if self._time_exhausted(state):
            return "time-expired"
        if self.max_rounds and self._ran >= self.max_rounds:
            return "max-rounds"
        return None

    def _time_exhausted(self, state: HuntState) -> bool:
        return time_left(state, self.clock()) <= 0.0

    def _budget_exhausted(self, state: HuntState) -> bool:
        budget = _num(state.budget_usd, 0.0)
        return budget > 0 and _num(state.spent_usd, 0.0) >= budget

    # -- helpers ---------------------------------------------------------- #
    def _verifier_call(self, system: str, user: str) -> str:
        """LLM access for the adversarial (L2) reviewer.

        L2 is the layer that turns an anchored claim into a verified one. If the
        loop never supplies an LLM here, L2 degrades to UNREVIEWED and nothing can
        ever reach "verified" — which is exactly what happened before this hook.
        The verifier tier is preferred when the client exposes a provider.
        """
        provider = getattr(self.llm, "provider", None)
        if provider is not None and not self._verifier_llm_failed:
            try:
                sibling = type(self.llm)(provider, tier="verifier")
                return sibling.complete(system, user)
            except Exception as exc:  # noqa: BLE001
                self._verifier_llm_failed = True
                self._log(f"verifier tier unavailable ({type(exc).__name__}) — "
                          f"falling back to the hunter model")
        return self.llm.complete(system, user)

    def _ctx(self, state: HuntState, tier: str) -> dict[str, Any]:
        # ``target_root`` is what the deterministic layer reads to resolve a cited
        # file:line. Without it L1 has no tree to search and every finding is
        # refuted no matter how well anchored it is.
        root = state.target or str(self.workdir)
        return {
            "target": state.target,
            "target_root": root,
            "round": int(state.round),
            "workdir": str(self.workdir),
            "evidence_root": str(
                Path(str(self.state_path)).parent / "evidence"
            ),
            "call_llm": self._verifier_call,
            "state": state,
            "state_path": str(self.state_path),
            "llm": self.llm,
            "log": self._log,
            "tier": (state.model_tiers or {}).get(tier, tier),
            "findings": [dict(f) for f in state.findings if isinstance(f, dict)],
            "titles": _known_titles(state),
        }

    def _charge(self, state: HuntState, cost: Any) -> None:
        amount = _num(cost, 0.0)
        if amount > 0:
            state.spent_usd = round(_num(state.spent_usd, 0.0) + amount, 6)

    def _print_stop(self, state: HuntState) -> None:
        ok, why = goals_met(state)
        detail = why if ok else why
        self._log(
            f"[R{state.round}] stop: {state.completion_reason or 'done'} "
            f"({detail}) — findings={len(state.findings)} "
            f"verified={count_verified(state)} chains={len(state.chains)} "
            f"spent=${_num(state.spent_usd, 0.0):.4f} "
            f"elapsed={elapsed_seconds(state, self.clock()):.1f}s"
        )

    def _log(self, message: str) -> None:
        try:
            self.log(message)
        except Exception:  # a broken logger must not kill a hunt
            pass


# --------------------------------------------------------------------------- #
# module-level entry points
# --------------------------------------------------------------------------- #
def run_hunt(llm: Any, verify_claim: Callable | None, **kwargs: Any) -> HuntState:
    """``HuntLoop(llm, verify_claim, **kwargs).run()`` — the llm-first entry."""
    return HuntLoop(llm, verify_claim, **kwargs).run()


def run_loop(target: str, llm: Any, verify_claim: Callable | None, **kwargs: Any) -> HuntState:
    """``HuntLoop(llm, verify_claim, target=..., **kwargs).run()`` — target-first."""
    kwargs.setdefault("target", target)
    return HuntLoop(llm, verify_claim, **kwargs).run()


def run(*args: Any, **kwargs: Any) -> HuntState:
    """Convenience dispatcher for both argument orders.

    ``run(target, llm, verify_claim, ...)`` and ``run(llm, verify_claim, ...)``
    both work; the first argument's type selects the interpretation.
    """
    if len(args) >= 3 and isinstance(args[0], (str, os.PathLike)):
        return run_loop(*args, **kwargs)
    return run_hunt(*args, **kwargs)


def _apply_verdict(
    state: HuntState, claim: dict, verdict: Any
) -> tuple[dict, bool]:
    """Merge the verify result over the claim and store it (de-duplicated)."""
    if verdict is None:
        verdict = {"status": "unverified"}
    elif isinstance(verdict, bool):
        verdict = {"status": "verified" if verdict else "unverified"}
    elif not isinstance(verdict, dict):
        verdict = {"status": "unverified", "verifier_note": _clip(str(verdict))}

    rec = dict(claim)
    rec.update(verdict)
    for key in ("l1", "l2", "l3", "l4"):
        rec.setdefault(key, None)
    if not rec.get("status"):
        rec["status"] = "unverified"
    if not rec.get("round"):
        rec["round"] = int(state.round or 0)
    added = add_finding(state, rec)
    return (rec, added)


def _known_titles(state: HuntState, limit: int = 200) -> list[str]:
    titles = []
    for finding in state.findings[-limit:]:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "").strip()
        if title:
            titles.append(title)
    return titles


def _num(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _clip(text: str, limit: int = _LOG_LIMIT) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _print_flush(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------- #
# optional CLI (needs the in-repo verify layer + provider router)
# --------------------------------------------------------------------------- #
def _default_llm() -> Any:
    """Best-effort adapter onto the in-repo provider router; None if absent."""
    try:
        from hunter.llm.router import ProviderRouter  # type: ignore
    except Exception:
        return None
    for factory in ("from_config", "build", "default", "from_env"):
        fn = getattr(ProviderRouter, factory, None)
        if callable(fn):
            try:
                return fn()
            except Exception:
                continue
    try:
        return ProviderRouter()
    except Exception:
        return None


def _default_verify() -> Callable | None:
    """Best-effort lookup of the 4-layer verify entry point."""
    for module_name, attr in (
        ("hunter.verify", "verify_claim"),
        ("hunter.verify.l1_deterministic", "verify_claim"),
    ):
        try:
            module = __import__(module_name, fromlist=[attr])
        except Exception:
            continue
        fn = getattr(module, attr, None)
        if callable(fn):
            return fn
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="loop_v3",
        description="Run the 3-phase hunt loop against a target directory or URL.",
    )
    parser.add_argument("target", help="target directory or URL")
    parser.add_argument("--state", default=None, help="hunt_state.json path")
    parser.add_argument("--workdir", default=None, help="working directory for file access")
    parser.add_argument("--goals", default="", help="e.g. verified-min:2,findings-min:5")
    parser.add_argument("--time", type=float, default=None, help="total wall seconds")
    parser.add_argument("--idle", type=float, default=None, help="seconds between rounds")
    parser.add_argument("--budget", type=float, default=None, help="USD budget (0=unlimited)")
    parser.add_argument("--rounds", type=int, default=0, help="max rounds this run (0=unbounded)")
    args = parser.parse_args(argv)

    goals: dict[str, int] = {}
    for chunk in (args.goals or "").split(","):
        if ":" in chunk:
            key, _, val = chunk.partition(":")
            try:
                goals[key.strip()] = int(float(val.strip()))
            except ValueError:
                continue
        elif chunk.strip():
            goals[chunk.strip()] = 1

    llm = _default_llm()
    verify_claim = _default_verify()
    if llm is None or verify_claim is None:
        print(
            "loop_v3: no CLI wiring available in this environment "
            f"(llm={'ok' if llm else 'missing'}, verify={'ok' if verify_claim else 'missing'}).\n"
            "Use the API instead: HuntLoop(llm=<client>, verify_claim=<fn>, target=...).run()",
            file=sys.stderr,
        )
        return 2

    state = HuntLoop(
        llm,
        verify_claim,
        target=args.target,
        goals=goals or None,
        wall_seconds=args.time,
        idle_seconds=args.idle,
        budget_usd=args.budget,
        state_path=args.state,
        workdir=args.workdir,
        max_rounds=args.rounds,
    ).run()
    print(json.dumps(state.to_dict(), indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())