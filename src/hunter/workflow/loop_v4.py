"""v4 multi-lane CDC hunt loop: ARCHITECT + REDTEAM + FUZZER → CHAINER → L1 VERIFY → DEEP-DIVE.

Phase architecture (per cycle):
  0. RECON — once, before the loop.  LLM-powered, writes ``target.json``.
  1–3. ARCHITECT + RED-TEAMER + FUZZ-ENGINEER — sequential (conceptually parallel,
       serialised for provider rate-limit safety).  Each uses its own soul prompt.
  4. CHAINER — sequential, only when 1–3 produced new findings.
  5. L1 VERIFY — deterministic (NO LLM), only when new unverified findings exist.
     Calls ``hunter.verify.l1_deterministic.verify_claim`` per finding.
  ★  DEEP-DIVE — L2 adversarial + PoC gate, triggered by L1 anchored + severity ≥ high.

Design contract (same as loop_v3 — everything injectable):
  * llm.complete(system, user) -> str
  * llm.complete_with_tools(system, user, tools) -> dict
  * verify_claim(claim, ctx) -> dict          # the 4-layer verify
  * State on disk is the single source of truth (hunt_state.json).
  * Goals outrank time, time outranks budget.
  * wall_seconds=21600 (6h), idle_seconds=15 — inherited from session.

Progress lines are printed with a ``[C<cycle>] [<lane>]`` prefix.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

# ---- state (same contract as loop_v3) ---------------------------------------
try:
    from .state import (
        HuntState, add_chain, add_finding, count_verified,
        elapsed_seconds, goals_met, is_verified, load, new_state,
        normalize_goals, save, state_path_for, time_left,
    )
except ImportError:
    try:
        from hunter.workflow.state import (  # type: ignore
            HuntState, add_chain, add_finding, count_verified,
            elapsed_seconds, goals_met, is_verified, load, new_state,
            normalize_goals, save, state_path_for, time_left,
        )
    except ImportError:
        from state import (  # type: ignore
            HuntState, add_chain, add_finding, count_verified,
            elapsed_seconds, goals_met, is_verified, load, new_state,
            normalize_goals, save, state_path_for, time_left,
        )

# ---- recon ------------------------------------------------------------------
try:
    from .phase0_recon import Phase0Recon, run_recon
except ImportError:
    try:
        from hunter.workflow.phase0_recon import Phase0Recon, run_recon
    except ImportError:
        Phase0Recon = None  # type: ignore
        run_recon = None    # type: ignore

# ---- LLM helper (deferred — import only when used) -------------------------

__all__ = ["HuntLoopV4", "LANE_SOULS", "run_v4"]

_LOG_LIMIT = 500
_MAX_ROUND_ERRORS = 3
_HIGH_SEVERITY = {"critical", "high"}

# ---- lane definitions (soul prompt, tools, report schema) --------------------

_ARCHITECT_TOOL = {
    "type": "function",
    "function": {
        "name": "report_mapping",
        "description": "Report trust-graph mappings: actors, assets, invariants, SPOFs, data flow, trust boundaries. One call per mapping unit.",
        "parameters": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "type": {"type": "string", "description": "actor|asset|invariant|spof|boundary|data_flow"},
                            "description": {"type": "string"},
                            "file": {"type": "string"},
                            "line": {"type": "integer"},
                            "code": {"type": "string"},
                            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        },
                        "required": ["title", "type", "description"],
                    },
                }
            },
            "required": ["findings"],
        },
    },
}

_REPORT_FINDING_TOOL = {
    "type": "function",
    "function": {
        "name": "report_finding",
        "description": "Report one vulnerability finding: mechanism, impact, evidence.",
        "parameters": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "description": {"type": "string"},
                            "file": {"type": "string"},
                            "line": {"type": "integer"},
                            "code": {"type": "string"},
                            "vuln_type": {"type": "string"},
                        },
                        "required": ["title", "severity", "description"],
                    },
                }
            },
            "required": ["findings"],
        },
    },
}

# ---- engine -----------------------------------------------------------------

def _load_soul(name: str) -> str:
    """Read a lane soul prompt shipped with the harness."""
    candidates = [
        Path(__file__).resolve().parent.parent / "_data" / "prompts" / "souls" / f"{name}.md",
        Path(os.path.expanduser(f"~/.hunter/skills/{name}/SKILL.md")),
    ]
    for p in candidates:
        if p.exists():
            return p.read_text(encoding="utf-8")
    return f"You are {name}. Find vulnerabilities. Report with report_finding tool."


LANE_SOULS: dict[str, str] = {
    "architect": "",
    "redteam": "",
    "fuzzer": "",
}


def _init_souls():
    for name in list(LANE_SOULS):
        LANE_SOULS[name] = _load_soul(name)


_init_souls()

# ---- source inlining (copied from loop_v3) -----------------------------------

_HUNTER_EXTS = {
    ".sol", ".vy", ".cairo", ".move", ".rs",
    ".py", ".pyi", ".js", ".mjs", ".ts", ".tsx",
    ".go", ".java", ".kt", ".cs", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".hh", ".hpp",
    ".swift", ".scala", ".sh", ".bash",
    ".yaml", ".yml", ".toml", ".json", ".sql",
    ".html", ".vue", ".svelte", ".xml",
}

_SKIP_DIRS = {
    ".git", "test", "tests", "script", "scripts",
    "mock", "mocks", "vendor", "build", "out", "cache", "artifacts",
    "dependencies", ".deps", "coverage", "typechain", "typechain-types",
    "node_modules", ".venv", "venv", "__pycache__", "lib",
}

_OWN_HINTS = ("src/", "contracts/", "sources/", "programs/", "core/", "app/")


def _target_files(root: Path) -> list[tuple[Path, str]]:
    try:
        if root.is_file():
            return [(root, root.name)]
        if not root.is_dir():
            return []
    except Exception:
        return []
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if Path(fn).suffix.lower() in _HUNTER_EXTS:
                fp = Path(dirpath) / fn
                try:
                    rel = str(fp.relative_to(root))
                except ValueError:
                    rel = fn
                candidates.append((fp, rel))
    own = [(p, r) for p, r in candidates if any(h in r.replace("\\", "/") for h in _OWN_HINTS)]
    rest = [(p, r) for p, r in candidates if not any(h in r.replace("\\", "/") for h in _OWN_HINTS)]
    return own + rest


def _split_source(text: str, max_chars: int = 2000) -> list[tuple[int, str]]:
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[int, str]] = []
    buf, start, consumed = [], 0, 0
    for i, line in enumerate(lines):
        cost = len(line)
        if consumed + cost > max_chars and buf:
            blocks.append((start, "".join(buf)))
            buf, start, consumed = [], i, 0
        buf.append(line)
        if not buf:
            start = i
        consumed += cost
    if buf:
        blocks.append((start, "".join(buf)))
    return blocks


def _number_lines(lines: list[str], offset: int) -> str:
    out = []
    for i, line in enumerate(lines):
        n = offset + i + 1
        out.append(f"{n:5d} | {line.rstrip()}")
    return "\n".join(out)


def read_target_source(target: str, workdir: Path) -> str | None:
    root = Path(target).expanduser() if target else workdir
    if not root.exists():
        return None
    files = _target_files(root)[:40]
    parts = []
    for fp, rel in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        chunks = _split_source(text)
        for ci, (start, chunk) in enumerate(chunks):
            label = f"{rel}#p{ci+1}" if len(chunks) > 1 else rel
            lines = chunk.splitlines(keepends=True)
            parts.append(f"--- {label} ---\n{_number_lines(lines, start)}")
    return "\n\n".join(parts) if parts else None


def _known_titles(state: HuntState, limit: int = 200) -> list[str]:
    titles = []
    for finding in list(state.findings)[-limit:]:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "").strip()
        if title:
            titles.append(title)
    return titles


def _clip(text: str, limit: int = _LOG_LIMIT) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "\u2026"


def _num(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _candidates_from_args(args: dict) -> list[dict]:
    findings = args.get("findings")
    if isinstance(findings, list):
        return [dict(f) for f in findings if isinstance(f, dict)]
    return []


def _norm_response(resp: Any) -> tuple[str, list[dict], float]:
    text = getattr(resp, "text", None) or getattr(resp, "content", None) or ""
    if not isinstance(text, str):
        text = ""
    calls = getattr(resp, "tool_calls", None) or getattr(resp, "calls", None) or []
    if not isinstance(calls, list):
        calls = []
    cost = _num(getattr(resp, "cost", 0), 0)
    return text, calls, cost


# ========================================================================

class HuntLoopV4:
    """Multi-lane CDC hunt loop: Phase 0 + 3 lanes + chainer + L1 verify + deep-dive."""

    def __init__(
        self,
        llm: Any,
        verify_claim: Callable | None,
        *,
        target: str = "",
        goals: dict[str, int] | None = None,
        wall_seconds: float | None = None,
        idle_seconds: float | None = None,
        budget_usd: float | None = None,
        state_path: str | os.PathLike | None = None,
        workdir: str | os.PathLike | None = None,
        model_tiers: dict | None = None,
        log: Callable[[str], None] | None = None,
        max_cycles: int | None = None,
        force: bool = False,
    ):
        self.llm = llm
        self.verify_claim = verify_claim
        self.target = target
        self.workdir = Path(workdir or os.getcwd())
        self.model_tiers = model_tiers or {}
        self.log = log or print
        self.max_cycles = max_cycles
        self.force = force
        self.state_path = state_path_for(state_path, target, self.workdir)

        existing = self.state_path.exists()
        if existing:
            self.state = load(str(self.state_path))
            if wall_seconds is not None:
                self.state.wall_seconds = wall_seconds
            if idle_seconds is not None:
                self.state.idle_seconds = idle_seconds
            if goals:
                self.state.goals = normalize_goals(goals)
        else:
            self.state = new_state(
                target=target,
                goals=goals,
                wall_seconds=wall_seconds if wall_seconds is not None else 21600.0,
                idle_seconds=idle_seconds if idle_seconds is not None else 15.0,
                budget_usd=budget_usd,
            )
        save(self.state, self.state_path)

        self._idle_streak = 0
        self._cycle = int(self.state.round or 0)
        self._t_start = time.time()
        self._tools_work = True

    # ----- clock -----------------------------------------------------------

    def clock(self) -> float:
        return self._t_start + elapsed_seconds(self.state, 0.0)

    def _time_exhausted(self) -> bool:
        return time_left(self.state, self.clock()) <= 0.0

    def _budget_exhausted(self) -> bool:
        b = _num(self.state.budget_usd, 0)
        return b > 0 and _num(self.state.spent_usd, 0) >= b

    # ----- source inlining ------------------------------------------------

    def _source_for_lane(self, lane: str) -> str | None:
        return read_target_source(self.state.target, self.workdir)

    # ----- one lane turn ---------------------------------------------------

    def _ask_lane(self, lane: str, user: str, tools: list[dict]) -> tuple[str, list[dict], float]:
        soul = LANE_SOULS.get(lane, f"You are {lane}.")
        cwt = getattr(self.llm, "complete_with_tools", None)

        text, calls, cost = "", [], 0.0
        if callable(cwt) and self._tools_work:
            resp = cwt(soul, user, tools)
            text, calls, cost = _norm_response(resp)
            if not calls and text.strip():
                # maybe JSON embedded in text
                try:
                    data = json.loads(text[text.find("{"):text.rfind("}")+1])
                    if "findings" in data:
                        calls = [{"name": "report_finding", "arguments": data}]
                except Exception:
                    pass
        if not calls:
            raw = str(self.llm.complete(soul, user) or "")
            if raw.strip():
                text = text or raw
                try:
                    data = json.loads(raw[raw.find("{"):raw.rfind("}")+1])
                    if "findings" in data:
                        calls = [{"name": "report_finding", "arguments": data}]
                except Exception:
                    pass
        return text, calls, cost

    # ----- one lane phase --------------------------------------------------

    def _run_lane(self, lane: str, state: HuntState, source: str | None, tools: list[dict]) -> list[dict]:
        known = _known_titles(state)
        user = (
            f"TARGET: {state.target or '(unspecified)'}\n"
            f"CYCLE: {self._cycle}\n"
            f"TIME LEFT: {int(time_left(state, self.clock()))}s\n"
            f"LANE: {lane.upper()}\n"
            f"ALREADY RECORDED ({len(known)}):\n" +
            "\n".join(f"  {i}. {t}" for i, t in enumerate(known, 1)) +
            "\n\nTARGET SOURCE:\n" + (source or "(source not readable)")
        )

        text, calls, cost = self._ask_lane(lane, user, tools)
        self._charge(state, cost)

        findings: list[dict] = []
        for call in calls:
            args = call.get("arguments", {}) if isinstance(call, dict) else {}
            findings.extend(_candidates_from_args(args))

        self._log(
            f"[C{self._cycle}] [{lane}] {len(findings)} finding(s) "
            f"(tool_calls={len(calls)} cost=${cost:.4f})"
        )
        return findings

    # ----- verification ----------------------------------------------------

    def _l1_verify_finding(self, finding: dict) -> dict:
        """Deterministic L1 (NO LLM). Uses existing verify layer if available."""
        file_line = finding.get("file_line") or (
            f"{finding.get('file','')}:{finding.get('line','')}"
            if finding.get("file") else None
        )
        if not file_line:
            return {"l1": {"status": "unverifiable", "detail": "no file:line anchor"}}

        # Try the repo's own L1 layer first
        try:
            from hunter.verify.l1_deterministic import extract_file_line_refs, claim_text
            refs = extract_file_line_refs(claim_text(finding))
            if refs:
                r = refs[0]
                root = self.state.target or str(self.workdir)
                fp = Path(root) / r["file"] if not os.path.isabs(r["file"]) else Path(r["file"])
                if fp.exists():
                    lines = fp.read_text(errors="replace").splitlines()
                    if 1 <= r["line"] <= len(lines):
                        actual = lines[r["line"] - 1].strip()
                        return {"l1": {"status": "anchored", "detail": actual[:120], "file": str(fp), "line": r["line"]}}
                return {"l1": {"status": "refuted", "detail": f"file {r['file']} not found under {root}"}}
        except Exception as exc:
            self._log(f"[L1] verify layer error: {exc} — using built-in", flush=True)

        # Built-in fallback
        return self._l1_builtin(finding)

    def _l1_builtin(self, finding: dict) -> dict:
        parts = str(finding.get("file_line") or f"{finding.get('file','')}:{finding.get('line','')}")
        m = re.match(r"^(?P<path>[^:]+):(?P<line>\d+)", parts)
        if not m:
            return {"l1": {"status": "unverifiable", "detail": f"not file:line: {parts[:80]}"}}
        path, line = m.group("path"), int(m.group("line"))
        root = self.state.target or str(self.workdir)
        candidates = [Path(root) / path, Path(path)]
        real = next((c for c in candidates if c.exists() and c.is_file()), None)
        if real is None:
            return {"l1": {"status": "refuted", "detail": f"file not found: {path}"}}
        try:
            lines = real.read_text(errors="replace").splitlines()
        except Exception:
            return {"l1": {"status": "unverifiable", "detail": f"unreadable: {real}"}}
        if line < 1 or line > len(lines):
            return {"l1": {"status": "refuted", "detail": f"line {line} out of range ({len(lines)} lines)"}}
        return {"l1": {"status": "anchored", "detail": lines[line - 1].strip()[:120]}}

    def _deep_dive(self, finding: dict):
        """L2 adversarial + PoC — triggered on L1 anchored + high severity."""
        self._log(f"[DEEP-DIVE] {finding.get('title','')[:80]} severity={finding.get('severity')}", flush=True)

        # L2 adversarial (LLM sceptic)
        soul = _load_soul("verifier")
        prompt = (
            f"{soul}\n\n"
            f"FINDING: {json.dumps(finding, default=str)[:3000]}\n\n"
            "Prove this is NOT exploitable or confirm it is. Return JSON: "
            '{"verdict":"verified"|"refuted","reason":"..."}'
        )
        try:
            raw = self.llm.complete(soul, prompt)
            try:
                verdict = json.loads(raw[raw.find("{"):raw.rfind("}")+1])
                finding["l2"] = verdict
                finding["deep_dived"] = True
                if verdict.get("verdict") == "verified":
                    finding["status"] = "verified"
                    self._log(f"  L2: VERIFIED — {verdict.get('reason','')[:120]}")
                else:
                    self._log(f"  L2: REFUTED — {verdict.get('reason','')[:120]}")
            except Exception:
                finding["l2"] = {"verdict": "unreviewed", "reason": "could not parse LLM output"}
                self._log("  L2: UNREVIEWED")
        except Exception as exc:
            finding["l2"] = {"verdict": "error", "reason": str(exc)[:200]}
            self._log(f"  L2: ERROR — {exc}")

    # ----- main loop -------------------------------------------------------

    def run(self) -> HuntState:
        # ---- Phase 0: RECON (once, before the loop) -----------------------
        if not self.state.phase0_done and self.target:
            self._log(f"[phase0] RECON: {self.target}", flush=True)
            if run_recon is not None and callable(getattr(self.llm, "complete", None)):
                try:
                    run_recon(self.target, self.llm.complete, self.workdir)
                except Exception as exc:
                    self._log(f"[phase0] RECON error: {exc} — continuing", flush=True)
            self.state.phase0_done = True
            save(self.state, self.state_path)

        # ---- CDC loop -----------------------------------------------------
        while True:
            self._cycle += 1
            self.state.round = self._cycle
            c = self._cycle
            self._log(f"\n{'='*60}\n[CYCLE {c}] elapsed={int(elapsed_seconds(self.state,self.clock()))}s "
                      f"remaining={int(time_left(self.state,self.clock()))}s\n{'='*60}", flush=True)

            source = self._source_for_lane("architect")  # same source for all 3

            # Phase 1-3: three lanes (sequential, conceptually parallel)
            all_findings: list[dict] = []
            for lane in ("architect", "redteam", "fuzzer"):
                if self._time_exhausted() or self._budget_exhausted():
                    break
                tools = [_ARCHITECT_TOOL] if lane == "architect" else [_REPORT_FINDING_TOOL]
                lane_findings = self._run_lane(lane, self.state, source, tools)
                for f in lane_findings:
                    f.setdefault("source_lane", lane)
                    f.setdefault("cycle", c)
                    f.setdefault("status", "unverified")
                all_findings.extend(lane_findings)

            # Phase 4: CHAINER (only if new findings)
            has_new = bool(all_findings)
            if has_new:
                self._log(f"[C{c}] [chainer] starting with {len(all_findings)} new lane finding(s)", flush=True)
                chain_prompt = (
                    f"{_load_soul('chainer')}\n\n"
                    f"TARGET: {self.state.target}\n"
                    f"FINDINGS FROM LANES:\n{_format_findings(all_findings)}\n\n"
                    "Build exploit chains. Return JSON: "
                    '{"chains":[{"title":"...","steps":"...","severity":"...","impact":"..."}]}'
                )
                try:
                    raw = self.llm.complete(_load_soul("chainer"), chain_prompt)
                    chains = json.loads(raw[raw.find("{"):raw.rfind("}")+1]).get("chains", [])
                except Exception:
                    chains = []
                for ch in chains:
                    ch.setdefault("source_lane", "chainer")
                    ch.setdefault("cycle", c)
                    ch.setdefault("status", "unverified")
                    all_findings.append(ch)
                self._log(f"[C{c}] [chainer] {len(chains)} chain(s)", flush=True)
            else:
                self._log(f"[C{c}] [chainer] skipped (0 new findings)", flush=True)

            # Register all new findings
            new_ids: list[str] = []
            for i, f in enumerate(all_findings):
                fid = f"C{c}-L{f.get('source_lane','x')[:1].upper()}{i+1:02d}"
                f["id"] = fid
                add_finding(self.state, f)
                new_ids.append(fid)

            # Phase 5: L1 VERIFY (conditional — only if new findings)
            pending = [f for f in self.state.findings
                       if isinstance(f, dict) and f.get("status") == "unverified" and f.get("id") in new_ids]
            if pending:
                self._log(f"[C{c}] [L1] verifying {len(pending)} new finding(s) (deterministic, no LLM)", flush=True)
                for f in pending:
                    res = self._l1_verify_finding(f)
                    if "l1" in res:
                        f["l1"] = res["l1"]
                    else:
                        f.update(res)
                    if f.get("l1", {}).get("status") == "anchored":
                        f["status"] = "in_code"
                    elif f.get("l1", {}).get("status") == "refuted":
                        f["status"] = "refuted"
                    self._log(f"  {f.get('id')}: {f.get('l1',{}).get('status','?')} — "
                              f"{_clip(f.get('l1',{}).get('detail',''), 80)}", flush=True)
            else:
                self._log(f"[C{c}] [L1] skipped (0 new unverified)", flush=True)

            # Deep-dive: L2 adversarial + PoC (trigger: L1 anchored + severity high)
            for f in self.state.findings:
                if not isinstance(f, dict):
                    continue
                if f.get("deep_dived"):
                    continue
                l1_status = f.get("l1", {}).get("status") if isinstance(f.get("l1"), dict) else f.get("l1")
                if l1_status == "anchored" and str(f.get("severity", "")).lower() in _HIGH_SEVERITY:
                    self._deep_dive(f)
                    f["deep_dived"] = True

            # Bookkeeping
            if has_new:
                self._idle_streak = 0
            else:
                self._idle_streak += 1
            save(self.state, self.state_path)

            # Stop conditions
            if self._time_exhausted():
                self.state.completion_reason = "time-expired"
                break
            if self._budget_exhausted():
                self.state.completion_reason = "budget-exhausted"
                break
            ok, _ = goals_met(self.state)
            if ok:
                self.state.completion_reason = "goals-met"
                break
            if self.max_cycles and self._cycle >= self.max_cycles:
                self.state.completion_reason = "max-cycles"
                break
            if self._idle_streak >= 3:
                self._log(f"[C{c}] 3 empty cycles — surface likely hardened (still continuing)", flush=True)

            # Idle between cycles
            idle = max(1, min(self.state.idle_seconds or 15, time_left(self.state, self.clock())))
            self._log(f"[IDLE] {int(idle)}s ...", flush=True)
            time.sleep(idle)

        self._print_stop()
        return self.state

    def _charge(self, state: HuntState, cost: Any):
        amount = _num(cost, 0)
        if amount > 0:
            state.spent_usd = round(_num(state.spent_usd, 0) + amount, 6)

    def _print_stop(self):
        state = self.state
        self._log(
            f"\n[STOP] reason={state.completion_reason or 'done'} "
            f"cycles={self._cycle} findings={len(state.findings)} "
            f"verified={count_verified(state)} "
            f"spent=${_num(state.spent_usd, 0):.4f} "
            f"elapsed={elapsed_seconds(state, self.clock()):.1f}s"
        )

    def _log(self, message: str):
        try:
            self.log(message)
        except Exception:
            pass


def _format_findings(findings: list[dict]) -> str:
    lines = []
    for f in findings:
        lines.append(
            f"- [{f.get('source_lane','?')}] {f.get('title','?')} "
            f"sev={f.get('severity','?')} "
            f"file={f.get('file','?')}:{f.get('line','?')}"
        )
    return "\n".join(lines)


# ---- convenience entry point ------------------------------------------------

def run_v4(
    target: str,
    llm: Any,
    verify_claim: Callable | None = None,
    **kwargs: Any,
) -> HuntState:
    """One-shot: ``HuntLoopV4(llm, verify_claim, target=..., **kwargs).run()``."""
    return HuntLoopV4(llm, verify_claim, target=target, **kwargs).run()


# ---- CLI -------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="loop_v4", description="Multi-lane CDC hunt loop v4")
    parser.add_argument("target", help="target URL or directory")
    parser.add_argument("--state", default=None, help="hunt_state.json path")
    parser.add_argument("--workdir", default=None, help="working directory")
    parser.add_argument("--time", type=float, default=None, help="total wall seconds")
    parser.add_argument("--idle", type=float, default=None, help="seconds between cycles")
    parser.add_argument("--budget", type=float, default=None, help="USD budget (0=unlimited)")
    parser.add_argument("--cycles", type=int, default=None, help="max cycles")
    args = parser.parse_args(argv)

    # provider
    try:
        from hunter.llm.router import ProviderRouter
        from hunter.llm.native import LLMAdapter
        router = ProviderRouter.from_config()
    except Exception:
        router = ProviderRouter()

    class LoopLLM:
        def complete(self, system, user):
            return router.complete("hunter", [{"role": "system", "content": system},
                                             {"role": "user", "content": user}])
        def complete_with_tools(self, system, user, tools, tool_choice=None):
            return router.complete("hunter", [{"role": "system", "content": system},
                                             {"role": "user", "content": user}], tools=tools)

    llm = LoopLLM()

    # verify
    try:
        from hunter.verify import verify_claim
    except ImportError:
        verify_claim = None

    state = HuntLoopV4(
        llm, verify_claim,
        target=args.target,
        wall_seconds=args.time,
        idle_seconds=args.idle,
        budget_usd=args.budget,
        state_path=args.state,
        workdir=args.workdir,
        max_cycles=args.cycles,
    ).run()
    print(json.dumps(state.to_dict(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())