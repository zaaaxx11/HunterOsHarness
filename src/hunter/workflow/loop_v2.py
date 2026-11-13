#!/usr/bin/env python3
"""
hunt_loop_v3.py — Direct provider.complete(), no AgentLoop.
Parse tool_calls manually. Simple, no nudging, no claim gates.
"""

import json, os, sys, time, uuid
from dataclasses import dataclass, field, asdict
from hunter.agent.soul import CORE_IDENTITY
from pathlib import Path
from typing import Any

# ── Core Finding ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    id: str = ""
    title: str = ""
    severity: str = "medium"
    status: str = "claim"       # claim → verified → refuted → chained
    description: str = ""
    evidence: str = ""
    poc: str = ""
    verifier_note: str = ""
    chain_from: list[str] = field(default_factory=list)
    round: int = 0

@dataclass
class HuntState:
    target: str = ""
    goals: dict = field(default_factory=lambda: {"findings-min": 5, "verified-min": 2})
    started_at: float = 0.0
    wall_seconds: float = 3600.0
    round: int = 0
    findings: list[dict] = field(default_factory=list)
    last_error: str = ""
    completed: bool = False
    completion_reason: str = ""

# ── Persistence ────────────────────────────────────────────────────────────

def load_state(path: str) -> HuntState:
    p = Path(path)
    if p.exists():
        try:
            d = json.loads(p.read_text())
            s = HuntState()
            for k, v in d.items():
                if hasattr(s, k): setattr(s, k, v)
            return s
        except: pass
    return HuntState()

def save_state(state: HuntState, path: str):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(state), indent=2, default=str))
    tmp.replace(p)

# ── Direct LLM call ────────────────────────────────────────────────────────

def call_llm(provider, messages: list, tool_schemas: list) -> dict:
    """Call provider.complete() and return parsed result."""
    turn = provider.complete("orchestrator", messages, tools=tool_schemas)
    findings = []
    for tc in turn.tool_calls:
        if tc.name in ("report_finding", "create_finding_request"):
            args = tc.arguments; import json as _j
            if isinstance(args, str):
                try: args = _j.loads(args)
                except: args = {}
            if not isinstance(args, dict): args = {}
            title = str(args.get("title") or "Bug found")[:200]
            sev = str(args.get("severity") or "medium")[:20]
            desc = str(args.get("description") or "")[:2000]
            findings.append(Finding(
                id="F-" + __import__("uuid").uuid4().hex[:8],
                title=title, severity=sev, description=desc,
            ))
    return {"text": turn.text or getattr(turn, "reasoning", "") or "",
            "tool_calls": len(turn.tool_calls),
            "findings": [asdict(f) for f in findings]}

# ── Tool schema ────────────────────────────────────────────────────────────

REPORT_FINDING_SCHEMA = [{
    "type": "function",
    "function": {
        "name": "report_finding",
        "description": "Report a security finding. Only 3 fields required: title, severity, description.",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short title"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "description": {"type": "string", "description": "What the bug is, file:line, impact, evidence"}
            },
            "required": ["title", "severity", "description"]
        }
    }
}]

FINISH_SCHEMA = [{
    "type": "function",
    "function": {
        "name": "finish_scan",
        "description": "End the audit. Call this after reporting all findings.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    }
}]

ALL_SCHEMAS = REPORT_FINDING_SCHEMA + FINISH_SCHEMA

# ── Read file helper ───────────────────────────────────────────────────────

def read_target(target: str) -> str:
    """Read target content. Supports files, dirs (list .sol files), and URLs (return as-is)."""
    if target.startswith("http"):
        return f"URL target: {target}"
    path = Path(target)
    if path.is_dir():
        sol_files = list(path.rglob("*.sol"))
        content = f"Directory: {target}\n\n"
        for sf in sol_files[:5]:
            try:
                content += f"--- {sf.name} ---\n{sf.read_text()[:3000]}\n\n"
            except: pass
        return content
    elif path.is_file():
        return path.read_text()
    return target

# ── Round runner ───────────────────────────────────────────────────────────

def run_round(state: HuntState, top_dir: str, provider) -> HuntState:
    rid = state.round + 1
    print(f"  [Round {rid}] scanning...", flush=True)

    logs = Path(top_dir) / "logs"; logs.mkdir(parents=True, exist_ok=True)

    # Phase 1: HUNTER
    target_content = read_target(state.target)
    context = f"Target: {state.target}\n\nContent:\n{target_content[:5000]}"
    if state.findings:
        prev = "\n".join(f"[{f['id']}] {f.get('status','claim')}: {f.get('title','')}"
                        for f in state.findings[-10:])
        context += f"\n\nPrevious findings:\n{prev}"

    hunter_msgs = [
        {"role": "system", "content": f"{CORE_IDENTITY}\n\nYou are the hunter in an authorized audit. Read the code. Report EVERY observation as a finding using report_finding — even informational ones. For code that is clean, report_finding with severity=info and title like: No critical bugs found. Then finish_scan."},
        {"role": "user", "content": context}
    ]

    result = call_llm(provider, hunter_msgs, ALL_SCHEMAS)
    # If model analyzed but didn't call tools, retry with forced instruction
    if result["tool_calls"] == 0 and result["text"]:
        hunter_msgs.append({"role": "assistant", "content": result["text"][:2000]})
        hunter_msgs.append({"role": "user", "content": "Now call report_finding for each bug found above. You MUST call the tool."})
        result = call_llm(provider, hunter_msgs, ALL_SCHEMAS)
    (logs / f"round{rid}_hunter.txt").write_text(
        f"turns=1 tool_calls={result['tool_calls']}\ntext={result['text'][:2000]}\n\nfindings={json.dumps(result['findings'],indent=1)}")

    for f in result["findings"]:
        f["round"] = rid
        f["status"] = "claim"
        state.findings.append(f)

    print(f"  [Round {rid}] hunter: {len(result['findings'])} claims, {result['tool_calls']} tool calls", flush=True)

    # Phase 2: VERIFIER (if there are unverified claims)
    unverified = [f for f in state.findings if f.get("status") == "claim"]
    if unverified:
        claims_text = "\n\n".join(
            f"CLAIM [{f['id']}]: {f.get('severity','medium')} — {f.get('title','')}\n"
            f"Description: {f.get('description','')[:500]}\n"
            f"Evidence: {f.get('evidence','')[:300]}"
            for f in unverified[-5:])

        verifier_msgs = [
            {"role": "system", "content": f"{CORE_IDENTITY}\n\nYou are the verifier in an authorized audit. For each claim: state VERIFIED (evidence exists, logic sound) or REFUTED (false positive, no evidence, wrong logic). Use report_finding with title='VERIFIED:<original>' or 'REFUTED:<original>' and description explaining WHY."},
            {"role": "user", "content": f"Verify these claims from the target {state.target}:\n\n{claims_text}"}
        ]

        vresult = call_llm(provider, verifier_msgs, ALL_SCHEMAS)
        (logs / f"round{rid}_verifier.txt").write_text(
            f"tool_calls={vresult['tool_calls']}\ntext={vresult['text'][:2000]}\n")

        # Mark claims based on verifier findings
        vtext = vresult["text"].lower()
        for f in unverified[-5:]:
            fid_lower = f["id"].lower()
            # Check if the verifier text mentions this finding
            desc_lower = f.get("description", "").lower()[:100]
            if fid_lower in vtext or desc_lower in vtext:
                if "verified" in vtext and "refuted" not in vtext:
                    f["status"] = "verified"
                    f["verifier_note"] = vresult["text"][:500]
                    print(f"    ✓ {f['id']}: verified", flush=True)
                elif "refut" in vtext or "false" in vtext:
                    f["status"] = "refuted"
                    f["verifier_note"] = vresult["text"][:500]
                    print(f"    ✗ {f['id']}: refuted", flush=True)

        print(f"  [Round {rid}] verifier: {vresult['tool_calls']} tool calls", flush=True)

    # Phase 3: CHAINER (if 2+ verified)
    verified = [f for f in state.findings if f.get("status") == "verified"]
    if len(verified) >= 2:
        vlist = "\n".join(f"[{f['id']}] ({f.get('severity','')}) {f.get('title','')}"
                         for f in verified)
        chainer_msgs = [
            {"role": "system", "content": "Exploit chainer. Build attack chains from verified findings. Use report_finding: title='CHAIN: X→Y', severity='high', description='Precondition from X enables Y. Impact: ...'. Then finish_scan."},
            {"role": "user", "content": f"Build chains from:\n\n{vlist}"}
        ]
        cresult = call_llm(provider, chainer_msgs, ALL_SCHEMAS)
        for f in cresult["findings"]:
            f["round"] = rid
            f["status"] = "chained"
            state.findings.append(f)
        (logs / f"round{rid}_chainer.txt").write_text(
            f"tool_calls={cresult['tool_calls']}\ntext={cresult['text'][:2000]}\nfindings={json.dumps(cresult['findings'],indent=1)}")
        print(f"  [Round {rid}] chainer: {len(cresult['findings'])} chains", flush=True)

    state.round = rid
    return state


def hunt_loop_v3(target: str, state_dir: str, time_budget: str = "6h", goals: str = "findings-min:5"):
    os.environ.setdefault("DEVORA_API_KEY", os.environ.get("DEVORA_API_KEY", ""))
    from hunter.llm.config import load_config
    from hunter.llm import provider_from_config as pfc

    wall_s = 0
    for part in time_budget.split():
        if part.endswith("h"): wall_s += float(part[:-1]) * 3600
        elif part.endswith("m"): wall_s += float(part[:-1]) * 60
        elif part.endswith("s"): wall_s += float(part[:-1])
    wall_s = wall_s or 21600

    goal_dict = {}
    for g in goals.split(","):
        if ":" in g:
            k, v = g.split(":", 1)
            goal_dict[k.strip()] = int(v.strip())

    sp = os.path.join(state_dir, "hunt_state.json")
    state = load_state(sp)
    if not state.target:
        state.target = target; state.goals = goal_dict
        state.wall_seconds = wall_s; state.started_at = time.time()

    cfg = load_config()
    provider = pfc(cfg)

    print(f"Hunt v3: {target}")
    print(f"  goals: {state.goals}  time: {wall_s}s  round: {state.round}")
    print(f"  findings: {len(state.findings)}")

    deadline = state.started_at + state.wall_seconds
    while time.time() < deadline and not state.completed:
        try:
            state = run_round(state, state_dir, provider)
            save_state(state, sp)
            total = len(state.findings)
            verified = sum(1 for f in state.findings if f.get("status") == "verified")
            print(f"  total: {total} findings ({verified} verified)", flush=True)
            if goal_dict.get("findings-min", 0) and total >= goal_dict["findings-min"]:
                state.completed = True; state.completion_reason = "goals-met"
                save_state(state, sp); print("GOALS MET"); break
        except KeyboardInterrupt:
            state.completion_reason = "stopped"; save_state(state, sp); break
        except Exception as e:
            state.last_error = str(e)[:500]; save_state(state, sp)
            print(f"  error: {e}"); time.sleep(5)

    if time.time() >= deadline:
        state.completed = True; state.completion_reason = "time-expired"
        save_state(state, sp); print("TIME EXPIRED")
    return state


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--state", required=True)
    ap.add_argument("--time", default="6h")
    ap.add_argument("--goals", default="findings-min:5,verified-min:2")
    args = ap.parse_args()
    hunt_loop_v3(args.target, args.state, args.time, args.goals)