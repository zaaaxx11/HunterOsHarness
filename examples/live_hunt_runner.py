#!/usr/bin/env python3
"""Live hunt: loop_v4 + a direct OpenAI-compatible provider (customin / mistral).

Target: /tmp/hunt-target-pv (PracticeVault server.py — 9 planted vulns).

Usage:
  PROVIDER=customin python3 run_live_hunt2.py [seconds]
  PROVIDER=mistral  python3 run_live_hunt2.py [seconds]
"""

import json
import os
import shutil
import ssl
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, "/tmp/hunteros-clone/src")
from hunter.workflow.loop_v4 import HuntLoopV4, LANE_SOULS

# ---- provider registry (base_url, api_key, model) ---------------------------
PROVIDERS = {
    "customin": ("https://api.customin.biz.id/v1",
                 "sk-AtxGXe0mY9EqQBBML4mCZi3PH5y2NnYa",  # replaced below at runtime
                 "deepseek-v4-flash"),
    "mistral": ("https://api.mistral.ai/v1", "", "ministral-14b-2512"),
}


def _load_keys():
    """Read provider keys straight from the Hermes config (source of truth)."""
    import yaml
    cfg = yaml.safe_load(Path(os.path.expanduser("~/.hermes/config.yaml")).read_text())
    out = {}
    for p in (cfg.get("custom_providers") or []):
        if isinstance(p, dict) and p.get("name"):
            out[p["name"].lower()] = (p.get("base_url"), p.get("api_key"),
                                      list((p.get("models") or {}).keys()))
    return out


KEYS = _load_keys()


def _pick_model(name, wanted):
    info = KEYS.get(name)
    if not info:
        return wanted
    models = info[2] or []
    if wanted in models:
        return wanted
    for pref in ("flash", "small", "mini", "lite"):
        for m in models:
            if pref in m.lower():
                return m
    return models[0] if models else wanted


class OpenAICompatLLM:
    """Direct OpenAI-compatible client with retries — no hunter provider plumbing."""

    def __init__(self, name, model=None, timeout=180):
        info = KEYS.get(name)
        if not info:
            raise RuntimeError(f"provider {name} not found in hermes config")
        self.base, self.key = info[0], info[1]
        self.model = model or _pick_model(name, "deepseek-v4-flash")
        self.name = name
        self.timeout = timeout
        self.calls = 0
        self.t0 = time.time()
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _post(self, payload):
        req = urllib.request.Request(
            f"{self.base}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as r:
                    return json.loads(r.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")[:200]
                print(f"    [{self.name}] HTTP {e.code}: {body}", flush=True)
                if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(2 ** attempt * 3)
                    continue
                return {"error": body}
            except Exception as e:
                print(f"    [{self.name}] {type(e).__name__}: {e}", flush=True)
                if attempt < 2:
                    time.sleep(2 ** attempt * 3)
                    continue
                return {"error": str(e)}
        return {"error": "exhausted retries"}

    def _turn(self, system, user, tools=None, tool_choice=None):
        self.calls += 1
        payload = {
            "model": self.model,
            "max_tokens": 6000,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        if tools:
            payload["tools"] = tools
            if tool_choice:
                payload["tool_choice"] = tool_choice
        dt = time.time() - self.t0
        print(f"    [{self.name}#{self.calls} @{dt:.0f}s] {len(user)}ch "
              f"tools={len(tools) if tools else 0} choice={tool_choice}", flush=True)
        d = self._post(payload)
        if "choices" not in d:
            print(f"    [{self.name}#{self.calls}] ERR {str(d)[:150]}", flush=True)
            return None
        ch = d["choices"][0]
        msg = ch.get("message") or {}
        print(f"    [{self.name}#{self.calls}] finish={ch.get('finish_reason')} "
              f"tool_calls={len(msg.get('tool_calls') or [])}", flush=True)
        return msg

    def complete(self, system, user):
        msg = self._turn(system, user)
        return (msg or {}).get("content") or ""

    def complete_with_tools(self, system, user, tools, tool_choice=None):
        msg = self._turn(system, user, tools=tools, tool_choice=tool_choice)
        if msg is None:
            return {"text": "", "tool_calls": [], "cost": 0.0}
        calls = []
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            calls.append({"name": fn.get("name", ""), "arguments": args or {}})
        return {"text": msg.get("content") or "", "tool_calls": calls, "cost": 0.0}


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
    provider = os.environ.get("PROVIDER", "customin")
    target = "/tmp/hunt-target-pv"
    workdir = Path("/tmp/hunt-live-ws")
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    llm = OpenAICompatLLM(provider)

    print("=== LIVE HUNT ===")
    print(f"provider: {llm.name} / {llm.model}")
    print(f"target  : {target}")
    print(f"budget  : {seconds}s")
    print(f"lanes   : {', '.join(LANE_SOULS)}")
    print()

    loop = HuntLoopV4(
        llm=llm, verify_claim=None, target=target,
        wall_seconds=seconds, idle_seconds=10, budget_usd=0.0,
        workdir=workdir, log=lambda m: print(m, flush=True),
    )
    state = loop.run()

    print("\n" + "=" * 60)
    print("HUNT SUMMARY")
    print("=" * 60)
    print(f"  provider    : {llm.name}/{llm.model}")
    print(f"  cycles      : {state.round}")
    print(f"  llm calls   : {llm.calls}")
    print(f"  findings    : {len(state.findings)}")
    print(f"  stop reason : {state.completion_reason}")

    by = {}
    for f in state.findings:
        if isinstance(f, dict):
            by[f.get("status", "?")] = by.get(f.get("status", "?"), 0) + 1
    print(f"  by status   : {by}")

    print("\n  FINDINGS:")
    for f in state.findings:
        if not isinstance(f, dict):
            continue
        print(f"    - [{f.get('status','?'):10s}] {str(f.get('title',''))[:72]}")
        print(f"        sev={f.get('severity','?')} lane={f.get('source_lane','?')} "
              f"anchor={f.get('file_line') or (str(f.get('file',''))+':'+str(f.get('line','')))}")

    out = Path("/tmp/hunt-live-result.json")
    out.write_text(json.dumps(state.to_dict(), indent=2, default=str))
    print(f"\n  state -> {out}")


if __name__ == "__main__":
    raise SystemExit(main())
