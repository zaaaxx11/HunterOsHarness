#!/usr/bin/env python3
"""
HUNT — session adapter (orchestrator-owned glue).

Wires together, without either side importing the other directly:
    CLI shell  (A)  ->  HuntSession  ->  command registry (C)
                              |
                              +-> engine loop_v3 (D)
                              +-> verification layers (B, via ORCHESTRATOR)

The session object is the *only* mutable state the chat surface sees.
It owns the HuntState on disk and exposes the attribute surface that
the slash-command layer was specified against.
"""
from __future__ import annotations

import json, os, threading, time, uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional

HUNT_HOME = Path(os.path.expanduser("~/.hunter"))
SESSIONS  = HUNT_HOME / "sessions"
STEPFUN   = "devora-01/stepfun/stepfun-5-preview"

MODELS    = [
    STEPFUN,
    "devora-01/deepseek/deepseek-v4-flash",
    "devora-01/deepseek/deepseek-v4-pro",
]

#: Every tier defaults to StepFun: it is the model that reliably emits
#: report_finding on the default output budget here.
DEFAULT_TIERS = {
    "hunter":       STEPFUN,
    "verifier":     STEPFUN,
    "chainer":      STEPFUN,
    "orchestrator": STEPFUN,
}

PRESETS = {
    "balanced":  {k: STEPFUN for k in DEFAULT_TIERS},
    "aggressive": {k: STEPFUN for k in DEFAULT_TIERS},
    "cheap":     {k: STEPFUN for k in DEFAULT_TIERS},
}


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s)[:48].strip("-") or "session"


@dataclass
class HuntSession:
    # ---- identity -------------------------------------------------------
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = "untitled"
    target: str = ""
    created_at: float = field(default_factory=time.time)

    # ---- hunt parameters (command layer reads/writes these) --------------
    goals: dict = field(default_factory=lambda: {"findings-min": 5})
    wall_seconds: int = 6 * 3600
    idle_seconds: int = 15
    budget: float = 0.0            # 0 == unlimited
    model_tiers: dict = field(default_factory=lambda: dict(DEFAULT_TIERS))

    # ---- live state -----------------------------------------------------
    round: int = 0
    findings: list = field(default_factory=list)
    running: bool = False
    completion_reason: Optional[str] = None
    log_lines: list = field(default_factory=list)

    # ---- injected collaborators (set by the shell) ----------------------
    _engine: Any = None            # loop_v3.run_hunt callable
    _chat: Any = None              # callable(text)->str  plain chat
    _verify: Any = None            # callable(claim, ctx)->dict
    _thread: Any = None
    _stop_flag: bool = False

    # =====================================================================
    # config surface used by /model /set /config /cost /stats
    # =====================================================================
    @property
    def available_models(self) -> list:
        """Models the loaded config names, plus the curated defaults.

        The bare constant was misleading: /model offered two ids while the
        provider was configured with others. Read the live config first.
        """
        out: list[str] = []
        try:
            from hunter.llm.config import load_config

            blocks = getattr(load_config(), "model_tiers", None)
            if isinstance(blocks, dict):
                for _tier, block in blocks.items():
                    model = (block.get("model") if isinstance(block, dict)
                             else getattr(block, "model", None))
                    if model and str(model) not in out:
                        out.append(str(model))
        except Exception:  # noqa: BLE001 - a broken config must not break /model
            pass
        for model in MODELS:
            if model not in out:
                out.append(model)
        return out

    @property
    def skills(self) -> list:
        d = Path(os.path.expanduser("~/.hermes/skills"))
        try:
            return sorted(p.name for p in d.iterdir() if p.is_dir())[:64]
        except Exception:
            return []

    @property
    def tools(self) -> list:
        return ["read_file", "search_files", "write_file", "terminal",
                "web_search", "web_extract", "report_finding", "chain_findings"]

    def set_preset(self, name: str) -> bool:
        if name not in PRESETS:
            return False
        self.model_tiers = dict(PRESETS[name])
        return True

    # =====================================================================
    # persistence
    # =====================================================================
    def _path(self) -> Path:
        return SESSIONS / f"{_slug(self.name or self.id)}.json"

    def save(self) -> str:
        SESSIONS.mkdir(parents=True, exist_ok=True)
        p = self._path()
        tmp = p.with_suffix(".tmp")
        data = asdict(self)
        # drop non-serialisable injected collaborators
        for k in list(data):
            if k.startswith("_") or k == "log_lines":
                data.pop(k, None)
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, p)
        self.log(f"saved -> {p}")
        return str(p)

    @classmethod
    def load(cls, key: str) -> "HuntSession":
        p = SESSIONS / f"{_slug(key)}.json"
        if not p.is_file():
            p = SESSIONS / f"{key}.json"
        d = json.loads(p.read_text())
        s = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        return s

    @staticmethod
    def list_sessions() -> list:
        out = []
        if not SESSIONS.is_dir():
            return out
        for f in sorted(SESSIONS.glob("*.json")):
            try:
                d = json.loads(f.read_text())
                out.append({
                    "id": d.get("id", f.stem), "name": d.get("name", f.stem),
                    "target": d.get("target", ""), "round": d.get("round", 0),
                    "findings": len(d.get("findings", [])),
                    "verified": sum(1 for x in d.get("findings", []) if x.get("status") == "verified"),
                    "running": d.get("running", False),
                    "age_s": int(time.time() - d.get("created_at", time.time())),
                })
            except Exception:
                continue
        return out

    # =====================================================================
    # lifecycle
    # =====================================================================
    def log(self, line: str) -> None:
        self.log_lines.append(line)
        if len(self.log_lines) > 5000:
            del self.log_lines[:1000]

    def start(self, goals: Optional[dict] = None) -> None:
        if goals:
            self.goals = goals
        if self.running:
            self.log("already running"); return
        self.running = True
        self._stop_flag = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.log(f"hunt started: target={self.target} goals={self.goals}")

    def _run(self) -> None:
        try:
            if callable(self._engine):
                self._engine(self)          # the engine drives rounds + state
        except Exception as e:              # never let a hunt kill the shell
            self.log(f"[error] engine: {type(e).__name__}: {e}")
        finally:
            self.running = False

    def stop(self) -> None:
        self._stop_flag = True
        self.running = False
        self.save()

    def chat(self, text: str) -> str:
        if callable(self._chat):
            return self._chat(text)
        return f"(no chat backend wired) echo: {text}"

    # =====================================================================
    # view helpers for /status /findings
    # =====================================================================
    def status_line(self) -> str:
        left = max(0, int(self.wall_seconds - (time.time() - self.created_at)))
        return (f"round={self.round} findings={len(self.findings)} "
                f"verified={sum(1 for f in self.findings if f.get('status')=='verified')} "
                f"time_left={left}s running={self.running}")


# ---------------------------------------------------------------------------
# orchestrator-side verification hook
# ---------------------------------------------------------------------------
def make_verify_hook(verify_pkg: Any, target: str) -> Callable[[dict, dict], dict]:
    """Returns a verify_claim(claim, ctx) callable bound to the repo's verify pkg."""
    def _hook(claim: dict, ctx: dict) -> dict:
        ctx = dict(ctx or {})
        ctx.setdefault("target_root", target)
        try:
            return verify_pkg.verify_claim(claim, ctx)
        except Exception as e:
            claim = dict(claim)
            claim["status"] = "claim"
            claim["l4"] = {"error": f"{type(e).__name__}: {e}"}
            return claim
    return _hook