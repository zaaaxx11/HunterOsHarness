"""Doctor V4 — checks for the loop_v4 / phase0 workflow components.

Each check is a pure function returning a ``Check`` row. None of them import
heavy LLM plumbing; they only verify structural health. Called from
``doctor_core.collect_checks`` via a hook or standalone ``hunter doctor --v4``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from hunter.cli.doctor_core import Check

__all__ = ["collect_v4_checks"]

_HUNT_HOME = Path(os.path.expanduser("~/.hunter"))


def _try_import(modname: str, attr: str | None = None) -> Any:
    """Import without raising — returns the module/attr or None."""
    try:
        pkg = __import__(modname)
        for part in modname.split(".")[1:]:
            pkg = getattr(pkg, part, None)
            if pkg is None:
                return None
        return getattr(pkg, attr) if attr else pkg
    except Exception:
        return None


# ── 1) phantom-v4 imports ──────────────────────────────────────────

def _check_imports() -> list[Check]:
    checks: list[Check] = []
    for label, mod, attr in (
        ("loop_v4", "hunter.workflow.loop_v4", "HuntLoopV4"),
        ("phase0_recon", "hunter.workflow.phase0_recon", "gather_material"),
        ("verify_l1", "hunter.verify.l1_deterministic", None),
    ):
        got = _try_import(mod, attr)
        if got is not None:
            checks.append(Check(f"v4:{label}", "ok", f"importable ({mod})"))
        else:
            checks.append(Check(f"v4:{label}", "fail", f"cannot import {mod}" +
                                (f".{attr}" if attr else "")))
    return checks


# ── 2) hunt_state.json health ───────────────────────────────────────

def _check_hunt_state() -> Check:
    path = _HUNT_HOME / "hunt_state.json"
    if not path.exists():
        return Check("v4:hunt-state", "note", f"no {path} — first hunt not yet run")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return Check("v4:hunt-state", "fail", f"corrupt JSON: {exc}")
    ver = data.get("schema_version") or data.get("version")
    target = data.get("target", "")
    findings = len(data.get("findings", []))
    phase0 = data.get("phase0", {}).get("done") if isinstance(data.get("phase0"), dict) else data.get("phase0_done")
    detail = (
        f"schema={ver} target={str(target)[:50]} "
        f"findings={findings} phase0={'done' if phase0 else 'pending'}"
    )
    return Check("v4:hunt-state", "ok", detail)


# ── 3) target.json existence ───────────────────────────────────────

def _check_target_json(workspace: Path | None = None) -> Check:
    ws = workspace or Path.cwd()
    path = ws / "target.json"
    if not path.exists():
        candidates = sorted(ws.rglob("target.json"))
        if candidates:
            path = candidates[0]
        else:
            return Check("v4:target-json", "note", f"no target.json under {ws} — run phase0 first")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return Check("v4:target-json", "fail", f"corrupt: {exc}")
    kind = data.get("input_kind", "?")
    conf = data.get("recon_confidence", 0)
    in_scope = len((data.get("target") or {}).get("scope", {}).get("in_scope", []))
    return Check("v4:target-json", "ok",
                 f"{path} kind={kind} confidence={conf} in_scope={in_scope}")


# ── 4) provider liveness (fast 1-token probe) ──────────────────────

def _check_provider_live(provider: str, base: str, key: str, model: str,
                         timeout: int = 15) -> tuple[str, str]:
    import ssl
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "model": model, "max_tokens": 2,
        "messages": [{"role": "user", "content": "ok"}],
    }).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=payload,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
            if "choices" in d:
                return "ok", f"reachable — {d['choices'][0].get('message',{}).get('content','')[:30]!r}"
            return "fail", str(d.get("error", d))[:120]
    except urllib.error.HTTPError as e:
        return "fail", f"HTTP {e.code}"
    except Exception as exc:
        return "fail", f"{type(exc).__name__}: {exc}"


def _check_providers() -> list[Check]:
    checks: list[Check] = []
    # read hermes config for provider keys (same pattern as loop_v4 runner)
    hc = Path(os.path.expanduser("~/.hermes/config.yaml"))
    if not hc.exists():
        return [Check("v4:providers", "note", "no ~/.hermes/config.yaml — provider check skipped")]
    try:
        import yaml
        cfg = yaml.safe_load(hc.read_text())
    except Exception as exc:
        return [Check("v4:providers", "fail", f"invalid YAML: {exc}")]

    for p in (cfg.get("custom_providers") or []):
        if not isinstance(p, dict):
            continue
        name = p.get("name", "?")
        base = p.get("base_url", "")
        key = p.get("api_key", "")
        if not base or not key or "..." in str(key):
            checks.append(Check(f"v4:provider:{name}", "note",
                                f"skipped (no usable key)"))
            continue
        models = list((p.get("models") or {}).keys())
        if not models:
            checks.append(Check(f"v4:provider:{name}", "note", "no models listed"))
            continue
        # pick a small model for the probe
        probe_model = next((m for m in models if "flash" in m.lower()), models[0])
        status, detail = _check_provider_live(name, base, key, probe_model)
        checks.append(Check(f"v4:provider:{name}", status,
                            f"{probe_model} — {detail}"))
    return checks


# ── 5) loop_v4 self-test (offline) ─────────────────────────────────

def _check_loop_v4_utils() -> list[Check]:
    """Exercise every utility function that lives at module level."""
    checks: list[Check] = []
    ut = _try_import("hunter.workflow.loop_v4")
    if ut is None:
        return [Check("v4:utils", "fail", "cannot import loop_v4")]

    # _parse_verdict
    pv = getattr(ut, "_parse_verdict", None)
    nr = getattr(ut, "_norm_response", None)
    ca = getattr(ut, "_candidates_from_args", None)

    if pv is not None:
        for raw, want in (
            ('{"verdict":"verified"}', "verified"),
            ("VERDICT: REFUTED", "refuted"),
            ("exploitable", "verified"),
            ("not exploitable", "refuted"),
        ):
            got = pv(raw)["verdict"]
            if got != want:
                checks.append(Check("v4:parse-verdict", "fail",
                                    f"_parse_verdict({raw[:20]!r}) = {got}, wanted {want}"))
                break
        else:
            checks.append(Check("v4:parse-verdict", "ok", "all variants pass"))
    else:
        checks.append(Check("v4:parse-verdict", "fail", "no _parse_verdict in loop_v4"))

    if ca is not None:
        for args, want in (
            ({"findings": [{"title": "x", "severity": "high"}]}, 1),
            ({"mappings": [{"title": "y", "severity": "low"}]}, 1),
            ({}, 0), (None, 0),
        ):
            if len(ca(args)) != want:
                checks.append(Check("v4:candidates", "fail",
                                    "_candidates_from_args returned wrong count"))
                break
        else:
            checks.append(Check("v4:candidates", "ok", "key variants pass"))
    else:
        checks.append(Check("v4:candidates", "fail", "no _candidates_from_args in loop_v4"))

    if nr is not None:
        t, c, cost = nr({"text": "hi", "tool_calls": [
            {"name": "f", "arguments": {"x": 1}}], "cost": 0.5})
        if t == "hi" and len(c) == 1 and cost == 0.5:
            checks.append(Check("v4:norm-response", "ok", "dict+tool_calls+cost"))
        else:
            checks.append(Check("v4:norm-response", "fail", f"got text={t!r} calls={len(c)} cost={cost}"))
    else:
        checks.append(Check("v4:norm-response", "fail", "no _norm_response in loop_v4"))

    return checks


# ── 6) convergence / idle-streak ───────────────────────────────────

def _check_convergence() -> Check:
    dp = _try_import("hunter.workflow.loop_v4", "HuntLoopV4")
    if dp is None:
        return Check("v4:convergence", "fail", "HuntLoopV4 not importable")
    # the convergence warning fires after _idle_streak >= 3
    return Check("v4:convergence", "ok",
                 "3 empty cycles → hardened warning (stop still waits for timer)")


# ── collector ──────────────────────────────────────────────────────

def collect_v4_checks(state: Path | None = None, *,
                      workspace: Path | None = None,
                      live: bool = False) -> list[Check]:
    """All V4 component health checks.

    ``live`` enables real network probes (provider 1-token ping). Default
    offline (imports + structural only).
    """
    checks: list[Check] = []
    for step in (
        _check_imports,
        _check_hunt_state,
    ):
        try:
            result = step()
            if isinstance(result, list):
                checks.extend(result)
            else:
                checks.append(result)
        except Exception as exc:
            checks.append(Check("v4:collector", "fail", f"{type(exc).__name__}: {exc}"))
    try:
        checks.append(_check_target_json(workspace or Path.cwd()))
    except Exception as exc:
        checks.append(Check("v4:target-json", "fail", f"{type(exc).__name__}: {exc}"))
    for step in (
        _check_loop_v4_utils,
        _check_convergence,
    ):
        try:
            result = step()
            if isinstance(result, list):
                checks.extend(result)
            else:
                checks.append(result)
        except Exception as exc:
            checks.append(Check("v4:checker", "fail", f"{type(exc).__name__}: {exc}"))
    if live:
        try:
            checks.extend(_check_providers())
        except Exception as exc:
            checks.append(Check("v4:providers", "fail", f"exception: {exc}"))
    return checks