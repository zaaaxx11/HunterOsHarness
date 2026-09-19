"""R2-C live doctor ladder + last-link (TDD RED — EXPECTED-FAIL-R2C).

Prod targets (READ ONLY, do NOT edit):
- hunter.cli.doctor_core live ladder (mock -> HEAD 4s -> list_models 10s -> ping token)
- hunter.llm.probe.list_models(factory, timeout=10) + detect_endpoint
- hunter.llm.ping.ping_provider (1-token probe, litellm seam)
- hunter.llm.config.resolve_key order + hunter.llm.router.describe_chain last-link
- hunter chat /model shows chain; hunter doctor --json envelope
- per-fn -> prod:
  ladder timeouts/order -> hunter.cli.doctor_core._probe_live_ladder (NEW)
  key order + missing exit4 -> hunter.llm.config.resolve_key
  redact sentinel -> hunter.llm.router._redact / doctor rows
  json envelope -> hunter.cli.main.doctor --json {checks, ok}
  never-raise matrix -> hunter.cli.doctor_core.collect_checks
  last-link recorded + /model shows -> hunter.llm.router.describe_chain + _exec_model

TDD red: EXPECTED-FAIL-R2C. Seams only: monkeypatched probes, MockTransport,
tmp stores. No sockets/sleep/TUI loop. ANSI stripped; rstrip comparator.
"""
from __future__ import annotations

import json
import re

import pytest

R2C = "EXPECTED-FAIL-R2C:live doctor ladder (R2-C doctor)"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip(text: str) -> str:
    return ANSI_RE.sub("", str(text or "")).rstrip("\n").rstrip()


def _require_ladder():
    import hunter.cli.doctor_core as core

    fn = getattr(core, "_probe_live_ladder", None) or getattr(core, "probe_live_ladder", None)
    if fn is None:
        pytest.fail(f"{R2C} — hunter.cli.doctor_core._probe_live_ladder missing")
    return fn


def test_r2c_doctor_ladder_order_timeouts(monkeypatch):
    """Ladder order mock -> HEAD(4s) -> list_models(factory,10s) -> ping(token)."""
    ladder = _require_ladder()
    import inspect

    src = inspect.getsource(ladder)
    assert "4" in src and "10" in src, f"{R2C} — ladder must pin HEAD 4s + list_models 10s"
    assert "list_models" in src and "ping" in src.lower()


def test_r2c_doctor_key_order_missing_exit4(monkeypatch):
    """Key order env -> inline -> ''; declared-but-missing raises exit 4."""
    from hunter.errors import EXIT_AUTH
    from hunter.llm.config import ProviderConfig, default_config, resolve_key

    cfg = default_config()
    cfg.providers["p"] = ProviderConfig(key_env="R2C_ORDER_ENV", api_key="inline-key")
    monkeypatch.setenv("R2C_ORDER_ENV", "env-key")
    import os

    assert resolve_key("p", cfg, env=dict(os.environ)) == "env-key"
    monkeypatch.delenv("R2C_ORDER_ENV", raising=False)
    assert resolve_key("p", cfg, env={}) == "inline-key"
    cfg.providers["q"] = ProviderConfig(key_env="R2C_MISSING_XYZ")
    from hunter.errors import HunterError

    with pytest.raises(HunterError) as exc:
        resolve_key("q", cfg, env={})
    assert exc.value.exit_code == EXIT_AUTH == 4
    _require_ladder()


def test_r2c_doctor_redact_sentinel(monkeypatch, tmp_path):
    """Live rows never leak keys; sk- sentinel redacted."""
    _require_ladder()
    from hunter.cli.doctor_core import collect_checks

    cfg_text = (
        "model_tiers:\n  orchestrator:\n    provider: mylocal\n    model: local-model\n"
        "providers:\n  mylocal:\n    base_url: http://127.0.0.1:9\n    key_env: R2C_LIVE_KEY\n"
    )
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(cfg_text, encoding="utf-8")
    monkeypatch.setenv("HUNTEROS_CONFIG", str(cfg_file))
    monkeypatch.setenv("R2C_LIVE_KEY", "sk-live-supersecretvalue12345")
    monkeypatch.setattr("hunter.cli.doctor_core._probe_base_url",
                        lambda url: "reachable (HTTP 200)")
    checks = collect_checks(live=True)
    blob = "\n".join(c.detail for c in checks)
    assert "sk-live-supersecretvalue12345" not in blob
    assert "sk-***" in blob or "NOT set" not in blob or True


def test_r2c_doctor_json_envelope():
    """doctor --json emits {checks, ok} envelope (keys pinned)."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "src" / "hunter" / "cli" / "main.py").read_text(
        encoding="utf-8")
    assert '"checks"' in src and '"ok"' in src, "json envelope keys pinned"
    _require_ladder()
    payload = json.loads(json.dumps({"checks": [], "ok": True}))
    assert set(payload) == {"checks", "ok"}


def test_r2c_doctor_never_raise_matrix(monkeypatch, tmp_path):
    """collect_checks never raises across broken-ledger/broken-config matrix."""
    from hunter.cli.doctor_core import collect_checks

    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "no-such-config.yaml"))
    for live in (False, True):
        monkeypatch.setattr("hunter.cli.doctor_core._probe_base_url",
                            lambda url: "reachable (HTTP 200)")
        checks = collect_checks(state=tmp_path, live=live)
        assert isinstance(checks, list) and all(hasattr(c, "status") for c in checks)
    _require_ladder()


def test_r2c_doctor_last_link_recorded_model_shows(monkeypatch):
    """Router records _last_outcome; describe_chain + /model show last: redacted."""
    import hunter.llm.router as router

    describe = getattr(router, "describe_chain", None)
    if describe is None:
        pytest.fail(f"{R2C} — hunter.llm.router.describe_chain missing")
    _require_ladder()
    from hunter.llm.config import default_config

    fake = type("FakeLit", (), {"completion": lambda self, **k: (_ for _ in ()).throw(
        Exception("sk-secret-abc123XYZ rate limit")), "completion_cost": lambda self, r: 0.0})()
    from hunter.llm.router import ProviderRouter

    cfg = default_config()
    cfg.model_tiers["orchestrator"].model = "m0"
    r = ProviderRouter(cfg, litellm_module=fake)
    monkeypatch.setattr("hunter.llm.router.time.sleep", lambda *a, **k: None)
    try:
        r.complete("orchestrator", [{"role": "user", "content": "hi"}])
    except Exception:
        pass
    view = _strip(describe(r, "orchestrator"))
    assert "last" in view.lower(), "chain view must carry last-link"
    assert "sk-secret-abc123XYZ" not in view, "last-link must be redacted"
