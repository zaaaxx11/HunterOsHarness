"""V11 improvements — provider-fallback last-outcome + CORS probe regression tests.

Covers:
  1. ProviderRouter last-dial outcome must be SHARED across router instances
     (module-scoped registry) so the ``/model`` chain view (which builds a fresh
     router each call) actually reports a last-link outcome after a dial.
  2. The new deterministic ``cors-misconfig`` probe is registered, resolvable to
     the ``cors`` taxonomy klass, and replays through RECHECKS.
"""

from __future__ import annotations

import contextlib

from hunter.errors import HunterError
from hunter.llm.config import default_config
from hunter.llm.router import ProviderRouter, _LAST_OUTCOMES, describe_chain


class _FakeLiteLLM:
    def __init__(self, *, fail: bool) -> None:
        self.fail = fail

    def completion(self, **kwargs):
        if self.fail:
            raise RuntimeError("sk-sec...3XYZ rate limit exceeded")
        from types import SimpleNamespace

        msg = SimpleNamespace(content="ok", tool_calls=[])
        choice = SimpleNamespace(message=msg, finish_reason="stop")
        usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1)
        return SimpleNamespace(choices=[choice], usage=usage, model="m0")

    def completion_cost(self, response) -> float:
        return 0.0


def _fresh_router(cfg) -> ProviderRouter:
    router = ProviderRouter(cfg, litellm_module=_FakeLiteLLM(fail=True))
    return router


def test_last_outcome_shared_across_router_instances(monkeypatch):
    """After a failing dial, a SECOND fresh router must still see the outcome."""
    from hunter.llm.config import TierConfig

    cfg = default_config()
    cfg.model_tiers["orchestrator"] = TierConfig(provider="openai", model="gpt-4o", timeout=5)
    monkeypatch.setattr("hunter.llm.router.time.sleep", lambda *a, **k: None)

    r1 = _fresh_router(cfg)
    with contextlib.suppress(HunterError):
        r1.complete("orchestrator", [{"role": "user", "content": "hi"}])
    assert _LAST_OUTCOMES.get("orchestrator") is not None

    # Fresh instance (what /model does) — must inherit the outcome.
    r2 = _fresh_router(cfg)
    view = describe_chain(r2, "orchestrator")
    assert "last" in view.lower()
    assert "no attempts recorded yet" not in view, (
        "fresh router must fall back to module-scoped last outcome"
    )


def test_describe_chain_before_any_dial_says_no_attempts(monkeypatch):
    _LAST_OUTCOMES.clear()
    cfg = default_config()
    cfg.model_tiers["orchestrator"].model = "m0"
    monkeypatch.setattr("hunter.llm.router.time.sleep", lambda *a, **k: None)
    router = ProviderRouter(cfg, litellm_module=_FakeLiteLLM(fail=True))
    view = describe_chain(router, "orchestrator")
    assert "no attempts recorded yet" in view.lower()


def test_cors_misconfig_check_registered_and_typology():
    from hunter.engine.deterministic import probes
    from hunter.taxonomy import klass_for_check_id

    assert any(getattr(p, "CHECK_ID", None) == "cors-misconfig" for p in probes.PROBES)
    assert "cors-misconfig" in probes.CHECK_IDS
    assert probes.RECHECKS["cors-misconfig"] is not None
    assert klass_for_check_id("cors-misconfig") == "cors"
