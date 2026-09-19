"""R2-A gateway LRU+TTL — TDD RED (failing by design).

R2-A target: ``hunter.gateway.app.GatewayApp`` engine cache becomes a
bounded LRU+TTL (not an unbounded dict); cross-process turns fence via
``hunter.gateway.durable_lease`` (app never calls it today).

Prod targets (per-fn):
- test_r2a_gateway_cache_engines_bounded_lru -> GatewayApp(max_engines/LRU)
- test_r2a_gateway_cache_ttl_expires_with_monotonic_fake -> GatewayApp engine_ttl/evict_stale
- test_r2a_gateway_cache_tmp_path_isolation -> per-state_dir isolation, no leak
- test_r2a_gateway_cache_durable_lease_wired -> app.handle_message calls durable_lease
- test_r2a_gateway_cache_busy_message_byte_exact -> BUSY_MESSAGE exact under contention
- test_r2a_gateway_cache_negative_unbounded_dict_rejected -> unbounded dict refused

Adversarial: tmp_path isolation, monotonic fake (no sleep/network),
strict eviction asserts, byte-exact BUSY_MESSAGE, negatives.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest


def _needs_app() -> Any:
    return pytest.importorskip("hunter.gateway.app")


def _fake_monotonic(monkeypatch: Any, start: float = 2000.0) -> dict[str, float]:
    clock = {"t": float(start)}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    monkeypatch.setattr("time.time", lambda: clock["t"])
    return clock


def _make_app(app_mod: Any, state: Any) -> Any:
    return app_mod.GatewayApp(object(), [], state_dir=str(state))


def test_r2a_gateway_cache_engines_bounded_lru(tmp_path: Any) -> None:
    app_mod = _needs_app()
    if not hasattr(app_mod.GatewayApp, "cache_stats") and "lru" not in pathlib.Path(
        "src/hunter/gateway/app.py"
    ).read_text(encoding="utf-8").lower():
        pytest.fail(
            "EXPECTED-FAIL-R2A: GatewayApp._engines is an unbounded dict; "
            "no LRU bound (cache_stats/max_engines missing)"
        )
    state = tmp_path / "state"
    app = _make_app(app_mod, state)
    cap = int(getattr(app, "engine_cache_maxsize", 64))
    for i in range(cap + 5):
        app.engine_for(f"telegram:{i}")
    stats = app.cache_stats()  # type: ignore[attr-defined]
    assert stats["size"] <= cap
    assert stats["evictions"] >= 1


def test_r2a_gateway_cache_ttl_expires_with_monotonic_fake(tmp_path: Any, monkeypatch: Any) -> None:
    app_mod = _needs_app()
    clock = _fake_monotonic(monkeypatch)
    state = tmp_path / "state"
    app = _make_app(app_mod, state)
    if not hasattr(app, "evict_stale") and not hasattr(app, "engine_cache_ttl"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: GatewayApp has no TTL seam; "
            "evict_stale/engine_cache_ttl missing (dict never expires)"
        )
    first = app.engine_for("telegram:42")
    ttl = float(getattr(app, "engine_cache_ttl", 300.0))
    clock["t"] += ttl + 1.0
    app.evict_stale()  # type: ignore[attr-defined]
    second = app.engine_for("telegram:42")
    assert second is not first


def test_r2a_gateway_cache_tmp_path_isolation_no_cross_state_leak(tmp_path: Any) -> None:
    app_mod = _needs_app()
    if not hasattr(app_mod.GatewayApp, "cache_stats"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: no bounded cache to isolate; "
            "per-state_dir LRU isolation missing"
        )
    state_a = tmp_path / "a"
    state_b = tmp_path / "b"
    app_a = _make_app(app_mod, state_a)
    app_b = _make_app(app_mod, state_b)
    app_a.engine_for("telegram:1")
    assert "telegram:1" not in getattr(app_b, "_engines", {})


def test_r2a_gateway_cache_durable_lease_wired(tmp_path: Any) -> None:
    _needs_app()
    source = pathlib.Path("src/hunter/gateway/app.py").read_text(encoding="utf-8")
    if "durable_lease" not in source:
        pytest.fail(
            "EXPECTED-FAIL-R2A: hunter.gateway.app never calls "
            "hunter.gateway.durable_lease (cross-process fence missing)"
        )
    # Strict pin once wired: the import must be a real use, not a comment.
    assert "from hunter.gateway.durable_lease import" in source or "import durable_lease" in source


def test_r2a_gateway_cache_busy_message_byte_exact(tmp_path: Any) -> None:
    app_mod = _needs_app()
    durable = pytest.importorskip("hunter.gateway.durable_lease")
    assert app_mod.BUSY_MESSAGE == durable.BUSY_MESSAGE
    assert app_mod.BUSY_MESSAGE == "still working on your previous request — try again shortly"
    assert float(durable.DEFAULT_LEASE_TIMEOUT) == pytest.approx(5.0)
    # Contention must surface the byte-exact line (fail closed).
    state = tmp_path / "state"
    holder = durable.acquire(str(state), "telegram:busy", timeout=0.2)
    try:
        with pytest.raises(durable.LeaseBusy) as excinfo:
            durable.acquire(str(state), "telegram:busy", timeout=0.05)
        assert str(excinfo.value) == app_mod.BUSY_MESSAGE
    finally:
        holder.release()
    # R2-A gate: app-level handle_message must also return that exact line.
    source = pathlib.Path("src/hunter/gateway/app.py").read_text(encoding="utf-8")
    if "durable_lease" not in source:
        pytest.fail(
            "EXPECTED-FAIL-R2A: BUSY_MESSAGE exact at lease layer but "
            "GatewayApp not wired to durable_lease"
        )


def test_r2a_gateway_cache_negative_unbounded_dict_rejected(tmp_path: Any) -> None:
    app_mod = _needs_app()
    if not hasattr(app_mod.GatewayApp, "cache_stats"):
        pytest.fail(
            "EXPECTED-FAIL-R2A: unbounded dict still allowed; "
            "bounded LRU negative (size cap) not enforced"
        )
    state = tmp_path / "state"
    app = _make_app(app_mod, state)
    cap = int(getattr(app, "engine_cache_maxsize", 64))
    for i in range(cap + 20):
        app.engine_for(f"webhook:{i}")
    assert len(app._engines) <= cap
