"""M8 F1 — ``runtime_inventory`` tool and ``hunter.agent.inventory`` (test-first).

The tool is ``danger="none"`` / ``min_tier="basic"``: a passive capability
read that caches per run and never shells out. ``shutil.which`` is monkeypatched
at the inventory module so the count seam works regardless of how the handler
passes ``which_fn`` through.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from hunter.agent.inventory import INVENTORY_BINARIES
from hunter.agent.tools import build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

PINNED_15 = (
    "curl",
    "wget",
    "nmap",
    "sqlmap",
    "nuclei",
    "ffuf",
    "dig",
    "nslookup",
    "whois",
    "whatweb",
    "gobuster",
    "masscan",
    "testssl",
    "openssl",
    "httpx",
)
# R2-B B3 heavy opt-in tail (append-only, sorted): the first 15 never move.
PINNED_HEAVY_SORTED = ("anvil", "cast", "slither")
# Offensive toolchain tail (append-only, sorted within the group): the
# compile/test half of Foundry plus the bare Solidity compiler. Appended
# after the R2-B tail so the append-only contract still holds end to end.
PINNED_TOOLCHAIN_SORTED = ("forge", "solc")
PINNED_BINARIES = PINNED_15 + PINNED_HEAVY_SORTED + PINNED_TOOLCHAIN_SORTED


@pytest.fixture()
def env(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)
    events: list[tuple[str, dict[str, Any]]] = []
    ctx = ToolContext(
        run_id="R-INVENTORY",
        ledger=ledger,
        http=http,
        scope=scope,
        target_url="http://127.0.0.1/",
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"tier": "basic"},
    )
    try:
        yield ctx, events
    finally:
        http.close()
        ledger.close()


def test_inventory_pinned_binary_list():
    # R2-B append-only: pinned 18 = original 15 first + sorted heavy tail.
    assert INVENTORY_BINARIES == PINNED_BINARIES
    assert len(INVENTORY_BINARIES) == 20
    assert INVENTORY_BINARIES[:15] == PINNED_15
    assert INVENTORY_BINARIES[15:] == PINNED_HEAVY_SORTED + PINNED_TOOLCHAIN_SORTED
    # Sortedness is per-group, not across the whole tail: the R2-B group and
    # the toolchain group are each sorted, but "slither" > "forge" so the
    # concatenation is not. Asserting the whole tail is sorted would force a
    # reorder that breaks the append-only contract.
    assert tuple(sorted(PINNED_HEAVY_SORTED)) == PINNED_HEAVY_SORTED
    assert tuple(sorted(PINNED_TOOLCHAIN_SORTED)) == PINNED_TOOLCHAIN_SORTED


def test_runtime_inventory_tool_returns_model_json(env, monkeypatch):
    ctx, events = env
    monkeypatch.setattr(
        "hunter.agent.inventory.shutil.which",
        lambda name: f"C:/fake-bin/{name}.exe",
    )
    outcome = build_registry("basic").dispatch("runtime_inventory", {}, ctx)
    assert outcome.ok is True, outcome.result_for_model
    payload = json.loads(outcome.result_for_model)
    assert set(payload) == {"available", "missing", "platform"}
    assert payload["platform"] == sys.platform
    assert set(payload["available"]) == set(PINNED_BINARIES)
    assert payload["available"]["nmap"] == "C:/fake-bin/nmap.exe"
    assert payload["missing"] == []
    assert any(
        kind == "engine_event"
        and item.get("tool") == "runtime_inventory"
        and item.get("available_count") == len(PINNED_BINARIES)
        for kind, item in events
    )


def test_inventory_cached_and_which_seamed(env, monkeypatch):
    ctx, _events = env
    calls: list[str] = []

    def counting_which(name: str) -> str | None:
        calls.append(name)
        return None if name == "masscan" else f"C:/fake-bin/{name}.exe"

    monkeypatch.setattr("hunter.agent.inventory.shutil.which", counting_which)
    registry = build_registry("basic")
    first = registry.dispatch("runtime_inventory", {}, ctx)
    second = registry.dispatch("runtime_inventory", {}, ctx)
    assert first.ok is True and second.ok is True
    # the run-scoped cache means which_fn ran exactly once over all binaries.
    # Only the inventory's own calls are counted here: build_registry also
    # resolves the toolchain binaries (forge/cast/slither/anvil/solc) through
    # toolchain._resolve, which is a separate PATH scan by design.
    inventory_calls = [c for c in calls if c in PINNED_BINARIES]
    assert inventory_calls == list(PINNED_BINARIES)
    assert json.loads(first.result_for_model)["missing"] == ["masscan"]
    assert second.result_for_model == first.result_for_model
