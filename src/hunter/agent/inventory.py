"""Runtime capability inventory — which audit binaries exist on THIS machine.

``inventory_binaries`` is a passive read: ``shutil.which`` over the pinned
15-binary list (which is already Windows-aware via PATHEXT) — no shell-outs,
no network, nothing executed. The agent tool wraps it with a run-scoped cache
(``ctx.state["runtime_inventory"]``) so ``which`` runs at most once per run.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Callable
from typing import Any

__all__ = ["INVENTORY_BINARIES", "inventory_binaries"]

# Pinned tuple (M8 F1) — order is part of the contract.
INVENTORY_BINARIES: tuple[str, ...] = (
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


def inventory_binaries(
    *,
    which_fn: Callable[[str], str | None] | None = None,
    platform_name: str = sys.platform,
) -> dict[str, Any]:
    """``{"available": {name: path}, "missing": [names], "platform": str}``.

    ``which_fn`` defaults to ``shutil.which`` resolved at CALL time (so tests
    can monkeypatch ``hunter.agent.inventory.shutil.which``); the pinned
    binary order is preserved in both ``available`` (insertion order) and
    ``missing``.
    """
    lookup = shutil.which if which_fn is None else which_fn
    available: dict[str, str] = {}
    missing: list[str] = []
    for name in INVENTORY_BINARIES:
        try:
            path = lookup(name)
        except Exception:  # noqa: BLE001 — a broken which must not crash the read
            path = None
        if path:
            available[name] = str(path)
        else:
            missing.append(name)
    return {"available": available, "missing": missing, "platform": platform_name}
