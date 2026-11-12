"""Shared test helpers (import as ``from _support import write_poc``).

These live beside the tests, not only in conftest.py, because pytest does not
re-export conftest helpers as importable module attributes.
"""
from __future__ import annotations

from pathlib import Path


def write_poc(tmp_path, name: str = "poc.py", *, url: str = "http://127.0.0.1:1/",
              method: str = "GET", status: int = 200) -> str:
    """Write a minimal, runnable PoC artifact and return its path.

    The claim gate refuses CANDIDATE -> VERIFIED without a ``poc_path`` (see
    ``hunter/kernel/claimgate.py`` — "Evidence or Nothing"). That column is
    append-only, so the artifact must exist BEFORE ``create_finding``.

    A test that promotes a claim without an artifact is asserting a transition
    the product deliberately forbids.
    """
    pocs = Path(tmp_path) / "pocs"
    pocs.mkdir(parents=True, exist_ok=True)
    poc = pocs / name
    poc.write_text(
        "\n".join([
            "#!/usr/bin/env python3",
            '"""Test PoC artifact — proof-of-reproduction record."""',
            "import urllib.request",
            "",
            f"URL = {url!r}",
            f"METHOD = {method!r}",
            "EXPECT_STATUS = " + repr(status),
            "",
            "",
            "def replay() -> int:",
            "    req = urllib.request.Request(URL, method=METHOD)",
            "    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310",
            "        return resp.status",
            "",
            "",
            "if __name__ == '__main__':",
            "    raise SystemExit(0 if replay() == EXPECT_STATUS else 1)",
            "",
        ]),
        encoding="utf-8",
    )
    return str(poc)


def replay_evidence(ledger, run_id: str, finding_id: str, *,
                    url: str = "http://127.0.0.1:1/search?q=canary",
                    method: str = "GET", status: int = 200) -> str:
    """Bind a replay-flagged http_exchange for ``finding_id`` (RULE-E2)."""
    return ledger.add_evidence(run_id, "http_exchange", {
        "method": method,
        "url": url,
        "status": status,
        "replay": True,
        "finding_id": finding_id,
    })
