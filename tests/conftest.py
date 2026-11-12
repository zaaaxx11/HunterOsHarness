"""Test-suite configuration and shared helpers.

The daemon-era tests under ``tests/archive_daemon_era/`` target an API that
was deliberately removed (see 990238b "purge: remove daemon"). They are kept
for reference but must not break collection of the live suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

collect_ignore = ["archive_daemon_era"]


def write_poc(tmp_path, name: str = "poc.py", *, url: str = "http://127.0.0.1:1/",
              method: str = "GET", status: int = 200) -> str:
    """Write a minimal, runnable PoC artifact and return its path.

    The claim gate refuses CANDIDATE -> VERIFIED without a ``poc_path`` (see
    ``hunter/kernel/claimgate.py`` — "Evidence or Nothing"). That column is
    append-only, so the artifact must exist BEFORE ``create_finding``; this
    helper makes that a one-liner instead of boilerplate in every test.

    A test that promotes a claim without calling this is asserting a transition
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
    """Bind a replay-flagged http_exchange for ``finding_id`` (RULE-E2).

    VERIFIED also needs the independent replay evidence; this is the other
    half of the contract and belongs next to ``write_poc``.
    """
    return ledger.add_evidence(run_id, "http_exchange", {
        "method": method,
        "url": url,
        "status": status,
        "replay": True,
        "finding_id": finding_id,
    })


def promote_to_verified(ledger, run_id: str, finding, tmp_path,
                        reason: str = "independent replay reproduced"):
    """Carry a CANDIDATE finding through the whole gate to VERIFIED.

    Equivalent to what the pipeline's verify ladder now does: bind the replay
    evidence, then promote. Requires the finding to already have poc_path from
    ``write_poc`` at create time.
    """
    replay_evidence(ledger, run_id, finding.id)
    return ledger.set_finding_status(finding.id, "verified", reason)


@pytest.fixture()
def poc_factory(tmp_path):
    """Fixture form of :func:`write_poc` for tests that prefer injection."""
    def _make(name: str = "poc.py", **kw) -> str:
        return write_poc(tmp_path, name, **kw)
    return _make


__all__ = [
    "write_poc",
    "replay_evidence",
    "promote_to_verified",
    "poc_factory",
    "json",
]
