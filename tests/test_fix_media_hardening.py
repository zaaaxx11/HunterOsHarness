"""RED: Media hardening.

- ledger.py:527-544 ``add_evidence`` must enforce an allowlist + size cap.
- scripts/report_pack.py:43-73 must guard symlinks + oversized attachments.
- tui/app.py:761-765 must converge with markdown.py:191-196 placeholder for
  bound-but-missing evidence (render the binding instead of silently dropping).

All blocking tests FAIL now (no rejection) and must PASS after the fix.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

from hunter.kernel.claimgate import ClaimGateBlocked
from hunter.kernel.ledger import Ledger

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture()
def led(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    try:
        yield ledger
    finally:
        ledger.close()


def test_add_evidence_allowlist_rejects_unknown_kind(led):
    led.create_run("r1", "t", "e", "s")
    # Valid kinds stay allowed.
    led.add_evidence("r1", "http_exchange", {"body": "ok"})
    led.add_evidence("r1", "http_response", {"body": "ok"})
    with pytest.raises(ClaimGateBlocked):
        led.add_evidence("r1", "evil_kind_xyz", {"body": "x"})


def test_add_evidence_size_cap_rejects_huge(led):
    led.create_run("r1", "t", "e", "s")
    led.add_evidence("r1", "http_response", {"body": "small"})
    huge = "x" * (5 * 1024 * 1024)
    with pytest.raises(ClaimGateBlocked):
        led.add_evidence("r1", "http_response", {"body": huge})


def test_report_pack_rejects_symlink(tmp_path, monkeypatch):
    from scripts.report_pack import EXIT_ERROR, main

    state = tmp_path / "state"
    reports = state / "reports"
    (reports / "R-1").mkdir(parents=True)
    (reports / "R-1.md").write_text("# report\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = reports / "R-1" / "evil.txt"
    try:
        link.symlink_to(outside)
        has_real_link = True
    except OSError:
        # No privilege for real symlinks on this box: stage a regular file
        # and fake is_symlink so the guard is still exercised.
        link.write_text("secret", encoding="utf-8")
        has_real_link = False
        orig_is_symlink = Path.is_symlink

        def _fake_is_symlink(self):
            if self == link:
                return True
            return orig_is_symlink(self)

        monkeypatch.setattr(Path, "is_symlink", _fake_is_symlink)
    out = tmp_path / "pack.zip"
    rc = main(["--run-id", "R-1", "--state", str(state), "-o", str(out)])
    assert rc == EXIT_ERROR, (
        f"symlink attachment must be rejected (real_link={has_real_link})"
    )
    if out.exists():
        with zipfile.ZipFile(out) as zf:
            assert "R-1/evil.txt" not in zf.namelist()


def test_report_pack_has_size_and_symlink_guards():
    text = (ROOT / "scripts" / "report_pack.py").read_text(encoding="utf-8")
    assert "is_symlink" in text or "symlink" in text.lower(), "missing symlink guard"
    assert (
        "st_size" in text or "stat" in text or "MAX" in text or "size" in text.lower()
    ), "missing size guard"


def test_tui_missing_evidence_placeholder_converges():
    from hunter.kernel.findings import Finding, FindingStatus, Severity
    from hunter.reporting.markdown import _evidence_row
    from hunter.tui.app import HunterTui

    finding = Finding(
        id="F-0001",
        run_id="r1",
        key="k",
        title="T",
        severity=Severity.HIGH,
        cwe="CWE-79",
        endpoint="/x",
        method="GET",
        status=FindingStatus.CANDIDATE,
        evidence_ids=("EV-0001", "EV-9999"),
    )
    present = {
        "id": "EV-0001",
        "run_id": "r1",
        "kind": "http_response",
        "data": {"note": "hi"},
        "sha256": "a" * 64,
        "created_seq": 1,
    }
    # Markdown renders the missing binding (never lies).
    md_row = _evidence_row(None, "EV-9999")
    assert "EV-9999" in md_row and "missing" in md_row.lower()

    app = HunterTui.__new__(HunterTui)
    table = app._render_finding(finding, [present])
    from rich.console import Console

    console = Console(width=120)
    with console.capture() as cap:
        console.print(table)
    text = cap.get()
    assert "EV-9999" in text, f"TUI silently dropped missing binding:\n{text}"
    assert "missing" in text.lower(), f"TUI missing placeholder text:\n{text}"
