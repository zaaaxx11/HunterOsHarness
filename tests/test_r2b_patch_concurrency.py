"""R2-B patch concurrency + crash-safety (TDD RED).

B-gate: B4 (patch concurrency) — R decision gate: locked retryable vs stale dry_run_required.

Prod targets (READ ONLY):
- src/hunter/agent/tools_patch.py:60-198 preview 8k .bak-ms jail dry-run + danger approval advanced
- src/hunter/agent/approval.py catastrophic/TTL300/single-use (fingerprint seam)
- per-fn -> prod:
  patch lock (patch.locked) -> tools_patch.py (NEW file lock, retryable)
  atomic os.replace -> tools_patch.py (NEW crash-safe write)
  backup chain N=3 prune -> tools_patch.py (NEW .bak rotation)
  crash marker + diff_hash/fingerprint -> tools_patch.py (NEW stale protocol)
  diff <=32k / preview redact -> tools_patch.py (NEW bounds)

Mock only: tmp_path jail, :memory: Ledger, no network (MockTransport guard).
Adversarial: Windows jail (C:/ + backslash), secret redact in preview, size+time
budgets (diff 32k, preview 8k), crash leaves original (atomic replace), negatives.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest

R2B = "EXPECTED-FAIL-R2B:patch concurrency (R2-B B4)"
DIFF = "--- a/app.py\n+++ b/app.py\n@@\n-print('old')\n+print('new')\n"


def _require_patch():
    import hunter.agent.tools_patch as patch
    for sym in ("acquire_patch_lock", "PATCH_LOCK_TIMEOUT", "MAX_DIFF_CHARS"):
        if getattr(patch, sym, None) is None:
            pytest.fail(f"{R2B} — hunter.agent.tools_patch.{sym} missing (concurrency seam)")
    return patch


def _ctx(jail: Path, events=None):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope
    import httpx
    if events is None:
        events = []
    def _never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("patch must never touch the network")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=httpx.MockTransport(_never), min_interval=0)
    return ToolContext(run_id="R-PATCH", ledger=Ledger(":memory:"), http=http, scope=scope,
                       target_url="http://127.0.0.1:9/", emit=lambda k, p: events.append((k, dict(p))),
                       config={"tier": "advanced", "jail": str(jail)}, state={}), events


def _jail(tmp_path: Path) -> Path:
    jail = tmp_path / "repo"
    jail.mkdir(exist_ok=True)
    (jail / "app.py").write_text("print('old')\n", encoding="utf-8")
    return jail


def test_r2b_patch_two_threads_one_ok_one_locked():
    """Two threads: one ok + one patch.locked retryable + engine_event locked:true."""
    patch = _require_patch()
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        jail = _jail(Path(td))
        ctx, events = _ctx(jail)
        results: list = []
        def _run():
            results.append(patch.patch_write({"path": "app.py", "diff": DIFF}, ctx))
        t1, t2 = threading.Thread(target=_run), threading.Thread(target=_run)
        t1.start(); t2.start(); t1.join(); t2.join()
        codes = sorted(r.get("code", "ok") for r in results)
        assert "patch.locked" in codes, f"one writer must report patch.locked, got {codes}"
        assert any(p.get("locked") is True for k, p in events if k == "engine_event")


def test_r2b_patch_atomic_os_replace_crash_leaves_original(tmp_path: Path):
    """Atomic os.replace: crash mid-write leaves the original intact."""
    patch = _require_patch()
    import hunter.agent.tools_patch as pm
    import inspect
    assert "os.replace" in inspect.getsource(pm.patch_write), "apply must use atomic os.replace"
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail)
    before = (jail / "app.py").read_text(encoding="utf-8")
    out = patch.patch_write({"path": "app.py", "diff": DIFF, "crash_after_tmp": True}, ctx)
    assert out.get("code") in ("patch.crashed", "patch.io_error", "patch.locked")
    assert (jail / "app.py").read_text(encoding="utf-8") == before


def test_r2b_patch_backup_chain_n3_prune(tmp_path: Path):
    """Backup chain N=3: fourth apply prunes oldest, keeps newest 3."""
    patch = _require_patch()
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail)
    for i in range(4):
        patch.patch_write({"path": "app.py", "diff": DIFF}, ctx)
    backups = sorted(jail.glob("app.py.bak-*"))
    assert len(backups) == 3, f"must prune to N=3, got {len(backups)}"


def test_r2b_patch_crash_marker_stale_dry_run_required(tmp_path: Path):
    """Crash marker present -> stale -> dry_run_required BLOCKED until fresh dry-run."""
    patch = _require_patch()
    jail = _jail(tmp_path)
    (jail / "app.py.patch-crash").write_text("stale", encoding="utf-8")
    ctx, _ = _ctx(jail)
    out = patch.patch_write({"path": "app.py", "diff": DIFF}, ctx)
    assert out.get("blocked") is True and out.get("code") == "patch.dry_run_required"


def test_r2b_patch_diff_hash_mismatch_stale(tmp_path: Path):
    """diff_hash mismatch vs fingerprint -> stale BLOCKED."""
    patch = _require_patch()
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail)
    preview = patch.patch_write({"path": "app.py", "diff": DIFF, "dry_run": True,
                                 "fingerprint": "abc123"}, ctx)
    assert preview.get("ok") is True
    stale = patch.patch_write({"path": "app.py", "diff": DIFF.replace("new", "evil"),
                               "fingerprint": "abc123"}, ctx)
    assert stale.get("blocked") is True and "stale" in str(stale.get("code", "")).lower()


def test_r2b_patch_dry_run_default_without_fingerprint_blocked(tmp_path: Path):
    """Apply without prior fingerprint -> dry_run_required BLOCKED (dry-run-default)."""
    patch = _require_patch()
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail)
    out = patch.patch_write({"path": "app.py", "diff": DIFF}, ctx)
    assert out.get("blocked") is True and out.get("code") == "patch.dry_run_required"


def test_r2b_patch_preview_redact_secrets(tmp_path: Path):
    """Preview redacts secret-shaped leaves (no leak into model text)."""
    patch = _require_patch()
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail)
    out = patch.patch_write({"path": "app.py",
                             "diff": DIFF + "+token=TOPSECRET-abc123\n",
                             "dry_run": True}, ctx)
    assert "TOPSECRET-abc123" not in json.dumps(out)
    assert "[REDACTED]" in str(out.get("preview", ""))


def test_r2b_patch_diff_32k_limit(tmp_path: Path):
    """diff >32k -> diff_too_large BLOCKED (size budget)."""
    patch = _require_patch()
    jail = _jail(tmp_path)
    ctx, _ = _ctx(jail)
    big = "+x\n" * 20000
    out = patch.patch_write({"path": "app.py", "diff": big, "dry_run": True}, ctx)
    assert out.get("blocked") is True and out.get("code") == "patch.diff_too_large"
