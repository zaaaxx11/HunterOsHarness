"""T5 mutating-gated contracts — patch_write (future) + approval matrix (present) (TDD red).

Planner B T5: the ONLY mutating file tool, behind the approval gate.

Production target: ``hunter.agent.tools_patch`` (NEW module to create):
  - ``patch_write`` spec: danger="approval", unified-diff preview (bounded),
    automatic backup (<path>.bak-<ts>) before apply, jail containment
    (tmp_path-style jail; escape -> BLOCKED), dry-run mode.
  - Registration with the approval gate: dispatch without a gate fails closed
    (approval.unavailable); catastrophic-shaped patches always pending.

Approval-matrix tests below pin PRESENT behavior (they pass today); the
patch_write tests FAIL today via EXPECTED-FAIL-TDD, keeping the file red.
"""

from __future__ import annotations


import pytest

TDD_PATCH = "EXPECTED-FAIL-TDD:hunter.agent.tools_patch (Planner B T5: patch_write danger=approval)"


def _require_patch():
    try:
        import hunter.agent.tools_patch as patch  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{TDD_PATCH} — module missing; create patch_write with diff-preview+backup+jail")
    return patch


def _ctx(tmp_path=None, approval_gate=None, tier="advanced"):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=_never_transport())
    config: dict = {"tier": tier}
    if approval_gate is not None:
        config["approval_gate"] = approval_gate
    return ToolContext(
        run_id="R-T5", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://127.0.0.1:9/", emit=lambda k, p: None,
        config=config, state={},
    )


def _never_transport():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("T5 must not touch the network")

    return httpx.MockTransport(handler)


# -- patch_write (red) -------------------------------------------------------------------

def test_t5_patch_write_importorskip(tmp_path):
    """Contract: the future module exists and exposes a danger=approval spec."""
    patch = _require_patch()
    assert patch.PATCH_WRITE_SPEC["danger"] == "approval"
    assert patch.PATCH_WRITE_SPEC["min_tier"] == "advanced"


def test_t5_patch_write_diff_preview_backup_jail(tmp_path):
    """Contract: diff preview + .bak backup + jail containment; escape BLOCKED."""
    patch = _require_patch()
    jail = tmp_path / "repo"
    jail.mkdir()
    target = jail / "app.py"
    target.write_text("print('old')\n", encoding="utf-8")
    ctx = _ctx(approval_gate=lambda *a: None)
    ctx.config["jail"] = str(jail)
    preview = patch.patch_write(
        {
            "path": "app.py",
            "diff": "--- a/app.py\n+++ b/app.py\n@@\n-print('old')\n+print('new')\n",
            "dry_run": True,
        },
        ctx,
    )
    assert preview["ok"] and "print('new')" in preview.get("preview", "")
    assert target.read_text(encoding="utf-8") == "print('old')\n", "dry-run must not mutate"
    applied = patch.patch_write(
        {"path": "app.py", "diff": "--- a/app.py\n+++ b/app.py\n@@\n-print('old')\n+print('new')\n"},
        ctx,
    )
    assert applied["ok"] and len(list(jail.glob("app.py.bak-*"))) == 1, (
        "apply must leave a timestamped backup"
    )
    evil = patch.patch_write({"path": "../escape.py", "diff": "x"}, ctx)
    assert evil.get("blocked") is True, "jail escape must be BLOCKED"


# -- approval matrix (pins present behavior; green today) ----------------------------------

def test_t5_matrix_readonly_mutating_catastrophic_preserved():
    """Contract: classifier matrix — readonly stays readonly; ;|&<> force mutating."""
    from hunter.agent.approval import classify_shell_command

    assert classify_shell_command("ls") == "readonly"
    assert classify_shell_command("git status") == "readonly"
    for chaining in ("ls; rm x", "ls | grep x", "a & b", "echo hi > out.txt", "cat < in.txt"):
        assert classify_shell_command(chaining) == "mutating", chaining
    assert classify_shell_command("git push origin main") == "mutating"
    assert classify_shell_command("rm -rf /") == "catastrophic"


def test_t5_catastrophic_always_pending_even_with_auto_allow(tmp_path):
    """Contract: catastrophic NEVER auto-allows; it always pends (approval.catastrophic)."""
    from hunter.agent.approval import ApprovalStore, make_approval_gate
    from hunter.kernel.ledger import Ledger

    store = ApprovalStore(tmp_path / "approvals")
    ledger = Ledger(":memory:")
    gate = make_approval_gate(store, ledger=ledger, run_id="R-T5", auto_allow=True)
    decision = gate("shell_exec", {"command": "rm -rf /"}, _ctx())
    assert decision is not None and decision.code == "approval.catastrophic"


def test_t5_single_use_consume_and_300s_expiry(tmp_path):
    """Contract: approvals are single-use; TTL is 300s; consumed approval passes exactly once."""
    from hunter.agent.approval import APPROVAL_TTL_SECONDS, ApprovalStore

    assert APPROVAL_TTL_SECONDS == 300
    store = ApprovalStore(tmp_path / "approvals")
    req = store.create("patch_write", {"path": "a"})
    assert store.decide(req.request_id, "approved") is not None
    assert store.find_approved(req.fingerprint) is not None
    store.consume(req.request_id)
    assert store.find_approved(req.fingerprint) is None, "consumed approval must not pass twice"
    expired = store.create("patch_write", {"path": "b"})
    from hunter.agent.approval import effective_status

    assert effective_status(expired, now=expired.expires_ts + 1) == "expired"


def test_t5_consumed_approved_passes_exactly_once(tmp_path):
    """Contract: gate consumes the approval inline — first dispatch passes, retry re-pends."""
    from hunter.agent.approval import ApprovalStore, make_approval_gate
    from hunter.kernel.ledger import Ledger

    store = ApprovalStore(tmp_path / "approvals")
    ledger = Ledger(":memory:")
    gate = make_approval_gate(store, ledger=ledger, run_id="R-T5", auto_allow=False)
    args = {"command": "ls"}
    assert gate("shell_exec", args, _ctx()) is not None  # no prior approval -> pending BLOCKED
    from hunter.kernel.events import canonical_json, sha256_hex

    fingerprint = sha256_hex(canonical_json({"tool": "shell_exec", "args": args}))
    record = next(r for r in [store.create("shell_exec", args)] if r.fingerprint == fingerprint)
    assert store.decide(record.request_id, "approved") is not None
    assert gate("shell_exec", args, _ctx()) is None, "approved approval passes the gate"
    retry = gate("shell_exec", args, _ctx())
    assert retry is not None and retry.code == "approval.required", "single-use: retry must re-pend"
    ledger.close()
