"""Fase 0 baseline freeze — TDD STEP 1 (red-team repro, NO src/ changes).

GREEN by design: tiap test mendokumentasikan perilaku LONGGAR saat ini
supaya Builder melihat gap persis sebelum mengetatkan. Pasangan STRICT-nya
ada di test_shell_jail / test_soul_boundary / test_tier_skill_budget.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from hunter.agent.approval import ApprovalStore, classify_shell_command, make_approval_gate
from hunter.agent.skills import MAX_BLOCK_CHARS, Skill, load_corpus, render_block
from hunter.agent.soul import load_soul, sanitize_soul, soul_block
from hunter.agent.tools import _SHELL_OUTPUT_LIMIT, _shell_cwd, build_registry
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope

PY = sys.executable.replace("\\", "/")
SECRET = "phase0-outside-secret-xyz"


def py_command(code: str) -> str:
    return f'"{PY}" -c "{code}"'


@pytest.fixture()
def shell(tmp_path):
    """Isolated jail: state_dir=<tmp>/jail, outside secret di <tmp>/ (di luar jail)."""
    jail = tmp_path / "jail"
    jail.mkdir(parents=True, exist_ok=True)
    run_id = "R-PHASE0"
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run(run_id, "http://127.0.0.1/", "agent-chat", "localhost-only")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)

    def emit(kind: str, payload: dict[str, Any]) -> None:
        ledger.append(run_id, kind, dict(payload))

    store = ApprovalStore(tmp_path / "approvals")
    gate = make_approval_gate(
        store, ledger=ledger, run_id=run_id,
        auto_allow=True, confirm_fn=lambda _request: True, surface="repl",
    )
    ctx = ToolContext(
        run_id=run_id, ledger=ledger, http=http, scope=scope,
        target_url="http://127.0.0.1/", emit=emit,
        config={"tier": "advanced", "state_dir": str(jail), "approval_gate": gate},
    )
    try:
        yield {"ctx": ctx, "jail": jail, "root": tmp_path}
    finally:
        http.close()
        ledger.close()


def test_repro_cat_absolute_allowed(shell):
    """BASELINE (harus GREEN): path absolut di luar jail kini TERBACA.

    Membuktikan bug: _shell_cwd hanya memagari `cwd`, argv file tidak dicek.
    ASUMSI: biner `cat` tak ada di win32, jadi eksekusi memakai carrier
    python + klasifikasi `cat` untuk sisi policy-nya.
    """
    ctx: ToolContext = shell["ctx"]
    jail = shell["jail"]
    outside = shell["root"] / "outside_secret.txt"
    outside.write_text(SECRET, encoding="utf-8")
    abs_posix = str(outside.resolve()).replace("\\", "/")

    # sisi policy: `cat <abs>` kini readonly (lolos auto-allow), termasuk varian spasi ganda
    assert classify_shell_command(f"cat {abs_posix}") == "readonly", \
        "baseline: 'cat <abs>' kini readonly"
    assert classify_shell_command(f"cat    {abs_posix}  ") == "readonly", \
        "baseline: varian bypass spasi-ekstra kini tetap readonly"

    # sisi jail: cwd default = state dir (pin _shell_cwd)
    cwd, err = _shell_cwd({}, ctx)
    assert err is None and cwd == str(jail), "baseline: cwd default adalah state dir"

    # sisi eksekusi: baca file luar jail kini ok=True + secret bocor ke model
    outcome = build_registry("advanced").dispatch(
        "shell_exec", {"command": py_command(f"print(open('{abs_posix}').read())")}, ctx,
    )
    assert outcome.ok is True, \
        f"baseline: baca luar-jail kini sukses (code={outcome.code}): {outcome.result_for_model[:200]}"
    assert SECRET in outcome.result_for_model, "baseline: secret luar-jail kini bocor ke model"


def test_repro_soul_cwd_mounted(tmp_path, monkeypatch):
    """Opsi B GREEN (dulu BASELINE cwd auto-load): ./SOUL.md diabaikan, .hunter/soul.md UNTRUSTED."""
    monkeypatch.delenv("HUNTER_SOUL_FILE", raising=False)
    monkeypatch.delenv("HUNTEROS_SOUL", raising=False)
    monkeypatch.setattr(
        "hunter.agent.soul._default_home_soul", lambda: tmp_path / "no-home" / "SOUL.md",
    )
    marker = "phase0-cwd-soul-marker-xyz"
    (tmp_path / "SOUL.md").write_text(f"# hello\n{marker}\n", encoding="utf-8")
    proj_marker = "phase0-hunter-soul-marker-xyz"
    (tmp_path / ".hunter").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".hunter" / "soul.md").write_text(f"# proj\n{proj_marker}\n", encoding="utf-8")

    loaded = load_soul(repo_root=tmp_path)
    assert marker not in loaded, "Opsi B: ./SOUL.md (cwd root) wajib DIABAIKAN, bukan auto-load"
    assert proj_marker in loaded, "Opsi B: .hunter/soul.md wajib di-load (pengganti ./SOUL.md)"
    assert "[UNTRUSTED]" in loaded.upper(), "Opsi B: project-local soul wajib stamp [UNTRUSTED]"
    block = soul_block(loaded)  # loop.py:148-150 mem-pin block ini ke system prompt
    assert proj_marker in block, "Opsi B: soul .hunter kini mendarat di system prompt block"
    assert marker not in block, "Opsi B: soul cwd-root tak boleh bocor ke block"
    assert marker in sanitize_soul(marker), "sanitize tak boleh menghapus teks biasa"


def test_repro_skill_oversize_single_card():
    """Opsi B GREEN (dulu BASELINE >16k): 1 kartu 20k body kini truncate <=16k."""
    assert _SHELL_OUTPUT_LIMIT == 16_384, "pin kontrak output-cap shell"
    assert load_corpus() is not None, "korpus nyata harus bisa di-load"
    body = "A" * 20_000
    skill = Skill(
        name="oversize-repro", description="repro card", version="0.1.0",
        min_tier="basic", tags=("core",), source="user", body=body,
        quarantined=False, path="",
    )
    rendered = render_block([skill], corpus_size=1)
    assert len(body) == 20_000, "syarat: body tepat 20k"
    assert len(rendered) <= 16_000, f"Opsi B: single card dipotong ke <=16k ({len(rendered)})"
    assert len(rendered) <= MAX_BLOCK_CHARS, "Opsi B: single card kini patuh MAX_BLOCK_CHARS"
