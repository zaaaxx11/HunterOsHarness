"""Tier + skill budget — STRICT + LOOSE (TDD STEP 1, NO src/ changes).

- LOOSE/terdokumentasi (GREEN): tier counts 16/17 + shell_exec hanya advanced.
- STRICT (RED kini): 1 kartu 20k harus terpotong/ditolak agar <= MAX_BLOCK_CHARS;
  docstring build_registry tak boleh mengklaim skema "identical" (faktanya
  shell_exec membuat basic=16 vs advanced=17).
"""

from __future__ import annotations

from hunter.agent.skills import MAX_BLOCK_CHARS, MAX_MOUNTED, Skill, load_corpus, render_block
from hunter.agent.tools import build_registry


def _oversize_skill(body: str, name: str = "oversize-card") -> Skill:
    return Skill(
        name=name, description="oversize budget probe", version="0.1.0",
        tags=("core",), source="user", body=body,
        quarantined=False, path="",
    )


def test_no_tier_every_tool_registered_once():
    """No capability tier exists: one flat registry, one tool surface.

    Plugins are disabled here on purpose so the pin describes the BUILT-IN
    surface instead of whatever drop-in tools live in ``~/.hunter/tools``.
    """
    registry = build_registry(plugins_enabled=False)
    names = [t["function"]["name"] for t in registry.schemas_for_tier()]
    assert len(names) == len(set(names)), "no duplicate tool names"
    assert len(names) == 36, f"pin count: {len(names)}"
    for expected in ("shell_exec", "delegate_task", "nuclei_scan", "sqlmap_test"):
        assert expected in names, expected
    # tier requests are inert: the same surface comes back either way
    assert registry.schemas_for_tier("basic") == registry.schemas_for_tier("advanced")
    assert load_corpus() is not None and MAX_MOUNTED == 5, "pin konstanta skill"


def test_single_card_oversize_truncated_or_rejected():
    """Opsi B GREEN (dulu STRICT RED): satu kartu 20k wajib <= MAX_BLOCK_CHARS."""
    for label, body in (("single-line", "A" * 20_000), ("multi-line", "x\n" * 10_000)):
        assert len(body) == 20_000, f"syarat: body {label} tepat 20k"
        rendered = render_block([_oversize_skill(body, name=f"over-{label}")], corpus_size=1)
        assert len(rendered) <= MAX_BLOCK_CHARS, \
            f"Opsi B: kartu tunggal {label} dipotong/ditolak ke <={MAX_BLOCK_CHARS}"


def test_docstring_not_claim_identical():
    """Opsi B GREEN (dulu STRICT RED docs): docstring tak boleh klaim identical."""
    doc = build_registry.__doc__ or ""
    assert "identical" not in doc.lower(), \
        "Opsi B(docs): skema basic(16) vs advanced(17) beda — klaim 'identical' menyesatkan"
