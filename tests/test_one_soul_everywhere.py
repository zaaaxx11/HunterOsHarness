"""ONE soul, EVERY prompt surface.

The rule this guards: every system prompt the harness builds carries the same
authorization frame from ``_core.md``. A surface that quietly lost it is a model
being asked to audit a live host with no context — it refuses, or worse, spends
its turn reasoning about permission instead of hunting.

Adding a new LLM call site? Add it to SURFACES below; this test then forces you
to decide whether it carries the soul.
"""
from __future__ import annotations

import inspect
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "hunter"
CORE = (SRC / "_data" / "prompts" / "souls" / "_core.md").read_text(encoding="utf-8")

# Every module that renders a system prompt, and what proves it carries the core.
SURFACES: dict[str, tuple[str, ...]] = {
    # module path relative to src/hunter, then the callables to test
    "agent/soul.py": ("soul_block", "role_soul_block"),
    "workflow/loop.py": ("_load_soul",),
    "workflow/scope_recognize.py": ("recognize",),
    "agent/debunk.py": ("debunk_finding",),
    "verify/l2_adversarial.py": ("ADVERSARIAL_PROMPT",),
}

MARKERS = ("Authorized work", "Evidence or nothing", "Stay in scope", "Ship, do not narrate")


def test_core_md_is_small_and_complete():
    assert len(CORE) // 4 <= 1000, f"_core.md is {len(CORE)//4} tokens"
    for marker in MARKERS:
        assert marker in CORE, f"_core.md lost its law: {marker}"


def test_core_is_the_single_source():
    """agent/soul.py must READ _core.md, not carry a second copy."""
    from hunter.agent.soul import CORE_IDENTITY

    assert CORE_IDENTITY.strip() == CORE.strip(), (
        "CORE_IDENTITY drifted from _core.md — two souls are forming again"
    )


def test_hunt_lanes_all_carry_the_core():
    from hunter.workflow.loop import _load_soul

    for lane in ("architect", "redteam", "fuzzer", "chainer", "verifier", "recon"):
        soul = _load_soul(lane)
        assert CORE.strip()[:60] in soul, f"lane {lane} lost the core soul"


def test_subagent_roles_all_carry_the_core():
    from hunter.agent.soul import role_soul_block

    for role in ("architect", "redteam", "fuzzer", "chainer", "verifier", "recon"):
        block = role_soul_block(role)
        assert CORE.strip()[:60] in block, f"subagent role {role} lost the core soul"


def test_scope_recognizer_carries_the_core():
    from hunter.workflow import scope_recognize

    src = inspect.getsource(scope_recognize.recognize) + inspect.getsource(
        scope_recognize
    )
    assert "CORE_IDENTITY" in src, "scope recognizer renders a system prompt without the soul"


def test_debunk_carries_the_core():
    from hunter.agent import debunk

    assert "CORE_IDENTITY" in inspect.getsource(
        debunk
    ), "debunk renders a system prompt without the soul"


def test_l2_adversarial_states_authorization():
    from hunter.verify.l2_adversarial import ADVERSARIAL_PROMPT

    assert "authorized" in ADVERSARIAL_PROMPT.lower(), (
        "the skeptic prompt lost its authorization frame"
    )


def test_no_new_unmarked_system_prompt():
    """Guard against a NEW call site that renders 'role: system' bare.

    A module that builds a system prompt must either inject CORE_IDENTITY or
    explain in SURFACES why it does not need to (pure JSON utility turns are
    exempt — they carry no judgement).
    """
    exempt = {
        "chat/",          # chat repl composes from build_system_prompt (soul-aware)
        "cli/",           # CLI banners, not model prompts
        "doctor_core.py",
        "phases.py",      # gate logic, no LLM
        "agent/prompts/",  # build_system_prompt itself, soul-aware
        "agent/loop.py",   # uses build_system_prompt
        "agent/subagents.py",  # uses role_soul_block
        "agent/output_formats.py",  # fragments appended to a soul-bearing prompt
        "tools_expand.py",  # carries the soul now
        "tools/registry.py",
        "prompt_builder.py",  # hunt-lane builders, soul comes from _ask_lane
        "loop_v3.py",
        "workflow/phase0_recon.py",  # composes lane souls
        # Not model prompts at all:
        "llm/base.py",            # a type-definition docstring
        "workflow/failover.py",   # passes `system` through from the caller
    }
    offenders = []
    for path in SRC.rglob("*.py"):
        rel = path.relative_to(SRC).as_posix()
        if any(rel.startswith(e) or rel == e for e in exempt):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if '"role": "system"' not in text and '"role":"system"' not in text:
            continue
        if "CORE_IDENTITY" not in text and "soul_block" not in text and "_load_soul" not in text:
            offenders.append(rel)
    assert not offenders, (
        "these modules render a system prompt with no soul injection: "
        + ", ".join(sorted(offenders))
        + " — inject CORE_IDENTITY or add them to `exempt` with a reason"
    )
