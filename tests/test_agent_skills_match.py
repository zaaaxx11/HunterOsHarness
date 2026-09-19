"""M5 matching, rendering, selector, and loop wiring contracts (MT1-MT9)."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clean_selector():
    from hunter.agent.prompts import install_skill_selector

    install_skill_selector(None)
    yield
    install_skill_selector(None)


def _skill(
    name: str,
    *,
    description: str = "ordinary doctrine",
    tags: tuple[str, ...] = (),
    source: str = "user",
    body: str | None = None,
    quarantined: bool = False,
):
    from hunter.agent.skills import Skill

    return Skill(
        name=name,
        description=description,
        version="0.1.0",
        min_tier="basic",
        tags=tags,
        source=source,
        body=body or f"---\nname: {name}\n---\n\n# {name}\n\n{description}",
        quarantined=quarantined,
        path="",
    )


def test_target_hint_pure_and_table(monkeypatch):
    import socket

    from hunter.agent.skills import target_hint, tokenize

    assert target_hint("Please audit https://example.test/path?q=1).") == "https://example.test/path?q=1"
    assert target_hint("focus on staging.example.test, then stop") == "staging.example.test"
    assert target_hint("no target here, only prose") == ""

    def fail(*_args, **_kwargs):
        raise AssertionError("matching must not perform I/O")

    monkeypatch.setattr(socket.socket, "connect", fail, raising=False)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(Path, "exists", fail)
    monkeypatch.setattr(Path, "stat", fail)
    assert target_hint("https://safe.example.test/")
    assert tokenize("The audit target is https and evidence evidence") == ("audit", "target", "evidence")

    source = inspect.getsource(__import__("hunter.agent.skills", fromlist=["target_hint"]))
    assert "import httpx" not in source
    assert "import urllib" not in source
    assert "import socket" not in source


def test_scoring_weights_threshold_and_order():
    from hunter.agent.skills import match_skills

    skills = [
        _skill("tag-card", description="ordinary", tags=("needle",)),
        _skill("name-needle", description="ordinary"),
        _skill("description-card", description="needle detail"),
        _skill("one-only", description="needle"),
        _skill("aaa-name", description="needle needle", tags=("other",)),
    ]
    result = match_skills("needle", "needle", skills)
    assert [skill.name for skill in result] == ["tag-card", "aaa-name", "name-needle", "description-card"]
    assert "one-only" not in {skill.name for skill in result}
    assert result == match_skills("needle", "needle needle needle", skills)


def test_max_five_cap_and_tiebreak():
    from hunter.agent.skills import MAX_MOUNTED, match_skills

    skills = [_skill(f"skill-{index:02d}", tags=("target",)) for index in range(8)]
    result = match_skills("target", "", skills)
    assert len(result) == MAX_MOUNTED == 5
    assert [skill.name for skill in result] == [f"skill-{index:02d}" for index in range(5)]


def test_empty_match_falls_back_to_core_tags():
    from hunter.agent.skills import load_corpus, match_skills

    corpus = load_corpus()
    selected = match_skills("nothing.example", "unrelated vocabulary", corpus.skills)
    assert [skill.name for skill in selected] == ["scope-discipline", "verification-ladder"]


def test_no_core_tags_renders_empty_block():
    from hunter.agent.skills import render_block

    from hunter.agent.prompts import build_system_prompt

    selected = [_skill("not-core", tags=("other",))]
    assert render_block([], corpus_size=1) == ""
    prompt = build_system_prompt(
        target_url="https://example.test/",
        scope_summary="example",
        tier="basic",
        skills_index="",
    )
    assert "(no skills mounted)" in prompt
    assert render_block([], corpus_size=len(selected)) == ""


def test_block_budget_drops_tail_deterministically():
    from hunter.agent.skills import MAX_BLOCK_CHARS, render_block

    selected = [
        _skill(
            f"large-{index}",
            tags=("target",),
            body=(f"---\nname: large-{index}\n---\n\n" + ("x" * 3500)),
        )
        for index in range(5)
    ]
    first = render_block(selected, corpus_size=5)
    second = render_block(selected, corpus_size=5)
    assert len(first) <= MAX_BLOCK_CHARS
    assert first == second
    assert "large-0" in first
    assert "large-4" not in first
    assert first


def test_default_selector_install_and_seam_contract(monkeypatch):
    from hunter.agent.skills import install_default_skill_selector

    from hunter.agent.prompts import (
        install_skill_selector,
        load_skills_index,
        resolve_skills_index,
    )

    install_default_skill_selector()
    goal = "Audit https://example.test/ for evidence and verification."
    block = resolve_skills_index(question=goal)
    assert block.startswith("# Skills mounted for this run")
    assert "Rules for new skills" not in block

    received: list[str] = []
    install_skill_selector(lambda question: received.append(question) or "RECORDED")
    install_default_skill_selector()
    assert resolve_skills_index(question=goal) == "RECORDED"
    assert received == [goal]
    install_skill_selector(None)
    assert resolve_skills_index() == load_skills_index()


def test_agent_loop_auto_installs_and_override_wins(tmp_path):
    from hunter.agent.loop import AgentLoop
    from hunter.agent.prompts import install_skill_selector
    from hunter.agent.tools import build_registry
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.llm.base import ToolCall, TurnResult
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    class Provider:
        name = "match-test"

        def __init__(self):
            self.calls = []

        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            self.calls.append(messages)
            return TurnResult(
                text="",
                tool_calls=(ToolCall(id="y", name="respond_to_user", arguments={"message": "done"}),),
            )

    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope)
    try:
        ctx = ToolContext(
            run_id="R-MT8",
            ledger=ledger,
            http=http,
            scope=scope,
            target_url="https://example.test/",
            emit=lambda _kind, _payload: None,
            config={"tier": "basic"},
        )
        provider = Provider()
        loop = AgentLoop(provider, build_registry("basic"), tier="basic")
        loop.run(ctx, "Audit https://example.test/ verification evidence")
        assert "# Skills mounted for this run" in provider.calls[0][0]["content"]

        ctx.config["skills_index"] = "OVERRIDE"
        provider_override = Provider()
        AgentLoop(provider_override, build_registry("basic"), tier="basic").run(ctx, "goal")
        assert "OVERRIDE" in provider_override.calls[0][0]["content"]

        install_skill_selector(lambda _question: "EXPLICIT")
        provider_explicit = Provider()
        AgentLoop(provider_explicit, build_registry("basic"), tier="basic").run(ctx, "goal")
        assert "EXPLICIT" in provider_explicit.calls[0][0]["content"]
    finally:
        http.close()
        ledger.close()


def test_normative_selections_for_goal_and_arming_text():
    from hunter.agent.skills import selected_skill_names

    from hunter.agent.prompts import build_goal
    from hunter.engine.base import TargetSpec
    from hunter.tools.scope import localhost_scope

    goal = build_goal(TargetSpec(url="https://example.test/", scope=localhost_scope()), "basic")
    assert selected_skill_names(goal, goal) == [
        ("verification-ladder", "bundled"),
        ("recon-basics", "bundled"),
    ]
    assert selected_skill_names("audit http://127.0.0.1:8941/", "audit http://127.0.0.1:8941/") == [
        ("scope-discipline", "bundled"),
        ("verification-ladder", "bundled"),
    ]
