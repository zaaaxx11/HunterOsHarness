"""Skills-surface seam tests (M3 K1-K2) — the documented M5 extension point.

`mounted_skills()` reports the bundled corpus (pre-hunt line); the selector
(`install_skill_selector`/`resolve_skills_index`) is INERT until M5 installs
a matcher — the default path must stay byte-identical to load_skills_index(),
the AgentLoop must consume resolve_skills_index(), and nothing may leak the
selector across tests (always restored in a finally).
"""

from __future__ import annotations

from importlib import resources

from hunter.kernel.ledger import Ledger
from hunter.llm.base import ToolCall, TurnResult


class FakeProvider:
    """Scripted ChatProvider: records messages, yields after one turn."""

    name = "fake"

    def __init__(self, script) -> None:
        self.script = list(script)
        self.calls: list[list[dict]] = []

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        self.calls.append([dict(m) for m in messages])
        index = len(self.calls) - 1
        if index >= len(self.script):
            raise AssertionError(f"script exhausted after {len(self.script)} turns")
        return self.script[index]


def _yield_turn(message: str = "yield") -> TurnResult:
    return TurnResult(
        text="",
        tool_calls=(ToolCall(id="y", name="respond_to_user", arguments={"message": message}),),
        cost_usd=0.01,
    )


# -- K1 -----------------------------------------------------------------------


def test_mounted_skills_lists_bundled_names(monkeypatch):
    from hunter.agent.prompts import mounted_skills

    # Expected derived independently from the shipped corpus: INDEX.md and
    # _-prefixed helpers excluded, sorted.
    root = resources.files("hunter") / "_data" / "skills"
    expected = sorted(
        entry.name
        for entry in root.iterdir()
        if entry.name != "INDEX.md" and not entry.name.startswith("_")
    )
    result = mounted_skills()
    assert result == expected
    assert result == sorted(result)
    assert result and "recon-basics" in result  # the real corpus is mounted

    # []-tolerant: a missing corpus degrades to [] — never a raise.
    def _missing(*_args, **_kwargs):
        raise ModuleNotFoundError("skills corpus gone")

    monkeypatch.setattr("hunter.agent.prompts.resources.files", _missing)
    assert mounted_skills() == []


# -- K2 -----------------------------------------------------------------------


def test_skill_selector_extension_point_mounts_custom_block(monkeypatch, tmp_path):
    from hunter.agent.loop import AgentLoop
    from hunter.agent.prompts import (
        install_skill_selector,
        load_skills_index,
        resolve_skills_index,
    )
    from hunter.agent.tools import build_registry
    from hunter.agent.tools_base import ToolContext
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    # Inert by default: the default path IS load_skills_index().
    assert resolve_skills_index() == load_skills_index()

    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope)
    try:
        ctx = ToolContext(
            run_id="R-SEAM",
            ledger=ledger,
            http=http,
            scope=scope,
            target_url="http://127.0.0.1:8941/",
            emit=lambda kind, payload: None,
            config={"tier": "basic"},  # no skills_index key → the resolver decides
        )
        install_skill_selector(lambda _question: "SENTINEL-BLOCK")
        try:
            assert resolve_skills_index() == "SENTINEL-BLOCK"

            # A real AgentLoop turn mounts the sentinel in the system prompt.
            provider = FakeProvider([_yield_turn()])
            loop = AgentLoop(provider, build_registry("basic"), tier="basic")
            loop.run(ctx, "audit the target")
            system = provider.calls[0]["messages"][0]
            assert system["role"] == "system"
            assert "SENTINEL-BLOCK" in system["content"]
        finally:
            install_skill_selector(None)  # restore, even on failure

        assert resolve_skills_index() == load_skills_index()
    finally:
        http.close()
        ledger.close()
