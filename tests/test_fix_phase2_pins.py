"""Phase2 pin RED — proves remaining gaps, no src fixes.

Style follows tests/test_fix_media_hardening.py (plain asserts, tmp_path,
CliRunner seams). Each test asserts the POST-builder end state from the
planner: pins at 0.6.0 / 25 / .hunter / 130, welcome disclaimer (the one src
fix), /audit vs free-text, daemon banner+tip + auto-authorize 0, min-time
/50, brand-zero 0 hits + renamed guard + .kilo ignore.

Most fail now (stale pins + missing welcome line + brand hits); builder
makes them green via test-only pin updates + 1 src welcome fix + docs sweep
+ .gitignore .kilo + rename.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_release_pin_is_060():
    """RELEASE_VERSION bumped to 0.6.0 everywhere (was 0.5.0 pin)."""
    import hunter

    text = _read("tests/test_release_m7.py")
    assert 'RELEASE_VERSION = "0.6.0"' in text, "stale pin still 0.5.0"
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    assert project["version"] == "0.6.0"
    assert hunter.__version__ == "0.6.0"
    from hunter.cli.main import app

    result = RUNNER.invoke(app, ["version"])
    assert result.exit_code == 0, (result.stdout, result.exception)
    assert result.stdout.strip() == "hunter 0.6.0"


def test_registry_len_25_no_stale_pins():
    """Registry is 25 (mode+note); stale 23 / 20 pins gone from tests+docs."""
    from hunter.chat.commands import COMMAND_REGISTRY

    names = [c.name for c in COMMAND_REGISTRY]
    assert len(names) == 25, names
    assert "mode" in names and "note" in names
    assert "curate" in names and "audit" in names
    # stale test pin: M8 comment claimed 23
    skills_text = _read("tests/test_skills_surfaces.py")
    assert "== 23" not in skills_text, "stale 23 pin still present"
    assert "== 25" in skills_text or "len(names) == 25" in skills_text
    # stale docs pin: 20 slash commands -> 25
    assert "20 slash commands" not in _read("README.md").lower()
    assert "20 slash commands" not in _read("tests/test_release_m7.py").lower()
    assert "25 slash commands" in _read("README.md").lower()


def test_keys_path_is_hunter():
    """Keys live under ~/.hunter; docs/tests swept off ~/.hunteros for config."""
    from hunter.llm.keys import keys_env_path

    p = keys_env_path(env={}, home=Path("/tmp/phase2-home"))
    assert ".hunter" in str(p), p
    assert ".hunteros" not in str(p), p
    assert str(p).endswith("keys.env")
    # example config swept
    example = _read("examples/config.example.yaml")
    assert "~/.hunter/config.yaml" in example
    assert "~/.hunteros/config.yaml" not in example
    # provider-add wizard tests swept
    wiz = _read("tests/test_cli_provider_add_wizard.py")
    assert '.hunteros" / "keys.env' not in wiz and ".hunteros\" /" not in wiz
    assert wiz.count('".hunter"') >= 2 or wiz.count("'.hunter'") >= 1 or ".hunter" in wiz
    # current docs must not point config/keys/chat at the legacy plumbing home
    for rel in (
        "README.md",
        "QUICKSTART.md",
        "docs/FIRST-RUN.md",
        "docs/LLM.md",
        "docs/ARCHITECTURE.md",
        "examples/config.example.yaml",
    ):
        docs = _read(rel)
        assert "~/.hunteros/config.yaml" not in docs, rel
        assert "~/.hunteros/keys.env" not in docs, rel
        assert "~/.hunteros/chat.db" not in docs, rel


def test_init_cancel_is_130():
    """Wizard cancel is 130 with disclaimer last (was pinned 0 in init_v2)."""
    import io

    from rich.console import Console

    from hunter.cli.init_wizard import SCOPE_DISCLAIMER, run_init_wizard

    out = io.StringIO()
    err = io.StringIO()
    console = Console(file=out, width=200, legacy_windows=False)
    err_console = Console(file=err, width=200, legacy_windows=False)

    def cancelling_ask(prompt: str, default: str = "") -> str:
        if "provider" in prompt:
            raise KeyboardInterrupt
        return "1" if "mode" in prompt else default

    code = run_init_wizard(
        path=Path("/tmp/phase2-cancel.yaml"),
        console=console,
        err_console=err_console,
        ask=cancelling_ask,
        environ={},
        home=Path("/tmp/phase2-cancel-home"),
        checks_fn=lambda: [],
    )
    assert code == 130, f"cancel must be 130, got {code}"
    text = out.getvalue() + err.getvalue()
    assert text.strip().endswith(SCOPE_DISCLAIMER)
    # pin file must expect 130 for the cancel path (not blanket 0)
    pin = _read("tests/test_cli_init_v2.py")
    assert "130" in pin, "cancel pin still expects 0"


def test_welcome_contains_disclaimer():
    """Bare-hunter welcome carries the scope disclaimer (the 1 src fix)."""
    from hunter._data.branding import welcome_lines
    from hunter.cli.init_wizard import SCOPE_DISCLAIMER

    body = "\n".join(welcome_lines("0.6.0"))
    assert "Scan only systems you own" in body
    assert SCOPE_DISCLAIMER in body


def test_audit_creates_hunt_free_text_does_not(tmp_path):
    """Slashes create hunts; free text never arms without human confirm."""
    from hunter.chat.commands import CommandContext, resolve_command, safe_execute
    from hunter.chat.repl import ChatEngine
    from hunter.chat.sessions import ChatStore

    # /audit resolves and declares a one-shot hunt
    resolved = resolve_command("/audit http://127.0.0.1:1/ --engine deterministic")
    assert resolved is not None and resolved[0].name == "audit"
    store = ChatStore(tmp_path / "chat.db")
    try:
        ctx = CommandContext(store=store, config=None, args="http://127.0.0.1:1/", options={})
        reply = safe_execute("audit", ctx)
        assert "audit_start" in reply.data, reply.text
        assert reply.data["audit_start"]["target"] == "http://127.0.0.1:1/"
        # free text is not a slash command
        assert resolve_command("audit http://127.0.0.1:1/") is None
        # free text without confirm never arms (headless decline or hint, no run)
        engine = ChatEngine(store=store, config=None, provider=None, options={"state_dir": str(tmp_path)})
        try:
            out = engine.handle_text("audit http://127.0.0.1:1/")
            assert engine._audit is None, "free text must not arm an audit"
            assert out.data.get("hunt", {}).get("action") != "started"
        finally:
            engine.close()
    finally:
        store.close()
    # pins: adversarial arming must use the slash form (no bare free-text arm)
    adv = _read("tests/test_adversarial_v02.py")
    assert 'handle_text(f"audit ' not in adv, "5x free-text arming still present"
    assert adv.count("/audit ") >= 5 or adv.count('"/audit') >= 5


def test_daemon_banner_startswith_and_tip(tmp_path, monkeypatch):
    """Idle start prints banner startswith + tip; off-localhost auto-authorizes 0."""
    from hunter.cli.main import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    from hunter.cli import update_core

    update_core.reset()
    try:
        monkeypatch.setattr("hunter.cli.daemon._resolve_engine", lambda explicit: ("deterministic", 0))
        monkeypatch.setattr("hunter.daemon.start_daemon", lambda *a, **k: 0, raising=False)
        monkeypatch.setattr("hunter.cli.daemon.start_daemon", lambda *a, **k: 0, raising=False)
        idle = RUNNER.invoke(app, ["hunt", "start", "--state", str(tmp_path)])
        assert idle.exit_code == 0, idle.output
        assert idle.stdout.startswith("engine started"), repr(idle.stdout[:200])
        assert "tip:" in idle.stdout.lower() and "hunt start" in idle.stdout

        monkeypatch.setattr("hunter.daemon.start_daemon", lambda *a, **k: 0, raising=False)
        monkeypatch.setattr("hunter.cli.daemon.start_daemon", lambda *a, **k: 0, raising=False)
        evil = RUNNER.invoke(
            app, ["hunt", "start", "--target", "https://evil.example", "--state", str(tmp_path)]
        )
        assert evil.exit_code == 0, (evil.output, evil.exception)
    finally:
        update_core.reset()
    # pin file must expect banner+tip (not exact single line) and auto 0 (not 3)
    pin = _read("tests/test_cli_engine.py")
    assert "tip" in pin.lower(), "banner+tip pin missing"
    assert "startswith" in pin or "tip:" in pin.lower()


def test_min_time_nudge_contains_slash50(tmp_path):
    """Min-time nudge is bounded: 1/50 hold then 50/50 cap, fail-open."""
    import types

    import hunter.llm.budget as budget_mod
    from hunter.agent.loop import AgentLoop
    from hunter.agent.tools import build_registry
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.llm.base import ToolCall, TurnResult
    from hunter.llm.budget import RunBudget
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    clock = {"now": 1000.0}
    orig_time = budget_mod.time
    budget_mod.time = types.SimpleNamespace(monotonic=lambda: clock["now"])
    ledger = Ledger(tmp_path / "ledger.db")
    http = ScopedHttpClient(localhost_scope(), min_interval=0)
    try:
        ctx = ToolContext(
            run_id="R-PHASE2",
            ledger=ledger,
            http=http,
            scope=localhost_scope(),
            target_url="http://127.0.0.1/",
            emit=lambda kind, payload: None,
            config={"tier": "basic"},
        )
        budget = RunBudget(min_wall_seconds=600.0, max_cost_usd=0.0, max_iterations=0, wall_seconds=0.0)
        budget.start()

        def hold(messages):
            return TurnResult(
                text="",
                tool_calls=(ToolCall(id="c1", name="finish_scan", arguments={}),),
                finish_reason="tool_calls",
                cost_usd=0.0,
                model="fake",
                provider="fake",
            )

        def release(messages):
            clock["now"] += 700.0
            return TurnResult(
                text="",
                tool_calls=(ToolCall(id="c2", name="finish_scan", arguments={}),),
                finish_reason="tool_calls",
                cost_usd=0.0,
                model="fake",
                provider="fake",
            )

        class FakeProvider:
            name = "fake"

            def __init__(self, script):
                self.script = list(script)
                self.calls = []

            def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
                self.calls.append({"messages": [dict(m) for m in messages]})
                idx = len(self.calls) - 1
                step = self.script[min(idx, len(self.script) - 1)]
                return step(messages) if callable(step) else step

            def classify(self, exc):
                from hunter.llm.base import ClassifiedError

                return ClassifiedError(reason="unknown")

        provider = FakeProvider([hold, release])
        loop = AgentLoop(provider, build_registry("basic"), tier="basic", budget=budget)
        result = loop.run(ctx, "Audit the target.")
        assert result.finished is True
        held = provider.calls[1]["messages"][-1]
        assert "[BUDGET min-time]" in held["content"]
        assert "(min-time nudge 1/50)" in held["content"]
        assert "/50" in held["content"]
    finally:
        budget_mod.time = orig_time
        http.close()
        ledger.close()


def test_brand_zero_including_renamed_guard():
    """No brand literal remains; renamed guard exists; .kilo ignored."""
    token = "her" + "mes"
    lowered = token.lower()
    self_path = Path(__file__).resolve()
    exclude = {
        ".git",
        "__pycache__",
        ".venv",
        ".venv-ci",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".kilo",
        ".hunter",
        ".hunter-cli-smoke",
    }

    def _excluded(p: Path) -> bool:
        if p.resolve() == self_path:
            return True
        return any(part in exclude for part in p.parts)

    content_hits: list[str] = []
    name_hits: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if _excluded(path) or _excluded(rel):
            continue
        if lowered in path.name.lower():
            name_hits.append(str(rel))
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
            except (UnicodeDecodeError, OSError):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if lowered in line.lower():
                    # allow the split-token construction itself, never a literal
                    if '"her" + "mes"' in line or "'her' + 'mes'" in line or '"her"+"mes"' in line:
                        continue
                    content_hits.append(f"{rel}:{i}")
                    if len(content_hits) >= 50:
                        break
    hits = [f"filename: {h}" for h in sorted(name_hits)] + sorted(content_hits)
    assert not hits, f"brand-zero violated with {len(hits)} hit(s):\n" + "\n".join(hits[:50])
    # renamed guard: new generic file exists, old literal file gone
    assert (ROOT / "tests" / "test_fix_brand_zero.py").is_file(), "renamed guard missing"
    old = ROOT / "tests" / f"test_fix_{token}_zero.py"
    assert not old.exists(), f"old literal file still present: {old}"
    # hygiene: .kilo must be ignored
    assert ".kilo" in _read(".gitignore"), ".gitignore missing .kilo"
