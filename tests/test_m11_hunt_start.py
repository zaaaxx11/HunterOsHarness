"""M11 M7 — `hunt start` two-question flow + approved_scopes audit (§11).

Spec: docs/plans/m11-ux.md §2.1 decision 3, §2.2 Q3/Q5/Q11, §11.
Interactive runs inject ``interactive_ask`` into ``_cmd_start`` directly (the
seam M7 introduces) or go through the CLI with daemon internals seamed via
``_patch_daemon_fn`` — no process is ever spawned. The chat ``/hunt``
alignment runs at the engine level with a scripted ``ask_fn`` (Q3: the
manifest gate is NOT loosened there). Zero network.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from hunter.cli.main import app
from hunter.chat.repl import ChatEngine
from hunter.chat.sessions import ChatStore
from hunter.llm.base import TurnResult
from hunter.llm.config import default_config

runner = CliRunner()

LOCAL_URL = "http://127.0.0.1:9/"
REMOTE_URL = "https://example.com"

TARGET_PROMPT = "Target URL:"
TIME_PROMPT = "Time — how long may the hunt run? [2h]:"
CANCELLED_LINE = "⏸️ cancelled — nothing was started."
PAUSED_LINE = "⏸️ Hunter is paused. New work is on hold; run `hunter resume` to pick things back up."


def _patch_daemon_fn(monkeypatch, name, fn):
    monkeypatch.setattr(f"hunter.daemon.{name}", fn)
    try:
        import hunter.cli.daemon as cli_daemon
    except ImportError:
        return
    if hasattr(cli_daemon, name):
        monkeypatch.setattr(cli_daemon, name, fn)


def _home() -> Path:
    return Path(os.environ["USERPROFILE"])


def _config_path() -> Path:
    return _home() / ".hunter" / "config.yaml"


def _seed_config(text: str) -> Path:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _record_ask(answers: list, prompts: list | None = None):
    def ask(prompt: str, default: str = "") -> str:
        if prompts is not None:
            prompts.append(prompt)
        item = answers.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    return ask


def _patch_engine_bits(monkeypatch, engine_name: str = "deterministic"):
    monkeypatch.setattr(
        "hunter.cli.daemon._resolve_engine", lambda explicit: (engine_name, 0)
    )


class _FakeProvider:
    name = "fake"

    def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
        return TurnResult(text="ok", cost_usd=0.01)


# -- 1 --------------------------------------------------------------------------


def test_interactive_asks_exactly_two_questions_then_launches(tmp_path, monkeypatch, capsys):
    """Two prompts (pinned strings), then the flag-equivalent launch: no y/N."""
    from hunter.cli.daemon import _cmd_start

    prompts: list = []
    answers = [REMOTE_URL, "30m"]
    captured: dict = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)
    # A confirm must NEVER be touched on this path.
    import hunter.hunt as hunt_module

    monkeypatch.setattr(
        hunt_module, "confirm_prompt",
        lambda _p: (_ for _ in ()).throw(AssertionError("no y/N on the two-question path")),
    )

    state = tmp_path / "state"
    code = _cmd_start(
        target=None, scope=None, engine=None, time_text=None, min_time_text=None,
        budget_text=None, yes=False, force=False, state=state,
        interactive_ask=_record_ask(answers, prompts),
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert prompts == [TARGET_PROMPT, TIME_PROMPT]  # EXACTLY two questions
    assert captured["target"] == REMOTE_URL
    assert captured["max_wall_seconds"] == pytest.approx(1800.0)
    assert "engine started" in out


# -- 2 --------------------------------------------------------------------------


def test_interactive_blank_time_uses_default(tmp_path, monkeypatch):
    """Blank time -> 7200s; with budget.wall_seconds set, THAT wins."""
    from hunter.cli.daemon import _cmd_start

    captured: dict = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)
    state = tmp_path / "state"

    prompts: list = []
    code = _cmd_start(
        target=None, scope=None, engine=None, time_text=None, min_time_text=None,
        budget_text=None, yes=False, force=False, state=state,
        interactive_ask=_record_ask([REMOTE_URL, ""], prompts),
    )
    assert code == 0
    assert captured["max_wall_seconds"] == pytest.approx(7200.0)
    assert prompts == [TARGET_PROMPT, TIME_PROMPT]

    # A configured wall_seconds overrides the 2h default.
    _seed_config("budget:\n  wall_seconds: 3600\n")
    prompts2: list = []
    code2 = _cmd_start(
        target=None, scope=None, engine=None, time_text=None, min_time_text=None,
        budget_text=None, yes=False, force=False, state=state,
        interactive_ask=_record_ask([REMOTE_URL, ""], prompts2),
    )
    assert code2 == 0
    assert captured["max_wall_seconds"] == pytest.approx(3600.0)
    assert "[2h]" not in prompts2[1]  # the bracket renders the resolved default


# -- 3 --------------------------------------------------------------------------


def test_interactive_blank_target_cancels_cleanly(tmp_path, monkeypatch, capsys):
    from hunter.cli.daemon import _cmd_start

    starts: list = []

    def fake_start(state_dir, **kwargs):
        starts.append(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)
    state = tmp_path / "state"

    code = _cmd_start(
        target=None, scope=None, engine=None, time_text=None, min_time_text=None,
        budget_text=None, yes=False, force=False, state=state,
        interactive_ask=_record_ask([""]),
    )
    out = capsys.readouterr().out
    assert code == 0
    assert CANCELLED_LINE in out
    assert starts == []  # nothing spawned
    assert not _config_path().exists()  # nothing recorded


# -- 4 (adversarial: unparsable time) --------------------------------------------


def test_interactive_garbage_time_reasks_then_cancels(tmp_path, monkeypatch, capsys):
    from hunter.cli.daemon import _cmd_start

    prompts: list = []
    answers = [REMOTE_URL, "abc", "still garbage", "nope"]
    starts: list = []

    def fake_start(state_dir, **kwargs):
        starts.append(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    code = _cmd_start(
        target=None, scope=None, engine=None, time_text=None, min_time_text=None,
        budget_text=None, yes=False, force=False, state=tmp_path / "state",
        interactive_ask=_record_ask(answers, prompts),
    )
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert code == 0
    assert combined.count("[Nh][Nm][Ns]") >= 1  # the grammar hint on garbage
    assert len(prompts) == 4  # url, time, re-ask, re-ask
    assert CANCELLED_LINE in combined
    assert starts == []


# -- 5 (Q11 positional + the flag path) -------------------------------------------


def test_non_interactive_flag_path_unchanged(tmp_path, monkeypatch):
    """`hunter start <url> --time 30m` (positional) and `hunt start --target`
    both reach start_daemon with 1800.0 and never prompt."""
    captured: dict = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    def forbidden_ask(prompt, default=""):
        raise AssertionError(f"no prompts on the flag path: {prompt!r}")

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(app, ["start", LOCAL_URL, "--time", "30m", "--state", str(tmp_path)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert captured["target"] == LOCAL_URL
    assert captured["max_wall_seconds"] == pytest.approx(1800.0)

    result2 = runner.invoke(
        app, ["hunt", "start", "--target", LOCAL_URL, "--time", "30m", "--state", str(tmp_path)]
    )
    assert result2.exit_code == 0, (result2.output, result2.exception)
    assert captured["max_wall_seconds"] == pytest.approx(1800.0)
    # interactive_ask was never engaged (the forbidden default above would raise
    # only if the interactive branch fired; assert no prompt artifact instead).
    assert "Target URL:" not in result.output + result2.output


# -- 6 --------------------------------------------------------------------------


def test_non_tty_no_args_boots_idle_engine_with_hint(tmp_path, monkeypatch):
    captured: dict = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(app, ["start", "--state", str(tmp_path)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "engine started — 24/7 engine is on" in result.output  # idle boot kept
    assert "💡 tip: hunt start <url> --time 30m to queue a hunt immediately" in result.output
    assert captured.get("target") in (None, "")


# -- 7 (locked decision 3: auto-authorized minimal scope, recorded) ----------------


def test_auto_authorizes_and_records_approved_scope(tmp_path, monkeypatch):
    state = tmp_path / "state"
    captured: dict = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(app, ["start", REMOTE_URL, "--time", "30m", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    scope = captured.get("scope")
    assert scope is not None and scope.allowed_hosts == frozenset({"example.com"})

    # The audit trail landed in the config.
    raw = yaml.safe_load(_config_path().read_text(encoding="utf-8"))
    scopes = raw["agent"]["approved_scopes"]
    assert len(scopes) == 1
    entry = scopes[0]
    assert entry["host"] == "example.com"
    assert entry["name"] == "example.com"
    assert entry["allow_subdomains"] is False
    assert isinstance(entry["ts"], float) and entry["ts"] > 0
    assert entry["source"] == "hunt-start"


# -- 8 (scope soul: the opt-back-in switch) ----------------------------------------


def test_scope_confirm_true_restores_refusal(tmp_path, monkeypatch):
    _seed_config("agent:\n  scope_confirm: true\n")
    starts: list = []

    def fake_start(state_dir, **kwargs):
        starts.append(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(app, ["start", REMOTE_URL, "--time", "30m", "--state", str(tmp_path)])
    assert result.exit_code == 3, (result.output, result.exception)
    assert "BLOCKED" in result.output
    assert starts == []  # nothing launched
    raw = yaml.safe_load(_config_path().read_text(encoding="utf-8"))
    assert not raw.get("agent", {}).get("approved_scopes")  # nothing recorded


# -- 9 --------------------------------------------------------------------------


def test_approved_scopes_cap_at_50(tmp_path, monkeypatch):
    entries = "\n".join(
        f"    - host: h{i}.example.com\n      name: h{i}.example.com\n      ts: {1700000000.0 + i}\n"
        f"      source: hunt-start"
        for i in range(50)
    )
    _seed_config(f"agent:\n  approved_scopes:\n{entries}\n")

    captured: dict = {}

    def fake_start(state_dir, **kwargs):
        captured.update(kwargs)
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(
        app, ["start", "https://new-host.com", "--time", "30m", "--state", str(tmp_path)]
    )
    assert result.exit_code == 0, (result.output, result.exception)
    raw = yaml.safe_load(_config_path().read_text(encoding="utf-8"))
    scopes = raw["agent"]["approved_scopes"]
    assert len(scopes) == 50  # capped
    hosts = [s["host"] for s in scopes]
    assert "new-host.com" in hosts
    assert "h0.example.com" not in hosts  # the OLDEST was evicted
    assert hosts[-1] == "new-host.com"  # appended last


# -- 10 -------------------------------------------------------------------------


def test_localhost_never_recorded(tmp_path, monkeypatch):
    seeded = _seed_config("agent:\n  tier: basic\n")
    before = seeded.read_bytes()

    def fake_start(state_dir, **kwargs):
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(app, ["start", LOCAL_URL, "--time", "30m", "--state", str(tmp_path)])
    assert result.exit_code == 0, (result.output, result.exception)
    assert seeded.read_bytes() == before  # the config was NOT written


# -- 11 -------------------------------------------------------------------------


def test_pause_flag_prepends_paused_line(tmp_path, monkeypatch):

    state = tmp_path / "state"
    (state / "daemon").mkdir(parents=True)
    (state / "daemon" / "pause.flag").write_text("", encoding="utf-8")

    def fake_start(state_dir, **kwargs):
        return 0

    _patch_engine_bits(monkeypatch)
    _patch_daemon_fn(monkeypatch, "start_daemon", fake_start)

    result = runner.invoke(app, ["start", LOCAL_URL, "--time", "30m", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    text = result.output
    assert PAUSED_LINE in text
    assert "engine started" in text
    assert text.index(PAUSED_LINE) < text.index("engine started")  # the line comes FIRST


# -- 12 (chat /hunt alignment) -----------------------------------------------------


def _chat_engine(tmp_path, ask=None):
    store = ChatStore()
    options = {"state_dir": str(tmp_path), "verbosity": "normal"}
    if ask is not None:
        options["ask_fn"] = ask
    engine = ChatEngine(
        store=store, config=default_config(), provider=_FakeProvider(), options=options,
    )
    return engine, store


def test_chat_hunt_two_question_flow(tmp_path, monkeypatch):
    import hunter.chat.commands as commands_module

    enqueued: list = []

    monkeypatch.setattr(commands_module, "daemon_running", lambda state_dir: (True, "ok"))
    monkeypatch.setattr(
        commands_module, "enqueue_hunts",
        lambda state_dir, tasks: (enqueued.extend(tasks) or len(tasks)),
    )

    prompts: list = []
    answers = [LOCAL_URL, "30m"]

    def ask(prompt: str, default: str = "") -> str:
        prompts.append(prompt)
        return answers.pop(0) if answers else "30m"  # later asks take 30m

    engine, store = _chat_engine(tmp_path, ask=ask)
    try:
        reply = engine.handle_text("/hunt")
        assert "queued" in reply.text
        assert prompts == [TARGET_PROMPT, TIME_PROMPT]  # the same two questions
        assert len(enqueued) == 1
        assert enqueued[0]["target"] == LOCAL_URL
        assert enqueued[0]["max_wall_seconds"] == pytest.approx(1800.0)

        # `/hunt <target>` asks ONLY the time question.
        prompts.clear()
        reply2 = engine.handle_text(f"/hunt {LOCAL_URL}")
        assert "queued" in reply2.text
        assert len(prompts) == 1 and prompts[0].startswith("Time —")
        assert len(enqueued) == 2
    finally:
        store.close()

    # Headless (no ask_fn): no questions, nothing queued.
    engine2, store2 = _chat_engine(tmp_path)
    try:
        monkeypatch.setattr(
            commands_module, "enqueue_hunts",
            lambda state_dir, tasks: (_ for _ in ()).throw(AssertionError("headless must not queue")),
        )
        reply3 = engine2.handle_text("/hunt")
        assert "queued" not in reply3.text
    finally:
        store2.close()


# -- 13 (Q3: the chat manifest gate is NOT loosened) --------------------------------


def test_chat_hunt_keeps_manifest_gate(tmp_path, monkeypatch):
    import hunter.chat.commands as commands_module

    monkeypatch.setattr(commands_module, "daemon_running", lambda state_dir: (True, "ok"))
    monkeypatch.setattr(
        commands_module, "enqueue_hunts",
        lambda state_dir, tasks: (_ for _ in ()).throw(AssertionError("refused hunts never queue")),
    )

    prompts: list = []
    ask = _record_ask(["30m"], prompts)
    engine, store = _chat_engine(tmp_path, ask=ask)
    try:
        reply = engine.handle_text("/hunt http://evil.example.com")
        assert "scope manifest" in reply.text  # the unchanged refusal
        assert len(prompts) == 1  # only the time question was asked first
        raw = _config_path()
        assert not raw.exists() or "approved_scopes" not in raw.read_text(encoding="utf-8")
    finally:
        store.close()


# -- 14 (regression: plain `hunter hunt` keeps its confirm gate) ---------------------


def test_plain_hunt_confirmation_untouched(monkeypatch, tmp_path):
    import hunter.hunt as hunt_module

    prompts: list = []

    def recording_confirm(prompt: str) -> bool:
        prompts.append(prompt)
        return False  # decline: nothing runs

    monkeypatch.setattr(hunt_module, "confirm_prompt", recording_confirm)

    result = runner.invoke(app, ["hunt", LOCAL_URL, "--state", str(tmp_path)])
    assert result.exit_code == 3, (result.output, result.exception)
    assert len(prompts) == 1 and "Authorize this exact scope" in prompts[0]
    assert "BLOCKED" in result.output
