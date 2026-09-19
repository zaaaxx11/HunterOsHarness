import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# M11 shared fixtures (spec docs/plans/m11-ux.md §13) — ADDITIVE ONLY.
# The sys.path bootstrap above is untouched. No hunter module is imported at
# module scope: fixtures and tests import hunter lazily so a missing M11
# implementation fails a test, never the collection.
# ===========================================================================

import pytest  # noqa: E402  (after the sys.path bootstrap, per repo pattern)

_ISOLATED_ENV_VARS = (
    "HUNTER_STATE_DIR",
    "HUNTEROS_CONFIG",
    "HUNTEROS_KEYS_FILE",
    "HUNTEROS_CHAT_DB",
    "HUNTEROS_MODEL",
    "HUNTEROS_TIER",
    "HUNTEROS_BUDGET_USD",
    "HUNTEROS_MAX_ITERATIONS",
    "HUNTEROS_DRAIN_TIMEOUT",
    "HUNTEROS_ONBOARD_DECLINED",
    "HUNTEROS_VERBOSE",
)


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Every test runs with a private HOME/USERPROFILE and a quiet update
    check (spec §13). Test-level monkeypatch overrides still win — they run
    later than this autouse fixture. Nothing may touch the real ``~/.hunter``
    or ``~/.hunteros`` in the suite.

    The home directory is deliberately NOT pre-created: migration and
    first-boot tests model the first-run experience by calling
    ``home.mkdir()`` themselves (and some assert on the pre-existing state),
    so a pre-created directory would make those tests fail with a
    ``FileExistsError`` or hide first-boot behavior. Production code always
    creates the home on demand, so tests that never mkdir still work."""
    home = tmp_path / "hunter-home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for var in _ISOLATED_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    yield home


class _StringConsole:
    """Scripted rich.Console stand-in (test_chat_repl.FakeConsole convention):
    records prints as plain text, pops scripted inputs, ``is_terminal=False``.

    Used directly by tests that need a console object; the ``fake_console``
    fixture below is the factory. Prints survive rich renderables (Text
    ``.plain``, Markdown ``.markup``, Panel ``.renderable`` recursion)."""

    is_terminal = False

    def __init__(self, inputs=()) -> None:
        self._inputs = list(inputs)
        self.printed: list[str] = []

    def print(self, *args, **kwargs) -> None:
        for arg in args:
            self.printed.append(stringify_renderable(arg))

    def input(self, prompt: str = "") -> str:
        self.printed.append(prompt)
        item = self._inputs.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def text(self) -> str:
        return "\n".join(self.printed)


def stringify_renderable(renderable) -> str:
    """Pull plain text out of the rich renderables hunter prints."""
    if hasattr(renderable, "plain"):  # rich.text.Text
        return renderable.plain
    if hasattr(renderable, "markup"):  # rich.markdown.Markdown
        return renderable.markup
    if hasattr(renderable, "renderable"):  # rich.panel.Panel etc.
        return stringify_renderable(renderable.renderable)
    return str(renderable)


@pytest.fixture
def fake_console():
    """Factory for a string-console: ``con = fake_console(["y"])`` records
    prints and scripts ``input()`` replies (an Exception entry is raised);
    ``fake_console()`` scripts none (first input raises IndexError)."""
    return _StringConsole


class _ScriptedAsk:
    """Needle-matching ask/secret pair (spec §13): the script is a list of
    ``(needle, reply)`` pairs, most-specific needle FIRST. A reply of ``""``
    means "take the prompt's default"; an Exception instance is raised
    (KeyboardInterrupt/EOFError scripting). A prompt matching no needle
    raises AssertionError — tests must script every prompt they expect."""

    def __init__(self, script=()) -> None:
        self.script = list(script)
        self.prompts: list[str] = []
        self.secret_prompts: list[str] = []

    def _reply_for(self, prompt: str, bucket: list[str]):
        bucket.append(prompt)
        for needle, reply in self.script:
            if needle in prompt:
                if isinstance(reply, BaseException):
                    raise reply
                return reply
        raise AssertionError(
            f"scripted_ask: no needle matched prompt {prompt!r} "
            f"(script needles: {[n for n, _ in self.script]!r})"
        )

    def ask(self, prompt: str, default: str = "") -> str:
        reply = self._reply_for(prompt, self.prompts)
        return default if reply == "" else str(reply)

    def secret(self, prompt: str = "") -> str:
        return str(self._reply_for(prompt, self.secret_prompts))


@pytest.fixture
def scripted_ask():
    """Factory for the needle-matching ask/secret pair:
    ``sa = scripted_ask([("Target URL", url), ("Time", "30m")])`` — pass
    ``sa.ask`` / ``sa.secret`` into wizard seams; inspect ``sa.prompts``."""
    return _ScriptedAsk


class _FakeLiteLLMModule:
    """Zero-network litellm module double for the router seam
    (``ProviderRouter(config, litellm_module=...)``). Records every
    ``completion(**kwargs)`` call and returns a fixed completion object."""

    name = "fake-litellm"

    def __init__(self, reply_text: str = "ok", model: str = "fake-model") -> None:
        self.reply_text = reply_text
        self.wire_model = model
        self.calls: list[dict] = []
        self.fail_after: int | None = None

    def completion(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_after is not None and len(self.calls) > self.fail_after:
            raise RuntimeError("fake litellm exhausted")
        return _fake_completion(self.reply_text, self.wire_model)

    def completion_cost(self, _response) -> float:
        return 0.0


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls = []


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)
        self.finish_reason = "stop"


class _FakeUsage:
    prompt_tokens = 3
    completion_tokens = 2


class _FakeResponse:
    def __init__(self, content: str, model: str) -> None:
        self.choices = [_FakeChoice(content)]
        self.usage = _FakeUsage()
        self.model = model


def _fake_completion(content: str, model: str) -> _FakeResponse:
    return _FakeResponse(content, model)


@pytest.fixture
def fake_litellm():
    """Factory for the zero-network litellm seam double:
    ``llm = fake_litellm("reply")`` then
    ``ProviderRouter(cfg, litellm_module=llm)``; inspect ``llm.calls``."""
    return _FakeLiteLLMModule


@pytest.fixture
def no_update_check(monkeypatch):
    """Explicit update-check silencing — covered by the autouse
    ``isolated_home`` fixture; kept for clarity (spec §13)."""
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")

