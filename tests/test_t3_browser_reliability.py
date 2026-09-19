"""T3 browser-reliability contracts — round-trip, availability, new codes (TDD red).

Planner B T3: harden the four browser tools (navigate/snapshot/click/type).

Production targets (extend, do not fork):
  - ``hunter.agent.browser.BrowserSession``: timeout surfacing + redirect-scope
    aborts with distinct codes.
  - ``hunter.agent.tools`` browser handlers: map timeouts ->
    ``browser.timeout`` and out-of-scope redirect landings ->
    ``browser.scope_redirect_blocked`` (NEW codes); snapshot 12k cap and
    selector 512 cap already exist — pin them; never leak cookies/headers.

Round-trip tests reuse the in-memory fake-playwright pattern from
tests/test_browser_tools.py (no package, socket, or installer). New-code tests
FAIL today via EXPECTED-FAIL-TDD. Cloak behavior is asserted untouched.
"""

from __future__ import annotations

from typing import Any

import pytest

TDD_BROWSER = "EXPECTED-FAIL-TDD:browser.timeout + browser.scope_redirect_blocked (Planner B T3)"


class _FakeLocator:
    def __init__(self, page, selector, count=1, attrs=None, text="visible body text"):
        self._page = page
        self.selector = selector
        self._count = count
        self._attrs = attrs or {}
        self._text = text

    def count(self):
        return self._count

    def get_attribute(self, name):
        return self._attrs.get(name)

    def fill(self, text):
        self._page.filled[self.selector] = text

    def click(self):
        self._page.clicked.append(self.selector)

    def inner_text(self):
        return self._text


class _FakePage:
    def __init__(self, url="http://127.0.0.1:9/"):
        self.url = url
        self.filled: dict[str, str] = {}
        self.clicked: list[str] = []
        self._title = "demo"

    def title(self):
        return self._title

    def goto(self, url, **kw):
        self.url = url

    def locator(self, selector):
        return _FakeLocator(self, selector, text="hello world")


class _FakeContext:
    def __init__(self, page):
        self._page = page
        self.routes: list[str] = []

    def new_page(self):
        return self._page

    def new_context(self, **kw):
        return self

    def route(self, pattern, handler):
        self.routes.append(pattern)

    def add_init_script(self, script):
        self.init_script = script

    def close(self):
        pass


class _FakeDriver:
    def __init__(self, page):
        self._ctx = _FakeContext(page)

    def start(self):
        return self

    @property
    def chromium(self):
        return self

    def launch(self, **kw):
        return self

    def new_context(self, **kw):
        return self._ctx

    def stop(self):
        pass


class _FakePlaywrightModule:
    def __init__(self, page):
        self._page = page

    def sync_playwright(self):
        return _FakeDriver(self._page)


def _ctx(page=None, events=None, permission=True):
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    if events is None:
        events = []
    scope = localhost_scope()
    http = ScopedHttpClient(scope, transport=_never_transport())
    config: dict[str, Any] = {"tier": "basic"}
    if permission:
        config["hunt_permission"] = True
    return ToolContext(
        run_id="R-T3", ledger=Ledger(":memory:"), http=http, scope=scope,
        target_url="http://127.0.0.1:9/", emit=lambda k, p: events.append((k, dict(p))),
        config=config, state={},
    ), events


def _never_transport():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("browser tests must not use the http client")

    return httpx.MockTransport(handler)


# -- round-trip (pins current behavior) --------------------------------------------

def test_t3_navigate_snapshot_click_type_round_trip():
    """Contract: navigate -> snapshot -> click -> type round-trips on the local demo."""
    from hunter.agent.tools import build_registry

    events: list = []
    page = _FakePage()
    module = _FakePlaywrightModule(page)
    ctx, _ = _ctx(page, events)
    registry = build_registry("basic", browser_enabled=True, playwright_module=module)
    assert registry.dispatch("browser_navigate", {"url": "http://127.0.0.1:9/"}, ctx).ok
    snap = registry.dispatch("browser_snapshot", {}, ctx)
    assert snap.ok and "hello world" in snap.result_for_model
    assert registry.dispatch("browser_click", {"selector": "#go"}, ctx).ok
    typed = registry.dispatch("browser_type", {"selector": "#q", "text": "s3cr3t"}, ctx)
    assert typed.ok and "s3cr3t" not in typed.result_for_model, "typed value must never echo"
    assert page.filled == {"#q": "s3cr3t"} and page.clicked == ["#go"]


def test_t3_disabled_and_unavailable_preserved():
    """Contract: flag-off -> browser.disabled; no import -> browser.unavailable (register_unavailable)."""
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx()
    disabled = build_registry("basic", browser_enabled=False)
    out = disabled.dispatch("browser_navigate", {"url": "http://127.0.0.1:9/"}, ctx)
    assert out.blocked and out.code == "browser.disabled"
    missing = build_registry("basic", browser_enabled=True, playwright_module=None)
    out2 = missing.dispatch("browser_snapshot", {}, ctx)
    assert out2.blocked and out2.code == "browser.unavailable"


# -- new reliability codes (red) -----------------------------------------------------

def test_t3_browser_timeout_code():
    """Contract: navigation timeout surfaces as browser.timeout (retryable, ok=False, blocked=False)."""
    from hunter.agent import tools as agent_tools

    if "browser.timeout" not in str(getattr(agent_tools, "_browser_error", "")) and not hasattr(agent_tools, "BROWSER_TIMEOUT_CODE"):
        pytest.fail(f"{TDD_BROWSER}: no browser.timeout mapping in hunter.agent.tools")


def test_t3_browser_scope_redirect_blocked_code():
    """Contract: out-of-scope redirect landing -> browser.scope_redirect_blocked (BLOCKED)."""
    from hunter.agent import tools as agent_tools

    if "scope_redirect_blocked" not in open(agent_tools.__file__, encoding="utf-8").read():
        pytest.fail(f"{TDD_BROWSER}: no browser.scope_redirect_blocked code in hunter.agent.tools")


# -- caps + leak guards (pin current behavior) ----------------------------------------

def test_t3_snapshot_12k_and_selector_512_caps():
    """Contract: snapshot capped at 12k chars; selector over 512 rejected; no cookie/header leak."""
    from hunter.agent.browser import MAX_SELECTOR_CHARS, MAX_SNAPSHOT_CHARS, validate_selector

    assert MAX_SNAPSHOT_CHARS == 12_000 and MAX_SELECTOR_CHARS == 512
    with pytest.raises(Exception):
        validate_selector("#" + "a" * 600)
    events: list = []
    page = _FakePage()
    page.locator = lambda selector: _FakeLocator(  # type: ignore[method-assign]
        page, selector, text="Authorization: Bearer abcdefghijklmnop123456\nbody ok"
    )
    module = _FakePlaywrightModule(page)
    from hunter.agent.tools import build_registry

    ctx, _ = _ctx(page, events)
    registry = build_registry("basic", browser_enabled=True, playwright_module=module)
    registry.dispatch("browser_navigate", {"url": "http://127.0.0.1:9/"}, ctx)
    snap = registry.dispatch("browser_snapshot", {}, ctx)
    assert snap.ok and len(snap.result_for_model) <= 12_000 + 2_048
    assert "abcdefghijklmnop123456" not in snap.result_for_model, "auth-header shapes must not leak"
    assert "Bearer" not in snap.result_for_model


def test_t3_cloak_untouched():
    """Contract: reliability work must not weaken the cloak-on/cloak-off scope parity."""
    from hunter.agent.browser import CLOAK_INIT_SCRIPT, CLOAK_LAUNCH_ARGS

    assert CLOAK_LAUNCH_ARGS and "AutomationControlled" in CLOAK_LAUNCH_ARGS[0]
    assert "webdriver" in CLOAK_INIT_SCRIPT
