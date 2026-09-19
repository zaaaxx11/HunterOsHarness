"""M8 F5 — browser cloak (test-first).

Local minimal fake Playwright graph with the same shape as the fakes in
tests/test_browser_tools.py (defined in-file per the plan). Pins: cloak ON
adds stealth launch args + fingerprint context kwargs + ONE masking init
script; cloak OFF is byte-identical to today's stock behavior; the scope
route interceptor is ALWAYS installed and still aborts out-of-scope requests
when cloak is on; the loader's ``agent.browser_cloak`` key flows through the
factory seam. No Playwright package, executable, socket, or installer.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import ScopeViolation, localhost_scope

CLOAK_VIEWPORT_POOL = {(1280, 720), (1366, 768), (1440, 900), (1536, 864), (1920, 1080)}
CLOAK_LOCALE_POOL = {"en-US", "en-GB"}
CLOAK_TIMEZONE_POOL = {"UTC", "America/New_York", "Europe/London"}


# -- fake Playwright graph ---------------------------------------------------------


class FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url


class FakeRoute:
    def __init__(self, request: FakeRequest) -> None:
        self.request = request
        self.continued = False
        self.aborted = False

    def continue_(self) -> None:
        self.continued = True

    def abort(self) -> None:
        self.aborted = True


class FakeBodyLocator:
    def inner_text(self) -> str:
        return "cloak body"

    def count(self) -> int:
        return 1


class FakePage:
    def __init__(self, *, request_urls: list[str] | None = None) -> None:
        self.url = ""
        self.route_handler: Any = None
        self.routes: list[FakeRoute] = []
        self.request_urls = request_urls

    def goto(self, url: str, **kwargs: Any) -> None:
        request_urls = self.request_urls if self.request_urls is not None else [url]
        if self.route_handler is not None:
            for request_url in request_urls:
                route = FakeRoute(FakeRequest(request_url))
                self.routes.append(route)
                self.route_handler(route)
                if route.aborted:
                    raise ScopeViolation(f"blocked request: {request_url}")
        self.url = url

    def title(self) -> str:
        return "cloak page"

    def locator(self, selector: str) -> FakeBodyLocator:
        return FakeBodyLocator()

    def close(self) -> None:
        return None


class FakeContext:
    def __init__(self, page: FakePage) -> None:
        self.page = page
        self.route_calls: list[tuple[str, Any]] = []
        self.init_scripts: list[str] = []
        self.close_count = 0

    def new_page(self) -> FakePage:
        return self.page

    def route(self, pattern: str, handler: Any) -> None:
        self.route_calls.append((pattern, handler))
        self.page.route_handler = handler

    def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    def close(self) -> None:
        self.close_count += 1


class FakeBrowser:
    def __init__(self, context: FakeContext) -> None:
        self.context = context
        self.new_context_calls: list[dict[str, Any]] = []
        self.close_count = 0

    def new_context(self, **kwargs: Any) -> FakeContext:
        self.new_context_calls.append(dict(kwargs))
        return self.context

    def close(self) -> None:
        self.close_count += 1


class FakeDriver:
    def __init__(self, page: FakePage) -> None:
        self.page = page
        self.context = FakeContext(page)
        self.browser = FakeBrowser(self.context)
        self.chromium = self
        self.launch_calls: list[dict[str, Any]] = []
        self.stop_count = 0

    def launch(self, **kwargs: Any) -> FakeBrowser:
        self.launch_calls.append(dict(kwargs))
        return self.browser

    def stop(self) -> None:
        self.stop_count += 1


class FakeStarter:
    def __init__(self, driver: FakeDriver) -> None:
        self.driver = driver

    def start(self) -> FakeDriver:
        return self.driver


class FakePlaywrightModule:
    def __init__(self, page_factory: Any = None) -> None:
        self.page_factory = page_factory or (lambda: FakePage())
        self.drivers: list[FakeDriver] = []

    def sync_playwright(self) -> FakeStarter:
        driver = FakeDriver(self.page_factory())
        self.drivers.append(driver)
        return FakeStarter(driver)


# -- helpers ------------------------------------------------------------------------


def _navigate(module: FakePlaywrightModule, *, cloak: bool | None = None, rng: random.Random | None = None):
    """Build a BrowserSession through the pinned constructor kwargs."""
    from hunter.agent.browser import BrowserSession

    kwargs: dict[str, Any] = {}
    if cloak is not None:
        kwargs["cloak"] = cloak
    if rng is not None:
        kwargs["cloak_rng"] = rng
    session = BrowserSession(localhost_scope(), playwright_module=module, **kwargs)
    session.navigate("http://127.0.0.1/")
    return module.drivers[0]


# -- tests --------------------------------------------------------------------------


def test_cloak_on_launch_args_and_context_fingerprint():
    driver = _navigate(FakePlaywrightModule(), cloak=True)
    launch = driver.launch_calls[0]
    assert launch.get("headless") is True
    assert "--disable-blink-features=AutomationControlled" in launch.get("args", [])
    context_kwargs = driver.browser.new_context_calls[0]
    for key in ("user_agent", "viewport", "locale", "timezone_id"):
        assert key in context_kwargs
    assert context_kwargs["locale"] in CLOAK_LOCALE_POOL
    assert context_kwargs["timezone_id"] in CLOAK_TIMEZONE_POOL
    assert tuple(context_kwargs["viewport"]) in CLOAK_VIEWPORT_POOL
    assert isinstance(context_kwargs["user_agent"], str) and context_kwargs["user_agent"]


def test_cloak_off_is_stock_browser():
    driver = _navigate(FakePlaywrightModule(), cloak=False)
    assert driver.launch_calls == [{"headless": True}]  # no stealth args
    assert driver.browser.new_context_calls == [{}]  # bare context
    assert driver.context.init_scripts == []  # no init scripts


def test_cloak_seeded_rng_deterministic_and_pools():
    from hunter.agent.browser import CLOAK_USER_AGENTS

    driver_a = _navigate(FakePlaywrightModule(), rng=random.Random(1234))
    driver_b = _navigate(FakePlaywrightModule(), rng=random.Random(1234))
    assert driver_a.launch_calls[0].get("args") == driver_b.launch_calls[0].get("args")
    kwargs_a = driver_a.browser.new_context_calls[0]
    kwargs_b = driver_b.browser.new_context_calls[0]
    assert kwargs_a == kwargs_b  # same seed -> identical fingerprint
    assert kwargs_a["user_agent"] in CLOAK_USER_AGENTS
    assert tuple(kwargs_a["viewport"]) in CLOAK_VIEWPORT_POOL
    assert kwargs_a["locale"] in CLOAK_LOCALE_POOL
    assert kwargs_a["timezone_id"] in CLOAK_TIMEZONE_POOL


def test_cloak_init_scripts_mask_webdriver():
    driver = _navigate(FakePlaywrightModule(), cloak=True)
    scripts = driver.context.init_scripts
    assert len(scripts) == 1  # exactly ONE masking init script
    text = scripts[0]
    assert "navigator.webdriver" in text
    assert "plugins" in text
    assert "languages" in text


def test_cloak_interceptor_still_installed():
    driver = _navigate(FakePlaywrightModule(), cloak=True)
    patterns = [pattern for pattern, _handler in driver.context.route_calls]
    assert patterns == ["**/*"]  # the scope interceptor is installed under cloak


def test_cloak_out_of_scope_still_aborts():
    page = FakePage(request_urls=["http://127.0.0.1/", "https://evil.example/redirect"])
    module = FakePlaywrightModule(page_factory=lambda: page)
    from hunter.agent.browser import BrowserSession

    session = BrowserSession(localhost_scope(), playwright_module=module, cloak=True)
    with pytest.raises(ScopeViolation):
        session.navigate("http://127.0.0.1/")
    assert page.routes[0].continued is True
    assert page.routes[-1].aborted is True  # cloak must not weaken the scope gate


def test_browser_cloak_config_key_flows(tmp_path):
    from hunter.agent.tools import build_registry
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.llm.config import default_config, load_config

    assert default_config().agent.browser_cloak is True
    path = tmp_path / "config.yaml"
    path.write_text("agent:\n  browser_cloak: false\n", encoding="utf-8")
    assert load_config(path, env={}, home=tmp_path).agent.browser_cloak is False

    def tool_context(tier_config: dict[str, Any]) -> ToolContext:
        ledger = Ledger(tmp_path / f"ledger-{abs(hash(str(tier_config)))}.db")
        http = ScopedHttpClient(localhost_scope(), min_interval=0)
        ctx = ToolContext(
            run_id="R-CLOAK",
            ledger=ledger,
            http=http,
            scope=localhost_scope(),
            target_url="http://127.0.0.1/",
            emit=lambda kind, payload: None,
            # hunt_permission=True mirrors a real audit ToolContext (the
            # production hunt gate lives in agent/tools.py and stays intact);
            # this test verifies cloak-config FLOW, not the permission gate.
            config={
                "tier": "basic",
                "browser_enabled": True,
                "hunt_permission": True,
                **tier_config,
            },
        )
        return ctx

    # browser_cloak: False reaches BrowserSession(cloak=...) through the factory
    module_off = FakePlaywrightModule()
    registry = build_registry("basic", browser_enabled=True, playwright_module=module_off)
    ctx = tool_context({"browser_cloak": False})
    try:
        outcome = registry.dispatch("browser_navigate", {"url": "http://127.0.0.1/"}, ctx)
        assert outcome.ok is True, outcome.result_for_model
        driver = module_off.drivers[0]
        assert driver.launch_calls == [{"headless": True}]
        assert driver.browser.new_context_calls == [{}]
        assert driver.context.init_scripts == []
    finally:
        ctx.close_browser()
        ctx.http.close()
        ctx.ledger.close()

    # absent key -> default cloak ON (stealth args present)
    module_on = FakePlaywrightModule()
    registry_default = build_registry("basic", browser_enabled=True, playwright_module=module_on)
    ctx = tool_context({})
    try:
        outcome = registry_default.dispatch("browser_navigate", {"url": "http://127.0.0.1/"}, ctx)
        assert outcome.ok is True, outcome.result_for_model
        driver = module_on.drivers[0]
        assert "--disable-blink-features=AutomationControlled" in driver.launch_calls[0].get("args", [])
        assert driver.context.init_scripts
    finally:
        ctx.close_browser()
        ctx.http.close()
        ctx.ledger.close()
