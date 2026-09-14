"""M6 browser-tool acceptance tests.

These tests are intentionally written against the design seams before the M6
implementation exists.  All browser behavior uses the small in-memory fake
Playwright graph below: no Playwright package, executable, socket, or installer
is involved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from hunter.agent.loop import AgentLoop
from hunter.agent.tools_base import ToolContext
from hunter.kernel.ledger import Ledger
from hunter.llm.base import ToolCall, TurnResult
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import ScopeViolation, localhost_scope

BROWSER_NAMES = {
    "browser_click",
    "browser_navigate",
    "browser_snapshot",
    "browser_type",
}
SENTINEL = "m6-typed-secret-never-returned-314159"


@pytest.fixture(autouse=True)
def sandbox_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("HUNTER_STATE_DIR", raising=False)
    monkeypatch.delenv("HUNTEROS_CONFIG", raising=False)


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


class FakeLocator:
    def __init__(
        self,
        selector: str,
        *,
        count: int = 1,
        attributes: dict[str, str] | None = None,
        body_text: str = "",
        page: FakePage | None = None,
    ) -> None:
        self.selector = selector
        self.match_count = count
        self.attributes = attributes or {}
        self.body_text = body_text
        self.page = page
        self.fill_values: list[str] = []
        self.click_count = 0
        self.attribute_reads: list[str] = []

    def count(self) -> int:
        return self.match_count

    def get_attribute(self, name: str) -> str | None:
        self.attribute_reads.append(name)
        return self.attributes.get(name)

    def fill(self, text: str) -> None:
        self.fill_values.append(text)

    def click(self) -> None:
        self.click_count += 1

    def inner_text(self) -> str:
        return self.body_text


class FakePage:
    def __init__(
        self,
        *,
        url: str = "",
        title: str = "Fake page",
        body_text: str = "fake body",
        locators: dict[str, FakeLocator] | None = None,
        request_urls: list[str] | None = None,
        final_url: str | None = None,
        close_raises: bool = False,
    ) -> None:
        self.url = url
        self._title = title
        self.goto_calls: list[tuple[str, dict[str, Any]]] = []
        self.locator_calls: list[str] = []
        self.route_handler: Any = None
        self.routes: list[FakeRoute] = []
        self.route_errors: list[BaseException] = []
        self.request_urls = request_urls
        self.final_url = final_url
        self.close_count = 0
        self.close_raises = close_raises
        self.forbidden_api_calls: list[str] = []
        self.locators = locators or {}
        self.body = FakeLocator("body", body_text=body_text, page=self)
        for locator in self.locators.values():
            locator.page = self

    def goto(self, url: str, **kwargs: Any) -> None:
        self.goto_calls.append((url, dict(kwargs)))
        request_urls = self.request_urls if self.request_urls is not None else [url]
        if self.route_handler is not None:
            for request_url in request_urls:
                route = FakeRoute(FakeRequest(request_url))
                self.routes.append(route)
                try:
                    self.route_handler(route)
                except BaseException as exc:
                    self.route_errors.append(exc)
                    raise
                if route.aborted:
                    raise ScopeViolation(f"blocked request: {request_url}")
        self.url = self.final_url or url

    def title(self) -> str:
        return self._title

    def locator(self, selector: str) -> FakeLocator:
        self.locator_calls.append(selector)
        if selector == "body":
            return self.body
        return self.locators.get(selector, FakeLocator(selector, count=0, page=self))

    def close(self) -> None:
        self.close_count += 1
        if self.close_raises:
            raise RuntimeError("cleanup sentinel")

    def __getattr__(self, name: str) -> Any:
        if name in {"cookies", "local_storage", "session_storage", "headers", "evaluate"}:
            self.forbidden_api_calls.append(name)
            raise AssertionError(f"forbidden browser API accessed: {name}")
        raise AttributeError(name)


class FakeContext:
    def __init__(self, page: FakePage) -> None:
        self.page = page
        self.route_calls: list[tuple[str, Any]] = []
        self.close_count = 0

    def new_page(self) -> FakePage:
        return self.page

    def route(self, pattern: str, handler: Any) -> None:
        self.route_calls.append((pattern, handler))
        self.page.route_handler = handler

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
        self.browser.context = self.context

    def launch(self, **kwargs: Any) -> FakeBrowser:
        self.launch_calls.append(dict(kwargs))
        return self.browser

    def stop(self) -> None:
        self.stop_count += 1


class FakePlaywrightStarter:
    def __init__(self, driver: FakeDriver) -> None:
        self.driver = driver
        self.start_count = 0

    def start(self) -> FakeDriver:
        self.start_count += 1
        return self.driver


class FakePlaywrightModule:
    """A deterministic replacement for only the sync Playwright calls used."""

    def __init__(self, page_factory: Any = None) -> None:
        self.page_factory = page_factory or (lambda _index: FakePage())
        self.drivers: list[FakeDriver] = []
        self.starters: list[FakePlaywrightStarter] = []

    def sync_playwright(self) -> FakePlaywrightStarter:
        page = self.page_factory(len(self.drivers))
        driver = FakeDriver(page)
        starter = FakePlaywrightStarter(driver)
        self.drivers.append(driver)
        self.starters.append(starter)
        return starter


@dataclass
class BrowserEnv:
    ctx: ToolContext
    ledger: Ledger
    http: ScopedHttpClient
    module: FakePlaywrightModule
    events: list[tuple[str, dict[str, Any]]]


def _browser_factory(scope: Any, module: FakePlaywrightModule):
    def factory() -> Any:
        # The import is deliberately inside the fake factory: normal test
        # collection does not require the optional Playwright implementation.
        from hunter.agent.browser import BrowserSession

        return BrowserSession(scope, playwright_module=module)

    return factory


def _make_env(
    tmp_path: Path,
    module: FakePlaywrightModule,
    *,
    scope: Any | None = None,
    config: dict[str, Any] | None = None,
    browser_factory: Any | None = None,
) -> BrowserEnv:
    actual_scope = scope or localhost_scope()
    ledger = Ledger(tmp_path / "ledger.db")
    http = ScopedHttpClient(actual_scope, min_interval=0)
    events: list[tuple[str, dict[str, Any]]] = []
    ctx = ToolContext(
        run_id="R-M6-TEST",
        ledger=ledger,
        http=http,
        scope=actual_scope,
        target_url="http://127.0.0.1/",
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"tier": "basic", "hunt_permission": True, **(config or {})},
        browser_factory=browser_factory or _browser_factory(actual_scope, module),
    )
    return BrowserEnv(ctx=ctx, ledger=ledger, http=http, module=module, events=events)


def _close_env(env: BrowserEnv) -> None:
    env.ctx.close_browser()
    env.http.close()
    env.ledger.close()


def _registry(*, enabled: bool, module: Any = None):
    from hunter.agent.tools import build_registry

    return build_registry("basic", browser_enabled=enabled, playwright_module=module)


def _browser_action_data(outcome: Any) -> list[dict[str, Any]]:
    if outcome.evidence is None:
        return []
    artifacts = outcome.evidence if isinstance(outcome.evidence, list) else [outcome.evidence]
    return [dict(artifact.get("data") or {}) for artifact in artifacts]


def test_registry_adds_exact_browser_tools_only_when_available():
    from hunter.agent.tools import build_registry

    module = FakePlaywrightModule()
    default_registry = build_registry("basic")
    assert len(default_registry.schemas_for_tier("basic")) == 15
    assert not (BROWSER_NAMES & {s["function"]["name"] for s in default_registry.schemas_for_tier("basic")})
    assert module.drivers == []

    registry = build_registry("basic", browser_enabled=True, playwright_module=module)
    schemas = registry.schemas_for_tier("basic")
    names = [schema["function"]["name"] for schema in schemas]
    assert len(names) == 19
    assert set(names) >= BROWSER_NAMES
    assert names == sorted(names)

    expected = {
        "browser_navigate": (
            {"url": {"type": "string", "minLength": 1, "maxLength": 2048}},
            ["url"],
        ),
        "browser_snapshot": ({}, []),
        "browser_click": (
            {"selector": {"type": "string", "minLength": 1, "maxLength": 512}},
            ["selector"],
        ),
        "browser_type": (
            {
                "selector": {"type": "string", "minLength": 1, "maxLength": 512},
                "text": {"type": "string", "maxLength": 4000},
            },
            ["selector", "text"],
        ),
    }
    for name, (properties, required) in expected.items():
        spec = registry.get(name)
        assert spec is not None
        assert spec.min_tier == "basic"
        schema = next(item["function"] for item in schemas if item["function"]["name"] == name)
        parameters = schema["parameters"]
        assert parameters["properties"] == properties
        assert parameters["required"] == required
        assert parameters["additionalProperties"] is False
        assert "eval" not in json.dumps(parameters).lower()
        assert "script" not in json.dumps(parameters).lower()


def test_browser_disabled_path_has_no_schema_and_no_factory_call(tmp_path):
    module = FakePlaywrightModule()
    factory_calls: list[int] = []
    env = _make_env(
        tmp_path,
        module,
        browser_factory=lambda: factory_calls.append(1),
    )
    try:
        registry = _registry(enabled=False, module=module)
        assert not (BROWSER_NAMES & {s["function"]["name"] for s in registry.schemas_for_tier("basic")})
        outcome = registry.dispatch("browser_navigate", {"url": "http://127.0.0.1/"}, env.ctx)
        assert outcome.ok is False
        assert outcome.blocked is True
        assert outcome.code == "browser.disabled"
        assert factory_calls == []
        assert module.drivers == []
    finally:
        _close_env(env)


def test_missing_playwright_is_graceful_without_install_or_download(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("M6 must not run an installer or subprocess"),
    )
    env = _make_env(tmp_path, FakePlaywrightModule())
    try:
        registry = _registry(enabled=True, module=None)
        assert not (BROWSER_NAMES & {s["function"]["name"] for s in registry.schemas_for_tier("basic")})
        outcome = registry.dispatch(
            "browser_navigate", {"url": "http://127.0.0.1/"}, env.ctx
        )
        assert outcome.ok is False and outcome.blocked is True
        assert outcome.code == "browser.unavailable"
        assert "hunteros-harness[browser]" in outcome.result_for_model
        assert "playwright install chromium" in outcome.result_for_model
        assert env.module.drivers == []
    finally:
        _close_env(env)


def test_tool_context_owns_one_lazy_session_and_idempotent_cleanup(tmp_path):
    module = FakePlaywrightModule()
    env = _make_env(tmp_path, module)
    second_env = None
    try:
        from hunter.agent.browser import BrowserSession

        registry = _registry(enabled=True, module=module)
        assert env.ctx.browser_session is None
        first = registry.dispatch("browser_navigate", {"url": "http://127.0.0.1/"}, env.ctx)
        second = registry.dispatch("browser_snapshot", {}, env.ctx)
        assert first.ok and second.ok
        assert env.ctx.browser_session is not None
        assert len(module.drivers) == 1
        driver = module.drivers[0]
        assert driver.launch_calls == [{"headless": True}]
        assert driver.browser.new_context_calls == [{}]
        assert len(driver.context.route_calls) == 1

        env.ctx.close_browser()
        env.ctx.close_browser()
        assert driver.page.close_count == 1
        assert driver.context.close_count == 1
        assert driver.browser.close_count == 1
        assert driver.stop_count == 1

        second_env = _make_env(tmp_path / "second", module)
        assert second_env.ctx.browser_session is None
        assert registry.dispatch("browser_navigate", {"url": "http://127.0.0.1/"}, second_env.ctx).ok
        assert second_env.ctx.browser_session is not env.ctx.browser_session
        assert len(module.drivers) == 2
        assert isinstance(second_env.ctx.browser_session, BrowserSession)
    finally:
        if second_env is not None:
            _close_env(second_env)
        _close_env(env)


def test_navigation_scope_and_scheme_checked_before_page_goto(tmp_path):
    module = FakePlaywrightModule()
    env = _make_env(tmp_path, module)
    try:
        registry = _registry(enabled=True, module=module)
        evil = registry.dispatch("browser_navigate", {"url": "https://evil.example/"}, env.ctx)
        javascript = registry.dispatch(
            "browser_navigate", {"url": "javascript:alert(1)"}, env.ctx
        )
        assert evil.ok is False and evil.blocked is True
        assert evil.code == "scope.target_out_of_scope"
        assert javascript.ok is False and javascript.blocked is True
        assert javascript.code in {"scope.target_out_of_scope", "browser.url_invalid"}
        assert module.drivers == [] or module.drivers[0].page.goto_calls == []
        assert evil.evidence is None and javascript.evidence is None
    finally:
        _close_env(env)


def test_redirect_route_escape_is_aborted_and_blocked(tmp_path):
    module = FakePlaywrightModule(
        page_factory=lambda _index: FakePage(
            request_urls=["http://127.0.0.1/", "https://evil.example/redirect"],
        )
    )
    env = _make_env(tmp_path, module)
    try:
        registry = _registry(enabled=True, module=module)
        outcome = registry.dispatch("browser_navigate", {"url": "http://127.0.0.1/"}, env.ctx)
        driver = module.drivers[0]
        assert len(driver.context.route_calls) == 1
        assert len(driver.page.routes) == 2
        assert driver.page.routes[0].continued is True
        assert driver.page.routes[1].aborted is True
        assert outcome.ok is False and outcome.blocked is True
        assert outcome.code == "scope.target_out_of_scope"
        assert outcome.evidence is None
        assert all(not route.aborted or not route.continued for route in driver.page.routes)
    finally:
        _close_env(env)


def test_click_preflights_href_and_current_page_scope(tmp_path):
    class RecordingScope:
        def __init__(self) -> None:
            self.base = localhost_scope()
            self.calls: list[str] = []
            self.name = self.base.name

        def check_url(self, url: str) -> str:
            self.calls.append(url)
            return self.base.check_url(url)

        def allows_host(self, host: str | None) -> bool:
            return self.base.allows_host(host)

        def summary(self) -> dict[str, Any]:
            return self.base.summary()

    scope = RecordingScope()
    page = FakePage(
        url="http://127.0.0.1/start",
        locators={
            "#ok": FakeLocator("#ok", attributes={"href": "/next"}),
            "#evil": FakeLocator("#evil", attributes={"href": "https://evil.example/"}),
            "#js": FakeLocator("#js", attributes={"href": "javascript:alert(1)"}),
        },
    )
    module = FakePlaywrightModule(page_factory=lambda _index: page)
    env = _make_env(tmp_path, module, scope=scope)
    try:
        registry = _registry(enabled=True, module=module)
        navigate = registry.dispatch("browser_navigate", {"url": page.url}, env.ctx)
        assert navigate.ok
        ok = registry.dispatch("browser_click", {"selector": "#ok"}, env.ctx)
        evil = registry.dispatch("browser_click", {"selector": "#evil"}, env.ctx)
        javascript = registry.dispatch("browser_click", {"selector": "#js"}, env.ctx)
        page.url = "https://evil.example/current"
        current_page = registry.dispatch("browser_click", {"selector": "#ok"}, env.ctx)

        assert ok.ok
        assert page.locators["#ok"].click_count == 1
        assert evil.ok is False and evil.blocked is True
        assert javascript.ok is False and javascript.blocked is True
        assert current_page.ok is False and current_page.blocked is True
        assert page.locators["#evil"].click_count == 0
        assert page.locators["#js"].click_count == 0
        assert any(url == page.url for url in scope.calls)
        assert all(
            result.code in {"scope.target_out_of_scope", "browser.url_invalid"}
            for result in (evil, javascript, current_page)
        )
    finally:
        _close_env(env)


def test_type_never_echoes_or_records_typed_secret(tmp_path):
    page = FakePage(
        url="http://127.0.0.1/login",
        locators={"#password": FakeLocator("#password")},
    )
    module = FakePlaywrightModule(page_factory=lambda _index: page)
    env = _make_env(tmp_path, module)
    try:
        registry = _registry(enabled=True, module=module)
        assert registry.dispatch("browser_navigate", {"url": page.url}, env.ctx).ok
        outcome = registry.dispatch(
            "browser_type", {"selector": "#password", "text": SENTINEL}, env.ctx
        )
        assert outcome.ok
        assert page.locators["#password"].fill_values == [SENTINEL]
        assert SENTINEL not in outcome.result_for_model
        assert all(SENTINEL not in json.dumps(data) for data in _browser_action_data(outcome))
        assert all(SENTINEL not in json.dumps(payload) for _, payload in env.events)
        assert "text_length" in outcome.result_for_model
        assert str(len(SENTINEL)) in outcome.result_for_model

        class TypeProvider:
            name = "fake-type"

            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
                self.calls.append({"messages": [dict(m) for m in messages], "tools": tools})
                if len(self.calls) == 1:
                    return TurnResult(
                        tool_calls=(
                            ToolCall(
                                id="type-1",
                                name="browser_type",
                                arguments={"selector": "#password", "text": SENTINEL},
                            ),
                        )
                    )
                return TurnResult(
                    tool_calls=(
                        ToolCall(
                            id="yield-1",
                            name="respond_to_user",
                            arguments={"message": "typed"},
                        ),
                    )
                )

            def classify(self, _exc: BaseException) -> Any:
                return SimpleNamespace(reason="unknown")

        provider = TypeProvider()
        result = AgentLoop(provider, registry, tier="basic").run(env.ctx, "type the value")
        assert result.yield_message == "typed"
        all_messages = json.dumps(provider.calls)
        assert SENTINEL not in all_messages
    finally:
        _close_env(env)


def test_selector_injection_is_refused_and_no_evaluate_exists(tmp_path):
    from hunter.agent.browser import BrowserSession

    source = Path(BrowserSession.__module__.replace(".", "/") + ".py")
    if not source.is_absolute():
        source = Path(__file__).parents[1] / "src" / source
    source_text = source.read_text(encoding="utf-8")
    assert "evaluate(" not in source_text
    assert "add_script" not in source_text
    assert "page.evaluate" not in source_text
    assert "locator.evaluate" not in source_text

    page = FakePage(url="http://127.0.0.1/")
    module = FakePlaywrightModule(page_factory=lambda _index: page)
    env = _make_env(tmp_path, module)
    try:
        registry = _registry(enabled=True, module=module)
        assert registry.dispatch("browser_navigate", {"url": page.url}, env.ctx).ok
        page.locator_calls.clear()
        selectors = [
            "xpath=//input",
            "text=Submit",
            "a >> span",
            "javascript:alert(1)",
            "eval(document.body)",
            "#field\n",
            "#" + "x" * 512,
        ]
        outcomes = [
            registry.dispatch("browser_click", {"selector": selector}, env.ctx)
            for selector in selectors
        ]
        assert all(outcome.ok is False and outcome.blocked for outcome in outcomes)
        assert all(outcome.code == "browser.selector_invalid" for outcome in outcomes)
        assert all(selector not in page.locator_calls for selector in selectors)
    finally:
        _close_env(env)


def test_snapshot_redacts_secrets_and_caps_output(tmp_path):
    from hunter.agent.browser import MAX_SNAPSHOT_CHARS

    secret_values = {
        "cookie": "m6-cookie-value-1001",
        "bearer": "m6-bearer-value-1002",
        "api": "m6-api-key-value-1003",
        "token": "m6-token-value-1004",
        "csrf": "m6-csrf-value-1005",
    }
    body = (
        f"cookie={secret_values['cookie']}\n"
        f"Set-Cookie: sid={secret_values['cookie']}\n"
        f"Authorization: Bearer {secret_values['bearer']}\n"
        f"api_key={secret_values['api']} token={secret_values['token']} "
        f"csrf_token={secret_values['csrf']}\n"
        + "visible text " * (MAX_SNAPSHOT_CHARS // 5)
    )
    page = FakePage(url="http://127.0.0.1/", body_text=body)
    module = FakePlaywrightModule(page_factory=lambda _index: page)
    env = _make_env(tmp_path, module)
    try:
        registry = _registry(enabled=True, module=module)
        assert registry.dispatch("browser_navigate", {"url": page.url}, env.ctx).ok
        outcome = registry.dispatch("browser_snapshot", {}, env.ctx)
        assert outcome.ok
        assert "...[snapshot truncated]" in outcome.result_for_model
        assert "truncated" in outcome.result_for_model
        data = _browser_action_data(outcome)[0]
        snapshot = data["snapshot"]
        marker = "...[snapshot truncated]"
        assert data["truncated"] is True
        assert len(snapshot) <= MAX_SNAPSHOT_CHARS + len(marker)
        assert snapshot.endswith(marker)
        for value in secret_values.values():
            assert value not in outcome.result_for_model
            assert all(value not in json.dumps(artifact) for artifact in _browser_action_data(outcome))
        assert page.forbidden_api_calls == []
        assert page.locator_calls.count("body") == 1
    finally:
        _close_env(env)


def test_browser_events_use_loop_evidence_contract(tmp_path):
    page = FakePage(url="http://127.0.0.1/", body_text="safe visible text")
    module = FakePlaywrightModule(page_factory=lambda _index: page)
    env = _make_env(tmp_path, module)
    try:
        registry = _registry(enabled=True, module=module)
        navigate = registry.dispatch("browser_navigate", {"url": page.url}, env.ctx)
        snapshot = registry.dispatch("browser_snapshot", {}, env.ctx)
        blocked = registry.dispatch("browser_navigate", {"url": "https://evil.example/"}, env.ctx)
        assert navigate.evidence is not None
        assert snapshot.evidence is not None
        assert _browser_action_data(navigate)[0]["action"] == "navigate"
        assert _browser_action_data(snapshot)[0]["action"] == "snapshot"
        assert blocked.evidence is None
        assert env.ledger.evidence(env.ctx.run_id) == []

        for name, outcome in (("browser_navigate", navigate), ("browser_snapshot", snapshot)):
            ids = AgentLoop._store_evidence(env.ctx, name, outcome.evidence)
            assert ids
        rows = env.ledger.evidence(env.ctx.run_id)
        assert [row["kind"] for row in rows] == ["browser_event", "browser_event"]
        assert all(row["kind"] != "http_exchange" for row in rows)
        assert all(row["data"]["action"] in {"navigate", "snapshot"} for row in rows)
    finally:
        _close_env(env)


def test_browser_actions_require_hunt_permission(tmp_path):
    module = FakePlaywrightModule()
    factory_calls: list[int] = []
    env = _make_env(
        tmp_path,
        module,
        config={"hunt_permission": None},
        browser_factory=lambda: factory_calls.append(1),
    )
    try:
        registry = _registry(enabled=True, module=module)
        calls = [
            ("browser_navigate", {"url": "http://127.0.0.1/"}),
            ("browser_snapshot", {}),
            ("browser_click", {"selector": "#one"}),
            ("browser_type", {"selector": "#one", "text": "not-used"}),
        ]
        outcomes = [registry.dispatch(name, args, env.ctx) for name, args in calls]
        assert all(outcome.ok is False and outcome.blocked for outcome in outcomes)
        assert all(outcome.code == "permission.hunt_required" for outcome in outcomes)
        assert factory_calls == []
        assert env.ctx.browser_session is None
        assert module.drivers == []
    finally:
        _close_env(env)


def test_llm_run_closes_browser_when_provider_raises(tmp_path, monkeypatch):
    from hunter.agent import tools as tools_module
    from hunter.engine.base import EngineContext, TargetSpec
    from hunter.engine.llm import LLMEngine

    page = FakePage(url="http://127.0.0.1/", close_raises=True)
    module = FakePlaywrightModule(page_factory=lambda _index: page)
    real_build_registry = tools_module.build_registry

    def build_with_fake(tier: str = "basic", **kwargs: Any) -> Any:
        return real_build_registry(
            tier,
            browser_enabled=True,
            playwright_module=module,
        )

    monkeypatch.setattr(tools_module, "build_registry", build_with_fake)

    class RaisingProvider:
        name = "fake-raising"

        def __init__(self) -> None:
            self.calls = 0

        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            self.calls += 1
            if self.calls == 1:
                return TurnResult(
                    tool_calls=(
                        ToolCall(
                            id="navigate-1",
                            name="browser_navigate",
                            arguments={"url": "http://127.0.0.1/"},
                        ),
                    )
                )
            raise RuntimeError("provider failure sentinel")

        def classify(self, _exc: BaseException) -> Any:
            return SimpleNamespace(reason="unknown")

    ledger = Ledger(tmp_path / "ledger.db")
    scope = localhost_scope()
    http = ScopedHttpClient(scope, min_interval=0)
    events: list[tuple[str, dict[str, Any]]] = []
    ctx = EngineContext(
        http=http,
        emit=lambda kind, payload: events.append((kind, dict(payload))),
        config={"browser_enabled": True},
        ledger=ledger,
        run_id="R-M6-LLM",
    )
    try:
        target = TargetSpec(url="http://127.0.0.1/", scope=scope)
        with pytest.raises(RuntimeError, match="provider failure sentinel"):
            LLMEngine(RaisingProvider()).run(target, ctx)
        assert module.drivers
        driver = module.drivers[0]
        assert driver.page.close_count == 1
        assert driver.context.close_count == 1
        assert driver.browser.close_count == 1
        assert driver.stop_count == 1
    finally:
        http.close()
        ledger.close()


def test_browser_flag_wires_only_governed_hunt_context(tmp_path, monkeypatch):
    from hunter.agent import tools as tools_module
    from hunter.chat.repl import ChatEngine
    from hunter.chat.sessions import ChatStore
    from hunter.llm.config import default_config

    calls: list[dict[str, Any]] = []
    real_build_registry = tools_module.build_registry
    module = FakePlaywrightModule()

    def recording_build(tier: str = "basic", **kwargs: Any) -> Any:
        calls.append(dict(kwargs))
        return real_build_registry(
            tier,
            browser_enabled=True,
            playwright_module=module,
        )

    monkeypatch.setattr(tools_module, "build_registry", recording_build)

    class FakeProvider:
        name = "fake-chat"

        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def complete(self, tier, messages, tools=None, *, stream_cb=None, budget=None):
            self.calls.append({"messages": list(messages), "tools": tools})
            if tools is not None:
                return TurnResult(
                    tool_calls=(
                        ToolCall(
                            id="yield-1",
                            name="respond_to_user",
                            arguments={"message": "audit yielded"},
                        ),
                    )
                )
            return TurnResult(text="ordinary chat")

    config = default_config()
    config.agent.browser = True
    store = ChatStore(tmp_path / "chat.db")
    audit_provider = FakeProvider()
    normal_provider = FakeProvider()
    audit = ChatEngine(
        store=store,
        config=config,
        provider=audit_provider,
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
    )
    normal = ChatEngine(
        store=store,
        config=config,
        provider=normal_provider,
        options={"state_dir": str(tmp_path), "verbosity": "normal"},
    )
    try:
        opening = audit._audit_open(
            {
                "target": "http://127.0.0.1/",
                "engine_name": "agent-chat",
                "scope": {"name": "localhost-only", "hosts": []},
            }
        )
        assert "audit run" in opening
        assert audit._audit["ctx"].config.get("hunt_permission") is True
        assert audit._audit["ctx"].config.get("browser_enabled") is True
        out_text, _result = audit._audit_turn_result("inspect the page")
        assert "audit yielded" in out_text
        assert calls and calls[0].get("browser_enabled") is True
        offered = audit_provider.calls[0]["tools"]
        assert {entry["function"]["name"] for entry in offered} >= BROWSER_NAMES

        normal_out = normal.handle_text("hello from ordinary chat")
        assert normal_out.text == "ordinary chat"
        assert normal_provider.calls
        normal_tools = normal_provider.calls[0]["tools"]
        assert not normal_tools or not (BROWSER_NAMES & {entry["function"]["name"] for entry in normal_tools})
        assert len(module.drivers) == 0
    finally:
        audit.close()
        normal.close()
        store.close()
