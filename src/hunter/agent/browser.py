"""Narrow, scope-gated Playwright adapter for governed hunt actions.

Playwright is deliberately imported only when a browser-enabled registry is
built, and a driver is started only on the first successful browser action.
The adapter exposes bounded data and never exposes the page/context objects or
an arbitrary page-code execution surface.
"""

from __future__ import annotations

import contextlib
import importlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from hunter.kernel.redaction import redact_text
from hunter.tools.scope import ScopeSet, ScopeViolation

BROWSER_TOOL_NAMES: tuple[str, ...] = (
    "browser_click",
    "browser_navigate",
    "browser_snapshot",
    "browser_type",
)
MAX_SNAPSHOT_CHARS = 12_000
MAX_SELECTOR_CHARS = 512
MAX_TYPED_CHARS = 4_000
NAVIGATION_TIMEOUT_MS = 15_000
PLAYWRIGHT_INSTALL_HINT = (
    "install browser support with: "
    "pip install 'hunteros-harness[browser]' && "
    "python -m playwright install chromium"
)

_AUTO = object()

# Browser output gets a second, browser-specific pass.  The ordinary ledger
# redactor intentionally does not know about every cookie spelling.
_SECRET_FIELD_RE = re.compile(
    r"(?i)\b(?:cookie|set-cookie|authorization|csrf(?:[-_ ]token)?|"
    r"access[-_ ]token|refresh[-_ ]token|api[-_ ]key|session(?:[-_ ]id)?|"
    r"secret|token)\b\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")


class BrowserUnavailable(RuntimeError):
    """The optional package or its browser executable is not available."""


class BrowserInputError(ValueError):
    """A browser input violates the deliberately small tool contract."""


@dataclass(frozen=True)
class BrowserAction:
    action: str
    url: str
    title: str = ""
    snapshot: str = ""
    truncated: bool = False
    text_length: int = 0


def load_playwright() -> Any | None:
    """Return the optional sync API without installing or launching anything."""
    try:
        return importlib.import_module("playwright.sync_api")
    except (ImportError, ModuleNotFoundError):
        return None


def playwright_available(*, module: Any = _AUTO) -> bool:
    """Pure availability check for the supplied seam or default import."""
    candidate = load_playwright() if module is _AUTO else module
    return candidate is not None


def sanitize_browser_text(value: Any, *, limit: int = 2_048) -> str:
    """Redact a bounded browser-facing string before returning it to a model."""
    text = redact_text(str(value or ""))
    text = _SECRET_FIELD_RE.sub("[REDACTED]", text)
    text = _BEARER_RE.sub("[REDACTED]", text)
    return text[:limit]


def validate_selector(selector: Any) -> str:
    """Accept only one bounded, ordinary CSS selector."""
    if not isinstance(selector, str) or not selector or len(selector) > MAX_SELECTOR_CHARS:
        raise BrowserInputError("selector must be a non-empty CSS selector of at most 512 characters")
    lowered = selector.lower()
    if (
        any(ord(char) < 32 or ord(char) == 127 for char in selector)
        or "xpath=" in lowered
        or "text=" in lowered
        or ">>" in selector
        or "javascript:" in lowered
        or "eval(" in lowered
        or any(char in selector for char in "{};`<>\\")
        or "||" in selector
    ):
        raise BrowserInputError("selector is not an allowed CSS selector")
    return selector


def validate_url(url: Any) -> str:
    """Reject relative, protocol-relative, and non-http(s) navigation inputs."""
    if not isinstance(url, str) or not url or len(url) > 2_048:
        raise BrowserInputError("url must be a non-empty absolute http(s) URL")
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise BrowserInputError("url is malformed") from exc
    if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise BrowserInputError("url must be an absolute http(s) URL")
    return url


class BrowserSession:
    """One fresh headless browser context and page owned by one run."""

    def __init__(
        self,
        scope: ScopeSet,
        *,
        playwright_module: Any = _AUTO,
        max_snapshot_chars: int = MAX_SNAPSHOT_CHARS,
    ) -> None:
        self.scope = scope
        self.playwright_module = playwright_module
        self.max_snapshot_chars = max_snapshot_chars
        self._driver: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._started = False
        self._closed = False
        self._blocked_request: str | None = None

    def _start(self) -> None:
        if self._started:
            if self._closed:
                raise BrowserUnavailable(PLAYWRIGHT_INSTALL_HINT)
            return
        module = load_playwright() if self.playwright_module is _AUTO else self.playwright_module
        if module is None:
            raise BrowserUnavailable(PLAYWRIGHT_INSTALL_HINT)
        try:
            starter = module.sync_playwright()
            self._driver = starter.start()
            self._browser = self._driver.chromium.launch(headless=True)
            self._context = self._browser.new_context()
            self._page = self._context.new_page()
            self._context.route("**/*", self._route_handler)
            self._started = True
        except Exception as exc:
            self._best_effort_close()
            raise BrowserUnavailable(PLAYWRIGHT_INSTALL_HINT) from exc

    def _route_handler(self, route: Any) -> None:
        request_url = str(getattr(getattr(route, "request", None), "url", ""))
        try:
            self.scope.check_url(request_url)
        except ScopeViolation:
            self._blocked_request = request_url
            route.abort()
            return
        route.continue_()

    def _begin_action(self) -> Any:
        self._start()
        self._blocked_request = None
        page = self._page
        if page is None:
            raise BrowserUnavailable(PLAYWRIGHT_INSTALL_HINT)
        current = str(getattr(page, "url", ""))
        if not current:
            raise ScopeViolation("BLOCKED: browser has no current in-scope page")
        self.scope.check_url(current)
        return page

    def _finish_url(self, page: Any) -> str:
        if self._blocked_request is not None:
            raise ScopeViolation("BLOCKED: browser request was outside the authorized scope")
        current = str(getattr(page, "url", ""))
        self.scope.check_url(current)
        return sanitize_browser_text(current, limit=2_048)

    def _title(self, page: Any) -> str:
        try:
            return sanitize_browser_text(page.title(), limit=512)
        except Exception:
            return ""

    def navigate(self, url: str) -> BrowserAction:
        url = validate_url(url)
        self.scope.check_url(url)
        self._start()
        self._blocked_request = None
        try:
            self._page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="domcontentloaded")
        except ScopeViolation:
            raise
        except Exception as exc:
            if self._blocked_request is not None:
                raise ScopeViolation("BLOCKED: browser request was outside the authorized scope") from exc
            raise
        current = self._finish_url(self._page)
        return BrowserAction(action="navigate", url=current, title=self._title(self._page))

    def snapshot(self) -> BrowserAction:
        page = self._begin_action()
        raw = page.locator("body").inner_text()
        safe = sanitize_browser_text(raw, limit=max(self.max_snapshot_chars * 2, self.max_snapshot_chars))
        truncated = len(safe) > self.max_snapshot_chars
        if truncated:
            safe = safe[: self.max_snapshot_chars] + "...[snapshot truncated]"
        current = self._finish_url(page)
        return BrowserAction(
            action="snapshot",
            url=current,
            title=self._title(page),
            snapshot=safe,
            truncated=truncated,
            text_length=len(safe),
        )

    def _locator(self, page: Any, selector: str) -> Any:
        locator = page.locator(selector)
        if locator.count() != 1:
            raise BrowserInputError("selector must match exactly one element")
        return locator

    def _check_destination(self, locator: Any, page: Any) -> None:
        current = str(getattr(page, "url", ""))
        self.scope.check_url(current)
        for attribute in ("href", "formaction", "action"):
            destination = locator.get_attribute(attribute)
            if destination:
                resolved = urljoin(current, str(destination))
                if urlparse(resolved).scheme == "javascript":
                    raise BrowserInputError("javascript destinations are not allowed")
                self.scope.check_url(resolved)
                return

    def click(self, selector: str) -> BrowserAction:
        selector = validate_selector(selector)
        page = self._begin_action()
        locator = self._locator(page, selector)
        self._check_destination(locator, page)
        try:
            locator.click()
        except Exception as exc:
            if self._blocked_request is not None:
                raise ScopeViolation("BLOCKED: browser request was outside the authorized scope") from exc
            raise
        current = self._finish_url(page)
        return BrowserAction(action="click", url=current, title=self._title(page))

    def type(self, selector: str, text: str) -> BrowserAction:
        selector = validate_selector(selector)
        if not isinstance(text, str) or len(text) > MAX_TYPED_CHARS:
            raise BrowserInputError("text must be a string of at most 4000 characters")
        page = self._begin_action()
        locator = self._locator(page, selector)
        self._check_destination(locator, page)
        try:
            locator.fill(text)
        except Exception as exc:
            if self._blocked_request is not None:
                raise ScopeViolation("BLOCKED: browser request was outside the authorized scope") from exc
            raise
        current = self._finish_url(page)
        return BrowserAction(action="type", url=current, title=self._title(page), text_length=len(text))

    def close(self) -> None:
        """Best-effort, idempotent cleanup that never masks the action error."""
        if self._closed:
            return
        self._closed = True
        self._best_effort_close()

    def _best_effort_close(self) -> None:
        for obj in (self._page, self._context, self._browser):
            close = getattr(obj, "close", None)
            if callable(close):
                with contextlib.suppress(Exception):
                    close()
        stop = getattr(self._driver, "stop", None)
        if callable(stop):
            with contextlib.suppress(Exception):
                stop()
        self._page = None
        self._context = None
        self._browser = None
        self._driver = None


__all__ = [
    "BROWSER_TOOL_NAMES",
    "BrowserAction",
    "BrowserInputError",
    "BrowserSession",
    "BrowserUnavailable",
    "MAX_SELECTOR_CHARS",
    "MAX_SNAPSHOT_CHARS",
    "MAX_TYPED_CHARS",
    "NAVIGATION_TIMEOUT_MS",
    "PLAYWRIGHT_INSTALL_HINT",
    "load_playwright",
    "playwright_available",
    "sanitize_browser_text",
    "validate_selector",
    "validate_url",
]
