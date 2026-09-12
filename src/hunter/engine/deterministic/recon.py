"""Recon phase — depth-1 same-origin crawl that harvests links and forms.

Breadth-first from the target root, at most ``max_pages`` same-origin pages.
Everything here rides the scope-gated client handed to it; no other network
access exists in the deterministic engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from hunter.tools.http_client import Exchange, ScopedHttpClient


@dataclass(frozen=True)
class FormSpec:
    """One <form> found during recon."""

    page_url: str
    action: str  # absolute URL
    method: str  # lower-case ("get"/"post"); HTML default is get
    fields: tuple[str, ...]  # named inputs, document order


@dataclass
class Recon:
    base_url: str
    pages: dict[str, Exchange] = field(default_factory=dict)  # url -> exchange
    links: list[str] = field(default_factory=list)  # same-origin hrefs discovered
    forms: list[FormSpec] = field(default_factory=list)


class _PageParser(HTMLParser):
    """Extract <a href> and <form> structure from one page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v for k, v in attrs if k is not None}
        if tag == "a" and a.get("href"):
            self.links.append(str(a["href"]))
        elif tag == "form":
            self._current = {
                "action": a.get("action") or "",
                "method": (a.get("method") or "get").strip().lower(),
                "fields": [],
            }
        elif tag == "input" and self._current is not None and a.get("name"):
            fields = self._current["fields"]
            assert isinstance(fields, list)
            fields.append(str(a["name"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _parse(html: str) -> _PageParser:
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never kill recon
        pass
    return parser


def _same_origin(url: str, base_parts) -> bool:
    parts = urlsplit(url)
    return (
        parts.scheme in ("http", "https")
        and parts.netloc != ""
        and parts.netloc.lower() == base_parts.netloc.lower()
    )


def run_recon(http: ScopedHttpClient, base_url: str, *, max_pages: int = 20) -> Recon:
    """Crawl ``max_pages`` same-origin pages breadth-first from ``base_url``."""
    base = base_url.rstrip("/")
    base_parts = urlsplit(base)
    start = base + "/"
    recon = Recon(base_url=base)
    queue = [start]
    seen: set[str] = set()

    while queue and len(recon.pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        exchange = http.get(url)
        recon.pages[url] = exchange
        parsed = _parse(exchange.response_body)

        for href in parsed.links:
            absolute = urljoin(url, href).split("#", 1)[0]
            if not _same_origin(absolute, base_parts):
                continue
            if absolute not in recon.links:
                recon.links.append(absolute)
            if absolute not in seen:
                queue.append(absolute)

        for form in parsed.forms:
            action_raw = str(form["action"])
            action = urljoin(url, action_raw) if action_raw else url
            recon.forms.append(
                FormSpec(
                    page_url=url,
                    action=action,
                    method=str(form["method"]),
                    fields=tuple(form["fields"]),  # type: ignore[arg-type]
                )
            )

    return recon
