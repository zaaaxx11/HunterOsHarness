#!/usr/bin/env python3
"""quick_recon — scope-gated recon of /, /robots.txt, and /sitemap.xml.

Refuses out-of-scope targets via ``ScopeSet.check_url`` BEFORE any socket
opens (exit 3 — silence is not consent). Fetches exactly three GETs through
the harness ``ScopedHttpClient`` (no redirects followed, header values
redacted) and reports status codes, headers, a robots.txt sha256 + head,
a sitemap.xml URL count, and extractive hints. Nothing is invented: hints
quote response headers only.

Exit codes: 0 ok, 1 error, 3 scope refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from hunter.kernel.redaction import redact_text  # noqa: E402
from hunter.tools.http_client import ScopedHttpClient  # noqa: E402
from hunter.tools.scope import ScopeSet, ScopeViolation, scope_from_manifest  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_SCOPE_REFUSED = 3

PATHS = ("/", "/robots.txt", "/sitemap.xml")
_MAX_HEADER_VALUE_CHARS = 160
_MAX_ROBOTS_HEAD_CHARS = 200


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quick_recon", description=__doc__)
    parser.add_argument("target", help="authorized target URL (http/https)")
    parser.add_argument("--scope", required=True, help="scope manifest JSON path")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON on stdout")
    return parser


def _fetch(client: ScopedHttpClient, base: str, path: str) -> dict:
    exchange = client.get(base.rstrip("/") + path)
    return {
        "status": exchange.status,
        "headers": {
            k: redact_text(v)[:_MAX_HEADER_VALUE_CHARS]
            for k, v in sorted(exchange.response_headers.items())
        },
        "body": exchange.response_body,
    }


def _sitemap_url_count(body: str) -> int:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return 0
    return sum(1 for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "url")


def _hints(results: dict[str, dict]) -> list[str]:
    """Extractive hints — response headers and robots content only."""
    hints: list[str] = []
    robots = results.get("/robots.txt") or {}
    sitemap = results.get("/sitemap.xml") or {}
    for path in PATHS:
        result = results.get(path)
        if result is None:
            continue
        server = result["headers"].get("server")
        powered = result["headers"].get("x-powered-by")
        generator = result["headers"].get("x-generator")
        if server:
            hints.append(f"{path}: server={server}")
        if powered:
            hints.append(f"{path}: x-powered-by={powered}")
        if generator:
            hints.append(f"{path}: x-generator={generator}")
    robots_body = robots.get("body") or ""
    disallows = sum(1 for line in robots_body.splitlines() if line.strip().lower().startswith("disallow:"))
    if disallows:
        hints.append(f"/robots.txt: {disallows} Disallow rule(s)")
    if sitemap.get("status") == 200:
        hints.append(f"/sitemap.xml: {_sitemap_url_count(sitemap.get('body') or '')} urls listed")
    return hints


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scope: ScopeSet = scope_from_manifest(args.scope)
    except (OSError, ValueError) as exc:
        print(f"[ERROR config] scope manifest unreadable: {exc}", file=sys.stderr)
        return EXIT_ERROR
    # Fail-closed BEFORE any I/O: out-of-scope targets are refused, not fetched.
    try:
        scope.check_url(args.target)
    except ScopeViolation as exc:
        print(f"[BLOCKED scope] {exc}", file=sys.stderr)
        print("refused: target is outside the authorized scope — nothing was fetched", file=sys.stderr)
        return EXIT_SCOPE_REFUSED

    with ScopedHttpClient(scope, min_interval=0) as client:
        results: dict[str, dict] = {}
        for path in PATHS:
            try:
                results[path] = _fetch(client, args.target, path)
            except ScopeViolation as exc:  # defense-in-depth: never fetch out of scope
                print(f"[BLOCKED scope] {exc}", file=sys.stderr)
                return EXIT_SCOPE_REFUSED
            except Exception:  # noqa: BLE001 — an unreachable path is data, not a crash
                results[path] = {"status": 0, "headers": {}, "body": ""}

    robots = results["/robots.txt"]
    sitemap = results["/sitemap.xml"]
    payload = {
        "target": args.target,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status_codes": {path: results[path]["status"] for path in PATHS},
        "headers": {path: results[path]["headers"] for path in PATHS},
        "robots": {
            "status": robots["status"],
            "sha256": hashlib.sha256(robots["body"].encode("utf-8")).hexdigest(),
            "head": robots["body"][:_MAX_ROBOTS_HEAD_CHARS],
        },
        "sitemap": {"status": sitemap["status"], "url_count": _sitemap_url_count(sitemap["body"])},
        "hints": _hints(results),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"target: {payload['target']}  fetched_at: {payload['fetched_at']}")
        for path in PATHS:
            print(f"  {path}: {payload['status_codes'][path]}")
        print(f"  robots sha256: {payload['robots']['sha256']}")
        print(f"  sitemap urls: {payload['sitemap']['url_count']}")
        for hint in payload["hints"]:
            print(f"  hint: {hint}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
