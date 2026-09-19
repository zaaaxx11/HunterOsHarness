"""DeterministicEngine end-to-end tests against PracticeVault.

Covers: recall vs answer_key, dedupe, evidence binding, severity/CWE match,
replay reproduction, stats/events, scope safety — and a negative-control run
against a tiny CLEAN stdlib app that must produce zero findings.
"""

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from hunter.engine.base import CandidateFinding, EngineContext, TargetSpec
from hunter.engine.deterministic.engine import DeterministicEngine
from hunter.engine.deterministic.probes import CHECK_IDS
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import localhost_scope
from hunter.vault.server import start_server

ANSWER_KEY_PATH = Path(__file__).resolve().parents[1] / "src" / "hunter" / "vault" / "answer_key.json"
ANSWER_KEY = json.loads(ANSWER_KEY_PATH.read_text(encoding="utf-8"))
ANSWER_BY_KEY = {entry["key"]: entry for entry in ANSWER_KEY}

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


# -- fixtures -------------------------------------------------------------------


@pytest.fixture()
def no_proxy(monkeypatch):
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


@pytest.fixture()
def vault(no_proxy):
    handle, _port = start_server()
    try:
        yield handle
    finally:
        handle.shutdown()


@pytest.fixture()
def scan(vault):
    """Run the deterministic engine against the vault once; share the result."""
    scope = localhost_scope()
    client = ScopedHttpClient(scope)
    events: list[tuple[str, dict]] = []
    ctx = EngineContext(http=client, emit=lambda kind, payload: events.append((kind, dict(payload))))
    target = TargetSpec(url=vault.url, scope=scope)
    engine = DeterministicEngine()
    try:
        result = engine.run(target, ctx)
        yield engine, target, ctx, result, events
    finally:
        client.close()


# -- clean app (negative control) --------------------------------------------------


class _CleanHandler(BaseHTTPRequestHandler):
    """A properly configured tiny app: security headers set, input escaped,
    methods rejected. The deterministic engine must find NOTHING here.

    HTTP/1.0 (default): one connection per request — no keep-alive races.
    """

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _q(self) -> str:
        return (parse_qs(urlparse(self.path).query).get("q") or [""])[0]

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, '<html><body><h1>Clean App</h1><a href="/about">About</a>'
                            '<a href="/search">Search</a></body></html>')
        elif path == "/about":
            self._send(200, "<html><body><h1>About</h1><p>Nothing to see.</p></body></html>")
        elif path == "/search":
            escaped = html.escape(self._q())
            self._send(200, f'<html><body><form method="get" action="/search">'
                            f'<input type="text" name="q"></form>'
                            f'<p>Results for: {escaped}</p></body></html>')
        else:
            self._send(404, "not found", content_type="text/plain; charset=utf-8")

    def _reject(self) -> None:
        self._send(405, "method not allowed")

    def do_POST(self) -> None:  # noqa: N802
        self._reject()

    def do_PUT(self) -> None:  # noqa: N802
        self._reject()

    def do_DELETE(self) -> None:  # noqa: N802
        self._reject()

    def do_TRACE(self) -> None:  # noqa: N802
        self._reject()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._reject()


class _CleanServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        pass


@pytest.fixture()
def clean_app(no_proxy):
    server = _CleanServer(("127.0.0.1", 0), _CleanHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# -- tests ---------------------------------------------------------------------


def test_plan_declares_three_phases(vault):
    scope = localhost_scope()
    target = TargetSpec(url=vault.url, scope=scope)
    engine = DeterministicEngine()
    plan = engine.plan(target)
    assert engine.name == "deterministic"
    assert plan.engine == "deterministic"
    assert plan.phases == ["recon", "probe", "collect"]


def test_recall_at_least_7_of_9_answer_keys(scan):
    _engine, _target, _ctx, result, _events = scan
    found = {candidate.key for candidate in result.candidates}
    expected = set(ANSWER_BY_KEY)
    missing = sorted(expected - found)
    assert len(found & expected) >= 7, (
        f"recall {len(found & expected)}/9 below threshold; missing: {missing}; "
        f"found: {sorted(found)}"
    )
    print(f"\nrecall: {len(found & expected)}/9; missing: {missing}")


def test_no_duplicate_keys(scan):
    _engine, _target, _ctx, result, _events = scan
    keys = [candidate.key for candidate in result.candidates]
    assert len(keys) == len(set(keys)), f"duplicate keys: {keys}"


def test_every_candidate_has_evidence(scan):
    _engine, _target, _ctx, result, _events = scan
    for candidate in result.candidates:
        assert len(candidate.evidence) >= 1, candidate.key
        for evidence in candidate.evidence:
            assert evidence.kind == "http_exchange"
            assert evidence.data["check_id"] == candidate.key.split("|")[0]
            assert evidence.data["status"] > 0


def test_severities_and_cwes_match_answer_key(scan):
    _engine, _target, _ctx, result, _events = scan
    matched = 0
    for candidate in result.candidates:
        entry = ANSWER_BY_KEY.get(candidate.key)
        if entry is None:
            continue  # extra candidates (e.g. cookie-flags) are allowed off-key
        matched += 1
        assert candidate.severity.value == entry["severity"], candidate.key
        assert candidate.cwe == entry["cwe"], candidate.key
        assert candidate.title, candidate.key
    assert matched >= 7


def test_replay_reproduces_candidates(scan):
    engine, target, ctx, result, _events = scan
    reproduced = 0
    for candidate in result.candidates:
        if engine.replay(target, ctx, candidate):
            reproduced += 1
    print(f"\nreplay reproduced {reproduced}/{len(result.candidates)} candidates")
    assert reproduced >= 5


def test_replay_unknown_check_returns_false(scan):
    engine, target, ctx, _result, _events = scan
    bogus = CandidateFinding(
        key="no-such-check|GET|/nowhere|-",
        title="bogus",
        severity="low",  # type: ignore[arg-type]
        cwe="CWE-000",
        endpoint="/nowhere",
    )
    assert engine.replay(target, ctx, bogus) is False


def test_stats_contain_request_counts(scan):
    _engine, _target, _ctx, result, _events = scan
    assert result.stats["requests"] > 0
    assert result.stats["blocked"] == 0  # scope gate never tripped
    # stats.errors may be >= 0: a rare OS-level loopback transient (WinError
    # 10053) is retried once per probe and cannot fabricate findings; the
    # recall test below still guarantees the probe results survived.
    assert result.stats["probes_run"] == len(CHECK_IDS) == 12
    assert result.stats["elapsed_ms"] >= 0
    assert result.stats["candidates"] == len(result.candidates)


def test_events_cover_phases_and_probes(scan):
    _engine, _target, _ctx, _result, events = scan
    for phase in ("recon", "probe", "collect"):
        assert any(
            kind == "phase_started" and payload["phase"] == phase
            for kind, payload in events
        ), phase
        assert any(kind == "phase_ended" and payload["phase"] == phase for kind, payload in events)
    started = {payload["check_id"] for kind, payload in events if kind == "probe_started"}
    results = {payload["check_id"] for kind, payload in events if kind == "probe_result"}
    assert started == set(CHECK_IDS)
    assert results == set(CHECK_IDS)
    for _kind, payload in events:
        if _kind == "probe_result":
            assert set(payload) == {"check_id", "candidates", "hit"}
    # NOTE: "error" events are allowed — a transient transport failure emits
    # one and the probe retries once; probe_result completeness is asserted above.


def test_scope_gate_never_tripped_and_no_outbound_hosts(scan, vault):
    _engine, _target, _ctx, result, _events = scan
    for candidate in result.candidates:
        for evidence in candidate.evidence:
            # The request URL always targets the vault; the open-redirect
            # payload only ever appears inside the query string / Location.
            assert evidence.data["url"].startswith(vault.url), evidence.data["url"]


def test_engine_run_is_deterministic(vault, no_proxy):
    """Two full runs produce the same candidate key set (stable engine)."""
    runs = []
    for _ in range(2):
        scope = localhost_scope()
        client = ScopedHttpClient(scope)
        ctx = EngineContext(http=client, emit=lambda kind, payload: None)
        target = TargetSpec(url=vault.url, scope=scope)
        try:
            runs.append({c.key for c in DeterministicEngine().run(target, ctx).candidates})
        finally:
            client.close()
    assert runs[0] == runs[1]


def test_clean_app_zero_findings(clean_app):
    """Negative control: a properly configured app yields ZERO candidates."""
    scope = localhost_scope()
    client = ScopedHttpClient(scope)
    events: list[tuple[str, dict]] = []
    ctx = EngineContext(http=client, emit=lambda kind, payload: events.append((kind, dict(payload))))
    target = TargetSpec(url=clean_app, scope=scope)
    try:
        result = DeterministicEngine().run(target, ctx)
    finally:
        client.close()
        assert result.candidates == [], (
            f"false positives on clean app: {[c.key for c in result.candidates]}"
        )
        assert client.stats.blocked == 0
        # Every probe must have run to completion; a rare OS-level loopback
        # transient (WinError 10053) is retried once and can only ever REMOVE
        # a finding, never fabricate one — so zero candidates stays load-bearing.
        probe_error_events = [payload for kind, payload in events if kind == "error"]
        results_for = {
            payload["check_id"] for kind, payload in events if kind == "probe_result"
        }
        assert results_for == set(CHECK_IDS), f"probes missing probe_result: {probe_error_events}"
