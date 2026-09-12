"""Contract tests: hash chain, scope gate, redaction, http client gate.

These pin the W0 contracts. Builders must not break them.
"""

import httpx
import pytest

from hunter.kernel.events import GENESIS_HASH, Event, EventKind
from hunter.kernel.redaction import redact_payload, redact_text
from hunter.tools.http_client import ScopedHttpClient
from hunter.tools.scope import ScopeViolation, localhost_scope, scope_from_manifest

# -- events: hash chain ------------------------------------------------------

def test_event_hash_chain_verifies():
    ev1 = Event.create(
        run_id="r1", kind=EventKind.RUN_STARTED, payload={"a": 1}, seq=1, ts=1.0, prev_hash=GENESIS_HASH
    )
    ev2 = Event.create(
        run_id="r1", kind=EventKind.PROBE_RESULT, payload={"b": 2}, seq=2, ts=2.0, prev_hash=ev1.hash
    )
    assert ev1.prev_hash == GENESIS_HASH
    assert ev1.verify() and ev2.verify()
    assert ev2.prev_hash == ev1.hash


def test_event_tamper_detected():
    ev = Event.create(
        run_id="r1", kind=EventKind.RUN_STARTED, payload={"a": 1}, seq=1, ts=1.0, prev_hash=GENESIS_HASH
    )
    tampered = Event(
        seq=ev.seq, run_id=ev.run_id, kind=ev.kind, payload={"a": 999},
        ts=ev.ts, prev_hash=ev.prev_hash, hash=ev.hash,
    )
    assert not tampered.verify()


def test_canonical_json_is_stable():
    from hunter.kernel.events import canonical_json

    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"a": 2, "b": 1}) == '{"a":2,"b":1}'


# -- scope gate ---------------------------------------------------------------

def test_scope_allows_localhost_always():
    scope = localhost_scope()
    assert scope.check_url("http://127.0.0.1:8941/") == "127.0.0.1"
    assert scope.check_url("http://localhost:8941/x") == "localhost"


def test_scope_blocks_out_of_scope_fail_closed():
    scope = localhost_scope()
    with pytest.raises(ScopeViolation):
        scope.check_url("http://evil.example.com/")
    with pytest.raises(ScopeViolation):
        scope.check_url("ftp://127.0.0.1/")  # unknown scheme
    with pytest.raises(ScopeViolation):
        scope.check_url("http:///no-host")


def test_scope_manifest_hosts_and_subdomains(tmp_path):
    manifest = tmp_path / "scope.json"
    manifest.write_text('{"name":"client-x","hosts":["example.com"],"allow_subdomains":true}')
    scope = scope_from_manifest(manifest)
    assert scope.check_url("https://example.com/a") == "example.com"
    assert scope.check_url("https://api.example.com/") == "api.example.com"
    manifest2 = tmp_path / "strict.json"
    manifest2.write_text('{"name":"strict","hosts":["example.com"]}')
    scope2 = scope_from_manifest(manifest2)
    with pytest.raises(ScopeViolation):
        scope2.check_url("https://api.example.com/")


def test_scope_manifest_requires_hosts(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"name":"x","hosts":[]}')
    with pytest.raises(ValueError):
        scope_from_manifest(bad)


# -- http client: gate before socket -----------------------------------------

def _mock_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="pong")


def test_http_client_allows_in_scope():
    scope = localhost_scope()
    client = ScopedHttpClient(scope, transport=httpx.MockTransport(_mock_handler))
    try:
        ex = client.get("http://127.0.0.1:1/ping")
        assert ex.status == 200
        assert ex.response_body == "pong"
        assert client.stats.requests == 1
    finally:
        client.close()


def test_http_client_blocks_out_of_scope_before_socket():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200)

    client = ScopedHttpClient(localhost_scope(), transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(ScopeViolation):
            client.get("http://evil.example.com/")
        assert calls["n"] == 0  # no I/O happened
        assert client.stats.requests == 0
    finally:
        client.close()


def test_exchange_is_evidence_ready():
    client = ScopedHttpClient(localhost_scope(), transport=httpx.MockTransport(_mock_handler))
    try:
        ex = client.get("http://localhost/x")
        d = ex.to_dict()
        assert set(d) == {
            "method", "url", "request_headers", "request_body",
            "status", "response_headers", "response_body", "elapsed_ms",
        }
    finally:
        client.close()


# -- redaction -----------------------------------------------------------------

def test_redaction_scrubs_secret_shapes():
    text = "key=sk-abcdefghij1234567890 password=hunter2 token=abc123def456ghi789"
    out = redact_text(text)
    assert "sk-abcdefghij1234567890" not in out
    assert "hunter2" not in out
    assert "abc123def456ghi789" not in out
    assert "[REDACTED]" in out


def test_redaction_deep():
    data = {
        "headers": {"Authorization": "Bearer abcdefghijklmnop123456"},
        "nested": ["x", "password=secret9"],
    }
    out = redact_payload(data)
    assert "abcdefghijklmnop123456" not in out["headers"]["Authorization"]
    assert "secret9" not in out["nested"][1]
