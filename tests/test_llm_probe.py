"""M1 probe module tests — `hunter.llm.probe` via httpx.MockTransport (offline).

`detect_endpoint` and `list_models` are new in M1: they dial an
OpenAI-compatible base URL to learn its API shape and model list, never
raise, and never echo the API key. The `client_factory` seam injects a
MockTransport-backed client so no test touches the network. The probe module
is imported inside the tests (red until it exists, without breaking
collection of the rest of the suite).
"""

from __future__ import annotations

import httpx
import pytest

BASE_URL = "https://llm.corp.example.com/v1"
KEY = "sk-probe-secret-1"


@pytest.fixture(autouse=True)
def _m1_env_hygiene(monkeypatch):
    for var in ("HUNTEROS_KEYS_FILE", "HUNTEROS_ONBOARD_DECLINED"):
        monkeypatch.delenv(var, raising=False)


def _mock_client(handler):
    def client_factory():
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=5)

    return client_factory


def _status_handler(chat_status, responses_status, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(chat_status, json={})
        if request.url.path.endswith("/responses"):
            return httpx.Response(responses_status, json={})
        return httpx.Response(404)

    return handler


def test_detect_endpoint_decision_table_mock_transport():
    """A33: the status decision table + auth header sent only with a key."""
    from hunter.llm.probe import detect_endpoint

    # chat route answers 200 -> "chat"
    seen: list[httpx.Request] = []
    result = detect_endpoint(
        BASE_URL, KEY, client_factory=_mock_client(_status_handler(200, 404, seen))
    )
    assert result == "chat"

    # An auth error still proves the route exists (200-499 except 404/405).
    assert (
        detect_endpoint(
            BASE_URL, KEY, client_factory=_mock_client(_status_handler(401, 404, []))
        )
        == "chat"
    )

    # chat 404 -> falls through to the responses probe -> "responses".
    assert (
        detect_endpoint(
            BASE_URL, KEY, client_factory=_mock_client(_status_handler(404, 200, []))
        )
        == "responses"
    )

    # Both routes 404 -> undetermined.
    assert (
        detect_endpoint(
            BASE_URL, KEY, client_factory=_mock_client(_status_handler(404, 404, []))
        )
        == ""
    )

    # Transport errors never raise: any failure collapses to "".
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    assert detect_endpoint(BASE_URL, KEY, client_factory=_mock_client(broken)) == ""

    # Authorization: Bearer <key> only when a key is passed.
    seen_with_key: list[httpx.Request] = []
    detect_endpoint(
        BASE_URL, KEY, client_factory=_mock_client(_status_handler(200, 404, seen_with_key))
    )
    assert seen_with_key[0].headers.get("authorization") == f"Bearer {KEY}"

    seen_keyless: list[httpx.Request] = []
    detect_endpoint(
        BASE_URL, "", client_factory=_mock_client(_status_handler(200, 404, seen_keyless))
    )
    assert "authorization" not in seen_keyless[0].headers


def test_list_models_mock_transport_and_garbage():
    """A34: sorted unique non-empty ids; [] on 404, bad JSON, or failure."""
    from hunter.llm.probe import list_models

    payload = {
        "data": [
            {"id": "zeta"},
            {"id": "alpha"},
            {"id": "zeta"},  # duplicate
            {"id": ""},  # empty id
            "not-a-dict",  # non-dict entry
            3,  # non-dict entry
            {"id": 3},  # non-string id
        ]
    }

    def ok_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(200, json=payload)

    assert list_models(BASE_URL, KEY, client_factory=_mock_client(ok_handler)) == [
        "alpha",
        "zeta",
    ]

    def missing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "nope"})

    assert list_models(BASE_URL, KEY, client_factory=_mock_client(missing_handler)) == []

    def garbage_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{definitely not json")

    assert list_models(BASE_URL, KEY, client_factory=_mock_client(garbage_handler)) == []

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    assert list_models(BASE_URL, KEY, client_factory=_mock_client(broken)) == []
