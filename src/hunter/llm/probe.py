"""Endpoint + model-list probes — "what shape is this OpenAI-compatible API?"

``detect_endpoint`` dials ``{base}/chat/completions`` and ``{base}/responses``
with 1-token bodies and classifies the route from the status alone (an auth
or model error still proves the route exists). ``list_models`` reads
``{base}/models`` into a sorted, de-duplicated id list. Both NEVER raise,
never retry, and never return or print the API key — the probe answers with
an enum / a list of ids, nothing else. ``client_factory`` is the test seam
(``httpx.MockTransport``) so no test touches the network.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

__all__ = ["detect_endpoint", "list_models"]

# 1-token probe bodies (the smallest legal request per API shape).
_CHAT_BODY = {"model": "probe", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}
_RESPONSES_BODY = {"model": "probe", "input": "ping", "max_output_tokens": 1}

_PROBE_TIMEOUT = 10.0


def _headers(api_key: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _route_status(client: Any, url: str, api_key: str, body: dict[str, Any]) -> int | None:
    """POST one probe body; the status code, or None on any transport error."""
    try:
        response = client.post(url, json=body, headers=_headers(api_key))
        return response.status_code
    except Exception:  # noqa: BLE001 — connect/timeout/URL errors all mean "no answer"
        return None


def _route_exists(status: int | None) -> bool:
    # 200-499 except 404/405 proves the route exists (401/422 still answer).
    return status is not None and 200 <= status < 500 and status not in (404, 405)


def detect_endpoint(
    base_url: str,
    api_key: str = "",
    timeout: float = _PROBE_TIMEOUT,
    *,
    client_factory: Callable[[], Any] | None = None,
) -> str:
    """POST ``{base}/chat/completions`` then ``{base}/responses`` with 1-token
    bodies. Returns "chat" | "responses" | "". NEVER raises, never includes
    the key in any returned data (it returns only the enum)."""
    factory = client_factory if client_factory is not None else (lambda: httpx.Client(timeout=timeout))
    try:
        client = factory()
    except Exception:  # noqa: BLE001 — an unusable client is an undetermined endpoint
        return ""
    base = base_url.rstrip("/")
    try:
        if _route_exists(_route_status(client, f"{base}/chat/completions", api_key, _CHAT_BODY)):
            return "chat"
        if _route_exists(_route_status(client, f"{base}/responses", api_key, _RESPONSES_BODY)):
            return "responses"
        return ""
    finally:
        client.close()


def list_models(
    base_url: str,
    api_key: str = "",
    timeout: float = _PROBE_TIMEOUT,
    *,
    client_factory: Callable[[], Any] | None = None,
) -> list[str]:
    """GET ``{base}/models`` -> sorted, de-duplicated, non-empty ``data[].id``
    list. [] on ANY failure (non-200, parse error, transport error). NEVER
    raises."""
    factory = client_factory if client_factory is not None else (lambda: httpx.Client(timeout=timeout))
    try:
        client = factory()
    except Exception:  # noqa: BLE001 — an unusable client is an empty model list
        return []
    base = base_url.rstrip("/")
    try:
        response = client.get(f"{base}/models", headers=_headers(api_key))
        if response.status_code != 200:
            return []
        payload = response.json()
    except Exception:  # noqa: BLE001 — garbage JSON / transport errors -> []
        return []
    finally:
        client.close()
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    ids = {
        entry["id"]
        for entry in data
        if isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"].strip()
    }
    return sorted(ids)
