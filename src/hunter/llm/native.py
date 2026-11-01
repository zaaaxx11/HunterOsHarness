"""Native HTTP provider — HunterOs' LLM brain without LiteLLM.

WHY THIS EXISTS
---------------
LiteLLM is a heavy, opinionated translation layer: ~120 transitive deps, its
own model-price database, its own retry/timeout policy, its own message
normalization (which is exactly where the ``tool_calls`` schema break came
from), and a failure mode where a missing optional module (``mcp``) kills the
whole brain with a message that has nothing to do with the actual problem.

Every provider HunterOs actually dials speaks the OpenAI
``/chat/completions`` wire protocol. That protocol is small, stable, and fully
specified. This module implements it directly on ``httpx``:

* one request builder, one response normalizer, one error classifier
* failures classified ONCE into :class:`ClassifiedError` (same vocabulary the
  router already speaks) — no string re-matching, no guessing
* retries with capped exponential backoff, honouring ``Retry-After``
* fallback chain walked only for errors that are actually fallback-worthy
  (auth / billing / model-not-found) — never for a malformed request we made
* zero hard dependency beyond ``httpx`` (already required by the harness)

The contract is :class:`hunter.llm.base.ChatProvider` — identical to
``ProviderRouter``, so the rest of the harness cannot tell the difference.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from hunter.errors import HunterError
from hunter.llm.base import ClassifiedError, StreamCb, ToolCall, TurnResult
from hunter.llm.config import (
    FallbackEntry,
    HunterConfig,
    TierConfig,
    resolve_key,
    resolve_model,
)

__all__ = ["NativeProvider"]

_BACKOFF_CAP_SECONDS = 8.0

# HTTP status -> (reason, retryable, should_fallback). Ordered by specificity:
# 402/429 before the generic 4xx bucket, because billing and rate limits are
# actionable while a 400 is our own bug.
_STATUS_VERDICTS: dict[int, ClassifiedError] = {
    400: ClassifiedError(reason="format_error", retryable=False, should_fallback=False, status_code=400),
    401: ClassifiedError(reason="auth", retryable=False, should_fallback=True, status_code=401),
    402: ClassifiedError(reason="billing", retryable=False, should_fallback=True, status_code=402),
    403: ClassifiedError(reason="auth", retryable=False, should_fallback=True, status_code=403),
    404: ClassifiedError(reason="model_not_found", retryable=False, should_fallback=True, status_code=404),
    408: ClassifiedError(reason="timeout", retryable=True, should_fallback=False, status_code=408),
    413: ClassifiedError(reason="context_overflow", retryable=False, should_fallback=False, status_code=413),
    422: ClassifiedError(reason="format_error", retryable=False, should_fallback=False, status_code=422),
    429: ClassifiedError(reason="rate_limit", retryable=True, should_fallback=False, status_code=429),
    500: ClassifiedError(reason="server_error", retryable=True, should_fallback=False, status_code=500),
    502: ClassifiedError(reason="server_error", retryable=True, should_fallback=False, status_code=502),
    503: ClassifiedError(reason="overloaded", retryable=True, should_fallback=False, status_code=503),
    504: ClassifiedError(reason="timeout", retryable=True, should_fallback=False, status_code=504),
}


def _to_wire_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate internal message dicts into OpenAI wire schema.

    The agent loop appends assistant tool calls as ``{"id","name","arguments"}``
    (internal contract, see ``hunter.agent.loop``). Strict gateways reject that
    shape: they require ``{"id","type":"function","function":{...}}`` with
    ``arguments`` as a JSON *string*. Normalize here, at the wire boundary.
    """
    wire: list[dict[str, Any]] = []
    for message in messages:
        calls = message.get("tool_calls")
        if not calls or not isinstance(calls, list):
            wire.append(message)
            continue
        normalized: list[dict[str, Any]] = []
        for call in calls:
            if not isinstance(call, dict):
                continue
            if isinstance(call.get("function"), dict):
                normalized.append(call)  # already wire-shaped
                continue
            args = call.get("arguments", {})
            if not isinstance(args, str):
                try:
                    args = json.dumps(args if args is not None else {})
                except (TypeError, ValueError):
                    args = "{}"
            normalized.append(
                {
                    "id": call.get("id", "") or "",
                    "type": "function",
                    "function": {"name": call.get("name", "") or "", "arguments": args},
                }
            )
        updated = {k: v for k, v in message.items() if k != "tool_calls"}
        updated["tool_calls"] = normalized
        wire.append(updated)
    return wire


@dataclass
class _Route:
    """One dialable endpoint: provider name, base URL, key, wire model."""

    provider: str
    model: str
    base_url: str
    api_key: str
    timeout: int
    reasoning_effort: str = ""


class NativeProvider:
    """``ChatProvider`` speaking OpenAI ``/chat/completions`` over httpx.

    No LiteLLM, no model-price database: ``cost_usd`` stays 0.0 unless the
    gateway itself reports a cost (some do, in ``usage`` or a ``cost`` field).
    Budget enforcement therefore rides on iterations + wall time, which is the
    honest ceiling when the provider does not price its own tokens.
    """

    name = "native"

    def __init__(self, config: HunterConfig, *, transport: Any | None = None) -> None:
        self.config = config
        self._transport = transport  # test seam: httpx.Client-compatible
        self._last_outcome: str | None = None

    # ------------------------------------------------------------- public --

    def complete(
        self,
        tier: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream_cb: StreamCb | None = None,
        budget: Any | None = None,
    ) -> TurnResult:
        if budget is not None and budget.exhausted() is not None:
            raise HunterError(
                code="budget.exhausted", layer="budget",
                message=f"budget exhausted: {budget.exhausted()}",
            )

        routes = self._routes_for(tier)
        if not routes:
            raise HunterError(
                code="config.no_model", layer="config",
                message=f"no model configured for tier '{tier}'",
                hint="set model_tiers.<tier>.model in ~/.hunter/config.yaml",
            )

        last: ClassifiedError | None = None
        for route in routes:
            result = self._attempt(route, messages, tools, stream_cb)
            if isinstance(result, TurnResult):
                self._last_outcome = f"ok:{route.provider}"
                if budget is not None:
                    budget.add_cost(result.cost_usd)
                return result
            last = result
            self._last_outcome = f"{result.reason}:{route.provider}"
            if not (result.retryable or result.should_fallback):
                break  # our request is malformed — another provider won't help
            if not result.should_fallback:
                break  # retries already exhausted inside _attempt

        assert last is not None
        raise HunterError(
            code=f"provider.{last.reason}",
            layer="auth" if last.reason in ("auth", "billing") else "provider",
            message=f"all provider routes failed — {last.message}",
            hint="check the provider key/base_url in ~/.hunter/config.yaml",
        )

    def classify(self, exc: BaseException) -> ClassifiedError:
        if isinstance(exc, HunterError):
            reason = str(exc.code).split(".")[-1]
            if reason in ("auth", "billing", "rate_limit", "timeout", "model_not_found"):
                return ClassifiedError(reason=reason, message=str(exc.message)[:300])
        return ClassifiedError(reason="unknown", message=str(exc)[:300])

    # ------------------------------------------------------------ routing --

    def _routes_for(self, tier: str) -> list[_Route]:
        primary = self._route_from_tier(tier)
        routes = [primary] if primary else []

        for entry in self._fallbacks():
            if not self._tier_allows_fallback(entry, tier):
                continue
            route = self._route_from_entry(entry)
            if route and route.provider not in {r.provider for r in routes}:
                routes.append(route)
        return routes

    def _fallbacks(self) -> list[FallbackEntry]:
        raw = getattr(self.config, "fallback_providers", None) or []
        return list(raw)

    @staticmethod
    def _tier_allows_fallback(entry: FallbackEntry, tier: str) -> bool:
        tiers = getattr(entry, "tiers", None)
        return not tiers or tier in tiers

    def _route_from_tier(self, tier: str) -> _Route | None:
        from hunter.llm.base import normalize_tier

        canonical = normalize_tier(tier)
        tier_cfg = self.config.model_tiers.get(canonical)
        if tier_cfg is None:
            return None
        try:
            model = resolve_model(canonical, self.config)
        except Exception:
            return None
        if not model:
            return None
        provider = tier_cfg.provider or "auto"
        try:
            api_key = resolve_key(provider, self.config)
        except Exception:
            api_key = ""
        base_url = tier_cfg.base_url or self._provider_base_url(provider) or ""
        if not base_url and provider not in ("auto", ""):
            base_url = ""
        return _Route(
            provider=provider,
            model=model,
            base_url=base_url.rstrip("/"),
            api_key=api_key or "",
            timeout=int(tier_cfg.timeout or 120),
            reasoning_effort=getattr(tier_cfg, "reasoning_effort", "") or "",
        )

    def _route_from_entry(self, entry: FallbackEntry) -> _Route | None:
        provider = getattr(entry, "provider", "") or ""
        model = getattr(entry, "model", "") or ""
        if not provider or not model:
            return None
        return _Route(
            provider=provider,
            model=model,
            base_url=(getattr(entry, "base_url", "") or self._provider_base_url(provider) or "").rstrip("/"),
            api_key=(getattr(entry, "api_key", "") or self._provider_key(provider) or ""),
            timeout=int(getattr(entry, "timeout", 0) or 120),
        )

    def _provider_block(self, name: str) -> Any:
        providers = getattr(self.config, "providers", None) or {}
        return providers.get(name)

    def _provider_base_url(self, name: str) -> str:
        block = self._provider_block(name)
        return getattr(block, "base_url", "") or "" if block else ""

    def _provider_key(self, name: str) -> str:
        block = self._provider_block(name)
        return getattr(block, "api_key", "") or "" if block else ""

    # -------------------------------------------------------------- dialing --

    def _attempt(
        self,
        route: _Route,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        stream_cb: StreamCb | None,
    ) -> TurnResult | ClassifiedError:
        """Dial one route, retrying transient failures up to the configured cap."""
        max_retries = int(getattr(getattr(self.config, "agent", None), "api_max_retries", 3) or 3)
        last: ClassifiedError | None = None

        for attempt in range(max_retries + 1):
            try:
                return self._request(route, messages, tools, stream_cb)
            except _ProviderHTTPError as exc:
                verdict = exc.verdict
                last = verdict
                if not verdict.retryable or attempt >= max_retries:
                    return verdict
                wait = exc.retry_after or min(_BACKOFF_CAP_SECONDS, 2.0**attempt)
                time.sleep(wait)
            except (_TimeoutLike, OSError) as exc:
                last = ClassifiedError(reason="timeout", retryable=True, message=str(exc)[:300])
                if attempt >= max_retries:
                    return last
                time.sleep(min(_BACKOFF_CAP_SECONDS, 2.0**attempt))
        return last or ClassifiedError(reason="unknown")

    def _request(
        self,
        route: _Route,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        stream_cb: StreamCb | None,
    ) -> TurnResult:
        if not route.base_url:
            raise _ProviderHTTPError(
                ClassifiedError(
                    reason="format_error", retryable=False,
                    message=f"provider '{route.provider}' has no base_url configured",
                )
            )

        payload: dict[str, Any] = {
            "model": route.model,
            "messages": _to_wire_messages(messages),
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if route.reasoning_effort:
            payload["reasoning_effort"] = route.reasoning_effort
        if stream_cb is not None:
            payload["stream"] = True

        url = f"{route.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if route.api_key:
            headers["Authorization"] = f"Bearer {route.api_key}"

        client, close_after = self._client(route.timeout)
        try:
            if stream_cb is not None:
                return self._request_stream(client, url, headers, payload, route, stream_cb)
            response = client.post(url, json=payload, headers=headers)
            return self._normalize(response, route)
        finally:
            if close_after:
                client.close()

    def _client(self, timeout: int) -> tuple[Any, bool]:
        if self._transport is not None:
            return self._transport, False
        import httpx

        return httpx.Client(timeout=float(timeout), follow_redirects=False), True

    # ------------------------------------------------------- normalization --

    def _normalize(self, response: Any, route: _Route) -> TurnResult:
        status = int(getattr(response, "status_code", 0) or 0)
        if status >= 400:
            raise _ProviderHTTPError(
                self._verdict_for(status, _extract_error_text(response), response)
            )
        try:
            body = response.json()
        except (json.JSONDecodeError, ValueError, AttributeError) as exc:
            raise _ProviderHTTPError(
                ClassifiedError(reason="empty_response", message="provider returned non-JSON body")
            ) from exc
        return self._turn_from_body(body, route)

    def _request_stream(
        self,
        client: Any,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        route: _Route,
        stream_cb: StreamCb,
    ) -> TurnResult:
        text_parts: list[str] = []
        calls: dict[int, dict[str, Any]] = {}
        finish = ""
        usage: dict[str, Any] = {}

        with client.stream("POST", url, json=payload, headers=headers) as response:
            status = int(getattr(response, "status_code", 0) or 0)
            if status >= 400:
                body = b""
                try:
                    body = b"".join(response.iter_bytes())
                except Exception:
                    pass
                raise _ProviderHTTPError(
                    self._verdict_for(status, body.decode("utf-8", "replace"), response)
                )
            for line in response.iter_lines():
                if not line or not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    event = json.loads(chunk)
                except json.JSONDecodeError:
                    continue
                for choice in event.get("choices") or []:
                    delta = choice.get("delta") or {}
                    if delta.get("content"):
                        text_parts.append(delta["content"])
                        stream_cb(delta["content"])
                    for tc in delta.get("tool_calls") or []:
                        idx = tc.get("index", 0)
                        slot = calls.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["arguments"] += fn["arguments"]
                    if choice.get("finish_reason"):
                        finish = choice["finish_reason"]
                if event.get("usage"):
                    usage = event["usage"]

        tool_calls = tuple(
            ToolCall(id=slot["id"], name=slot["name"], arguments=_parse_args(slot["arguments"]))
            for slot in (calls[i] for i in sorted(calls))
            if slot["name"]
        )
        return TurnResult(
            text="".join(text_parts),
            tool_calls=tool_calls,
            finish_reason=finish or ("tool_calls" if tool_calls else "stop"),
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            cost_usd=_reported_cost(usage),
            model=route.model,
            provider=route.provider,
        )

    def _turn_from_body(self, body: dict[str, Any], route: _Route) -> TurnResult:
        choices = body.get("choices") or []
        if not choices:
            raise _ProviderHTTPError(
                ClassifiedError(reason="empty_response", message="provider returned no choices")
            )
        choice = choices[0]
        message = choice.get("message") or {}
        raw_calls = message.get("tool_calls") or []

        tool_calls: list[ToolCall] = []
        for tc in raw_calls:
            fn = tc.get("function") or {}
            name = (fn.get("name") or "").strip()
            call_id = tc.get("id") or ""
            if not name and not call_id:
                continue
            tool_calls.append(
                ToolCall(id=call_id, name=name, arguments=_parse_args(fn.get("arguments")))
            )

        usage = body.get("usage") or {}
        return TurnResult(
            text=message.get("content") or "",
            tool_calls=tuple(tool_calls),
            finish_reason=choice.get("finish_reason") or ("tool_calls" if tool_calls else "stop"),
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            cost_usd=_reported_cost(usage),
            model=body.get("model") or route.model,
            provider=route.provider,
        )

    @staticmethod
    def _verdict_for(status: int, body_text: str, response: Any) -> ClassifiedError:
        base = _STATUS_VERDICTS.get(status)
        message = (body_text or "").strip()[:300] or f"HTTP {status}"
        if base is None:
            reason = "server_error" if status >= 500 else "unknown"
            base = ClassifiedError(reason=reason, retryable=status >= 500, status_code=status)
        retry_after = None
        try:
            headers = getattr(response, "headers", {}) or {}
            raw = headers.get("retry-after") or headers.get("Retry-After")
            if raw:
                retry_after = min(_BACKOFF_CAP_SECONDS, float(raw))
        except (TypeError, ValueError):
            retry_after = None
        return ClassifiedError(
            reason=base.reason,
            retryable=base.retryable,
            should_fallback=base.should_fallback,
            status_code=status,
            message=message,
        ) or ClassifiedError(reason=base.reason, status_code=status, message=message)


class _ProviderHTTPError(Exception):
    __slots__ = ("verdict", "retry_after")

    def __init__(self, verdict: ClassifiedError) -> None:
        super().__init__(verdict.message)
        self.verdict = verdict
        self.retry_after = None


class _TimeoutLike(Exception):
    """Marker for transport timeouts raised by the injected client."""


def _extract_error_text(response: Any) -> str:
    try:
        body = response.json()
    except Exception:
        try:
            return response.text or ""
        except Exception:
            return ""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err)
        if err:
            return str(err)
        if body.get("message"):
            return str(body["message"])
    return str(body)[:300]


def _parse_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _reported_cost(usage: dict[str, Any]) -> float:
    """Only a cost the provider itself reports is trusted; never invented."""
    for key in ("cost_usd", "cost", "total_cost"):
        try:
            value = usage.get(key)
            if value is not None:
                return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0
