"""Recursive attack-surface expansion, as an in-loop agent tool.

WHY THIS EXISTS
---------------
The old RAG workflow ("Recursive Autonomous Grind") did something genuinely
useful: given one finding it derived follow-up targets, and it could ask a model
to propose deeper variants. But it did that in a *feeder loop outside* the agent:
every child target became a separate queued hunt.

That separation is what broke the reasoning, not the idea. A child run starts
with an empty head — it does not know which finding spawned it, why, or what was
already ruled out. The recursion was real; the memory was not.

This module moves the same two mechanisms *inside* the agent loop as a tool:

* ``derive_child_targets``  — deterministic, cheap, no model call.
* ``wonder_followups``      — optional LLM assist, off by default.

The agent keeps one context, one budget, one chain of evidence, and expands its
own surface as it learns. That is the agent shape: tools + reasoning, not a
queue of amnesiac workers.

DESIGN NOTES
------------
* Scope is enforced HERE, on every candidate, in both modes. A follow-up target
  that leaves the approved scope is dropped before the model ever sees it — the
  expansion step must never be a scope-bypass primitive.
* The deterministic path never calls a provider, so it cannot stall a turn or
  fail on a rate limit. It is the default.
* The LLM path is opt-in per call (``assist=true``) and degrades to the
  deterministic result on any exception. A slow planner must never make an agent
  turn unusable.
* Results are recorded in ``ctx.state["expansions"]`` so a later turn (or the
  retro/curator pass) can see how the hunt actually spread.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse

from hunter.agent.tools_base import ToolContext, ToolOutcome

__all__ = [
    "expand_finding",
    "register_expand_tools",
    "derive_targets",
    "wonder_targets",
]

_MAX_TARGETS = 8


def _out(result_for_model: str, **extra: Any) -> ToolOutcome:
    return ToolOutcome(result_for_model=result_for_model, **extra)


def _origin_of(ctx: ToolContext) -> str:
    """Best-effort origin from the run's target URL."""
    target = str(getattr(ctx, "target_url", "") or "").strip()
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return target.rstrip("/")


def _in_scope(ctx: ToolContext, url: str) -> bool:
    """Fail-closed scope check. Any doubt means 'not a target'."""
    try:
        ctx.scope.check_url(url)
        return True
    except Exception:  # noqa: BLE001 — a scope check that raises is a refusal
        return False


def _absolute(endpoint: str, origin: str) -> str | None:
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return None
    if "://" in endpoint:
        return endpoint
    if not origin.lower().startswith(("http://", "https://")):
        return None
    base = origin.rstrip("/")
    if endpoint.startswith("/"):
        return f"{base}{endpoint}"
    return f"{base}/{endpoint.lstrip('/')}"


def derive_targets(ctx: ToolContext, endpoint: str, limit: int = _MAX_TARGETS) -> list[str]:
    """Deterministic follow-ups for one endpoint. No model call, no cost.

    Strategy: the endpoint itself, its path parent, its siblings under the same
    parent, and query-parameter variants that commonly change behaviour
    (pagination / id / redirect). Everything is scope-checked; a rejected
    candidate is simply absent from the result.
    """
    origin = _origin_of(ctx)
    seed = _absolute(endpoint, origin)
    if not seed:
        return []

    out: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if len(out) >= limit:
            return
        if url in seen:
            return
        seen.add(url)
        if _in_scope(ctx, url):
            out.append(url)

    add(seed)

    parsed = urlparse(seed)
    path = parsed.path or "/"

    # Path parent — findings often sit deep and the parent aggregates them.
    if path not in ("", "/"):
        parent = path.rstrip("/").rsplit("/", 1)[0] or "/"
        if parent != path:
            add(urlunparse((parsed.scheme, parsed.netloc, parent, "", "", "")))

    # Query variants: the same resource addressed differently is where auth and
    # filtering bugs live.
    if parsed.query:
        add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", "")))
    else:
        for probe in ("?page=2", "?id=1", "?redirect=/", "?debug=1"):
            add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", probe.lstrip("?"), "")))

    return out


def wonder_targets(
    ctx: ToolContext,
    endpoint: str,
    title: str,
    limit: int = 4,
) -> list[str]:
    """LLM-assisted follow-ups. Opt-in, degrades to [] on any failure."""
    provider = ctx.config.get("provider")
    if provider is None:
        return []

    origin = _origin_of(ctx)
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security-hunt planner. Given one finding, propose "
                f"up to {limit} in-scope follow-up URLs to hunt next: deeper "
                "variants, sibling routes, or parameter variants that could "
                "reveal the same class of bug. Return ONLY a JSON array of "
                "strings. No prose."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Finding: {title}\nEndpoint: {endpoint}\nOrigin: {origin}\n"
                f"Allowed hosts: {sorted(getattr(ctx.scope, 'allowed_hosts', set()) or [])}\n"
                f"Return a JSON array of at most {limit} URLs."
            ),
        },
    ]
    try:
        turn = provider.complete("utility", messages, budget=None)
    except Exception:  # noqa: BLE001 — an assist must never break the turn
        return []

    text = str(getattr(turn, "text", "") or "")
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end <= start:
        return []
    try:
        import json

        data = json.loads(text[start : end + 1])
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(data, list):
        return []

    out: list[str] = []
    for raw in data:
        cand = _absolute(str(raw).strip(), origin)
        if not cand or cand in out:
            continue
        if _in_scope(ctx, cand):
            out.append(cand)
        if len(out) >= limit:
            break
    return out


def expand_finding(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
    """Expand one finding into scope-checked follow-up targets, in this run."""
    finding_id = str(args.get("finding_id", "") or "").strip()
    endpoint_arg = str(args.get("endpoint", "") or "").strip()
    assist = bool(args.get("assist", False))
    limit = args.get("limit", _MAX_TARGETS)
    try:
        limit = max(1, min(int(limit), _MAX_TARGETS))
    except (TypeError, ValueError):
        limit = _MAX_TARGETS

    title = ""
    endpoint = endpoint_arg

    # Resolve the finding from the ledger when an id is given, so the caller
    # cannot invent a target that is not anchored to real evidence.
    if finding_id:
        rows = [f for f in ctx.ledger.findings(ctx.run_id) if str(getattr(f, "id", "")) == finding_id]
        if not rows:
            return _out(
                f"BLOCKED: finding {finding_id!r} does not exist in this run. "
                "expand_finding requires a real finding_id from list_findings."
            )
        finding = rows[0]
        title = str(getattr(finding, "title", "") or "")
        if not endpoint:
            endpoint = str(getattr(finding, "endpoint", "") or "")
    elif not endpoint:
        return _out(
            "BLOCKED: expand_finding requires either 'finding_id' (preferred) or an "
            "explicit 'endpoint'."
        )

    deterministic = derive_targets(ctx, endpoint, limit=limit)
    assisted: list[str] = []
    if assist:
        assisted = wonder_targets(ctx, endpoint, title or endpoint, limit=min(4, limit))

    merged: list[str] = []
    for url in deterministic + assisted:
        if url not in merged:
            merged.append(url)

    if not merged:
        return _out(
            f"no in-scope follow-up targets derived from {endpoint!r}. "
            "Either the endpoint is out of scope, the target has no URL origin "
            "(repo/dir hunts), or every derived variant failed the scope check."
        )

    expansions: list[dict[str, Any]] = ctx.state.setdefault("expansions", [])
    expansions.append(
        {
            "finding_id": finding_id or None,
            "endpoint": endpoint,
            "targets": merged,
            "assist": assist,
        }
    )

    lines = [
        f"expand_finding: {len(merged)} in-scope target(s) from {endpoint!r}",
        f"  deterministic: {len(deterministic)}   llm-assisted: {len(assisted)}",
        "targets:",
    ]
    lines.extend(f"  - {url}" for url in merged)
    lines.append(
        "next: probe these IN THIS RUN (run_probe / http_request / dns_resolve). "
        "Do not assume a finding exists — expand only follows what evidence shows."
    )
    return _out("\n".join(lines))


def register_expand_tools(registry: Any) -> Any:
    """Register the recursive-expansion surface. Mirrors the toolchain pattern."""
    from hunter.agent.tools_base import ToolSpec  # noqa: PLC0415

    registry.register(
        ToolSpec(
            name="expand_finding",
            description=(
                "Expand ONE finding into in-scope follow-up targets and hunt them in "
                "THIS run. Default is deterministic (free, no model call): the "
                "endpoint, its path parent, and query variants. Pass assist=true to "
                "additionally ask a planner model for deeper variants — it degrades "
                "to the deterministic set on any failure. Every target is "
                "scope-checked before it is returned."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Real finding id from list_findings (preferred).",
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Explicit endpoint/URL when no finding_id is given.",
                    },
                    "assist": {
                        "type": "boolean",
                        "description": "Opt-in LLM planner assist. Default false.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": f"Max targets (1-{_MAX_TARGETS}, default {_MAX_TARGETS}).",
                    },
                },
                "required": [],
            },
            handler=expand_finding,
        )
    )
    return registry
