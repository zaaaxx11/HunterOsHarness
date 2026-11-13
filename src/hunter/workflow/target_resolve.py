"""LLM-assisted hunt target resolution for the CLI.

`hunter hunt <target>` historically demanded that the positional argument be a
URL or an existing directory *before* the LLM was ever consulted. That made
free-form mandates ("hunt the relay chain contracts on 537713") and bare
contract addresses (`0xddd3...`) dead on arrival: the deterministic gate
rejected them with "BLOCKED: invalid hunt target".

This module keeps the deterministic gate as the fast path and adds an LLM
parsing pass behind it: when the deterministic answer is not usable, the LLM
classifies the mandate and proposes a scope. Only when the LLM also fails does
the caller refuse — fail-closed is preserved, the gate is just no longer blind.

Contract addresses get special handling. A bare `0x…` hex string is not a URL,
so the deterministic gate rejects it, but it is a perfectly good hunt target
for the EVM engine. The LLM pass recognises it and, when the caller supplied
no RPC, the resolver derives one from a built-in chain table so the run has a
reachable host instead of a dead scope.
"""

from __future__ import annotations

import json
import re
from typing import Any

__all__ = ["resolve_hunt_target", "DEFAULT_CHAIN_RPCS"]

# Minimal chain table. Only the chains HunterOS is actually pointed at — this
# is not a general RPC registry, it exists so a bare contract address can be
# turned into a runnable hunt when the operator gave no RPC of their own.
DEFAULT_CHAIN_RPCS: dict[str, str] = {
    "537713": "https://rpc.chain.relay.link",
    "1313161554": "https://mainnet.aurora.dev",
    "1": "https://eth.drpc.org",
    "42161": "https://arb1.arbitrum.io",
    "137": "https://polygon.drpc.org",
    "8453": "https://mainnet.base.org",
    "84532": "https://sepolia.base.org",
    "10": "https://mainnet.optimism.io",
}

_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_CHAIN_ID_RE = re.compile(r"\b(?:chain[_ ]?id[:\s]*|chain\s+)(\d{3,10})\b", re.IGNORECASE)
_RPC_RE = re.compile(r"https?://[^\s,;)\]]+")


class ResolvedTarget:
    """Outcome of resolving one positional hunt argument.

    ``ok`` is the only field a caller needs to branch on. ``target`` is the
    string to hand to ``run_hunt``; ``scope_manifest`` is an optional dict the
    caller may pass to ``scope_from_manifest``; ``reason`` explains a refusal.
    """

    __slots__ = ("ok", "target", "kind", "scope_manifest", "reason", "via_llm")

    def __init__(
        self,
        *,
        ok: bool,
        target: str = "",
        kind: str = "",
        scope_manifest: dict[str, Any] | None = None,
        reason: str = "",
        via_llm: bool = False,
    ) -> None:
        self.ok = ok
        self.target = target
        self.kind = kind
        self.scope_manifest = scope_manifest
        self.reason = reason
        self.via_llm = via_llm

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"ResolvedTarget(ok={self.ok}, kind={self.kind!r}, "
            f"target={self.target!r}, via_llm={self.via_llm}, reason={self.reason!r})"
        )


def _manifest_for_contract(
    address: str, chain_id: str, rpc: str, extra_hosts: list[str]
) -> dict[str, Any]:
    # `hosts` is consumed by the scope gate, which matches hostnames. A bare
    # 0x address is not a hostname, so it belongs in `addresses` instead —
    # otherwise the gate treats it as an unresolvable host and every request
    # against the real RPC host is judged out of scope.
    hosts = [h for h in (re.sub(r"^https?://", "", rpc).split("/")[0] if rpc else "", *extra_hosts) if h and not _ADDRESS_RE.fullmatch(h)]
    manifest: dict[str, Any] = {
        "name": f"contract-{address[:10]}-{chain_id}",
        "hosts": list(dict.fromkeys(hosts)),
        "addresses": [address],
        "allow_subdomains": False,
        "notes": (
            f"smart contract {address} on chain {chain_id} "
            f"(LLM-resolved from a free-form mandate)"
        ),
    }
    if chain_id:
        manifest["chain_id"] = chain_id
    if rpc:
        manifest["rpc"] = rpc
    return manifest


def _llm_parse(description: str, provider: Any) -> dict[str, Any] | None:
    """Ask the LLM for a structured parse of a free-form mandate."""
    if provider is None:
        return None
    from hunter.agent.soul import CORE_IDENTITY

    messages = [
        {
            "role": "system",
            "content": (
                f"{CORE_IDENTITY}\n\n"
                "You parse one hunt mandate for a security harness. "
                "Return ONLY a JSON object, no prose. Keys:\n"
                '  "targets": list of concrete targets (URLs, hosts, local paths, '
                "bare 0x contract addresses)\n"
                '  "kind": "smartcontract" | "url" | "repo" | "dir" | "api"\n'
                '  "chain_id": chain id string for contract targets, else ""\n'
                '  "rpc": JSON-RPC endpoint for contract targets, else ""\n'
                '  "local_roots": list of local directories to audit, else []\n'
                "Extract every concrete target mentioned. Never invent an address "
                "or URL that was not stated or strongly implied."
            ),
        },
        {"role": "user", "content": f"Mandate: {description}\nReturn JSON only."},
    ]
    try:
        turn = provider.complete("utility", messages, budget=None)
        text = str(getattr(turn, "text", "") or "").strip()
    except Exception:  # noqa: BLE001 - provider failure must not kill the hunt
        return None
    return _extract_json_obj(text)


def _extract_json_obj(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def resolve_hunt_target(
    raw: str,
    *,
    normalize_hunt_target,
    provider: Any = None,
    logger: Any = None,
) -> ResolvedTarget:
    """Resolve one positional hunt argument, using the LLM when the gate fails.

    ``normalize_hunt_target`` is passed in (rather than imported) so the
    resolver stays testable against the real function without an import cycle,
    and so a caller can substitute the deterministic gate.

    Order of operations:
      1. deterministic gate — URL, host, or existing directory
      2. LLM parse — free-form mandate or bare contract address
      3. regex salvage — a `0x…` address or an explicit RPC URL found in the text
      4. refuse
    """
    token = (raw or "").strip()
    if not token:
        return ResolvedTarget(ok=False, reason="empty target")

    # A bare contract address is not a host. `normalize_hunt_target` accepts a
    # token starting with a digit as a host, so `0xabc…` slips through as
    # `http://0xabc…`. Check for an address BEFORE the gate.
    if _ADDRESS_RE.fullmatch(token):
        parsed = _llm_parse(token, provider)
        chain_id = str((parsed or {}).get("chain_id") or "").strip()
        rpc = str((parsed or {}).get("rpc") or "").strip()
        if not chain_id:
            m = _CHAIN_ID_RE.search(token)
            if m:
                chain_id = m.group(1)
        if not rpc and chain_id in DEFAULT_CHAIN_RPCS:
            rpc = DEFAULT_CHAIN_RPCS[chain_id]
        if not rpc:
            return ResolvedTarget(
                ok=False,
                reason=(
                    f"contract {token} recognised but no RPC is known for chain "
                    f"{chain_id or '(unspecified)'} — pass an RPC in the mandate "
                    "or use --scope"
                ),
                via_llm=parsed is not None,
            )
        return ResolvedTarget(
            ok=True,
            target=rpc,
            kind="smartcontract",
            scope_manifest=_manifest_for_contract(token, chain_id, rpc, [token]),
            via_llm=parsed is not None,
        )

    normalized, kind = normalize_hunt_target(token)
    if kind != "invalid":
        return ResolvedTarget(ok=True, target=normalized, kind=kind)

    # The deterministic gate refused. Before giving up, ask the LLM — this is
    # the path that makes free-form mandates work at all.
    parsed = _llm_parse(token, provider)
    if parsed is not None:
        targets = parsed.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        targets = [str(t).strip() for t in targets if str(t).strip()]
        chain_id = str(parsed.get("chain_id") or "").strip()
        rpc = str(parsed.get("rpc") or "").strip()
        local_roots = [str(r) for r in (parsed.get("local_roots") or []) if str(r).strip()]
        via_llm = True

        if local_roots:
            return ResolvedTarget(
                ok=True,
                target=local_roots[0],
                kind="dir",
                scope_manifest={
                    "name": "llm-local-audit",
                    "hosts": [],
                    "local_roots": local_roots,
                    "allow_subdomains": False,
                    "notes": "LLM-resolved local audit scope",
                },
                via_llm=True,
            )

        for candidate in targets:
            c_norm, c_kind = normalize_hunt_target(candidate)
            if c_kind != "invalid":
                manifest = None
                if c_kind == "url":
                    host = c_norm
                    manifest = {
                        "name": host,
                        "hosts": [host],
                        "allow_subdomains": False,
                        "notes": "LLM-resolved target",
                    }
                return ResolvedTarget(
                    ok=True, target=c_norm, kind=c_kind, scope_manifest=manifest, via_llm=via_llm
                )

        # No URL-shaped target, but maybe contract addresses were named.
        addresses = [t for t in targets if _ADDRESS_RE.fullmatch(t)]
        if not addresses:
            addresses = _ADDRESS_RE.findall(token)
        if addresses:
            chosen_chain = chain_id or ""
            chosen_rpc = rpc
            if not chosen_chain:
                m = _CHAIN_ID_RE.search(token)
                if m:
                    chosen_chain = m.group(1)
            if not chosen_rpc and chosen_chain in DEFAULT_CHAIN_RPCS:
                chosen_rpc = DEFAULT_CHAIN_RPCS[chosen_chain]
            if not chosen_rpc:
                # Without an RPC the run has no reachable host and the scope
                # gate would reject every request. Refuse instead of failing
                # later with a confusing per-request error.
                return ResolvedTarget(
                    ok=False,
                    reason=(
                        f"contract {addresses[0]} recognised but no RPC is known for "
                        f"chain {chosen_chain or '(unspecified)'} — pass an RPC in the "
                        "mandate or use --scope"
                    ),
                    via_llm=True,
                )
            if logger is not None:
                try:
                    logger(
                        f"LLM parsed contract target {addresses[0]} on chain "
                        f"{chosen_chain or '?'} via {chosen_rpc}"
                    )
                except Exception:  # noqa: BLE001 - logging must never break a hunt
                    pass
            return ResolvedTarget(
                ok=True,
                target=chosen_rpc,
                kind="smartcontract",
                scope_manifest=_manifest_for_contract(
                    addresses[0], chosen_chain, chosen_rpc, targets
                ),
                via_llm=True,
            )

    # No LLM answer (or an unusable one). Salvage with regex before refusing:
    # a bare 0x address or an explicit RPC URL is enough to build a scope.
    addresses = _ADDRESS_RE.findall(token)
    if addresses:
        rpc_match = _RPC_RE.search(token)
        chain_match = _CHAIN_ID_RE.search(token)
        chain_id = chain_match.group(1) if chain_match else ""
        rpc = rpc_match.group(0) if rpc_match else DEFAULT_CHAIN_RPCS.get(chain_id, "")
        if rpc:
            return ResolvedTarget(
                ok=True,
                target=rpc,
                kind="smartcontract",
                scope_manifest=_manifest_for_contract(addresses[0], chain_id, rpc, []),
                reason="resolved by regex salvage (LLM unavailable)",
            )
        return ResolvedTarget(
            ok=False,
            reason=(
                f"contract {addresses[0]} recognised but no RPC is known for chain "
                f"{chain_id or '(unspecified)'} — pass an RPC in the mandate or use --scope"
            ),
        )

    return ResolvedTarget(
        ok=False,
        reason=(
            "could not parse the target — neither the deterministic gate nor the "
            "LLM found a URL, host, directory, or contract address"
        ),
    )
