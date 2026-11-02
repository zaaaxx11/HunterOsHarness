"""Tests for LLM-assisted hunt target resolution.

The deterministic gate in ``hunter.hunt.normalize_hunt_target`` only accepts a
URL, a bare host, or an existing directory. Free-form mandates ("audit the
relay chain contracts on 537713") and bare contract addresses never reach the
LLM at all — they die at the gate with "BLOCKED: invalid hunt target".

These tests pin the resolution order: deterministic first, LLM second, regex
salvage third, refusal last. Fail-closed is preserved at every step.
"""

from __future__ import annotations

import pytest

from hunter.hunt import normalize_hunt_target
from hunter.workflow.target_resolve import (
    DEFAULT_CHAIN_RPCS,
    resolve_hunt_target,
)


class FakeProvider:
    """Minimal provider stub returning a canned JSON answer."""

    def __init__(self, answer: str | None) -> None:
        self.answer = answer
        self.calls: list[list[dict]] = []

    def complete(self, tier: str, messages: list[dict], budget=None):
        self.calls.append(messages)
        from types import SimpleNamespace

        return SimpleNamespace(text=self.answer or "")


# ---------------------------------------------------------------- deterministic


def test_url_never_reaches_the_llm():
    provider = FakeProvider("{}")
    r = resolve_hunt_target(
        "https://api.relay.link/x", normalize_hunt_target=normalize_hunt_target, provider=provider
    )
    assert r.ok is True
    assert r.kind == "url"
    assert r.via_llm is False
    assert provider.calls == [], "a URL must not waste an LLM call"


def test_existing_directory_passes_through(tmp_path):
    d = tmp_path / "contracts"
    d.mkdir()
    provider = FakeProvider(None)
    r = resolve_hunt_target(
        str(d), normalize_hunt_target=normalize_hunt_target, provider=provider
    )
    assert r.ok is True
    assert r.kind == "dir"
    assert r.scope_manifest is None
    assert provider.calls == []


def test_empty_target_refused():
    r = resolve_hunt_target(
        "   ", normalize_hunt_target=normalize_hunt_target, provider=FakeProvider("{}")
    )
    assert r.ok is False
    assert "empty" in r.reason


# ------------------------------------------------------------------- LLM parsing


def test_free_form_mandate_parsed_by_llm():
    provider = FakeProvider(
        '{"targets": ["0xddd361727c22a01eb137880678a20b0beae69318"],'
        ' "kind": "smartcontract", "chain_id": "537713",'
        ' "rpc": "https://rpc.chain.relay.link"}'
    )
    r = resolve_hunt_target(
        "hunt the relay chain hub contract on 537713",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True
    assert r.via_llm is True
    assert r.kind == "smartcontract"
    assert r.target == "https://rpc.chain.relay.link"
    manifest = r.scope_manifest
    assert manifest is not None
    assert "rpc.chain.relay.link" in manifest["hosts"]
    assert manifest["chain_id"] == "537713"
    assert len(provider.calls) == 1


def test_llm_can_name_an_rpc_directly():
    provider = FakeProvider(
        '{"targets": ["0xabc0000000000000000000000000000000000001"],'
        ' "chain_id": "1", "rpc": "https://eth.drpc.org"}'
    )
    r = resolve_hunt_target(
        "check this contract 0xabc0000000000000000000000000000000000001",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True
    assert r.target == "https://eth.drpc.org"
    assert r.scope_manifest["hosts"] == ["eth.drpc.org"]


def test_llm_local_roots_resolve_to_a_dir_target(tmp_path):
    root = tmp_path / "relay-settlement"
    root.mkdir()
    provider = FakeProvider(
        '{"targets": [], "local_roots": ["%s"], "kind": "dir"}' % root
    )
    r = resolve_hunt_target(
        "audit the relay settlement contracts locally",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True
    assert r.kind == "dir"
    assert r.target == str(root)
    assert r.scope_manifest["local_roots"] == [str(root)]
    assert r.via_llm is True


def test_llm_failure_falls_back_to_regex_salvage():
    # No provider answer at all — but the mandate contains an address and an
    # explicit RPC, which is enough to build a runnable scope.
    r = resolve_hunt_target(
        "audit 0xddd361727c22a01eb137880678a20b0beae69318 via https://rpc.chain.relay.link",
        normalize_hunt_target=normalize_hunt_target,
        provider=FakeProvider("not json at all"),
    )
    assert r.ok is True
    assert r.target == "https://rpc.chain.relay.link"
    assert r.via_llm is False


def test_contract_without_any_rpc_is_refused():
    r = resolve_hunt_target(
        "audit 0xddd361727c22a01eb137880678a20b0beae69318 please",
        normalize_hunt_target=normalize_hunt_target,
        provider=FakeProvider("{}"),
    )
    assert r.ok is False
    assert "RPC" in r.reason


def test_unknown_chain_without_rpc_is_refused():
    provider = FakeProvider(
        '{"targets": ["0xabc0000000000000000000000000000000000001"], "chain_id": "999999"}'
    )
    r = resolve_hunt_target(
        "audit contract on chain 999999",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is False
    assert "RPC" in r.reason


def test_unparseable_mandate_is_refused():
    r = resolve_hunt_target(
        "do the thing with the stuff",
        normalize_hunt_target=normalize_hunt_target,
        provider=FakeProvider("{}"),
    )
    assert r.ok is False


def test_provider_exception_does_not_kill_resolution():
    class Exploding:
        def complete(self, *a, **kw):
            raise RuntimeError("provider down")

    r = resolve_hunt_target(
        "audit 0xddd361727c22a01eb137880678a20b0beae69318 on chain 537713",
        normalize_hunt_target=normalize_hunt_target,
        provider=Exploding(),
    )
    # The built-in chain table knows Relay's RPC, so salvage succeeds.
    assert r.ok is True
    assert r.target == DEFAULT_CHAIN_RPCS["537713"]


def test_fenced_json_answer_is_parsed():
    provider = FakeProvider(
        "```json\n"
        '{"targets": ["0xddd361727c22a01eb137880678a20b0beae69318"],'
        ' "chain_id": "537713", "rpc": "https://rpc.chain.relay.link"}\n'
        "```"
    )
    r = resolve_hunt_target(
        "relay chain hub",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True
    assert r.target == "https://rpc.chain.relay.link"


def test_prose_wrapped_json_is_parsed():
    provider = FakeProvider(
        "Sure! Here is the parse:\n"
        '{"targets": ["0xddd361727c22a01eb137880678a20b0beae69318"],'
        ' "chain_id": "537713", "rpc": "https://rpc.chain.relay.link"}\n'
        "Let me know if you need more."
    )
    r = resolve_hunt_target(
        "relay chain hub",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True


def test_llm_url_target_gets_a_scope_manifest():
    provider = FakeProvider('{"targets": ["https://rpc.chain.relay.link"]}')
    r = resolve_hunt_target(
        "probe the relay rpc",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True
    assert r.kind == "url"
    assert r.scope_manifest["hosts"] == ["https://rpc.chain.relay.link"]


def test_multiple_addresses_first_wins():
    provider = FakeProvider(
        '{"targets": ["0xddd361727c22a01eb137880678a20b0beae69318",'
        ' "0xd180dc3b8cb71b185c563b6e4857592ca93dacaf"],'
        ' "chain_id": "537713", "rpc": "https://rpc.chain.relay.link"}'
    )
    r = resolve_hunt_target(
        "audit the hub and oracle on relay chain",
        normalize_hunt_target=normalize_hunt_target,
        provider=provider,
    )
    assert r.ok is True
    assert "0xddd3" in r.scope_manifest["name"]
