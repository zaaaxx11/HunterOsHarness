"""Tests for the omnivore Phase 0 RECON — classification, gathering, fallback.

These are offline-safe: the classifier, file/directory/text gatherers and the
deterministic fallback never touch the network. The url/github/app/contract
gatherers are exercised only for their shape (guarded by a network marker).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hunter.workflow.phase0_recon import (
    Phase0Recon,
    classify_input,
    gather_material,
    run_recon,
    TARGET_JSON_SCHEMA,
)


# ---------------------------------------------------------------- classifier

@pytest.mark.parametrize("token,kind", [
    ("https://example.com/x", "url"),
    ("http://foo.bar", "url"),
    ("https://github.com/owner/repo", "github"),
    ("https://github.com/owner", "github"),
    ("https://play.google.com/store/apps/details?id=com.example.app", "playstore"),
    ("https://apps.apple.com/us/app/thing/id123456789", "appstore"),
    ("0x" + "a" * 40, "contract"),
    ("0x" + "b" * 64, "tx"),
    ("just some words", "text"),
    ("", "text"),
])
def test_classify_input(token, kind):
    assert classify_input(token) == kind


def test_classify_local_file_and_dir(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("x")
    assert classify_input(str(f)) == "file"
    assert classify_input(str(tmp_path)) == "directory"


# ---------------------------------------------------------------- gather (offline)

def test_gather_file_extracts_targets(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text(
        "in scope: *.example.com, api.example.com\n"
        "url https://app.example.com/dash\n"
        "repo https://github.com/example/backend\n"
        "addr 0x" + "a" * 40 + "\n"
        "mail security@example.com\n"
    )
    m = gather_material(str(f))
    assert m["kind"] == "file"
    assert "api.example.com" in m["domains_in_file"]
    assert "https://app.example.com/dash" in m["urls_in_file"]
    assert "0x" + "a" * 40 in m["addresses_in_file"]
    assert "security@example.com" in m["emails_in_file"]


def test_gather_text_extracts_targets():
    m = gather_material("hit https://foo.bar/api and api.baz.io plus github.com/org/repo")
    assert m["kind"] == "text"
    assert "https://foo.bar/api" in m["urls_in_text"]
    assert "api.baz.io" in m["domains_in_text"]
    assert any("github.com/org/repo" in g for g in m["github_in_text"])


def test_gather_directory_inventories(tmp_path):
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "b.sol").write_text("y")
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "c.go").write_text("z")
    m = gather_material(str(tmp_path))
    assert m["kind"] == "directory"
    assert m["file_count"] == 3
    assert m["extensions"].get(".py") == 1


# ---------------------------------------------------------------- fallback

def test_deterministic_fallback_contract(tmp_path):
    addr = "0x" + "c" * 40
    out = run_recon(addr, None, tmp_path)
    assert out["input_kind"] == "contract"
    contracts = out["target"]["contracts"]
    assert contracts and contracts[0]["address"] == addr
    assert (tmp_path / "target.json").exists()


def test_deterministic_fallback_file(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("api.example.com\nhttps://x.example.com\n")
    out = run_recon(str(f), None, tmp_path)
    assert out["input_kind"] == "file"
    assets = [e["asset"] for e in out["target"]["scope"]["in_scope"]]
    assert any("example.com" in a for a in assets)


def test_llm_path_used_when_available(tmp_path):
    def llm(system, user):
        return json.dumps({
            "target": {"name": "X", "url": "https://x", "type": "web2",
                       "scope": {"in_scope": [], "out_of_scope": [], "excluded_bugs": []},
                       "rules": {}, "rewards": {}, "stack_hints": [], "auth": {},
                       "repo_hints": [], "api_hints": [], "contracts": [], "mobile": [],
                       "contacts": [], "notes": []},
            "seed_leads": [], "open_questions": [], "recon_confidence": 42,
        })
    out = run_recon("https://github.com/owner/repo", llm, tmp_path)
    assert out["recon_confidence"] == 42
    assert out["input_kind"] == "github"
    assert (tmp_path / "target.json").exists()


def test_llm_bad_output_falls_back(tmp_path):
    out = run_recon("https://example.com", lambda s, u: "not json at all", tmp_path)
    assert out["recon_confidence"] > 0  # fallback produced something
    assert out["open_questions"]  # fallback records the miss


def test_target_json_is_written_atomically(tmp_path):
    run_recon("https://example.com", None, tmp_path)
    data = json.loads((tmp_path / "target.json").read_text())
    assert "target" in data and "recon_tools" in data and "recon_at" in data
    # no leftover temp file
    assert not list(tmp_path.glob("*.tmp"))


# ---------------------------------------------------------------- network (opt-in)

@pytest.mark.network
def test_gather_github_live(tmp_path):
    m = gather_material("https://github.com/zaaaxx11/HunterOsHarness")
    assert m["kind"] == "github"
    assert m.get("repo_meta", {}).get("full_name") == "zaaaxx11/HunterOsHarness"


@pytest.mark.network
def test_gather_contract_live(tmp_path):
    m = gather_material("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    assert m["kind"] == "contract"
    # at least one explorer or RPC should see USDC
    assert m.get("explorer_hits") or m.get("rpc_probes")
