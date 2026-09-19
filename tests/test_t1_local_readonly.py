"""T1 local readonly contracts — search_files / read_file / skill linter (TDD red).

Planner B T1: fixed-string+regex file search, jailed file reads, and the skill
frontmatter linter. All tools are danger=none: no network, no approval.

Production target: ``hunter.agent.tools_local`` (NEW module to create) exposing
  - ``search_files`` handler + spec (fixed-string default, opt-in regex with
    size/timeout caps, jail-relative paths, max_hits clamped to 1..50,
    ripgrep optional with stdlib fallback)
  - ``read_file`` handler + spec (offset/limit paging, 1MB cap, redaction,
    jail escape -> BLOCKED)
  - ``lint_skill_card`` helper (frontmatter parse, description <=60 chars for
    NEW cards, backtick linkage from body to registered native-tool names)
plus registration of both specs in ``build_registry`` (danger="none").

Every test below FAILS today via EXPECTED-FAIL-TDD until that module lands.
Adversarial notes: Windows jail bypass (``..\\`` vs ``/``) is exercised with
pathlib resolution against tmp_path; ReDoS is covered by fixed-string-default
+ regex size/timeout caps; fixtures are secret-shaped to prove redaction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

TDD = "EXPECTED-FAIL-TDD:hunter.agent.tools_local (Planner B T1: search_files/read_file/skill-linter)"


def _require_tools_local():
    try:
        import hunter.agent.tools_local as tools_local  # type: ignore[import-not-found]
    except ImportError:
        pytest.fail(f"{TDD} — module missing; create it with search_files/read_file/lint_skill_card")
    return tools_local


def _jail(tmp_path: Path) -> Path:
    jail = tmp_path / "jail"
    (jail / "docs").mkdir(parents=True)
    (jail / "docs" / "audit.md").write_text(
        "scope: example.com\nfinding: reflected xss in q\nsecret token=TOPSECRET-abc123\n", encoding="utf-8"
    )
    (jail / "docs" / "notes.txt").write_text("plain notes\nnothing here\n", encoding="utf-8")
    (jail / "big.bin").write_bytes(b"x" * (2 * 1024 * 1024))  # 2MB — over the 1MB read cap
    return jail


# -- search_files ---------------------------------------------------------------

def test_t1_search_files_fixed_string_default(tmp_path: Path):
    """Contract: default query is FIXED-STRING (no regex metachars honored)."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    hits = tools_local.search_files({"pattern": "reflected xss", "root": str(jail)}, _t1_ctx(jail))
    assert hits["ok"] and any("audit.md" in h["path"] for h in hits["hits"])
    # A regex metachar pattern must NOT behave as regex unless regex=true.
    literal = tools_local.search_files({"pattern": "reflected.*xss", "root": str(jail)}, _t1_ctx(jail))
    assert literal["ok"] and literal["hits"] == [], "default must be fixed-string, not regex"


def test_t1_search_files_regex_opt_in_with_caps(tmp_path: Path):
    """Contract: regex=true honors patterns but enforces size/timeout caps."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    outcome = tools_local.search_files(
        {"pattern": "reflect(ed)?\\s+xss", "root": str(jail), "regex": True}, _t1_ctx(jail)
    )
    assert outcome["ok"] and any("audit.md" in h["path"] for h in outcome["hits"])
    spec_params = tools_local.SEARCH_FILES_SPEC["parameters"]["properties"]
    assert "regex" in spec_params and "max_hits" in spec_params
    # ReDoS-shaped pattern against a capped corpus must terminate (not hang).
    evil = tools_local.search_files(
        {"pattern": "(a+)+$", "root": str(jail), "regex": True, "max_hits": 5}, _t1_ctx(jail)
    )
    assert evil["code"] in ("ok", "search.regex_timeout", "search.pattern_too_large")


def test_t1_search_files_jail_relative_and_max_hits(tmp_path: Path):
    """Contract: results are jail-relative; max_hits clamped to 1..50."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    for raw in (0, -3, 5000):
        outcome = tools_local.search_files(
            {"pattern": "e", "root": str(jail), "max_hits": raw}, _t1_ctx(jail)
        )
        assert outcome["ok"] and 1 <= len(outcome["hits"]) <= 50, f"max_hits={raw} must clamp to 1..50"
    outcome = tools_local.search_files({"pattern": "scope", "root": str(jail)}, _t1_ctx(jail))
    for hit in outcome["hits"]:
        assert not Path(hit["path"]).is_absolute(), "hits must be jail-relative, never absolute"


def test_t1_search_files_escape_blocked(tmp_path: Path):
    """Contract: root / pattern escaping the jail (-> BLOCKED, no read)."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret", encoding="utf-8")
    for evil_root in (str(tmp_path / "jail" / ".." / "outside.txt"), str(outside)):
        outcome = tools_local.search_files({"pattern": "secret", "root": evil_root}, _t1_ctx(jail))
        assert outcome.get("blocked") is True and "jail" in outcome.get("code", ""), evil_root
    # Windows-style backtrack must also be contained.
    win_evil = str(jail) + "..\\..\\" + outside.name
    outcome = tools_local.search_files({"pattern": "secret", "root": win_evil}, _t1_ctx(jail))
    assert outcome.get("blocked") is True


def test_t1_search_files_no_backtrack_bomb(tmp_path: Path):
    """Contract: ``..`` segments that resolve INSIDE stay; deep ``..`` chains blocked."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    inner = tools_local.search_files(
        {"pattern": "scope", "root": str(jail / "docs" / "..")}, _t1_ctx(jail)
    )
    assert inner["ok"], "harmless '..' resolving inside the jail must still work"
    bomb = tools_local.search_files(
        {"pattern": "secret", "root": str(jail / ".." / ".." / ".." / "etc")}, _t1_ctx(jail)
    )
    assert bomb.get("blocked") is True


# -- read_file --------------------------------------------------------------------

def test_t1_read_file_offset_limit_and_cap(tmp_path: Path):
    """Contract: offset/limit paging; files >1MB refused/truncated, never fully loaded."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    page1 = tools_local.read_file(
        {"path": "docs/audit.md", "offset": 1, "limit": 1}, _t1_ctx(jail)
    )
    assert page1["ok"] and "scope:" in page1["text"] and "finding:" not in page1["text"]
    big = tools_local.read_file({"path": "big.bin"}, _t1_ctx(jail))
    assert big["ok"] is False or big.get("truncated") is True, "2MB file must hit the 1MB cap"
    assert len(big.get("text", "")) <= 1_048_576 + 256


def test_t1_read_file_redacted_and_escape_blocked(tmp_path: Path):
    """Contract: secret-shaped leaves redacted; jail escape -> BLOCKED."""
    tools_local = _require_tools_local()
    jail = _jail(tmp_path)
    outcome = tools_local.read_file({"path": "docs/audit.md"}, _t1_ctx(jail))
    assert outcome["ok"]
    assert "TOPSECRET-abc123" not in outcome["text"], "secret-shaped fixture must be redacted"
    assert "[REDACTED]" in outcome["text"]
    for evil in ("../outside.txt", "..\\outside.txt", "/etc/passwd", "docs/../../outside.txt"):
        blocked = tools_local.read_file({"path": evil}, _t1_ctx(jail))
        assert blocked.get("blocked") is True and blocked.get("code", "").endswith("outside_jail"), evil


def test_t1_local_tools_danger_none_no_network():
    """Contract: both specs register danger=none and perform no network I/O."""
    tools_local = _require_tools_local()
    assert tools_local.SEARCH_FILES_SPEC["danger"] == "none"
    assert tools_local.READ_FILE_SPEC["danger"] == "none"
    assert "network" not in str(tools_local.SEARCH_FILES_SPEC).lower()


# -- skill linter -------------------------------------------------------------------

def test_t1_skill_linter_frontmatter_and_length():
    """Contract: frontmatter parse; NEW-card description <=60 chars; old 200 stays parser-level."""
    tools_local = _require_tools_local()
    good = "---\nname: x\n description: short desc under sixty chars ok\n---\nbody `http_request`\n"
    assert tools_local.lint_skill_card(good, is_new=True)["ok"] is True
    long_desc = "---\nname: x\ndescription: " + ("word " * 20).strip() + "\n---\nbody\n"
    verdict = tools_local.lint_skill_card(long_desc, is_new=True)
    assert verdict["ok"] is False and "60" in verdict["error"], "new cards must be <=60 chars"
    legacy = "---\nname: x\ndescription: " + ("word " * 30).strip() + "\n---\nbody\n"
    assert tools_local.lint_skill_card(legacy, is_new=False)["ok"] is True, "old 200-char cards stay valid"


def test_t1_skill_linter_backtick_tool_linkage():
    """Contract: body must backtick-link at least one registered native tool."""
    tools_local = _require_tools_local()
    from hunter.agent.tools import build_registry

    registry = build_registry("basic")
    names = {s.name for s in registry.specs_for_tier("advanced")}
    linked = "---\nname: x\ndescription: short desc ok\n---\nUse `http_request` then bind evidence.\n"
    assert tools_local.lint_skill_card(linked, is_new=True, known_tools=names)["ok"] is True
    orphan = "---\nname: x\ndescription: short desc ok\n---\nJust vibes, no tool mentions.\n"
    verdict = tools_local.lint_skill_card(orphan, is_new=True, known_tools=names)
    assert verdict["ok"] is False and "backtick" in verdict["error"].lower()


# -- helper ---------------------------------------------------------------------------

def _t1_ctx(jail: Path) -> Any:
    from hunter.agent.tools_base import ToolContext
    from hunter.kernel.ledger import Ledger
    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import localhost_scope

    scope = localhost_scope()
    ledger = Ledger(":memory:")
    http = ScopedHttpClient(scope, transport=_never_transport())
    return ToolContext(
        run_id="R-T1", ledger=ledger, http=http, scope=scope,
        target_url="http://127.0.0.1:9/", emit=lambda k, p: None,
        config={"tier": "basic", "jail": str(jail)}, state={},
    )


def _never_transport():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must never fire
        raise AssertionError(f"T1 local tools must never touch the network: {request.url}")

    return httpx.MockTransport(handler)


def test_t1_no_real_network_transport_guard(tmp_path: Path):
    """Meta-guard: this file's own harness can never open a socket (MockTransport only)."""
    import httpx

    from hunter.tools.http_client import ScopedHttpClient
    from hunter.tools.scope import ScopeSet

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    scope = ScopeSet(frozenset({"example.com"}), name="t1")
    client = ScopedHttpClient(scope, transport=httpx.MockTransport(handler))
    assert client.request("GET", "http://example.com/").status == 200
    assert seen == ["http://example.com/"]
    client.close()
