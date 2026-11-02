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

    registry = build_registry()
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


# -- multi-root jail (local_root + state_dir) ----------------------------------


def _multi_ctx(tmp_path: Path, *, jail: Path, local_root: Path) -> Any:
    """A ctx shaped like a real local-directory hunt.

    ``state_dir`` is where the ledger lives; ``local_root`` is the project
    being audited. They are different trees, and the agent must be able to
    read the second one.
    """
    tools_local = _require_tools_local()

    class _Ctx:
        config = {"state_dir": str(tmp_path / "state"), "local_root": str(local_root), "jail": str(jail)}
        run_id = "R-test"

        def emit(self, *args, **kwargs):  # noqa: D102 - test seam
            return None

    return _Ctx()


def test_local_root_is_a_jail_too(tmp_path: Path):
    """The target project must be readable on a local hunt.

    With the state dir as the only jail, every absolute path into the target
    was refused as "escapes jail" — backwards, since the target is the one
    place the agent MUST read. This is the bug that made a contract audit
    spend 8 of its 16 turns on archive_read failures.
    """
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    (project / "contracts").mkdir(parents=True)
    target = project / "contracts" / "Vault.sol"
    target.write_text("contract Vault { function sweep() external {} }\n", encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=tmp_path / "jail", local_root=project)

    outcome = tools_local.read_file({"path": str(target)}, ctx)

    assert outcome.get("ok") is True, outcome
    assert "Vault" in outcome.get("text", "")


def test_paths_outside_every_root_are_still_blocked(tmp_path: Path):
    """Multi-root must not become no-root."""
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("outside secret", encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=tmp_path / "jail", local_root=project)

    for evil in (str(outside), "/etc/passwd", "../outside/secret.txt"):
        outcome = tools_local.read_file({"path": evil}, ctx)
        assert outcome.get("blocked") is True, evil
        assert "jail" in outcome.get("code", ""), evil


def test_state_dir_still_readable_alongside_local_root(tmp_path: Path):
    """Both roots work in the same run — the ledger and the project."""
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    (state / "ledger.db").write_text("not really a db", encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=state, local_root=project)

    outcome = tools_local.read_file({"path": str(state / "ledger.db")}, ctx)

    assert outcome.get("ok") is True, outcome


def test_search_glob_finds_hits_under_local_root(tmp_path: Path):
    """search_glob walked only the first root before; the project was invisible."""
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    (project / "contracts").mkdir(parents=True)
    (project / "contracts" / "A.sol").write_text("// replay risk here\ncontract A {}\n", encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=tmp_path / "state", local_root=project)

    outcome = tools_local.search_glob({"glob": "contracts/*.sol", "pattern": "replay"}, ctx)

    assert outcome.get("ok") is True, outcome
    assert any("A.sol" in h.get("path", "") for h in outcome.get("hits", [])), outcome


# -- read_file must return the whole file --------------------------------------


def test_read_file_returns_the_whole_contract(tmp_path: Path):
    """A 200-line default silently hid most of every real contract.

    The agent read the first 200 lines, found nothing, and then re-fetched
    the SAME file over http_request (which has no line cap) a dozen times to
    see the rest — one audit burned 17 turns re-downloading one file. The
    default must cover a real Solidity file in one call.
    """
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    project.mkdir()
    target = project / "Big.sol"
    target.write_text("\n".join(f"// line {i}" for i in range(1, 726)), encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=project, local_root=project)

    outcome = tools_local.read_file({"path": str(target)}, ctx)

    assert outcome.get("ok") is True, outcome
    # The whole 725 lines must arrive, not the first 200.
    assert "line 725" in outcome.get("text", ""), "tail of the file was cut off"
    assert "line 1" in outcome.get("text", "")


def test_read_file_names_the_remainder_and_the_next_offset(tmp_path: Path):
    """When a file IS longer than the page, say so and say where to resume.

    A silent cut looks like a complete file, so the agent concludes "nothing
    here" — or routes around the tool. Naming the remainder turns the gap
    into one more read_file call.
    """
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    project.mkdir()
    target = project / "Long.sol"
    target.write_text("\n".join(f"// line {i}" for i in range(1, 901)), encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=project, local_root=project)

    outcome = tools_local.read_file({"path": str(target), "limit": 100}, ctx)

    assert outcome.get("ok") is True, outcome
    assert outcome.get("truncated") is True
    assert "line 101" not in outcome.get("text", ""), "page limit was ignored"
    assert "offset=101" in outcome.get("text", ""), "the next offset must be named"
    assert "900" in outcome.get("result_for_model", ""), "the total must be named"


def test_read_file_offset_resumes_where_the_page_ended(tmp_path: Path):
    """offset=101 must return line 101, not line 1 again."""
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    project.mkdir()
    target = project / "Long.sol"
    target.write_text("\n".join(f"// line {i}" for i in range(1, 901)), encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=project, local_root=project)

    outcome = tools_local.read_file({"path": str(target), "limit": 100, "offset": 101}, ctx)

    assert outcome.get("ok") is True, outcome
    assert "line 101" in outcome.get("text", "")
    assert "line 100" not in outcome.get("text", "")


# -- the search -> read round-trip ---------------------------------------------


def test_read_file_accepts_the_relative_path_search_reported(tmp_path: Path):
    """search reports root-relative paths; read_file must accept them.

    search_glob returns "contracts/Config.sol" (relative to local_root), but
    read_file resolved relative paths against the state dir — so the agent
    could find a file and then never open it. One 25-minute contract audit
    recorded 7 read_file failures out of 8 attempts and found nothing.
    """
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    (project / "contracts").mkdir(parents=True)
    target = project / "contracts" / "Config.sol"
    target.write_text("contract Config { uint256 x; }\n", encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    ctx = _multi_ctx(tmp_path, jail=project, local_root=project)

    found = tools_local.search_glob({"glob": "contracts/*.sol", "pattern": "contract"}, ctx)
    assert found.get("ok") is True and found.get("hits"), found
    reported = found["hits"][0]["path"]
    assert reported == "contracts/Config.sol", reported

    # The path search reported is relative to the root it searched. Read it
    # back exactly as reported, with the state dir (not the project) as the
    # jail — which is the real shape of a local hunt.
    ctx2 = _multi_ctx(tmp_path, jail=state, local_root=project)
    outcome = tools_local.read_file({"path": reported}, ctx2)

    assert outcome.get("ok") is True, outcome
    assert "contract Config" in outcome.get("text", "")


def test_relative_fallback_cannot_escape_the_root(tmp_path: Path):
    """The fallback must not become a traversal hole.

    Joining a root with "../x" escapes it, so the containment check has to
    run on the JOINED path, not just on the raw argument.
    """
    tools_local = _require_tools_local()
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("outside secret", encoding="utf-8")
    ctx = _multi_ctx(tmp_path, jail=project, local_root=project)

    for evil in ("../outside/secret.txt", "../../outside/secret.txt"):
        outcome = tools_local.read_file({"path": evil}, ctx)
        assert outcome.get("blocked") is True, evil
        assert "outside secret" not in outcome.get("text", ""), evil
