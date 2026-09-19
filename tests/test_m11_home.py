"""M11 M1 — one home ``~/.hunter``: hunter.home module, migration, defaults.

Spec: docs/plans/m11-ux.md §3.1 + §5 (test plan 1-13). Every test is
offline and HOME-isolated (the autouse ``isolated_home`` conftest fixture);
migration tests create BOTH the legacy ``.hunteros`` and the new ``.hunter``
layouts under their own tmp paths. New M11 symbols are imported INSIDE the
test bodies so a missing implementation fails the test, never the collection
(test_cli_init_v2 rule).
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import yaml
from typer.testing import CliRunner

from hunter.chat.sessions import ChatStore
from hunter.kernel.ledger import Ledger

runner = CliRunner()

# §3.1 pinned summary notice line (byte-exact contract).
MIGRATION_NOTICE = (
    "📋 migrated legacy HunterOS state from ~/.hunteros to ~/.hunter"
    " — originals kept (details: hunter where)"
)


def _seed_legacy(base, *, config: bytes | None = None, skills: bool = True) -> None:
    """Seed a legacy ~/.hunteros layout under ``base``."""
    legacy = base / ".hunteros"
    legacy.mkdir(parents=True, exist_ok=True)
    (legacy / "config.yaml").write_bytes(
        config if config is not None else b"agent:\n  tier: basic\n"
    )
    (legacy / "keys.env").write_bytes(b'ACME_KEY="sk-legacy-acme"\n')
    (legacy / "chat.db").write_bytes(b"legacy-chat-db-bytes")
    if skills:
        (legacy / "skills" / "my-skill").mkdir(parents=True, exist_ok=True)
        (legacy / "skills" / "my-skill" / "SKILL.md").write_bytes(b"# skill\n")


# -- §5 plan 1 -----------------------------------------------------------------


def test_hunter_home_resolution_and_isolation(tmp_path):
    """hunter_home(home=tmp) == tmp/.hunter; resolution never creates the dir."""
    from hunter.home import hunter_home

    base = tmp_path / "base"
    base.mkdir()
    resolved = hunter_home(home=base)
    assert resolved == base / ".hunter"
    assert not resolved.exists()  # resolution never touches the disk


# -- §5 plan 2 -----------------------------------------------------------------


def test_state_dir_precedence_flag_env_home(tmp_path):
    """Explicit --state beats $HUNTER_STATE_DIR beats the home default."""
    from hunter.home import state_dir

    base = tmp_path / "base"
    flag_dir = tmp_path / "flag-state"
    env_dir = tmp_path / "env-state"
    env = {"HUNTER_STATE_DIR": str(env_dir)}
    # 1. explicit flag wins.
    assert state_dir(flag_dir, env=env, home=base) == flag_dir
    # 2. then $HUNTER_STATE_DIR.
    assert state_dir(None, env=env, home=base) == env_dir
    # 3. then the home default ~/.hunter.
    assert state_dir(None, env={}, home=base) == base / ".hunter"


# -- §5 plan 3 (adversarial register: ~/.hunteros deleted/written by migration) --


def test_migration_copies_missing_counterparts_and_keeps_originals(tmp_path):
    """Legacy config/keys/chat.db/skills all COPY byte-equal; originals stay."""
    from hunter.home import ensure_home, migration_plan

    base = tmp_path / "base"
    base.mkdir()
    _seed_legacy(base)
    original_bytes = {
        name: (base / ".hunteros" / name).read_bytes()
        for name in ("config.yaml", "keys.env", "chat.db")
    }

    plan = migration_plan(home=base)
    assert [(src.name, dst.name) for src, dst in plan] == [
        ("config.yaml", "config.yaml"),
        ("keys.env", "keys.env"),
        ("chat.db", "chat.db"),
        ("skills", "skills"),
    ]

    home = ensure_home(home=base)
    assert home == base / ".hunter"
    # All four counterparts copied byte-equal.
    assert (home / "config.yaml").read_bytes() == original_bytes["config.yaml"]
    assert (home / "keys.env").read_bytes() == original_bytes["keys.env"]
    assert (home / "chat.db").read_bytes() == original_bytes["chat.db"]
    assert (home / "skills" / "my-skill" / "SKILL.md").read_bytes() == b"# skill\n"
    # The originals were KEPT (migration is a copy, never a move) and the
    # legacy dir still exists.
    assert (base / ".hunteros" / "config.yaml").read_bytes() == original_bytes["config.yaml"]
    assert (base / ".hunteros" / "keys.env").is_file()
    assert (base / ".hunteros" / "chat.db").is_file()
    assert (base / ".hunteros" / "skills" / "my-skill" / "SKILL.md").is_file()

    # Idempotent: the plan is empty now and a second ensure_home is a no-op.
    assert migration_plan(home=base) == []
    assert ensure_home(home=base) == home


# -- §5 plan 4 -----------------------------------------------------------------


def test_migration_new_home_wins_when_both_exist(tmp_path):
    """A differing config.yaml in BOTH homes: the new-home file is untouched."""
    from hunter.home import ensure_home, migration_plan

    base = tmp_path / "base"
    base.mkdir()
    _seed_legacy(base, skills=False)
    home = base / ".hunter"
    home.mkdir()
    (home / "config.yaml").write_bytes(b"agent:\n  tier: advanced\n")

    notices: list[str] = []
    assert migration_plan(home=base) == []  # dst exists -> nothing to migrate
    ensure_home(home=base, notice=notices.append)
    assert notices == []  # no notice when nothing migrated
    assert (home / "config.yaml").read_bytes() == b"agent:\n  tier: advanced\n"


# -- §5 plan 5 -----------------------------------------------------------------


def test_migration_notice_once_per_process(tmp_path):
    """The notice callback fires ONCE with the pinned summary; the moved paths
    land in migration_notes() (per-process accumulation)."""
    from hunter.home import ensure_home, migration_notes

    base = tmp_path / "base"
    base.mkdir()
    _seed_legacy(base, skills=False)

    notices: list[str] = []
    ensure_home(home=base, notice=notices.append)
    assert notices == [MIGRATION_NOTICE]  # exactly once, byte-exact

    notes = migration_notes()
    assert notes, "migration_notes() must record what this process migrated"
    joined = "\n".join(notes)
    assert str(base / ".hunter" / "config.yaml") in joined
    assert str(base / ".hunter" / "keys.env") in joined
    assert str(base / ".hunter" / "chat.db") in joined


# -- §5 plan 6 (adversarial: concurrent commands during migration) --------------


def test_migration_race_safe_two_threads(tmp_path):
    """Two threads ensure_home on the same home: both return, dst parses, no
    staging siblings (``.migrating`` etc.) remain."""
    from hunter.home import ensure_home

    base = tmp_path / "base"
    base.mkdir()
    _seed_legacy(base, skills=False)

    barrier = threading.Barrier(2)
    results: list = []
    failures: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=10)
            results.append(ensure_home(home=base))
        except BaseException as exc:  # pragma: no cover - surfaced via assert
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert failures == []
    assert results and all(r == base / ".hunter" for r in results)
    # Both racers converge on identical, loadable bytes; no tmp siblings left.
    for name in ("config.yaml", "keys.env", "chat.db"):
        dst = base / ".hunter" / name
        assert dst.is_file()
        if name == "config.yaml":
            assert yaml.safe_load(dst.read_text(encoding="utf-8")) == {"agent": {"tier": "basic"}}
    assert sorted(p.name for p in (base / ".hunter").iterdir()) == [
        "chat.db",
        "config.yaml",
        "keys.env",
    ]


# -- §5 plan 7 (adversarial: HOME != USERPROFILE on Windows) ---------------------


def test_migration_survives_home_userprofile_divergence(tmp_path, monkeypatch):
    """HOME != USERPROFILE: the ``home`` override derives legacy AND new home
    from the SAME base; env resolution is platform-pinned (HOME on POSIX,
    USERPROFILE on Windows)."""
    from hunter.home import ensure_home, legacy_home

    base = tmp_path / "diverged-base"
    other = tmp_path / "other-env-base"
    base.mkdir()
    other.mkdir()
    _seed_legacy(base, skills=False)

    monkeypatch.setenv("HOME", str(other))
    monkeypatch.setenv("USERPROFILE", str(other))
    # The explicit home override wins for BOTH derivations (divergence-safe).
    assert legacy_home(home=base) == base / ".hunteros"
    home = ensure_home(home=base)
    assert home == base / ".hunter"
    assert (home / "config.yaml").is_file()
    assert (base / ".hunteros" / "config.yaml").is_file()  # copy, not move

    # Without an override the SAME single env resolution feeds both dirs:
    # HOME wins on POSIX, USERPROFILE on Windows.
    from hunter.home import hunter_home

    env_pair = {"HOME": str(other), "USERPROFILE": str(base)}
    env_winner = other if sys.platform != "win32" else base
    assert hunter_home(env=env_pair) == env_winner / ".hunter"
    assert legacy_home(env=env_pair) == env_winner / ".hunteros"


# -- §5 plan 8 (adversarial: corrupt legacy during migration) -------------------


def test_migration_skips_corrupt_legacy_without_raising(tmp_path, monkeypatch):
    """Binary-garbage legacy config copies as bytes and ensure_home returns;
    a legacy ``skills`` entry that cannot be copied as a directory is skipped
    with a note — never raised (a corrupt legacy must not brick commands)."""
    from hunter.home import ensure_home

    base = tmp_path / "base"
    base.mkdir()
    garbage = bytes(range(256))
    _seed_legacy(base, config=garbage, skills=False)
    (base / ".hunteros" / "skills").write_bytes(b"not a directory")  # dir expected

    home = ensure_home(home=base)  # must NOT raise
    assert home == base / ".hunter"
    # The garbage config copied byte-for-byte (validity is the loader's job).
    assert (home / "config.yaml").read_bytes() == garbage
    # The broken skills entry was skipped with a recorded note (contract:
    # "skips it and records a note" — never raises).
    from hunter.home import migration_notes

    assert migration_notes(), "the skipped legacy entry must be recorded as a note"


# -- §5 plan 3/§14 item 3 -------------------------------------------------------


def test_ledger_default_state_dir_is_home(tmp_path, monkeypatch):
    """Ledger() (HOME isolated) creates ~/.hunter/ledger.db; $HUNTER_STATE_DIR
    still wins (cwd is NEVER the default anymore — §14 item 3)."""
    monkeypatch.chdir(tmp_path)  # a cwd ./.hunter must NOT receive the ledger
    ledger = Ledger()
    try:
        ledger.create_run("r1", "http://127.0.0.1:9/", "deterministic", "scope-x")
        home = Path(os.environ["USERPROFILE"])
        assert (home / ".hunter" / "ledger.db").is_file()
        assert not (tmp_path / ".hunter").exists()  # cwd default is gone
    finally:
        ledger.close()

    state = tmp_path / "state"
    monkeypatch.setenv("HUNTER_STATE_DIR", str(state))
    ledger2 = Ledger()
    try:
        ledger2.create_run("r2", "http://127.0.0.1:9/", "deterministic", "scope-x")
        assert (state / "ledger.db").is_file()
    finally:
        ledger2.close()


# -- §5 plan 10 ------------------------------------------------------------------


def test_chat_db_default_moved(tmp_path, monkeypatch):
    """ChatStore() lands in ~/.hunter/chat.db; $HUNTEROS_CHAT_DB still wins."""
    monkeypatch.delenv("HUNTEROS_CHAT_DB", raising=False)
    store = ChatStore()
    try:
        store.create_session("hello")
        home = Path(os.environ["USERPROFILE"])
        assert (home / ".hunter" / "chat.db").is_file()
        assert not (home / ".hunteros" / "chat.db").exists()
    finally:
        store.close()

    override = tmp_path / "elsewhere" / "chat.db"
    monkeypatch.setenv("HUNTEROS_CHAT_DB", str(override))
    store2 = ChatStore()
    try:
        store2.create_session("hi")
        assert override.is_file()
    finally:
        store2.close()


# -- §5 plan 11 ------------------------------------------------------------------


def test_where_human_and_json(tmp_path, monkeypatch):
    """`hunter where`: six labeled lines (human) / the JSON contract."""
    from hunter.cli.main import app

    state = tmp_path / "flag-state"
    result = runner.invoke(app, ["where", "--state", str(state)])
    assert result.exit_code == 0, (result.output, result.exception)
    text = result.output
    home = tmp_path / "hunter-home"
    # Six labeled lines; paths render platform-native (str(Path)).
    assert "home:" in text and str(home) in text
    assert "config:" in text and "config.yaml" in text
    assert "keys:" in text and "keys.env" in text
    assert "chat db:" in text and "chat.db" in text
    assert "state:" in text and str(state) in text
    assert "legacy:" in text and ".hunteros" in text
    assert "(kept: venv, bin shims, update-check)" in text

    # --json parses and carries the state source.
    result_json = runner.invoke(app, ["where", "--json", "--state", str(state)])
    assert result_json.exit_code == 0, (result_json.output, result_json.exception)
    payload = json.loads(result_json.output[result_json.output.index("{"):])
    for key in ("home", "config", "keys", "chat_db", "state", "state_source", "legacy"):
        assert key in payload
    assert payload["state_source"] == "flag"

    env_state = tmp_path / "env-state"
    monkeypatch.setenv("HUNTER_STATE_DIR", str(env_state))
    result_env = runner.invoke(app, ["where", "--json"])
    payload_env = json.loads(result_env.output[result_env.output.index("{"):])
    assert payload_env["state_source"] == "env" and payload_env["state"] == str(env_state)

    result_home = runner.invoke(app, ["where", "--json"])
    payload_home = json.loads(result_home.output[result_home.output.index("{"):])
    assert payload_home["state_source"] == "home"


# -- §5 plan 12 ------------------------------------------------------------------


def test_where_and_migration_notice_on_real_cli_path(tmp_path):
    """Seeding a legacy config makes `hunter doctor` print the pinned migration
    notice plus the `home` and `migration` doctor rows."""
    from hunter.cli.main import app

    home = tmp_path / "hunter-home"
    home.mkdir()
    (home / ".hunteros").mkdir()
    (home / ".hunteros" / "config.yaml").write_text(
        "agent:\n  tier: basic\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    text = result.output
    assert "migrated legacy HunterOS state" in text
    assert "originals kept" in text and "details: hunter where" in text
    payload = json.loads(text[text.index("{"):])
    labels = {row["label"]: row for row in payload["checks"]}
    assert "home" in labels
    assert labels["home"]["status"] == "ok"
    assert "migration" in labels
    assert labels["migration"]["status"] == "note"
    assert "migrated 1 item(s) this session" in labels["migration"]["detail"]


# -- §5 plan 13 (adversarial: pre-existing cwd ./.hunter dirs) --------------------


def test_doctor_legacy_project_state_note(tmp_path, monkeypatch):
    """cwd ./.hunter/ledger.db -> the `legacy-state` doctor row naming the
    exact --state flag; without it the row is absent (Q8: never abandoned)."""
    from hunter.cli.main import app

    workdir = tmp_path / "project"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    ledger = Ledger(workdir / ".hunter" / "ledger.db")
    try:
        ledger.create_run("r-old", "http://127.0.0.1:9/", "deterministic", "scope-x")
    finally:
        ledger.close()

    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    payload = json.loads(result.output[result.output.index("{"):])
    row = next((c for c in payload["checks"] if c["label"] == "legacy-state"), None)
    assert row is not None, "doctor must report pre-existing cwd ./.hunter state"
    assert row["status"] == "note"
    assert "1 run(s)" in row["detail"]
    assert "--state ./.hunter" in row["detail"]

    # A cwd without ./.hunter produces no such row.
    clean = tmp_path / "clean-project"
    clean.mkdir()
    monkeypatch.chdir(clean)
    result2 = runner.invoke(app, ["doctor", "--json"])
    assert result2.exit_code == 0, (result2.output, result2.exception)
    payload2 = json.loads(result2.output[result2.output.index("{"):])
    assert all(c["label"] != "legacy-state" for c in payload2["checks"])
