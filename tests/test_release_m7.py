"""M7 v0.4.0 release gates.

These checks are deliberately static or seam-driven.  They never contact a
provider, target, package index, GitHub, browser, or Chromium executable.
The builder must make the complete file green; this file is frozen before the
release implementation is changed.
"""

from __future__ import annotations

import json
import re
from importlib import metadata
from pathlib import Path

import httpx
import pytest
import tomllib
import yaml
from typer.testing import CliRunner

import hunter.cli.main as cli_main
from hunter.cli.main import app

ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.4.0"
CURL_ONE_LINER = (
    "curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash"
)
IRM_ONE_LINER = "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
NOTICE = "A new version of hunter is available: 0.3.1 → 0.4.0. Run: hunter update"
RUNNER = CliRunner()

CURRENT_DOCS = (
    "README.md",
    "QUICKSTART.md",
    "docs/FIRST-RUN.md",
    "docs/LLM.md",
    "docs/ARCHITECTURE.md",
    "examples/config.example.yaml",
)
ROLE_DOCS = (
    "README.md",
    "QUICKSTART.md",
    "docs/FIRST-RUN.md",
    "docs/LLM.md",
    "docs/ARCHITECTURE.md",
    "examples/config.example.yaml",
)


@pytest.fixture(autouse=True)
def _release_test_hygiene(monkeypatch, tmp_path):
    """Keep CLI state local and make accidental background checks impossible."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("HUNTER_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HUNTEROS_CHAT_DB", str(tmp_path / "chat.db"))
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")
    for name in (
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "BUILDKITE",
        "CIRCLECI",
    ):
        monkeypatch.delenv(name, raising=False)

    from hunter.cli import update_core

    update_core.reset()
    yield
    update_core.reset()


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _docs_text() -> str:
    return "\n".join(_read(path) for path in CURRENT_DOCS)


def _installed_version() -> str:
    try:
        return metadata.version("hunteros-harness")
    except metadata.PackageNotFoundError:
        import hunter

        return hunter.__version__


def _cache_path(home: Path) -> Path:
    return home / ".hunteros" / "update-check.json"


def _mock_client(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler), timeout=5)


def test_release_version_sources_are_0_4_0():
    """A1: source, package metadata, and the CLI must agree exactly."""
    import hunter

    project = tomllib.loads(_read("pyproject.toml"))["project"]
    assert project["version"] == RELEASE_VERSION
    assert hunter.__version__ == RELEASE_VERSION
    assert _installed_version() == RELEASE_VERSION

    result = RUNNER.invoke(app, ["version"])
    assert result.exit_code == 0, (result.stdout, result.stderr, result.exception)
    assert result.stdout.strip() == f"hunter {RELEASE_VERSION}"

    offenders: list[str] = []
    for path in sorted((ROOT / "src" / "hunter").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"(?<![0-9])0\.3\.\d+(?![0-9])", text):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"runtime source contains a conflicting v0.3 literal: {offenders}"


def test_release_semver_and_update_tag_contract():
    """A2: stable metadata is dotted, while update tags carry one leading v."""
    from hunter.cli import update_core

    assert update_core.parse_version("v0.4.0") == (0, 4, 0)
    assert update_core.parse_version("V0.4.0") == (0, 4, 0)
    assert update_core.parse_version("0.4.0-rc1") is None
    assert update_core.parse_version("0.4.0-beta1") is None

    changelog = _read("CHANGELOG.md")
    assert "## [0.4.0]" in changelog
    assert "v0.3.1...v0.4.0" in changelog
    assert re.search(r"\bv0\.4\.0\b", _read("src/hunter/cli/update_core.py"))
    assert not re.search(r"\[0\.4\.0-(?:beta|rc)", changelog, re.IGNORECASE)
    assert _installed_version() == RELEASE_VERSION


def test_changelog_has_exact_v040_inventory_and_security_notes():
    """A3: the changelog names the shipped M1-M6 inventory and safety notes."""
    changelog = _read("CHANGELOG.md")
    assert "# Changelog" in changelog
    assert "## [Unreleased]" in changelog
    assert "## [0.4.0]" in changelog

    for milestone in range(1, 7):
        assert re.search(rf"^### M{milestone} — ", changelog, re.MULTILINE)

    required_inventory = (
        "dedicated venv",
        "orchestrator/hunter/verifier/utility",
        "hunter hunt",
        "GitHub-first",
        "quarantine",
        "optional [browser]",
    )
    for phrase in required_inventory:
        assert phrase.lower() in changelog.lower(), phrase

    assert re.search(r"^### Security\s*$", changelog, re.MULTILINE)
    security = changelog[changelog.index("### Security") :]
    for phrase in ("scope", "claim", "redact", "JSON stdout", "Chromium"):
        assert phrase.lower() in security.lower(), phrase
    assert "playwright install" in security.lower()
    assert "executable code" in security.lower()


def test_v05_roadmap_covers_maintenance_tracks():
    """A4: the forward roadmap covers operability through distribution."""
    roadmap = _read("docs/ROADMAP-v0.5.md")
    lowered = roadmap.lower()
    for phrase in (
        "v0.5",
        "dashboard",
        "gateway",
        "provider catalog",
        "skills growth",
        "pypi",
        "continuous maintenance",
    ):
        assert phrase in lowered, phrase
    for invariant in ("evidence", "scope", "claim", "redaction", "invariant"):
        assert invariant in lowered, invariant
    assert re.search(r"not a promise of dates|no promise of dates", lowered)
    assert not re.search(
        r"\b(?:Q[1-4]|20\d{2}|January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\b",
        roadmap,
        re.IGNORECASE,
    )


def test_current_docs_have_install_and_update_contract():
    """A6: current docs agree on installers, advisory updates, and quiet output."""
    readme = _read("README.md")
    quickstart = _read("QUICKSTART.md")
    for doc in (readme, quickstart):
        assert CURL_ONE_LINER in doc
        assert IRM_ONE_LINER in doc

    docs = _docs_text()
    assert "hunter update" in docs
    assert re.search(r"GitHub[- ]first|checks GitHub", docs, re.IGNORECASE)
    assert re.search(r"PyPI[- ]fallback|falling back to PyPI", docs, re.IGNORECASE)
    assert re.search(r"24[- ]hour|24h", docs, re.IGNORECASE)
    assert "HUNTEROS_NO_UPDATE_CHECK=1" in docs
    assert "stderr" in docs.lower()
    assert re.search(r"quiet|long-lived", docs, re.IGNORECASE)
    assert "self-restart" not in docs.lower()
    assert not re.search(r"update.{0,100}pre[- ]release.{0,50}(support|channel)", docs, re.I | re.S)

    for installer in ("install.sh", "install.ps1"):
        text = _read(installer)
        assert "hunter hunt <url>" in text
        assert "coming in a later release" not in text.lower()


def test_current_docs_have_canonical_provider_roles():
    """A7: role vocabulary is canonical and legacy names are migration-only."""
    role_texts = [_read(path) for path in ROLE_DOCS]
    for text in role_texts:
        assert "orchestrator" in text
    docs = "\n".join(role_texts)
    assert all(role in docs for role in ("orchestrator", "hunter", "verifier", "utility"))
    assert "planner/exploit/verify" in docs
    assert re.search(r"legacy.{0,100}(load|accept|read|canonical|rename)", docs, re.I | re.S)
    assert re.search(r"next write|auto[- ]renamed|canonical", docs, re.I)
    assert "hunter verify" in docs
    assert re.search(r"score.{0,100}verify|verify.{0,100}report", docs, re.I | re.S)


def test_current_docs_have_chat_hunt_and_scope_contract():
    """A8: chat, governed hunt, local directories, and exit codes are documented."""
    docs = _docs_text()
    assert re.search(r"ordinary free text.{0,100}chat|free text remains chat", docs, re.I | re.S)
    assert re.search(r"confirmation|explicit permission|permission", docs, re.I)
    assert "/hunt on" in docs
    assert "/hunt off" in docs or re.search(r"/hunt\s+on\|off", docs)
    assert "/audit" in docs and "/hunt" in docs
    assert re.search(r"one[- ]shot", docs, re.I)
    assert "hunter hunt" in docs
    assert re.search(r"local director(?:y|ies)", docs, re.I)
    assert re.search(r"exit codes?\s+0.{0,150}\b1\b.{0,100}\b2\b.{0,100}\b3\b", docs, re.I | re.S)
    assert re.search(r"non[- ]localhost.{0,150}(scope|manifest)|scope manifest", docs, re.I | re.S)
    assert re.search(r"authorized manifest|authorized scope", docs, re.I)


def test_current_docs_have_optional_browser_contract():
    """A9: Playwright is explicit, optional, hunt-only, and never auto-installed."""
    docs = _docs_text().lower()
    assert "[browser]" in docs
    assert "pip install 'hunteros-harness[browser]'" in docs or "install `hunteros-harness[browser]`" in docs
    assert "python -m playwright install chromium" in docs
    assert "agent.browser" in docs
    assert re.search(r"hunt[- ]only", docs)
    assert "scope-gated" in docs
    assert "without the extra" in docs or "without [browser]" in docs
    assert "normal chat" in docs
    assert re.search(
        r"no automatic(?:ally)? .*chromium|does not install chromium|never .*chromium|"
        r"separately install chromium",
        docs,
    )
    assert "playwright" not in _read("pyproject.toml").split("[project.optional-dependencies]")[0].lower()


def test_current_docs_have_skills_and_curator_contract():
    """A10: skills are bounded data with source visibility and safe curation."""
    docs = _docs_text()
    assert "~/.hunteros/skills/<name>/SKILL.md" in docs
    assert re.search(r"bundled.{0,100}user|user.{0,100}bundled|source", docs, re.I | re.S)
    for marker in ("[bundled]", "[user]", "[quarantined]"):
        assert marker in docs
    assert re.search(r"max(?:imum)?[- ]five|up to five|at most five|five skills", docs, re.I)
    assert "/curate" in docs and "hunter curate" in docs
    assert re.search(
        r"preview.{0,120}(save|confirm|y/N)|(?:save|confirm|y/N).{0,120}preview",
        docs,
        re.I | re.S,
    )
    assert re.search(r"quarantined?.{0,120}(inert|review)|inert.{0,120}review", docs, re.I | re.S)


def test_current_docs_have_no_stale_release_claims():
    """A11: current examples show v0.4.0 and not obsolete M3/M5 copy."""
    current = "\n".join((*(_read(path) for path in CURRENT_DOCS), _read("install.sh"), _read("install.ps1")))
    for path in ("README.md", "QUICKSTART.md", "docs/FIRST-RUN.md"):
        assert RELEASE_VERSION in _read(path)
    assert not re.search(r"v?0\.3\.\d+", current)
    assert "17 slash commands" not in current.lower()
    assert "skills mounted: 7" not in current.lower()
    assert "coming in a later release" not in current.lower()
    assert "20 slash commands" in current.lower()
    assert re.search(r"skills mounted:.*\[(?:bundled|user|quarantined)\]", current, re.I) or all(
        marker in current for marker in ("[bundled]", "[user]", "[quarantined]")
    )


def test_ci_matrix_and_commands_are_explicit():
    """A12: CI declares four independent jobs and selected-interpreter commands."""
    workflow_text = _read(".github/workflows/ci.yml")
    workflow = yaml.safe_load(workflow_text)
    job = workflow["jobs"]["test"]
    matrix = job["strategy"]["matrix"]
    assert job["strategy"]["fail-fast"] is False
    assert matrix["os"] == ["ubuntu-latest", "windows-latest"]
    assert matrix["python-version"] == ["3.11", "3.13"]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["env"]["HUNTEROS_NO_UPDATE_CHECK"] == "1"
    assert job["env"]["CI"] == "true"

    commands = [step.get("run", "") for step in job["steps"]]
    assert 'python -m pip install -e ". [dev]"' not in commands
    assert 'python -m pip install -e ". [browser]"' not in commands
    assert 'python -m pip install -e ".[dev]"' in commands
    assert "python -m ruff check src tests" in commands
    assert "python -m pytest" in commands
    assert "ruff check src tests" not in commands


def test_ci_has_no_browser_install_or_network_test_path():
    """A13: CI and M6 tests remain offline and fake-browser-only."""
    workflow = _read(".github/workflows/ci.yml").lower()
    assert ".[browser]" not in workflow
    assert "pytest-playwright" not in workflow
    assert "playwright install" not in workflow
    assert "chromium" not in workflow
    assert "python -m ruff check src tests" in workflow

    browser_tests = _read("tests/test_browser_tools.py")
    assert "FakePlaywrightModule" in browser_tests
    assert "FakePage" in browser_tests
    assert not re.search(r"^\s*(?:from|import)\s+playwright(?:\.|\s|$)", browser_tests, re.MULTILINE)
    assert not re.search(r"^\s*(?:from|import)\s+socket(?:\.|\s|$)", browser_tests, re.MULTILINE)
    assert not re.search(r"\bsubprocess\.(?:run|Popen|check_call|check_output)\s*\(", browser_tests)
    browser_source = _read("src/hunter/agent/browser.py").lower()
    assert "subprocess" not in browser_source
    assert "socket" not in browser_source
    assert "playwright.install" not in browser_source
    assert "evaluate(" not in browser_source


def test_release_artifact_metadata_contract():
    """A5: package metadata keeps browser optional and core dependency-free."""
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    assert project["version"] == RELEASE_VERSION
    assert project["requires-python"] == ">=3.10"
    optional = project["optional-dependencies"]
    assert optional["browser"] == ["playwright>=1.40"]
    assert not any("playwright" in str(dep).lower() for dep in project["dependencies"])
    assert project["scripts"] == {"hunter": "hunter.cli.main:main", "hunt": "hunter.cli.main:main"}

    plan = _read("docs/plans/v0.4/M7-release-maintenance.md")
    assert "python -m build" in plan
    assert "twine check dist/*" in plan
    assert "M7-CHECK-ARTIFACT-METADATA" in plan


def test_scope_regression_contract_is_present_and_fail_closed():
    """A16: release scope/claim/browser regressions remain represented by tests."""
    adversarial = _read("tests/test_adversarial.py") + _read("tests/test_adversarial_v02.py")
    browser_tests = _read("tests/test_browser_tools.py")
    browser_source = _read("src/hunter/agent/browser.py")
    http_source = _read("src/hunter/tools/http_client.py")
    claim_source = _read("src/hunter/kernel/claimgate.py")

    for phrase in ("ScopeViolation", "out_of_scope", "redirect", "claim", "redact"):
        assert phrase.lower() in (adversarial + browser_tests).lower(), phrase
    assert "self.scope.check_url(url)" in http_source
    assert "check_url" in browser_source
    assert re.search(r"http[_ -]exchange", claim_source, re.I) or "http_exchange" in browser_tests
    assert "browser_event" in browser_tests
    assert "evidence is None" in browser_tests


def test_release_secret_scan_and_worktree_gate_contract():
    """A18: release inputs document secret scanning and generated-state review."""
    plan = _read("docs/plans/v0.4/M7-release-maintenance.md")
    for phrase in (
        "git status --short",
        "Secret scan passes",
        "no `.env`",
        "no changelog, transcript, cache, database, report, or release",
        "generated caches/keys/databases",
        "M7-CHECK-SECRET-SCAN",
    ):
        assert phrase.lower() in plan.lower(), phrase

    release_inputs = [
        "pyproject.toml",
        "README.md",
        "QUICKSTART.md",
        "docs/FIRST-RUN.md",
        "docs/LLM.md",
        "docs/ARCHITECTURE.md",
        "examples/config.example.yaml",
        "install.sh",
        "install.ps1",
        ".github/workflows/ci.yml",
        "tests/test_release_m7.py",
    ]
    credential_patterns = (
        r"sk-[A-Za-z0-9]{20,}",
        r"ghp_[A-Za-z0-9]{30,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    )
    findings = []
    for relative in release_inputs:
        text = _read(relative)
        for pattern in credential_patterns:
            if re.search(pattern, text):
                findings.append(f"{relative}: {pattern}")
    assert not findings, "credential-shaped release input: " + "; ".join(findings)


def test_release_installer_syntax_and_dryrun_contract():
    """A19: both installers retain parser, dry-run, idempotency, and safety gates."""
    plan = _read("docs/plans/v0.4/M7-release-maintenance.md")
    assert "bash -n install.sh" in plan
    assert "Parser]::ParseFile" in plan
    assert "install.sh --dry-run" in plan
    assert "install.sh --skip-setup --dry-run" in plan
    assert "PowerShell -DryRun and -SkipSetup -DryRun" in plan

    sh = _read("install.sh")
    ps1 = _read("install.ps1")
    for text in (sh, ps1):
        assert "hunter hunt <url>" in text
        assert "Scan only systems you own or are explicitly authorized to test." in text
        assert "Coming in a later release" not in text
        assert all(ord(char) < 128 for char in text)
    assert "bash -n" in plan
    assert "PATH_MARKER" not in sh
    assert sh.count("# >>> hunteros PATH >>>") == 1
    assert sh.count("# <<< hunteros PATH <<<") == 1
    assert ps1.count("# >>> hunteros PATH >>>") == 1
    assert ps1.count("# <<< hunteros PATH <<<") == 1
    for flag in ("--dry-run", "--skip-setup"):
        assert flag in sh
    for flag in ("-DryRun", "-SkipSetup"):
        assert flag in ps1
    assert "bin/hunter" in sh and "bin/hunt" in sh
    assert "hunter.cmd" in ps1 and "hunt.cmd" in ps1


def test_ci_four_job_quality_gate_contract():
    """A20: the release plan requires all four matrix jobs and fake browser tests."""
    workflow = _read(".github/workflows/ci.yml")
    plan = _read("docs/plans/v0.4/M7-release-maintenance.md")
    assert "python -m ruff check src tests" in workflow
    assert "python -m pytest" in workflow
    assert "M7-CHECK-CI-FOUR-JOBS" in plan
    assert "all four jobs green" in plan
    assert "test_browser_tools.py" in plan
    assert "no browser executable" in plan
    assert "No real provider/browser" not in workflow


def test_publication_parity_check_contract():
    """A21: publication parity is a static release-owner gate, never a network test."""
    plan = _read("docs/plans/v0.4/M7-release-maintenance.md")
    for phrase in (
        "annotated tag named exactly `v0.4.0`",
        "GitHub release for `v0.4.0`",
        "PyPI distribution version `0.4.0`",
        "M7-CHECK-PUBLISH-PARITY",
        "clean install",
        "commit SHA",
        "wheel/sdist metadata",
    ):
        assert phrase.lower() in plan.lower(), phrase
    assert _read("CHANGELOG.md").count("## [0.4.0]") == 1
    assert "v0.3.1...v0.4.0" in _read("CHANGELOG.md")


def test_rollback_rehearsal_check_contract():
    """A22: rollback preserves state and uses an immutable prior version."""
    plan = _read("docs/plans/v0.4/M7-release-maintenance.md")
    rollback = plan[plan.index("### 8.3 Rollback") : plan.index("---", plan.index("### 8.3 Rollback"))]
    for phrase in (
        "never force-move or reuse the tag",
        "0.4.1",
        "hunteros-harness==0.3.1",
        "config/state",
        "config.yaml",
        "keys.env",
        "skills",
        "ledger",
        "hunter doctor --json",
        "hunter verify",
        "M7-CHECK-ROLLBACK-REHEARSAL",
    ):
        assert phrase.lower() in rollback.lower() or phrase.lower() in plan.lower(), phrase
    assert "v0.3.1" in rollback
    assert "force-reinstall" in rollback


def test_update_release_path_is_github_first_and_hermetic(tmp_path):
    """A14: MockTransport proves GitHub-first, fallback, normalization, and silence."""
    from hunter.cli import update_core

    seen: list[str] = []

    def github_ok(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == update_core.GITHUB_RELEASES_URL:
            assert request.headers["accept"] == "application/vnd.github+json"
            return httpx.Response(200, json={"tag_name": "v0.4.0"})
        return httpx.Response(404, json={})

    result = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path,
        now_fn=lambda: 1_700_000_000.0,
        client_factory=_mock_client(github_ok),
    )
    assert result.latest == RELEASE_VERSION
    assert result.source == "github"
    assert seen == [update_core.GITHUB_RELEASES_URL]

    seen.clear()

    def github_403_pypi(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == update_core.GITHUB_RELEASES_URL:
            return httpx.Response(403, json={"message": "rate limit"})
        return httpx.Response(200, json={"info": {"version": RELEASE_VERSION}})

    fallback = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path / "fallback",
        now_fn=lambda: 1_700_000_000.0,
        client_factory=_mock_client(github_403_pypi),
    )
    assert fallback.latest == RELEASE_VERSION
    assert fallback.source == "pypi"
    assert seen == [update_core.GITHUB_RELEASES_URL, update_core.PYPI_JSON_URL]

    seen.clear()

    def malformed(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == update_core.GITHUB_RELEASES_URL:
            return httpx.Response(200, json={"tag_name": "0.4.0-rc1"})
        return httpx.Response(200, json={"info": {"version": "not-semver"}})

    failed = update_core.check_for_newer_version(
        current_version="0.3.1",
        home=tmp_path / "failed",
        now_fn=lambda: 1_700_000_000.0,
        client_factory=_mock_client(malformed),
    )
    assert failed.latest == ""
    assert failed.error == "unreachable"
    assert not _cache_path(tmp_path / "failed").exists()
    assert seen == [update_core.GITHUB_RELEASES_URL, update_core.PYPI_JSON_URL]
    assert _installed_version() == RELEASE_VERSION


def test_release_json_stdout_is_pure(monkeypatch, tmp_path):
    """A15: JSON commands stay parseable while advisory text remains stderr-only."""
    from hunter.cli import update_core

    real_start = update_core.start_background_check

    def forced_start(*, suppress_notice=False, **_kwargs):
        return real_start(
            environ={},
            wait=True,
            suppress_notice=suppress_notice,
            check_fn=lambda: update_core.CheckResult(
                latest=RELEASE_VERSION,
                current="0.3.1",
                source="github",
                update_available=True,
            ),
        )

    monkeypatch.setattr(update_core, "start_background_check", forced_start)
    doctor = RUNNER.invoke(app, ["doctor", "--json", "--state", str(tmp_path / "doctor")])
    assert doctor.exit_code == 0, (doctor.stdout, doctor.stderr, doctor.exception)
    doctor_payload = json.loads(doctor.stdout)
    assert isinstance(doctor_payload, dict)
    assert NOTICE not in doctor.stdout
    assert NOTICE in doctor.stderr

    hunt = RUNNER.invoke(
        app,
        [
            "hunt",
            "http://127.0.0.1/",
            "--engine",
            "mock",
            "--json",
            "--state",
            str(tmp_path / "hunt"),
        ],
    )
    assert hunt.exit_code == 2, (hunt.stdout, hunt.stderr, hunt.exception)
    hunt_payload = json.loads(hunt.stdout)
    assert isinstance(hunt_payload, dict)
    assert NOTICE not in hunt.stdout
    assert NOTICE in hunt.stderr

    update_core.reset()
    calls: list[dict] = []
    monkeypatch.setattr(
        update_core,
        "start_background_check",
        lambda **kwargs: calls.append(kwargs) or False,
    )
    import hunter.chat.repl as chat_repl
    import hunter.cli.init_wizard as init_wizard

    monkeypatch.setattr(init_wizard, "offer_onboarding", lambda **_kwargs: False)
    monkeypatch.setattr(chat_repl, "run_repl", lambda **_kwargs: None)
    quiet = RUNNER.invoke(app, ["chat"])
    assert quiet.exit_code == 0, (quiet.stdout, quiet.stderr, quiet.exception)
    assert calls == [{"suppress_notice": True}]
    assert frozenset({"chat", "tui", "gateway"}) == update_core.QUIET_COMMANDS
    assert cli_main._version() == RELEASE_VERSION


def test_release_config_migration_and_browser_default(tmp_path):
    """A17: a full legacy config heals on write without losing governed state."""
    from hunter.llm.config import load_config
    from hunter.llm.writing import write_config

    legacy = tmp_path / "legacy.yaml"
    legacy.write_text(
        "model_tiers:\n"
        "  planner:\n    provider: anthropic\n    model: old-orchestrator\n"
        "  exploit:\n    provider: openai\n    model: old-hunter\n"
        "  verify:\n    provider: openai\n    model: old-verifier\n"
        "providers:\n"
        "  anthropic:\n    key_env: ANTHROPIC_API_KEY\n"
        "  openai:\n    key_env: OPENAI_API_KEY\n    base_url: https://api.openai.example/v1\n"
        "fallback_providers:\n"
        "  - provider: backup\n    model: backup-model\n    key_env: BACKUP_API_KEY\n"
        "budget:\n  max_cost_usd: 12.5\n  max_iterations: 90\n  wall_seconds: 600\n"
        "agent:\n  tier: verify\n  api_max_retries: 5\n",
        encoding="utf-8",
    )
    cfg = load_config(legacy, env={}, home=tmp_path)
    assert set(cfg.model_tiers) == {"orchestrator", "hunter", "verifier", "utility"}
    assert cfg.agent.tier == "verifier"
    assert cfg.agent.browser is False
    assert cfg.budget.max_cost_usd == 12.5
    assert cfg.budget.max_iterations == 90
    assert cfg.budget.wall_seconds == 600
    assert cfg.fallback_providers[0].key_env == "BACKUP_API_KEY"
    assert cfg.providers["openai"].base_url.endswith("/v1")
    assert cfg.providers["openai"].endpoint == ""

    write_config({"agent": {"browser": False}}, legacy, env={}, home=tmp_path)
    healed = legacy.read_text(encoding="utf-8")
    for role in ("orchestrator", "hunter", "verifier", "utility"):
        assert f"  {role}:" in healed
    for old in ("planner", "exploit", "verify:"):
        assert old not in healed
    assert "max_cost_usd: 12.5" in healed
    assert "max_iterations: 90" in healed
    assert "wall_seconds: 600" in healed
    assert "key_env: OPENAI_API_KEY" in healed
    assert "browser: false" in healed
    assert _installed_version() == RELEASE_VERSION
