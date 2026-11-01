"""Part C of docs/RETENTION-SPEC.md — promotion of PROVEN-LIVE critical/high
findings into reusable skills and tools.

These tests build their OWN temp ledger (never the user's real ~/.hunter one)
and seed it with a finding in every status/severity combination that matters
to the eligibility rule, plus hostile payload material (a live-looking token,
traffic headers carrying a cookie) to prove the generated artifacts leak
neither the literal target hostname nor any secret.
"""

from __future__ import annotations

import json
import re

import pytest
from typer.testing import CliRunner

from hunter.errors import HunterError
from hunter.kernel.findings import Finding, FindingStatus, Severity
from hunter.kernel.ledger import Ledger

# ---------------------------------------------------------------- fixtures --

HOST = "rpc.chain.relay.link"
TARGET_URL = f"https://{HOST}"
TOKEN_SENTINEL = "tok_LIVE_sentinel_9f8e7d6c5b4a3210"
NAME_SENTINEL = "operator-private-run-label"
#: The evidence ladder's top rung (doctrine: theoretical -> promoted ->
#: proven-live). The FindingStatus enum does not carry it, so a proven finding
#: is stored as ``verified``; eligibility is decided by the full proof
#: (independent verifier artifact + adversary challenge), never by the label.
PROVEN_LIVE = "proven-live"


def _to_proven_live(ledger: Ledger, finding: Finding, run_id: str, *, klass: str) -> Finding:
    """Drive a VERIFIED finding to PROVEN-LIVE through its evidence."""
    ledger.add_evidence(
        run_id,
        "verifier_transcript",
        {
            "finding_id": finding.id,
            "role": "verifier",
            "artifact_type": "http_transcript",
            "body": f"independent replay of {klass} confirmed on the same endpoint",
        },
    )
    ledger.add_evidence(
        run_id,
        "note",
        {
            "finding_id": finding.id,
            "role": "adversary",
            "challenge": f"tried to refute {klass}: parameterized query still errored",
            "outcome": "survived",
        },
    )
    ledger.set_finding_status(finding.id, FindingStatus.PROVEN_LIVE, "proven-live by independent verifier + adversary challenge")
    return ledger.get_finding(finding.id)


def _seed_finding(
    ledger: Ledger,
    run_id: str,
    *,
    key: str,
    severity: Severity,
    status: str,
    klass: str = "sql-injection",
    title: str = "SQL injection in login username",
    poc_path: str | None = "/tmp/poc_sqli_login.py",
    extra_evidence: dict | None = None,
) -> Finding:
    """Create + drive a finding to ``status`` through the ledger's own paths."""
    base = ledger.add_evidence(
        run_id,
        "http_exchange",
        {
            "check_id": klass,
            "method": "POST",
            "purpose": "baseline probe of /login username handling",
            "request_body": f"username=hunter&session={TOKEN_SENTINEL}",
            "request_headers": {"cookie": f"sid={TOKEN_SENTINEL}", "host": HOST},
            "response_body": "<h1>401 Unauthorized</h1>",
            "response_headers": {"server": "openresty"},
            "url": f"{TARGET_URL}/login",
        },
    )
    ids = [base]
    if extra_evidence:
        ids.append(ledger.add_evidence(run_id, "note", extra_evidence))
    finding = ledger.create_finding(
        Finding(
            id="",
            run_id=run_id,
            key=key,
            title=title,
            severity=severity,
            cwe="CWE-89",
            endpoint=f"{TARGET_URL}/login",
            method="POST",
            param="username",
            description=f"Error-based SQLi on {HOST} username parameter.",
            impact="Database read as the app user.",
            remediation="Parameterize the query.",
            evidence_ids=tuple(ids),
            klass=klass,
            falsifier="Parameterized query returns a generic error.",
            action_class="auth-test",
            poc_path=poc_path,
        )
    )
    status = str(getattr(status, "value", status))
    if status == FindingStatus.THEORETICAL.value:
        # theoretical can only be born theoretical (0 evidence legal).
        return ledger.create_theoretical_finding(
            Finding(
                id="",
                run_id=run_id,
                key=key + "-theoretical",
                title=title,
                severity=severity,
                cwe="CWE-89",
                endpoint="/login",
                klass=klass,
            )
        )
    wanted = status
    path = [
        "candidate",
        "verified",
        PROVEN_LIVE,
        "ruled_out",
    ]
    # Drive through the legal ladder; anything skipped-over is clamped.
    target_index = path.index(wanted)
    for step in path[: target_index + 1]:
        if step == "candidate":
            continue
        if step == "verified":
            replay = ledger.add_evidence(
                run_id,
                "http_exchange",
                {
                    "check_id": klass,
                    "finding_id": finding.id,
                    "replay": True,
                    "method": "POST",
                    "request_body": f"username=%27&session={TOKEN_SENTINEL}",
                    "request_headers": {"cookie": f"sid={TOKEN_SENTINEL}"},
                    "response_body": '<pre>sqlite3.OperationalError: near "\'"</pre>',
                },
            )
            ledger.set_finding_status(finding.id, FindingStatus.VERIFIED, f"replayed for {step}")
            finding = ledger.get_finding(finding.id)
            assert replay in finding.evidence_ids
            continue
        if step == "ruled_out":
            ledger.set_finding_status(finding.id, FindingStatus.RULED_OUT, f"ladder to {step}")
            finding = ledger.get_finding(finding.id)
            continue
        finding = _to_proven_live(ledger, finding, run_id, klass=klass)
    return finding


@pytest.fixture
def seeded(tmp_path):
    """Temp ledger holding one finding per eligibility bucket + a medium."""
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.create_run(NAME_SENTINEL, TARGET_URL, "deterministic", "unit-test")
    crit = _seed_finding(
        ledger,
        NAME_SENTINEL,
        key="sql-injection|POST|/login|username",
        severity=Severity.CRITICAL,
        status=PROVEN_LIVE,
    )
    high = _seed_finding(
        ledger,
        NAME_SENTINEL,
        key="path-traversal|GET|/download|file",
        severity=Severity.HIGH,
        status=PROVEN_LIVE,
        klass="path-traversal",
        title="Path traversal in download",
        poc_path=None,
    )
    medium = _seed_finding(
        ledger,
        NAME_SENTINEL,
        key="open-redirect|GET|/goto|url",
        severity=Severity.MEDIUM,
        status=PROVEN_LIVE,
        klass="open-redirect",
        title="Open redirect",
    )
    verified_crit = _seed_finding(
        ledger,
        NAME_SENTINEL,
        key="ssti|POST|/render|tpl",
        severity=Severity.CRITICAL,
        status="verified",
        klass="ssti",
        title="SSTI in render",
    )
    candidate_crit = _seed_finding(
        ledger,
        NAME_SENTINEL,
        key="ssrf|GET|/fetch|url",
        severity=Severity.CRITICAL,
        status="candidate",
        klass="ssrf",
        title="SSRF in fetch",
    )
    theoretical_low = _seed_finding(
        ledger,
        NAME_SENTINEL,
        key="xxe|POST|/parse|xml",
        severity=Severity.LOW,
        status="theoretical",
        klass="xxe",
        title="XXE",
    )
    try:
        yield {
            "ledger": ledger,
            "run_id": NAME_SENTINEL,
            "critical": crit,
            "high": high,
            "medium": medium,
            "verified_critical": verified_crit,
            "candidate_critical": candidate_crit,
            "theoretical_low": theoretical_low,
            "tmp": tmp_path,
        }
    finally:
        ledger.close()


@pytest.fixture
def runner():
    return CliRunner()


def _cli_env(monkeypatch, ledger: Ledger, tmp_path):
    monkeypatch.setenv("HUNTER_STATE_DIR", str(ledger.path.parent))
    monkeypatch.setenv("HUNTEROS_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("HUNTEROS_NO_UPDATE_CHECK", "1")


# ------------------------------------------------------------- eligibility --


def test_proven_live_critical_and_high_are_eligible(seeded):
    from hunter.promote import eligible_promotions

    candidates = eligible_promotions(seeded["ledger"])
    keys = {c.finding_key for c in candidates}
    assert keys == {
        seeded["critical"].key,
        seeded["high"].key,
    }
    for candidate in candidates:
        assert candidate.severity in ("critical", "high")
        assert candidate.status == "proven-live"
        assert candidate.finding_id


def test_proven_medium_and_low_are_not_eligible(seeded):
    """Spec invariant 12: proven-medium stays in the ledger, never promoted."""
    from hunter.promote import eligible_promotions

    keys = {c.finding_key for c in eligible_promotions(seeded["ledger"])}
    assert seeded["medium"].key not in keys
    assert seeded["theoretical_low"].key not in keys


def test_unproven_findings_are_never_eligible(seeded):
    """Spec invariant 11: a skill built from an unproven finding is poison."""
    from hunter.promote import eligible_promotions

    keys = {c.finding_key for c in eligible_promotions(seeded["ledger"])}
    assert seeded["verified_critical"].key not in keys  # verified != proven-live
    assert seeded["candidate_critical"].key not in keys
    assert seeded["theoretical_low"].key not in keys


def test_eligible_promotions_is_resolved_by_finding_id_too(seeded):
    from hunter.promote import promote_to_skill

    path = promote_to_skill(
        seeded["ledger"], seeded["critical"].id, skills_dir=seeded["tmp"] / "skills"
    )
    assert path.is_file()


# ----------------------------------------------------------- refusals -------


@pytest.mark.parametrize("bucket", ["verified_critical", "candidate_critical", "medium"])
def test_promote_refuses_ineligible_with_not_eligible(seeded, bucket):
    from hunter.promote import NotEligible, promote_to_skill, promote_to_tool

    finding = seeded[bucket]
    with pytest.raises(NotEligible):
        promote_to_skill(seeded["ledger"], finding.key, skills_dir=seeded["tmp"] / "skills")
    with pytest.raises(NotEligible):
        promote_to_tool(seeded["ledger"], finding.key, tools_dir=seeded["tmp"] / "tools")
    assert not (seeded["tmp"] / "skills").exists()
    assert not (seeded["tmp"] / "tools").exists()


def test_promote_unknown_key_raises_keyerror(seeded):
    from hunter.promote import promote_to_skill

    with pytest.raises(KeyError):
        promote_to_skill(seeded["ledger"], "does-not-exist|GET|/|nope", skills_dir=seeded["tmp"])


# ------------------------------------------------------------ skill writer --


def test_skill_md_is_valid_frontmatter_with_short_description(seeded):
    from hunter.agent.skills import parse_skill_md
    from hunter.promote import promote_to_skill

    path = promote_to_skill(seeded["ledger"], seeded["critical"].key, skills_dir=seeded["tmp"] / "skills")
    assert path.name == "SKILL.md"
    text = path.read_text(encoding="utf-8")
    skill = parse_skill_md(text, directory_id=path.parent.name)
    assert skill is not None, f"generated SKILL.md did not validate:\n{text}"
    assert skill.name == path.parent.name
    assert 0 < len(skill.description) < 200
    assert "sql-injection" in text
    assert seeded["critical"].id in text or seeded["critical"].key in text


def test_skill_md_contains_no_hostname_and_no_token(seeded):
    """Spec invariant 13 — the security requirement of Part C."""
    from hunter.promote import promote_to_skill

    path = promote_to_skill(seeded["ledger"], seeded["critical"].key, skills_dir=seeded["tmp"] / "skills")
    text = path.read_text(encoding="utf-8")
    assert HOST not in text, f"literal target hostname leaked into {path}"
    assert TOKEN_SENTINEL not in text, f"seeded token leaked into {path}"
    assert "sid=" not in text
    assert NAME_SENTINEL not in text
    assert "username=hunter" not in text
    assert "401 Unauthorized" not in text
    text_lower = text.lower()
    assert "sql-injection" in text_lower
    assert "web2" in text_lower


def test_skill_md_without_traffic_evidence_still_leaks_nothing(seeded):
    from hunter.promote import promote_to_skill

    path = promote_to_skill(seeded["ledger"], seeded["high"].key, skills_dir=seeded["tmp"] / "skills")
    text = path.read_text(encoding="utf-8")
    assert HOST not in text
    assert TOKEN_SENTINEL not in text
    assert "path-traversal" in text


def test_unknown_klass_falls_back_to_unknown_class_not_the_hostname(seeded):
    from hunter.kernel.findings import Finding, Severity
    from hunter.promote import promote_to_skill

    ledger = seeded["ledger"]
    run = NAME_SENTINEL
    ev = ledger.add_evidence(run, "note", {"note": "custom class probe"})
    finding = ledger.create_theoretical_finding(
        Finding(
            id="", run_id=run, key="custom|GET|/x|-", title="Custom class bug",
            severity=Severity.CRITICAL, cwe="CWE-000", endpoint=f"{TARGET_URL}/x",
            klass="unknown", evidence_ids=(ev,),
        )
    )
    # theoretical is never eligible -> prove the fallback via the resolver only
    from hunter.promote import NotEligible, target_class

    assert target_class(finding) == "unknown"
    with pytest.raises(NotEligible):
        promote_to_skill(ledger, finding.key, skills_dir=seeded["tmp"] / "skills")


def test_skill_promotion_is_idempotent(seeded):
    from hunter.promote import promote_to_skill

    skills_dir = seeded["tmp"] / "skills"
    first = promote_to_skill(seeded["ledger"], seeded["critical"].key, skills_dir=skills_dir)
    second = promote_to_skill(seeded["ledger"], seeded["critical"].key, skills_dir=skills_dir)
    assert first == second
    dirs = [p for p in skills_dir.iterdir() if p.is_dir()]
    assert len(dirs) == 1, f"re-promotion duplicated the skill: {dirs}"
    assert first.read_text(encoding="utf-8")  # still a file, still readable


def test_skill_promotion_never_overwrites_a_foreign_skill(seeded):
    """An existing hand-written card at the target name must be left alone."""
    from hunter.promote import promote_to_skill

    skills_dir = seeded["tmp"] / "skills"
    scratch = promote_to_skill(seeded["ledger"], seeded["critical"].key, skills_dir=seeded["tmp"] / "scratch")
    target = skills_dir / scratch.parent.name
    target.mkdir(parents=True)
    handwritten = target / "SKILL.md"
    handwritten.write_text("---\nname: x\n---\nhand written\n", encoding="utf-8")
    with pytest.raises(HunterError):
        promote_to_skill(seeded["ledger"], seeded["critical"].key, skills_dir=skills_dir)
    assert handwritten.read_text(encoding="utf-8") == "---\nname: x\n---\nhand written\n"


# ------------------------------------------------------------- tool writer --


def test_tool_is_a_runnable_script_that_leaks_nothing(seeded):
    from hunter.promote import promote_to_tool

    path = promote_to_tool(seeded["ledger"], seeded["critical"].key, tools_dir=seeded["tmp"] / "tools")
    assert path.suffix == ".py"
    text = path.read_text(encoding="utf-8")
    compile(text, str(path), "exec")  # syntactically valid
    assert HOST not in text
    assert TOKEN_SENTINEL not in text
    assert "sql-injection" in text
    assert path.name.endswith(".py")


def test_tool_promotion_is_idempotent(seeded):
    from hunter.promote import promote_to_tool

    tools_dir = seeded["tmp"] / "tools"
    first = promote_to_tool(seeded["ledger"], seeded["critical"].key, tools_dir=tools_dir)
    second = promote_to_tool(seeded["ledger"], seeded["critical"].key, tools_dir=tools_dir)
    assert first == second
    assert len(list(tools_dir.iterdir())) == 1


# -------------------------------------------------------------------- CLI --


def test_cli_promote_list_json_is_pure_json(seeded, runner, monkeypatch):
    from hunter.cli.main import app

    _cli_env(monkeypatch, seeded["ledger"], seeded["tmp"])
    result = runner.invoke(app, ["promote", "list", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)  # nothing else on stdout
    assert isinstance(payload, list)
    keys = {row["finding_key"] for row in payload}
    assert keys == {seeded["critical"].key, seeded["high"].key}
    blob = result.stdout
    assert HOST not in blob
    assert TOKEN_SENTINEL not in blob


def test_cli_promote_skill_json_is_pure_json(seeded, runner, monkeypatch):
    from hunter.cli.main import app

    _cli_env(monkeypatch, seeded["ledger"], seeded["tmp"])
    result = runner.invoke(app, ["promote", "skill", seeded["critical"].key, "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["path"].endswith("SKILL.md")
    assert payload["finding_key"] == seeded["critical"].key
    assert HOST not in result.stdout


def test_cli_promote_refuses_unproven_with_nonzero_exit(seeded, runner, monkeypatch):
    from hunter.cli.main import app

    _cli_env(monkeypatch, seeded["ledger"], seeded["tmp"])
    result = runner.invoke(app, ["promote", "skill", seeded["verified_critical"].key])
    assert result.exit_code != 0
    assert not (seeded["ledger"].path.parent / "skills").exists()


def test_cli_promote_tool_writes_the_script(seeded, runner, monkeypatch):
    from hunter.cli.main import app

    _cli_env(monkeypatch, seeded["ledger"], seeded["tmp"])
    result = runner.invoke(app, ["promote", "tool", seeded["high"].key, "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["path"].endswith(".py")
    assert re.search(r"path-traversal", open(payload["path"], encoding="utf-8").read())
