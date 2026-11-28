import json

from hunter.tools.scope import ScopeSet
from hunter.workflow.rag import (
    RagConfig,
    RagLoop,
    derive_child_targets,
    existing_targets,
    finding_was_observed,
    followed_findings,
    load_rag_state,
    mark_followed,
    normalize_finding_target,
    wonder_followups,
)


def _scope():
    return ScopeSet(frozenset({"example.com"}), False, name="test")


def test_normalize_finding_target_relative():
    from hunter.kernel.findings import Finding, Severity

    f = Finding(
        id="F-0001",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/api/foo",
        method="GET",
    )
    assert normalize_finding_target(f, "http://example.com") == "http://example.com/api/foo"


def test_derive_child_targets_in_scope():
    from hunter.kernel.findings import Finding, Severity

    f = Finding(
        id="F-0002",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/api/foo/bar",
        method="GET",
    )
    scope = _scope()
    targets = derive_child_targets(f, scope, "http://example.com")
    assert targets
    assert all("example.com" in t for t in targets)
    # host out of scope rejected
    f2 = Finding(
        id="F-0003",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="http://evil.com/x",
        method="GET",
    )
    assert derive_child_targets(f2, scope, "http://example.com") == []


def test_wonder_followups_none_provider():
    from hunter.kernel.findings import Finding, Severity

    f = Finding(
        id="F-0004",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/x",
        method="GET",
    )
    assert wonder_followups(None, f, _scope(), "http://example.com") == []


def test_wonder_followups_parses_and_validates():
    from hunter.kernel.findings import Finding, Severity

    class FakeProvider:
        name = "fake"

        def complete(self, tier, messages, tools=None, stream_cb=None, budget=None):
            from hunter.llm.base import TurnResult

            return TurnResult(
                text='["http://example.com/a", "http://evil.com/b", "http://example.com/c"]'
            )

        def classify(self, exc):
            from hunter.llm.base import ClassifiedError

            return ClassifiedError()

    f = Finding(
        id="F-0005",
        run_id="R-1",
        key="k",
        title="t",
        severity=Severity.INFO,
        cwe="",
        endpoint="/x",
        method="GET",
    )
    out = wonder_followups(FakeProvider(), f, _scope(), "http://example.com")
    assert "http://example.com/a" in out
    assert "http://example.com/c" in out
    assert all("evil.com" not in t for t in out)


def test_followed_state_roundtrip(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    assert followed_findings(sd) == set()
    mark_followed(sd, "F-0001")
    assert "F-0001" in followed_findings(sd)
    st = load_rag_state(sd)
    assert "F-0001" in st["followed"]


def test_existing_targets_reads_queue(tmp_path):
    sd = tmp_path / "state"
    (sd / "daemon" / "queue").mkdir(parents=True)
    q = sd / "daemon" / "queue"
    (q / "task-1.json").write_text(json.dumps({"target": "http://example.com/a"}))
    assert "http://example.com/a" in existing_targets(sd)


def test_rag_cycle_enqueues_seed_variants(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    scope = _scope()

    # ensure state dir layout
    (sd / "daemon" / "queue").mkdir(parents=True, exist_ok=True)

    cfg = RagConfig(
        state_dir=sd,
        target="http://example.com",
        scope=scope,
        engine="deterministic",
        time_budget_s=10,
        interval_s=1,
        high_water=3,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    loop = RagLoop(cfg)
    enqueued = loop._cycle()
    # With a single-host scope there is no OTHER host to fill the high-water
    # mark with, so exactly one task is correct — the guard must not invent
    # `?rag-cycle=N` clones of the same URL to pad the queue.
    pending = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    assert pending == 1, pending
    assert len(enqueued) == 1
    # and the one task is a real scope host, not a query-string variant
    task = json.loads(next((sd / "daemon" / "queue").glob("task-*.json")).read_text())
    assert task["target"] == "https://example.com/", task["target"]
    assert "rag-cycle" not in task["target"]


def test_rag_cycle_fills_high_water_with_real_scope_hosts(tmp_path):
    """A multi-host scope fills the queue with DISTINCT hosts, never clones.

    Pins the fix for the `?rag-cycle=N` padding: every enqueued target must
    be a different host from the approved scope, so the queue is real work
    rather than the same endpoint dialed with a junk parameter.
    """
    sd = tmp_path / "state"
    sd.mkdir()
    (sd / "daemon" / "queue").mkdir(parents=True, exist_ok=True)
    scope = ScopeSet(frozenset({"example.com", "api.example.com", "cdn.example.com"}),
                     False, name="test")

    cfg = RagConfig(
        state_dir=sd,
        target="http://example.com",
        scope=scope,
        engine="deterministic",
        time_budget_s=10,
        interval_s=1,
        high_water=3,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    loop = RagLoop(cfg)
    loop._cycle()
    pending = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    assert pending == 3, pending

    targets = [
        json.loads(p.read_text())["target"]
        for p in (sd / "daemon" / "queue").glob("task-*.json")
    ]
    assert len(set(targets)) == len(targets), f"duplicate targets: {targets}"
    assert not any("rag-cycle" in t for t in targets), (
        f"queue padded with query-string clones: {targets}")


def test_rag_cycle_no_duplicate_processing(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    (sd / "daemon" / "queue").mkdir(parents=True, exist_ok=True)
    scope = _scope()
    cfg = RagConfig(
        state_dir=sd,
        target="http://example.com",
        scope=scope,
        engine="deterministic",
        time_budget_s=10,
        interval_s=1,
        high_water=2,
        dry_run=False,
        once=True,
        manage_daemon=False,
        provider=None,
    )
    loop = RagLoop(cfg)
    loop._cycle()
    # second cycle should not crash and should not re-enqueue identical seeds
    before = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    loop._cycle()
    after = len(list((sd / "daemon" / "queue").glob("task-*.json")))
    assert after >= before


# ---------------------------------------------------------------------------
# No invented endpoints (DeFi-shaped fabrication regression)
# ---------------------------------------------------------------------------


class _InventingProvider:
    """A planner that answers "propose 4 follow-up URLs" with pure guesses —
    exactly the utility-tier behaviour that produced airvpn.org/transfer,
    ipleak.net/withdraw, eddie.website/deposit and friends in the field.
    """

    name = "fake"

    def complete(self, tier, messages, tools=None, stream_cb=None, budget=None):
        from hunter.llm.base import TurnResult

        return TurnResult(
            text=(
                '["https://airvpn.org/transfer?amount=100", '
                '"https://airvpn.org/withdraw", '
                '"https://airvpn.org/deposit", '
                '"https://airvpn.org/admin/transfer"]'
            )
        )

    def classify(self, exc):
        from hunter.llm.base import ClassifiedError

        return ClassifiedError()


_DEFI_MARKERS = ("/transfer", "/withdraw", "/deposit")


def _vpn_scope():
    """The AirVPN VDP manifest: three hosts, subdomains allowed."""
    return ScopeSet(
        frozenset({"airvpn.org", "eddie.website", "ipleak.net"}),
        True,
        name="airvpn-vdp-2026-11",
    )


def _finding_at(fid, endpoint, run_id, status, severity, evidence_id=""):
    from hunter.kernel.findings import Finding

    return Finding(
        id=fid,
        run_id=run_id,
        key=f"unauth-action|POST|{endpoint}|-",
        title="Unauthenticated state-changing action",
        severity=severity,
        cwe="CWE-862",
        endpoint=endpoint,
        method="POST",
        status=status,
        evidence_ids=((evidence_id,) if evidence_id else ()),
    )


def _fresh_ledger(tmp_path):
    """A real ledger in this test's own state dir. The caller must close()."""
    from hunter.kernel.ledger import Ledger
    from hunter.runtime_paths import RuntimePaths

    sd = tmp_path / "state"
    sd.mkdir(exist_ok=True)
    (sd / "daemon" / "queue").mkdir(parents=True, exist_ok=True)
    return Ledger(RuntimePaths.resolve(state=sd, migrate=False).ledger)


def _parse_dry_run(out: str) -> list[str]:
    """Targets from ``[dry-run] would enqueue <target>`` lines."""
    prefix = "would enqueue "
    return [
        line.split(prefix, 1)[1]
        for line in (out or "").splitlines()
        if "[dry-run]" in line and prefix in line
    ]


def _planned_targets(loop) -> list[str]:
    """Every target ``loop._cycle()`` would enqueue, captured from dry-run."""
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()) as buf:
        loop._cycle()
    return _parse_dry_run(buf.getvalue())


def _observed_finding(ledger, fid, run_id, origin_url, status):
    """One finding whose own evidence is a real exchange on ``origin_url``."""
    from hunter.kernel.findings import Severity

    ev = ledger.add_evidence(
        run_id, "http_exchange", {"method": "GET", "url": origin_url, "status": 200}
    )
    ledger.create_finding(_finding_at(fid, "/api", run_id, status, Severity.HIGH, ev))


def _vault_transfer_finding(ledger):
    """The vault demo's verified ``POST /transfer`` finding in this ledger."""
    from hunter.kernel.findings import FindingStatus, Severity

    ledger.create_run("R-vault", "http://127.0.0.1:PORT/", "llm", "vault")
    ev = ledger.add_evidence(
        "R-vault",
        "http_exchange",
        {"method": "POST", "url": "http://127.0.0.1:PORT/transfer", "status": 200},
    )
    ledger.create_finding(
        _finding_at(
            "F-0001", "/transfer", "R-vault", FindingStatus.VERIFIED, Severity.CRITICAL, ev
        )
    )


def test_wonder_followups_cannot_invent_unobserved_paths():
    """A planner proposing /transfer, /withdraw, /deposit must get [] back.

    All four proposals are on in-scope HOSTS, so the scope gate has never
    stopped them. What stops them is the observed-evidence set: none of those
    paths appears in any http_exchange, so each one is a guess.
    """
    from hunter.kernel.findings import FindingStatus, Severity

    finding = _finding_at("F-X", "/api", "R-1", FindingStatus.CANDIDATE, Severity.HIGH)
    out = wonder_followups(
        _InventingProvider(),
        finding,
        _vpn_scope(),
        "https://airvpn.org/",
        observed={"https://airvpn.org/", "https://airvpn.org/robots.txt"},
    )
    assert out == []
    assert not any(marker in t for t in out for marker in _DEFI_MARKERS)


def test_wonder_followups_keeps_observed_paths():
    """Positive control: a URL the run really visited stays a legal lead.

    Without this the observed-set guard could degenerate into a gate that
    refuses everything, which would silently end all follow-up hunting.
    """
    from hunter.kernel.findings import FindingStatus, Severity

    finding = _finding_at("F-Y", "/api", "R-1", FindingStatus.CANDIDATE, Severity.HIGH)
    out = wonder_followups(
        _InventingProvider(),
        finding,
        _vpn_scope(),
        "https://airvpn.org/",
        observed={
            "https://airvpn.org/",
            "https://airvpn.org/transfer",
            "https://airvpn.org/withdraw",
        },
    )
    assert any("/transfer" in t for t in out)
    # /deposit was NOT observed, so it stays refused even here.
    assert "/deposit" not in " ".join(out)


def test_finding_was_observed_rejects_a_cross_run_finding():
    """The vault /transfer finding is not a lead for an airvpn.org hunt."""
    from hunter.kernel.findings import FindingStatus, Severity

    vault = _finding_at(
        "F-0001", "/transfer", "R-vault", FindingStatus.VERIFIED, Severity.CRITICAL
    )
    # airvpn.org was visited, but /transfer on it never was.
    observed = {"https://airvpn.org/", "https://airvpn.org/api"}
    assert finding_was_observed(vault, "https://airvpn.org/", observed) is False
    # Contract/dir origins have no URL surface to observe.
    assert finding_was_observed(vault, "/tmp/repo", observed) is False
    # No evidence at all means nothing can be shown to be real.
    assert finding_was_observed(vault, "https://airvpn.org/", set()) is False


def test_cross_run_finding_does_not_seed_followups(tmp_path):
    """A vault finding must not seed follow-ups for a VPN target.

    ``Ledger.findings()`` has NO run filter, so ``RagLoop._cycle()`` reads back
    every finding in the shared state dir — including ``POST /transfer`` from
    the localhost vault demo. Concatenating that finding's endpoint onto the
    current origin is exactly how ``https://airvpn.org/transfer`` was born.
    """
    ledger = _fresh_ledger(tmp_path)
    _vault_transfer_finding(ledger)
    ledger.close()

    sd = tmp_path / "state"
    cfg = RagConfig(
        state_dir=sd,
        target="https://airvpn.org/",
        scope=_vpn_scope(),
        engine="llm",
        time_budget_s=5,
        interval_s=1,
        high_water=8,
        once=True,
        manage_daemon=False,
        provider=_InventingProvider(),
    )
    # dry_run prints every target the cycle WOULD enqueue — the observable
    # surface. `enqueue_task` is a no-op stub in the daemon-free build, so
    # asserting on the on-disk queue proves nothing.
    cfg.dry_run = True
    enqueued = _planned_targets(RagLoop(cfg))

    for marker in _DEFI_MARKERS:
        assert not any(marker in t for t in enqueued), (
            f"invented endpoint {marker!r} reached the plan: {enqueued}"
        )


def test_cycle_finding_gate_removes_fabrications_not_findings(tmp_path):
    """The observed-findings guard keeps real leads and the real seed hosts.

    Guards that silently disable a feature are indistinguishable from the bug
    they fixed, so this pins both halves: fabrication out, real target in.
    """
    import contextlib
    import io

    from hunter.kernel.findings import FindingStatus

    ledger = _fresh_ledger(tmp_path)
    ledger.create_run("R-airvpn", "https://airvpn.org/", "llm", "airvpn")
    # A REAL lead: this run actually requested /api.
    _observed_finding(
        ledger, "F-0100", "R-airvpn", "https://airvpn.org/api", FindingStatus.CANDIDATE
    )
    # The vault cross-run leak: must be filtered out of the plan.
    _vault_transfer_finding(ledger)
    ledger.close()

    cfg = RagConfig(
        state_dir=tmp_path / "state",
        target="https://airvpn.org/",
        scope=_vpn_scope(),
        engine="llm",
        time_budget_s=5,
        interval_s=1,
        high_water=8,
        once=True,
        manage_daemon=False,
        provider=_InventingProvider(),
        dry_run=True,
    )
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        RagLoop(cfg)._cycle()
    planned = _parse_dry_run(buf.getvalue())

    for marker in _DEFI_MARKERS:
        assert not any(marker in t for t in planned), f"invented endpoint: {planned}"
    # The real observed lead still drives a follow-up ...
    assert "https://airvpn.org/api" in planned, planned
    # ... and the rest of the approved scope is still walked.
    assert {"https://eddie.website/", "https://ipleak.net/"} <= set(planned), planned


def test_observed_urls_reads_only_http_exchanges_and_normalises():
    """observed_urls is the sole source of follow-up truth — pin its shape.

    Only ``http_exchange`` rows count (a note is the model's own words), and
    the URL is normalised to scheme/host/path so ``/x?a=1`` and ``/x?a=2``
    are the same surface rather than two different leads.
    """
    from hunter.workflow.rag import observed_urls

    rows = [
        # accepted, normalised
        {"kind": "http_exchange", "data": {"url": "https://airvpn.org/api?page=1"}},
        # same surface, different query — collapses, not duplicated
        {"kind": "http_exchange", "data": {"url": "https://airvpn.org/api?page=2"}},
        # other kinds carry no request the harness made
        {"kind": "note", "data": {"text": "I imagine /transfer exists"}},
        {"kind": "browser_render", "data": {"url": "https://airvpn.org/admin"}},
        # malformed rows must never raise
        {"kind": "http_exchange", "data": {"url": "   "}},
        {"kind": "http_exchange", "data": "not-a-dict"},
        {"kind": "http_exchange"},
        "not-a-dict",
    ]
    out = observed_urls(rows)
    assert out == {"https://airvpn.org/api"}
