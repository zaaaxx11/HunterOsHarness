"""M8 F9 — ``scripts/`` (test-first): stdlib + httpx only, Windows-safe,
scope-gated. Scripts run as real subprocesses of the venv python with
``cwd=ROOT`` (they insert ``src`` onto sys.path themselves); the one HTTP
surface is a loopback ``mount_local_dir`` server — localhost only, offline.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from hunter.hunt import mount_local_dir
from hunter.kernel.ledger import Ledger

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SCRIPT_NAMES = (
    "huntctl.py",
    "stop_hunt.py",
    "audit_toolkit.py",
    "compress_session.py",
    "quick_recon.py",
    "report_pack.py",
)


def _run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_scripts_readme_covers_all_scripts():
    readme = (SCRIPTS / "README.md").read_text(encoding="utf-8")
    for name in SCRIPT_NAMES:
        assert name in readme
    assert "scope-gated" in readme  # the "all offline-safe, scope-gated" statement


def test_audit_toolkit_json_markdown():
    proc = _run_script("audit_toolkit.py", "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert set(payload) >= {"available", "missing", "platform"}

    proc = _run_script("audit_toolkit.py", "--format", "markdown")
    assert proc.returncode == 0, proc.stderr
    assert "|" in proc.stdout  # a markdown table header row exists


def test_quick_recon_scope_refusal_and_localhost_json(tmp_path):
    manifest = tmp_path / "scope.json"
    manifest.write_text(
        json.dumps({"name": "other", "hosts": ["other.example"], "allow_subdomains": False}),
        encoding="utf-8",
    )
    # out-of-scope target -> refused with exit 3, nothing fetched
    proc = _run_script("quick_recon.py", "https://example.com", "--scope", str(manifest))
    assert proc.returncode == 3

    (tmp_path / "index.html").write_text("<html><body>loopback</body></html>", encoding="utf-8")
    (tmp_path / "robots.txt").write_text("User-agent: *\nDisallow: /private\n", encoding="utf-8")
    (tmp_path / "sitemap.xml").write_text(
        "<?xml version='1.0'?>"
        "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
        "<url><loc>http://127.0.0.1/a</loc></url>"
        "<url><loc>http://127.0.0.1/b</loc></url>"
        "</urlset>",
        encoding="utf-8",
    )
    with mount_local_dir(tmp_path) as mount:
        proc = _run_script("quick_recon.py", mount.url, "--scope", str(manifest), "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    for key in ("target", "fetched_at", "status_codes", "headers", "robots", "sitemap", "hints"):
        assert key in payload
    assert payload["robots"]["status"] == 200
    assert re.fullmatch(r"[0-9a-f]{64}", payload["robots"]["sha256"])
    assert "head" in payload["robots"]
    assert payload["sitemap"]["status"] == 200
    assert payload["sitemap"]["url_count"] == 2


def test_report_pack_zip_and_sha256_manifest(tmp_path):
    state = tmp_path / "state"
    reports = state / "reports"
    reports.mkdir(parents=True)
    run_id = "R-PACK0001"
    (reports / f"{run_id}.md").write_text("# report\nbody\n", encoding="utf-8")
    attachments = reports / run_id
    attachments.mkdir()
    (attachments / "evidence.json").write_text('{"k": "v"}\n', encoding="utf-8")

    out_zip = tmp_path / "pack.zip"
    proc = _run_script("report_pack.py", "--run-id", run_id, "--state", str(state), "-o", str(out_zip))
    assert proc.returncode == 0, proc.stderr
    assert out_zip.is_file()

    verified: list[str] = []
    with zipfile.ZipFile(out_zip) as archive:
        names = archive.namelist()
        manifest_name = next(name for name in names if name.endswith("MANIFEST.txt"))
        manifest = archive.read(manifest_name).decode("utf-8")
        for line in manifest.splitlines():
            if not line.strip():
                continue
            tokens = line.split()
            digest = next((t for t in tokens if re.fullmatch(r"[0-9a-f]{64}", t)), None)
            name = next((t for t in tokens if t not in {"sha256", digest} and t in names), None)
            assert digest is not None and name is not None, line
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
            verified.append(name)
    assert f"{run_id}.md" in verified


def test_stop_hunt_flag_and_ledger_mark(tmp_path):
    state = tmp_path / "state"
    ledger = Ledger(state / "ledger.db")
    ledger.create_run("R-STOP01", "http://127.0.0.1:9/", "deterministic", "localhost-only")
    ledger.append("R-STOP01", "run_started", {"target": "http://127.0.0.1:9/"})
    events_before = len(ledger.events("R-STOP01"))
    ledger.close()

    proc = _run_script("stop_hunt.py", "--state", str(state))
    assert proc.returncode == 0, proc.stderr
    assert (state / "daemon" / "stop.flag").is_file()

    # --run-id marks the OPEN run "stopped" (runs table only; events untouched)
    proc = _run_script("stop_hunt.py", "--state", str(state), "--run-id", "R-STOP01")
    assert proc.returncode == 0, proc.stderr
    ledger = Ledger(state / "ledger.db")
    try:
        assert ledger.runs()[-1]["status"] == "stopped"
        assert len(ledger.events("R-STOP01")) == events_before
    finally:
        ledger.close()


def test_scripts_import_allowlist_and_windows_safe():
    scripts = sorted(SCRIPTS.glob("*.py"))
    assert {script.name for script in scripts} >= set(SCRIPT_NAMES)
    allowed = set(sys.stdlib_module_names) | {"httpx", "hunter"}
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root in allowed, f"{script.name}: import {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                root = node.module.split(".")[0]
                assert root in allowed, f"{script.name}: from {node.module}"
        assert "os.fork" not in source, script.name
        assert "posix_spawn" not in source, script.name
