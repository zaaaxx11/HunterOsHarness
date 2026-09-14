"""One-shot ``hunter hunt`` orchestration shared by the CLI and chat reports."""

from __future__ import annotations

import builtins
import os
import threading
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from hunter.tools.scope import ScopeSet
from hunter.workflow.pipeline import RunSummary, run_scan

__all__ = [
    "HuntOutcome",
    "normalize_hunt_target",
    "propose_manifest",
    "mount_local_dir",
    "write_hunt_report",
    "run_hunt",
    "confirm_prompt",
]


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return


def confirm_prompt(prompt: str) -> bool:
    try:
        answer = builtins.input(prompt)
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def normalize_hunt_target(raw: str) -> tuple[str, str]:
    """Return a normalized URL or an absolute existing directory."""
    token = (raw or "").strip()
    if not token:
        return "", "invalid"
    path = Path(token).expanduser()
    try:
        if path.is_dir():
            return str(path.resolve()), "dir"
    except OSError:
        return "", "invalid"
    parsed = urlparse(token)
    if parsed.scheme and parsed.scheme.lower() in ("http", "https"):
        if parsed.hostname:
            return token, "url"
        return "", "invalid"
    # A bare host is accepted, but arbitrary prose is not. URL-like host:port
    # strings are parsed only after adding the explicit scheme.
    host = token if ("." in token or token.lower().startswith("localhost") or token[0].isdigit()) else ""
    if not host:
        return "", "invalid"
    candidate = f"http://{host}"
    if not urlparse(candidate).hostname:
        return "", "invalid"
    return candidate, "url"


def propose_manifest(host: str) -> dict:
    return {"name": host, "hosts": [host], "allow_subdomains": False}


class mount_local_dir:
    """Serve one local directory on a loopback-only ephemeral HTTP server."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = str(Path(directory).resolve())
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""

    def __enter__(self) -> mount_local_dir:
        directory = self.directory

        class Handler(_QuietHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=directory, **kwargs)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        self.server = None
        self.thread = None


@dataclass(frozen=True)
class HuntOutcome:
    run_id: str
    status: str
    findings: int
    verified: int
    candidates: int
    report_path: str | None
    exit_code: int
    stats: dict | None = None
    finding_rows: list[dict] | None = None


def write_hunt_report(run_id: str, *, state_dir: str | Path | None = None) -> Path | None:
    """Render a verified ledger run into ``reports/<run_id>.md``; never raise."""
    try:
        from hunter.kernel.ledger import Ledger
        from hunter.reporting.markdown import ReportBlocked, render_markdown

        db = Path(state_dir) / "ledger.db" if state_dir is not None else None
        ledger = Ledger(db)
        try:
            text = render_markdown(ledger, run_id)
        except (ReportBlocked, KeyError):
            return None
        finally:
            ledger.close()
        root = Path(state_dir) if state_dir is not None else Path(
            os.environ.get("HUNTER_STATE_DIR", ".hunter")
        )
        output = root / "reports" / f"{run_id}.md"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        return output
    except Exception:  # noqa: BLE001 — reporting cannot change hunt outcome
        return None


def _finding_row(finding) -> dict:
    severity = getattr(getattr(finding, "severity", None), "value", "")
    status = getattr(getattr(finding, "status", None), "value", "")
    return {
        "id": getattr(finding, "id", ""),
        "title": getattr(finding, "title", ""),
        "severity": severity,
        "status": status,
        "cwe": getattr(finding, "cwe", ""),
        "endpoint": getattr(finding, "endpoint", ""),
        "method": getattr(finding, "method", "GET"),
        "param": getattr(finding, "param", None),
        "evidence": list(getattr(finding, "evidence_ids", ()) or ()),
    }


def run_hunt(target, *, scope: ScopeSet, engine_name: str, state_dir=None) -> HuntOutcome:
    """Run the existing governed pipeline and map it to Strix exit codes."""
    try:
        summary: RunSummary = run_scan(
            target, engine_name=engine_name, scope=scope, state_dir=state_dir
        )
        report = write_hunt_report(summary.run_id, state_dir=state_dir)
        count = len(summary.findings)
        code = 1 if summary.status != "completed" else (2 if count else 0)
        return HuntOutcome(
            run_id=summary.run_id,
            status=summary.status,
            findings=count,
            verified=summary.verified,
            candidates=summary.candidates,
            report_path=str(report) if report else None,
            exit_code=code,
            stats=dict(summary.stats),
            finding_rows=[_finding_row(f) for f in summary.findings],
        )
    except Exception as exc:  # noqa: BLE001 — CLI must not traceback
        return HuntOutcome(
            run_id="",
            status="failed",
            findings=0,
            verified=0,
            candidates=0,
            report_path=None,
            exit_code=1,
            stats={"error": f"{type(exc).__name__}: {exc}"},
            finding_rows=[],
        )
