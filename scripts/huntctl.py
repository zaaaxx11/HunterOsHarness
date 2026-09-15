#!/usr/bin/env python3
"""huntctl — start/stop/status/logs for the HunterOs hunt daemon.

Thin wrapper over the daemon core (``hunter.daemon`` — the same pinned
functions the ``hunter daemon`` CLI drives). All state lives under
``--state`` (default ``./.hunter``). Windows-safe: pathlib everywhere, no
platform-specific calls.

Exit codes mirror the CLI: 0 ok, 1 error, 3 refused, 8 config.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from hunter.duration import parse_duration  # noqa: E402
from hunter.errors import HunterError  # noqa: E402
from hunter.hunt import normalize_hunt_target, propose_manifest  # noqa: E402
from hunter.tools.scope import LOCAL_HOSTS  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 3

# The pinned task-file default; scripts do not widen budgets silently.
DEFAULT_MAX_COST_USD = 5.0


def _add_state_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state", default=".hunter", help="state directory (default ./.hunter)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="huntctl", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="enqueue a hunt task and start the daemon")
    start.add_argument("--target", required=True, help="authorized target URL")
    start.add_argument("--time", default=None, help="max wall time (e.g. 2h, 90m, 45)")
    start.add_argument("--min-time", default=None, help="min wall time — the engine will not stop earlier")
    start.add_argument("--scope", default=None, help="scope manifest JSON path (non-localhost)")
    start.add_argument("--engine", default="llm", help="engine name (default llm)")
    start.add_argument("--yes", action="store_true", help="accept the proposed exact-host scope")
    start.add_argument("--force", action="store_true", help="start even if a daemon looks alive")
    _add_state_arg(start)

    stop = sub.add_parser("stop", help="stop the daemon (cooperative stop flag, then force)")
    stop.add_argument("--force", action="store_true", help="terminate/kill a hung daemon")
    _add_state_arg(stop)

    status = sub.add_parser("status", help="daemon status")
    status.add_argument("--json", action="store_true", help="print machine-readable JSON")
    _add_state_arg(status)

    logs = sub.add_parser("logs", help="tail the daemon log")
    logs.add_argument("--lines", type=int, default=50, help="last N lines (default 50)")
    _add_state_arg(logs)
    return parser


def _resolve_scope(args: argparse.Namespace, target: str) -> dict | int:
    """A scope dict, or an exit code when the proposal is not authorized."""
    if args.scope:
        manifest = json.loads(Path(args.scope).read_text(encoding="utf-8"))
        hosts = manifest.get("hosts") or []
        if not isinstance(hosts, list) or not hosts:
            print("[ERROR config] scope manifest must contain a non-empty 'hosts' list", file=sys.stderr)
            return 8
        return {
            "name": str(manifest.get("name", Path(args.scope).stem)),
            "hosts": [str(h).strip().lower() for h in hosts],
            "allow_subdomains": bool(manifest.get("allow_subdomains", False)),
        }
    host = urlparse(target).hostname or ""
    if host not in LOCAL_HOSTS and not args.yes:
        proposal = propose_manifest(host)
        print(
            "proposed exact-host scope: " + json.dumps(proposal)
            + "\nre-run with --yes to accept, or pass --scope manifest.json",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    return propose_manifest(host)


def cmd_start(args: argparse.Namespace) -> int:
    target, kind = normalize_hunt_target(args.target)
    if kind != "url":
        print(f"[ERROR config] invalid target URL: {args.target!r}", file=sys.stderr)
        return EXIT_REFUSED
    resolved = _resolve_scope(args, target)
    if isinstance(resolved, int):
        return resolved
    try:
        from hunter.daemon import start_daemon

        return start_daemon(
            args.state,
            target=target,
            scope=resolved,
            engine=args.engine,
            min_wall_seconds=parse_duration(args.min_time),
            max_wall_seconds=parse_duration(args.time),
            max_cost_usd=DEFAULT_MAX_COST_USD,
            force=args.force,
        )
    except HunterError as exc:
        print(exc.user_message(), file=sys.stderr)
        return exc.exit_code


def cmd_stop(args: argparse.Namespace) -> int:
    try:
        from hunter.daemon import stop_daemon

        return stop_daemon(args.state, force=args.force)
    except HunterError as exc:
        print(exc.user_message(), file=sys.stderr)
        return exc.exit_code


def cmd_status(args: argparse.Namespace) -> int:
    try:
        from hunter.daemon import daemon_status

        status = daemon_status(args.state)
    except HunterError as exc:
        print(exc.user_message(), file=sys.stderr)
        return exc.exit_code
    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
        return EXIT_OK
    running = bool(status.get("running"))
    pid = status.get("pid")
    head = f"daemon: running (pid {pid})" if running else "daemon: stopped"
    if running and status.get("stale"):
        head += " — STALE (heartbeat aged out)"
    print(head)
    print(f"state: {Path(args.state).resolve()}")
    transports = status.get("transports") or []
    print(f"transports: {', '.join(transports) if transports else '(none)'}")
    print(
        f"queue: {status.get('queue_pending', 0)} pending, "
        f"{status.get('queue_claimed', 0)} claimed"
    )
    last = status.get("last_run")
    if last:
        print(f"last run: {last.get('run_id')} {last.get('status')} ({last.get('findings')} findings)")
    return EXIT_OK


def cmd_logs(args: argparse.Namespace) -> int:
    try:
        from hunter.daemon import log_path

        path = log_path(args.state)
    except HunterError as exc:
        print(exc.user_message(), file=sys.stderr)
        return exc.exit_code
    except ImportError:
        print("[ERROR config] hunter daemon module unavailable — install the harness", file=sys.stderr)
        return EXIT_ERROR
    if not path.is_file():
        print(f"(no daemon log at {path})")
        return EXIT_OK
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-max(1, args.lines) :]:
        print(line)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"start": cmd_start, "stop": cmd_stop, "status": cmd_status, "logs": cmd_logs}
    try:
        return handlers[args.command](args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"[ERROR engine] {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
