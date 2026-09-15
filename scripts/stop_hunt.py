#!/usr/bin/env python3
"""stop_hunt — cooperatively stop hunts: write stop.flag, mark runs stopped.

Writes ``<state>/daemon/stop.flag`` (the in-flight budget checks it FIRST —
a user-issued kill outranks cost). With ``--run-id`` / ``--all`` it also
marks open ledger runs as ``stopped`` (runs table only; events untouched).
``--kill`` additionally stops the daemon process (cooperative first, then
terminate/kill). Windows-safe; no shell-outs.

Exit codes: 0 ok, 1 error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from hunter.kernel.ledger import Ledger  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1

# Run statuses that describe work still in flight.
OPEN_RUN_STATUSES = frozenset({"running"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stop_hunt", description="write the daemon stop flag and optionally mark runs stopped"
    )
    parser.add_argument("--state", default=".hunter", help="state directory (default ./.hunter)")
    parser.add_argument("--run-id", default=None, help="mark this open run 'stopped'")
    parser.add_argument("--all", action="store_true", help="mark every open run 'stopped'")
    parser.add_argument("--kill", action="store_true", help="also stop the daemon process")
    return parser


def _write_stop_flag(state: Path) -> Path:
    daemon_dir = state / "daemon"
    daemon_dir.mkdir(parents=True, exist_ok=True)
    flag = daemon_dir / "stop.flag"
    flag.touch(exist_ok=True)
    return flag


def _mark_runs_stopped(db_path: Path, run_id: str | None, mark_all: bool) -> int:
    """Finish open runs as 'stopped' (runs table only; events untouched)."""
    ledger = Ledger(db_path)
    marked = 0
    try:
        if run_id:
            rows = [row for row in ledger.runs() if row.get("run_id") == run_id]
            if not rows:
                print(f"[ERROR ledger] run '{run_id}' not found", file=sys.stderr)
                return EXIT_ERROR
            status = str(rows[0].get("status") or "")
            if status not in OPEN_RUN_STATUSES:
                print(
                    f"[ERROR ledger] run '{run_id}' is not open (status: {status})",
                    file=sys.stderr,
                )
                return EXIT_ERROR
            ledger.finish_run(run_id, "stopped")
            marked += 1
            print(f"run {run_id} marked stopped")
        elif mark_all:
            for row in ledger.runs():
                if str(row.get("status") or "") in OPEN_RUN_STATUSES:
                    ledger.finish_run(str(row["run_id"]), "stopped")
                    marked += 1
                    print(f"run {row['run_id']} marked stopped")
            if marked == 0:
                print("no open runs to mark")
    finally:
        ledger.close()
    # --all with nothing open is a success; an explicit --run-id that could
    # not be marked already returned EXIT_ERROR above.
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = Path(args.state)
    try:
        flag = _write_stop_flag(state)
        print(f"stop flag written: {flag}")
        if args.kill:
            try:
                from hunter.daemon import stop_daemon

                code = stop_daemon(str(state), force=True)
                if code != EXIT_OK:
                    return code
            except ImportError:
                print(
                    "[ERROR config] hunter daemon module unavailable — flag written; "
                    "stop the daemon process manually",
                    file=sys.stderr,
                )
                return EXIT_ERROR
        rc = _mark_runs_stopped(state / "ledger.db", args.run_id, args.all)
        return rc
    except (OSError, ValueError) as exc:
        print(f"[ERROR engine] {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
