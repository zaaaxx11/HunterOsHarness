#!/usr/bin/env python3
"""report_pack — zip one run's report, attachments, and a sha256 MANIFEST.

Bundles ``reports/<run-id>.md`` plus that run's report attachments from the
state directory into a single archive with a ``MANIFEST.txt`` of
``sha256  <name>  <digest>`` lines — every member can be re-verified offline.
The ledger is never modified: this is a packaging view of rows that already
exist.

Exit codes: 0 ok, 1 error.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

EXIT_OK = 0
EXIT_ERROR = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="report_pack", description=__doc__)
    parser.add_argument("--run-id", required=True, help="run id (e.g. R-abc123)")
    parser.add_argument("--state", default=".hunter", help="state directory (default ./.hunter)")
    parser.add_argument(
        "-o", "--output", default=None, help="output zip path (default <state>/report_packs/<run-id>.zip)"
    )
    return parser


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = Path(args.state)
    reports_dir = state / "reports"
    report_path = reports_dir / f"{args.run_id}.md"
    if not report_path.is_file():
        print(f"[ERROR disk] no report for run '{args.run_id}' at {report_path}", file=sys.stderr)
        return EXIT_ERROR
    attachments_dir = reports_dir / args.run_id
    attachments = (
        sorted(p for p in attachments_dir.iterdir() if p.is_file()) if attachments_dir.is_dir() else []
    )

    output = Path(args.output) if args.output else state / "report_packs" / f"{args.run_id}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest_lines: list[str] = []
    try:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for arcname, source in [((args.run_id + ".md"), report_path)] + [
                (f"{args.run_id}/{p.name}", p) for p in attachments
            ]:
                data = source.read_bytes()
                archive.writestr(arcname, data)
                manifest_lines.append(f"sha256  {arcname}  {_sha256(data)}")
            archive.writestr("MANIFEST.txt", "\n".join(manifest_lines) + "\n")
    except OSError as exc:
        print(f"[ERROR disk] could not write {output}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"packed {len(manifest_lines)} file(s) -> {output}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
