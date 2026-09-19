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

# Attachment guards (media hardening): symlinks are never followed, a single
# oversized file is refused, and the whole pack has a total size budget.
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # per-file cap
MAX_PACK_BYTES = 50 * 1024 * 1024  # total attachments budget


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
    candidates = (
        sorted(attachments_dir.iterdir()) if attachments_dir.is_dir() else []
    )

    # -- attachment guards: symlinks, escape, size ---------------------------
    state_resolved = state.resolve()
    guarded: list[tuple[str, Path, bytes]] = []
    total_bytes = 0
    try:
        report_data = report_path.read_bytes()
    except OSError as exc:
        print(f"[ERROR disk] could not read {report_path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for member in candidates:
        if member.is_symlink():
            print(f"[ERROR disk] refusing symlink attachment: {member}", file=sys.stderr)
            return EXIT_ERROR
        if not member.is_file():
            continue
        try:
            if not member.resolve().is_relative_to(state_resolved):
                print(f"[ERROR disk] attachment escapes state dir: {member}", file=sys.stderr)
                return EXIT_ERROR
        except OSError as exc:
            print(f"[ERROR disk] could not resolve {member}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        try:
            size = member.stat().st_size
        except OSError as exc:
            print(f"[ERROR disk] could not stat {member}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if size > MAX_ATTACHMENT_BYTES:
            print(
                f"[ERROR disk] attachment too large ({size} bytes > "
                f"{MAX_ATTACHMENT_BYTES}): {member}",
                file=sys.stderr,
            )
            return EXIT_ERROR
        total_bytes += size
        if total_bytes > MAX_PACK_BYTES:
            print(
                f"[ERROR disk] attachments exceed the {MAX_PACK_BYTES}-byte pack budget",
                file=sys.stderr,
            )
            return EXIT_ERROR
        try:
            guarded.append((f"{args.run_id}/{member.name}", member, member.read_bytes()))
        except OSError as exc:
            print(f"[ERROR disk] could not read {member}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    output = Path(args.output) if args.output else state / "report_packs" / f"{args.run_id}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest_lines: list[str] = []
    try:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr((args.run_id + ".md"), report_data)
            manifest_lines.append(f"sha256  {(args.run_id + '.md')}  {_sha256(report_data)}")
            for arcname, _source, data in guarded:
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
