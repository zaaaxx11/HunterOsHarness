#!/usr/bin/env python3
"""audit_toolkit — runtime inventory of the audit binaries on this machine.

Reports which methodology tools (nmap, sqlmap, nuclei, ffuf, ...) are
available and which are missing, so an audit can be scoped to what the box
can actually run. JSON for scripts, markdown for humans. Offline: it only
probes PATH via shutil.which — nothing is executed, nothing is downloaded.

Exit codes: 0 ok, 1 error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

EXIT_OK = 0
EXIT_ERROR = 1


def _inventory() -> dict:
    try:
        from hunter.agent.inventory import inventory_binaries
    except ImportError as exc:
        print(
            "[ERROR config] hunter.agent.inventory is unavailable — "
            f"install the harness first ({exc})",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_ERROR) from exc
    return inventory_binaries()


def _markdown(payload: dict) -> str:
    lines = ["# Audit toolkit inventory", "", "| binary | status | path |", "| --- | --- | --- |"]
    available = payload.get("available") or {}
    for name in sorted({*available, *(payload.get("missing") or [])}):
        path = available.get(name)
        if path:
            lines.append(f"| {name} | available | {path} |")
        else:
            lines.append(f"| {name} | missing | (not on PATH) |")
    lines.append("")
    lines.append(f"platform: {payload.get('platform', '?')} — "
                 f"{len(available)} available, {len(payload.get('missing') or [])} missing")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="audit_toolkit", description=__doc__)
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="output format (default json)",
    )
    parser.add_argument("--json", action="store_true", help="force JSON on stdout (script-safe)")
    args = parser.parse_args(argv)

    payload = _inventory()
    if args.json or args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_markdown(payload))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
