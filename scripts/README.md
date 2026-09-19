# scripts/ — HunterOs helper scripts

Standalone Python helpers for audit, recon, daemon control, and session
hygiene. `scripts/` is exempt operator tooling, not the production surface:
nothing here ships as product code, and the test suite lives only in `tests/`
(`pyproject.toml` `testpaths = ["tests"]`) — no `test_*.py` belongs in this
directory. All scripts are **offline-safe by construction and scope-gated**:
the only network surface (`quick_recon.py`) runs through the harness
`ScopeSet` gate and refuses out-of-scope targets with exit code 3 before a
single byte leaves the machine. Scripts import only the Python standard
library, `httpx`, and `hunter`, never launch other scripts as subprocesses,
and are Windows-safe (pathlib everywhere, no POSIX-only calls).

Run them with the harness interpreter from the repo root (the scripts put
`src/` on `sys.path` themselves):

```bash
python scripts/audit_toolkit.py --json
python scripts/quick_recon.py http://127.0.0.1:8941/ --scope examples/scope.manifest.json --json
```

| Script | Purpose | Common usage |
| ------ | ------- | ------------ |
| `huntctl.py` | daemon lifecycle: start/stop/status/logs | `huntctl.py start --target http://127.0.0.1:8941/ --time 2h --yes` |
| `stop_hunt.py` | cooperative stop: writes `stop.flag`, marks open runs `stopped` | `stop_hunt.py --state .hunter --run-id R-abc123` |
| `audit_toolkit.py` | runtime inventory of audit binaries on PATH | `audit_toolkit.py --json` / `--format markdown` |
| `compress_session.py` | extractive compaction report for a chat session | `compress_session.py --session <sid> --state .hunter [--apply]` |
| `quick_recon.py` | scope-gated recon of `/`, `/robots.txt`, `/sitemap.xml` | `quick_recon.py <target> --scope scope.json --json` |
| `report_pack.py` | zip a run's report + attachments + sha256 `MANIFEST.txt` | `report_pack.py --run-id R-abc123 --state .hunter -o pack.zip` |

Notes:

- Exit codes mirror the CLI: `0` ok, `1` error, `3` refused (scope).
- `stop_hunt.py` marks runs in the **runs table only** — ledger events are
  never touched.
- `compress_session.py` is extractive-only: bullets are prefixes of real
  messages, evidence ids are never dropped or invented, and `--apply`
  appends one normal assistant row (the store stays append-only).
- `huntctl.py` wraps the same daemon core as `hunter daemon start/stop/
  status/logs`; state lives under `--state` (default `./.hunter`).
