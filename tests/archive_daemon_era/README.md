# Archived: daemon-era tests

These target the API deleted by 990238b "purge: remove daemon" (deliberate —
no daemon by design; `_daemon_shim.py` holds the noop stubs the CLI needs):

- `test_daemon.py`        — imports `hunter.daemon` (module deleted)
- `test_daemon_health.py` — imports `hunter.daemon_health` (purged; the
                           memory-probe half was inlined into
                           `hunter/workflow/scheduler.py`)
- `test_cli_daemon.py`    — same
- `test_session.py`       — the daemon-era session lifecycle API
                           (`create_session`/`close_session`/`SessionExists`);
                           today's `hunter.session` is `HuntSession`, a
                           different design with no per-session daemon

They are kept for reference, excluded from collection via `tests/conftest.py`.
