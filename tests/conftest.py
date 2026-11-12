"""Test-suite configuration.

The daemon-era tests under ``tests/archive_daemon_era/`` target an API that
was deliberately removed (see 990238b "purge: remove daemon"). They are kept
for reference but must not break collection of the live suite.
"""

collect_ignore = ["archive_daemon_era"]
