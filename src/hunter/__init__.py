"""HunterOs Harness — evidence-first security-audit harness."""

# The version is maintained in pyproject.toml (the single source of truth for
# packaging metadata). It is duplicated here because a source checkout that is
# not pip-installed has no distribution metadata to read, and `hunter --version`
# must work in exactly that situation. Keep the two in sync — the release
# tests (tests/test_release_m7.py) assert it.
__version__ = "0.11.0"

from hunter.session import DISCARD_ON_CLOSE, KEEP_ON_CLOSE  # noqa: E402
