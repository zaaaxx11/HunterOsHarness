"""keys.env — API keys stored OUTSIDE config.yaml, loaded at CLI startup.

Pasted keys never belong in ``config.yaml`` (it is a file users copy, share,
and commit); they land in ``~/.hunter/keys.env`` instead — a ``KEY="value"``
file that is parsed (never sourced/executed), written atomically, and loaded
into the environment by the ``hunter`` CLI at startup with setdefault
semantics (a real environment variable always wins).

The parser is deliberately shell-adjacent but shell-INDEPENDENT: malformed
lines are skipped, values are unescaped by this module alone, and nothing is
ever passed to a shell. POSIX perms are 0600; on Windows ``os.chmod`` is a
no-op and the file inherits the user-profile ACL — the env-var route remains
the recommended path on shared machines (documented in the file header).
"""

from __future__ import annotations

import contextlib
import os
import re
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from hunter.errors import HunterError

__all__ = [
    "KEYS_ENV_FILENAME",
    "KEYS_ENV_ENVVAR",
    "KEY_NAME_RE",
    "keys_env_path",
    "parse_keys_env",
    "load_keys_env",
    "write_keys_env",
    "atomic_write_text",
]

KEYS_ENV_FILENAME = "keys.env"
KEYS_ENV_ENVVAR = "HUNTEROS_KEYS_FILE"

# Public alias (M11): `config key set` validates variable names against it.
KEY_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KEY_RE = KEY_NAME_RE  # internal name kept for the parser below
# Characters the writer escapes inside double quotes (and the parser unescapes).
_ESCAPABLE = ("\\", '"', "$", "`")

_HEADER = """\
# HunterOs API keys — written by `hunter init`.
# Loaded into the environment by the `hunter` CLI at startup (real env
# vars win). POSIX perms 0600; on Windows the file inherits your user-profile
# ACL. NEVER commit, copy, or paste this file anywhere.
"""


# ------------------------------------------------------------------ helpers --


def _keys_error(code: str, message: str, hint: str) -> HunterError:
    return HunterError(code=code, layer="config", message=message, hint=hint)


def _is_within(path: Path, directory: Path) -> bool:
    """Same containment rule as writing.resolve_config_target."""
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _escape(value: str) -> str:
    """One value -> the inside of a double-quoted keys.env line."""
    return "".join(f"\\{ch}" if ch in _ESCAPABLE else ch for ch in value)


def _unescape(value: str) -> str:
    """Inverse of :func:`_escape` (only the four writer sequences collapse)."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in _ESCAPABLE:
            out.append(value[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# ------------------------------------------------------------------- parser --


def parse_keys_env(text: str) -> dict[str, str]:
    """Parse keys.env text into a mapping. Never raises.

    Line rules: strip; skip empty and ``#``-prefixed lines; optional leading
    ``export ``; split on the first ``=``; the key must match
    ``[A-Za-z_][A-Za-z0-9_]*``; the value is stripped of ONE layer of matching
    single or double quotes (double-quoted values are unescaped); malformed
    lines are silently skipped; duplicate keys — last wins.
    """
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        key, sep, value = line.partition("=")
        if not sep or not _KEY_RE.match(key.strip()):
            continue
        value = value.strip()
        quote = value[0] if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0] else ""
        if quote:
            # The trailing quote is a real closer only when even backslashes
            # precede it ("...\\"" ends with an escaped quote, not a closer).
            backslashes = 0
            cursor = len(value) - 2
            while cursor >= 0 and value[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2 == 0:
                inner = value[1:-1]
                value = _unescape(inner) if quote == '"' else inner
        parsed[key.strip()] = value
    return parsed


# --------------------------------------------------------------------- path --


def keys_env_path(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Where keys.env lives: ``$HUNTEROS_KEYS_FILE`` if set, else
    ``<home>/.hunter/keys.env`` (the unified M11 home).

    Pure resolution — ``migrate=False`` on purpose: path inspection (and the
    startup keys load) must never run the legacy migration as a side effect,
    or the CLI root callback could migrate before it diffs the notice.
    """
    env = os.environ if env is None else env
    from hunter.runtime_paths import RuntimePaths

    return RuntimePaths.resolve(keys=None, env=env, home=home, migrate=False).keys


# -------------------------------------------------------------------- write --


def atomic_write_text(target: Path, text: str) -> None:
    """Atomically replace a UTF-8 text file using a sibling temporary file."""
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=str(target.parent), suffix=".tmp", delete=False
    ) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    replaced = False
    error: OSError | None = None
    for attempt in range(5):
        try:
            os.replace(handle.name, target)
            replaced = True
            break
        except PermissionError as exc:
            error = exc
            time.sleep(0.01 * (attempt + 1))
        except OSError as exc:
            error = exc
            break
    if not replaced:
        with contextlib.suppress(OSError):
            os.unlink(handle.name)
        raise _keys_error(
            "keys.write_failed",
            f"could not write {target}: {error}",
            "check the permissions of the target directory",
        ) from None


def _atomic_write(target: Path, text: str) -> None:
    """Compatibility alias for the public atomic writer."""
    atomic_write_text(target, text)


def write_keys_env(
    entries: Mapping[str, str], *, env: Mapping[str, str] | None = None, home: Path | None = None
) -> Path:
    """Atomically write ``entries`` as a keys.env file. An empty mapping is a
    no-op that returns the path without creating anything. A
    ``$HUNTEROS_KEYS_FILE`` pointing outside the home directory is refused
    (same containment rule as the config target — a stray env var must not aim
    secret writes at arbitrary locations; no force override)."""
    env = os.environ if env is None else env
    from hunter.runtime_paths import RuntimePaths

    paths = RuntimePaths.resolve(env=env, home=home, migrate=False)
    target = paths.keys
    if not entries:
        return target
    from_env = (env.get(KEYS_ENV_ENVVAR) or "").strip()
    if from_env and not _is_within(target, paths.home.parent):
        raise _keys_error(
            "keys.refused",
            f"${KEYS_ENV_ENVVAR} points outside the home directory: {target}",
            f"set {KEYS_ENV_ENVVAR} to a path under your home directory, or unset it",
        )
    lines = [*_HEADER.splitlines()]
    for key, value in entries.items():
        lines.append(f'{key}="{_escape(value)}"')
    _atomic_write(target, "\n".join(lines) + "\n")
    with contextlib.suppress(OSError):  # chmod is a no-op on Windows (profile ACL)
        os.chmod(target, 0o600)
    return target


# --------------------------------------------------------------------- load --


def load_keys_env(
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    target: dict[str, str] | None = None,
) -> dict[str, str]:
    """Read keys.env and inject it with setdefault semantics — a real env var
    always wins. Missing file or any OSError -> {} (best-effort, never
    raises, never logs values). Returns the values actually injected."""
    env_map = os.environ if env is None else env
    path = keys_env_path(env=env_map, home=home)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    sink = os.environ if target is None else target
    injected: dict[str, str] = {}
    for key, value in parse_keys_env(text).items():
        if key not in sink:
            sink[key] = value
            injected[key] = value
    return injected
