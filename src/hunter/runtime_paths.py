"""Canonical, cross-platform paths for HunterOS runtime state.

All user-facing defaults derive from one HOME/USERPROFILE resolution. Explicit
arguments and environment variables remain higher priority than those defaults.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

__all__ = ["RuntimePaths", "resolve_runtime_paths"]

_HOME_DIRNAME = ".hunter"
_LEGACY_DIRNAME = ".hunteros"
_CONFIG_ENVVAR = "HUNTEROS_CONFIG"
_KEYS_ENVVAR = "HUNTEROS_KEYS_FILE"
_STATE_ENVVAR = "HUNTER_STATE_DIR"
_CHAT_ENVVAR = "HUNTEROS_CHAT_DB"


def _base_home(env: Mapping[str, str], home: str | Path | None) -> Path:
    """Resolve the one profile base used by new and legacy homes."""
    if home is not None:
        return Path(home).expanduser()
    if sys.platform == "win32":
        raw = (env.get("USERPROFILE") or env.get("HOME") or "").strip()
    else:
        raw = (env.get("HOME") or env.get("USERPROFILE") or "").strip()
    return Path(raw).expanduser() if raw else Path.home()


def _expand(raw: str | Path, base: Path) -> Path:
    """Expand ``~`` against the resolved profile base, including on Windows."""
    value = str(raw).strip()
    if value == "~":
        return base
    if value.startswith("~/") or value.startswith("~\\"):
        return base / value[2:].replace("\\", os.sep)
    return Path(value).expanduser()


@dataclass(frozen=True)
class RuntimePaths:
    """Resolved config, state, and persistence paths for one process."""

    home: Path
    legacy_home: Path
    config: Path
    keys: Path
    chat_db: Path
    state: Path
    ledger: Path
    reports: Path
    daemon: Path
    approvals: Path
    sessions: Path

    @classmethod
    def resolve(
        cls,
        *,
        config: str | Path | None = None,
        keys: str | Path | None = None,
        chat_db: str | Path | None = None,
        state: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        home: str | Path | None = None,
        migrate: bool = True,
    ) -> RuntimePaths:
        """Resolve paths while preserving explicit and environment overrides.

        ``migrate`` invokes the existing copy-only ``~/.hunteros`` migration;
        callers doing pure path inspection can disable it.
        """
        env_map = os.environ if env is None else env
        base = _base_home(env_map, home)
        user_home = base / _HOME_DIRNAME
        legacy = base / _LEGACY_DIRNAME
        if migrate:
            from hunter.home import ensure_home

            ensure_home(env=env_map, home=base)

        config_raw = config if config is not None else env_map.get(_CONFIG_ENVVAR)
        keys_raw = keys if keys is not None else env_map.get(_KEYS_ENVVAR)
        chat_raw = chat_db if chat_db is not None else env_map.get(_CHAT_ENVVAR)
        state_raw = state if state is not None else env_map.get(_STATE_ENVVAR)
        config_path = _expand(config_raw, base) if config_raw else user_home / "config.yaml"
        keys_path = _expand(keys_raw, base) if keys_raw else user_home / "keys.env"
        chat_path = _expand(chat_raw, base) if chat_raw else user_home / "chat.db"
        state_path = _expand(state_raw, base) if state_raw else user_home
        return cls(
            home=user_home,
            legacy_home=legacy,
            config=config_path,
            keys=keys_path,
            chat_db=chat_path,
            state=state_path,
            ledger=state_path / "ledger.db",
            reports=state_path / "reports",
            daemon=state_path / "daemon",
            approvals=state_path / "approvals",
            sessions=user_home / "sessions",
        )

    @classmethod
    def from_environment(cls, **kwargs: object) -> RuntimePaths:
        """Compatibility spelling for resolving paths from process settings."""
        return cls.resolve(**kwargs)  # type: ignore[arg-type]


def resolve_runtime_paths(**kwargs: object) -> RuntimePaths:
    """Return :class:`RuntimePaths` for explicit arguments or environment."""
    return RuntimePaths.resolve(**kwargs)  # type: ignore[arg-type]
