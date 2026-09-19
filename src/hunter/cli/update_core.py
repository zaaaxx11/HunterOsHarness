"""``hunter update`` + the polite background version check (M4).

Two halves, both silent-on-failure:

**The check** (:func:`check_for_newer_version`) asks GitHub for the latest
release and silently falls back to the PyPI JSON API (unauthenticated
``api.github.com`` is capped at 60 req/h per IP — a 403 there is a
designed-for outcome, not an edge). Any failure is a silent no-op
(``error="unreachable"``): never raises, never logs, never prints. A
successful fetch is cached for 24h in ``~/.hunteros/update-check.json``
(atomic write, keys.py pattern); the cache is disposable and a failed write
never surfaces. ``force=True`` (used only by ``hunter update``) bypasses the
freshness window — the CI/opt-out env gates do NOT live here, they gate the
*background spawn* only, so an explicit ``hunter update`` works everywhere.

**The notify machinery** (:func:`start_background_check` /
:func:`pop_pending_notice` / :func:`emit_notice`) mirrors the
Strix/reference pattern: one fire-and-forget daemon thread per process, the
notice printed AFTER the command output via a click context-close hook —
always on stderr so ``--json`` stdout stays machine-clean, never inside the
long-lived ``chat``/``tui``/``gateway`` surfaces, and never blocking exit
(the pop only fires when the check already finished; it never waits).

**The installer table** (:func:`classify_install` /
:func:`build_install_plan` / :func:`execute_plan`) detects how the harness
was installed and re-runs the matching upgrade — the M1 installer script
with ``--skip-setup``/``-SkipSetup``, ``pipx upgrade``, or ``pip install
--upgrade``. Every seam (``runner_fn``/``script_fetcher``/``ask``/
``is_windows``) is injectable so no test ever executes an installer.

``client_factory`` is the test seam for HTTP (``httpx.MockTransport``),
mirroring :mod:`hunter.llm.probe`.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import yaml

if TYPE_CHECKING:  # typing only — no runtime import cycle with cli.main
    from rich.console import Console

__all__ = [
    "CheckResult",
    "InstallPlan",
    "QUIET_COMMANDS",
    "OPT_OUT_ENV",
    "check_for_newer_version",
    "start_background_check",
    "pop_pending_notice",
    "emit_notice",
    "reset",
    "detect_install_method",
    "classify_install",
    "build_install_plan",
    "execute_plan",
    "run_update",
    "migration_notes",
    "example_schema",
    "parse_version",
]

GITHUB_RELEASES_URL = "https://api.github.com/repos/zaaaxx11/HunterOsHarness/releases/latest"
PYPI_JSON_URL = "https://pypi.org/pypi/hunteros-harness/json"
RAW_INSTALL_SH = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh"
RAW_INSTALL_PS1 = "https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1"

CHECK_TIMEOUT = 1.5  # seconds, per HTTP request
FETCH_SCRIPT_TIMEOUT = 15.0  # seconds, for the raw installer download
CACHE_TTL = 86400.0  # 24h
CACHE_FILENAME = "update-check.json"
OPT_OUT_ENV = "HUNTEROS_NO_UPDATE_CHECK"
_CI_ENV_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI")
QUIET_COMMANDS = frozenset({"chat", "tui", "gateway"})  # long-lived surfaces

_DIRNAME = ".hunteros"

# Manual one-liners (§5.1 normative copy) — the never-stranded fallback printed
# on every failure/decline path, keyed by platform.
_MANUAL_POSIX = f"curl -fsSL {RAW_INSTALL_SH} | bash"
_MANUAL_WINDOWS = f"irm {RAW_INSTALL_PS1} | iex"

_GITHUB_ACCEPT = "application/vnd.github+json"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one version check. ``latest == ""`` means the check failed
    (``error`` says why in one word); the comparison is always recomputed
    against the RUNNING version, never trusted from the cache file."""

    latest: str = ""  # normalized ("0.4.0"); "" when the check failed
    current: str = ""
    source: str = ""  # "github" | "pypi" | "cache"
    update_available: bool = False
    error: str = ""  # short reason when latest == ""


@dataclass(frozen=True)
class InstallPlan:
    """One upgrade command. ``argv`` carries a ``{script}`` placeholder for
    the installer method; ``fetch_url`` is non-empty only for "installer"."""

    method: str  # "installer" | "pipx" | "pip"
    argv: tuple[str, ...]
    fetch_url: str = ""


# ---------------------------------------------------------------- pure helpers --


def parse_version(tag: str) -> tuple[int, ...] | None:
    """``"v0.4.0"`` -> ``(0, 4, 0)``. Dot-separated integers only: whitespace
    and ONE leading ``v``/``V`` are stripped; every component must be
    non-empty and all-digits (pre-release suffixes are malformed -> None)."""
    text = tag.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    if not text:
        return None
    parts = text.split(".")
    if not all(part and all(ch in "0123456789" for ch in part) for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _normalize_version(tag: str) -> str:
    """Parsed tag -> the canonical dotted string ("v0.4.0" -> "0.4.0")."""
    parsed = parse_version(tag)
    if parsed is None:
        return ""
    return ".".join(str(part) for part in parsed)


def _newer(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Strict ``a > b`` with zero-padding — ``(0, 4)`` == ``(0, 4, 0)``."""
    if a is None or b is None:
        return False
    width = max(len(a), len(b))
    a_padded = a + (0,) * (width - len(a))
    b_padded = b + (0,) * (width - len(b))
    return a_padded > b_padded


def _truthy(value: str) -> bool:
    return (value or "").strip().lower() not in ("", "0", "false", "no")


def _auto_check_allowed(environ: Mapping[str, str] | None = None) -> bool:
    """The spawn gate (§4.1): False on any truthy CI var, on a truthy
    ``HUNTEROS_NO_UPDATE_CHECK`` (=0/false/empty re-enable checks), and on
    ``PYTEST_CURRENT_TEST`` being present AT ALL — the check can never fire
    under pytest, even if a future test forgets the conftest belt."""
    env = os.environ if environ is None else environ
    if "PYTEST_CURRENT_TEST" in env:
        return False
    if _truthy(env.get(OPT_OUT_ENV) or ""):
        return False
    return not any(_truthy(env.get(var) or "") for var in _CI_ENV_VARS)


def _current_version() -> str:
    """Installed version, with the same fallback as cli.main._version —
    duplicated 3 lines to avoid a main<->update_core import cycle."""
    try:
        return metadata.version("hunteros-harness")
    except metadata.PackageNotFoundError:
        from hunter import __version__

        return __version__


# ----------------------------------------------------------------- the check --


def check_for_newer_version(
    force: bool = False,
    *,
    environ: Mapping[str, str] | None = None,
    home: str | Path | None = None,
    now_fn: Callable[[], float] | None = None,
    client_factory: Callable[[], Any] | None = None,
    current_version: str | None = None,
) -> CheckResult:
    """Ask GitHub (then PyPI) for the newest release; 24h cache in between.

    Any error is a silent no-op: the function never raises, never logs,
    never prints — offline/403/malformed yields ``error="unreachable"`` and
    NO cache write (the next invocation retries). A downgrade (local build
    newer than the release) is "up to date" but still cached. ``force=True``
    re-fetches even with a fresh cache; the CI/opt-out gates do NOT live
    here (they gate the background spawn), so an explicit `hunter update`
    works everywhere. ``environ`` is accepted for seam symmetry only.
    """
    current = current_version or _current_version()
    now = (now_fn or time.time)()
    from hunter.runtime_paths import RuntimePaths

    base = RuntimePaths.resolve(home=home, migrate=False).home.parent

    if not force:
        cached_latest = _read_fresh_cache(base, now)
        if cached_latest:
            return CheckResult(
                latest=cached_latest,
                current=current,
                source="cache",
                update_available=_newer(parse_version(cached_latest), parse_version(current)),
            )

    latest, source = _fetch_latest(client_factory)
    if not latest:
        return CheckResult(current=current, error="unreachable")
    _write_cache(base, now, latest, current, source)
    return CheckResult(
        latest=latest,
        current=current,
        source=source,
        update_available=_newer(parse_version(latest), parse_version(current)),
    )


def _cache_path(base: Path) -> Path:
    return base / _DIRNAME / CACHE_FILENAME


def _read_fresh_cache(base: Path, now: float) -> str:
    """Cached ``latest`` when the cache is fresh and well-typed; "" otherwise.
    Corrupt/missing/stale cache is ignored (the network path proceeds)."""
    try:
        data = json.loads(_cache_path(base).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — garbage bytes, missing file, bad perms
        return ""
    if not isinstance(data, dict):
        return ""
    checked_at = data.get("checked_at")
    latest = data.get("latest")
    if isinstance(checked_at, bool) or not isinstance(checked_at, (int, float)):
        return ""
    if not isinstance(latest, str) or not latest:
        return ""
    age = now - checked_at
    if age < 0 or age >= CACHE_TTL:
        return ""
    return latest


def _write_cache(base: Path, checked_at: float, latest: str, current: str, source: str) -> None:
    """Best-effort atomic cache write — swallows EVERY exception (a failed
    cache write must never surface; the cache is disposable)."""
    payload = json.dumps(
        {"checked_at": checked_at, "latest": latest, "current": current, "source": source}
    )
    with contextlib.suppress(Exception):  # keys.py pattern, JSON variant, never raises
        _atomic_write_text(_cache_path(base), payload)


def _atomic_write_text(target: Path, text: str) -> None:
    """Temp file in the target directory, flush, fsync, ``os.replace`` with a
    bounded PermissionError retry — the keys.py commit path, verbatim."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(target.parent), suffix=".tmp", delete=False
    ) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    for attempt in range(5):
        try:
            os.replace(handle.name, target)
            return
        except PermissionError:
            time.sleep(0.01 * (attempt + 1))
        except OSError:
            break  # missing directory, cross-device, ... — not retryable
    with contextlib.suppress(OSError):
        os.unlink(handle.name)


def _fetch_latest(client_factory: Callable[[], Any] | None) -> tuple[str, str]:
    """GitHub ``tag_name`` first, silent PyPI ``info.version`` fallback.
    Returns ("", "") when both are unreachable/malformed. Never raises."""
    factory = client_factory if client_factory is not None else (
        lambda: httpx.Client(timeout=CHECK_TIMEOUT)
    )
    tag = _get_github_tag(factory)
    if tag:
        return tag, "github"
    version = _get_pypi_version(factory)
    if version:
        return version, "pypi"
    return "", ""


def _get_github_tag(factory: Callable[[], Any]) -> str:
    """Normalized latest release tag, or "" on any non-200 (esp. the 403
    rate limit), transport error, or malformed payload."""
    try:
        client = factory()
    except Exception:  # noqa: BLE001 — an unusable client is an unreachable API
        return ""
    try:
        response = client.get(GITHUB_RELEASES_URL, headers={"Accept": _GITHUB_ACCEPT})
        if response.status_code != 200:
            return ""
        payload = response.json()
    except Exception:  # noqa: BLE001 — transport/JSON errors fall through to PyPI
        return ""
    finally:
        client.close()
    if not isinstance(payload, dict) or not isinstance(payload.get("tag_name"), str):
        return ""
    return _normalize_version(payload["tag_name"])


def _get_pypi_version(factory: Callable[[], Any]) -> str:
    """Normalized version from the PyPI JSON API, or "" on any failure."""
    try:
        client = factory()
    except Exception:  # noqa: BLE001 — an unusable client is an unreachable API
        return ""
    try:
        response = client.get(PYPI_JSON_URL)
        if response.status_code != 200:
            return ""
        payload = response.json()
    except Exception:  # noqa: BLE001 — garbage JSON / transport errors -> ""
        return ""
    finally:
        client.close()
    info = payload.get("info") if isinstance(payload, dict) else None
    version = info.get("version") if isinstance(info, dict) else None
    if not isinstance(version, str):
        return ""
    return _normalize_version(version)


# ---------------------------------------------------------- background notify --


_state_lock = threading.Lock()
_pending: CheckResult | None = None
_check_done = threading.Event()
_suppressed = False


def reset() -> None:
    """Clear all notify state — used between tests so stale notices never
    leak (§11 #18); also run at the top of every spawn for a fresh process
    view."""
    global _pending, _suppressed
    with _state_lock:
        _pending = None
        _suppressed = False
    _check_done.clear()


def start_background_check(
    *,
    environ: Mapping[str, str] | None = None,
    check_fn: Callable[[], CheckResult] | None = None,
    suppress_notice: bool = False,
    wait: bool = False,
) -> bool:
    """Spawn ONE fire-and-forget daemon check thread; True iff spawned.

    Gated by :func:`_auto_check_allowed` (CI vars, opt-out env, hard pytest
    refusal). The thread stores the result under the module lock and sets
    the completion event; any exception it raises is swallowed into a failed
    CheckResult. Nothing in production ever joins it (``wait=True`` exists
    for tests only)."""
    global _suppressed
    reset()  # fresh per invocation — no stale result can survive a re-spawn
    env = os.environ if environ is None else environ
    if not _auto_check_allowed(env):
        return False
    with _state_lock:
        _suppressed = bool(suppress_notice)
    worker = threading.Thread(
        target=_run_check, args=(check_fn or check_for_newer_version,),
        name="hunter-update-check", daemon=True,
    )
    worker.start()
    if wait:  # tests only — production never joins
        worker.join(timeout=5)
    return True


def _run_check(check_fn: Callable[[], CheckResult]) -> None:
    """Thread body: run the check, store the result, set the event. Any
    exception is swallowed into a failed CheckResult — the daemon must never
    crash the process."""
    global _pending
    try:
        result = check_fn()
        if not isinstance(result, CheckResult):
            result = CheckResult(error="bad result")
    except Exception:  # noqa: BLE001 — background failures are silent
        result = CheckResult(error="failed")
    with _state_lock:
        _pending = result
    _check_done.set()


def pop_pending_notice() -> str | None:
    """The notice line, at most once per process. None when the check has
    not completed, found no update, or was spawned with suppress_notice."""
    global _pending
    if not _check_done.is_set():
        return None  # opportunistic: never waits, never blocks exit
    with _state_lock:
        result = _pending
        _pending = None
        suppressed = _suppressed
    if result is None or suppressed:
        return None
    if not result.latest or not result.update_available:
        return None
    return f"A new version of hunter is available: {result.current} → {result.latest}. Run: hunter update"


def emit_notice() -> None:
    """Context-close hook: print the pending notice on stderr, AFTER the
    command output, at most once. Must never break process exit."""
    try:
        line = pop_pending_notice()
        if line:
            from hunter.cli.main import err_console  # lazy — no module cycle

            err_console.print(f"[yellow]{line}[/yellow]")
    except Exception:  # noqa: BLE001 — the notice is advisory, exit comes first
        pass


def _stdin_isatty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except Exception:  # noqa: BLE001 — a dead stdin is a non-tty
        return False


# ---------------------------------------------------------- install machinery --


def _is_within(path: Path, directory: Path) -> bool:
    """Same containment rule as keys._is_within (resolve, then relative_to)."""
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def classify_install(*, sys_prefix: Path, home: Path, direct_url: dict | None, is_windows: bool) -> str:
    """The ordered detection table (§5.2) — pure, all inputs explicit.

    1. ``installer``: sys.prefix inside ``<home>/.hunteros/venv`` (prefix
       containment covers ``bin/`` and ``Scripts\\``) — checked FIRST because
       the installer's git-fallback path also produces direct_url.json.
    2. ``dev``: direct_url.json present (editable / file:// / VCS install).
    3. ``pipx``: "pipx" in the prefix parts.
    4. ``pip``: fallback.
    """
    prefix = Path(sys_prefix)
    if _is_within(prefix, Path(home) / _DIRNAME / "venv"):
        return "installer"
    if direct_url:
        return "dev"
    if "pipx" in prefix.parts:
        return "pipx"
    return "pip"


def _read_direct_url() -> dict | None:
    """direct_url.json of the installed dist, or None on any hiccup."""
    try:
        dist = metadata.distribution("hunteros-harness")
        raw = dist.read_text("direct_url.json") if dist is not None else None
    except Exception:  # noqa: BLE001 — metadata problems degrade to pip
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001 — malformed direct_url degrades to pip
        return None
    return data if isinstance(data, dict) else None


def detect_install_method() -> str:
    """``"dev" | "installer" | "pipx" | "pip"`` for THIS process. Never
    raises — any metadata hiccup degrades to "pip"."""
    from hunter.runtime_paths import RuntimePaths

    try:
        return classify_install(
            sys_prefix=Path(sys.prefix),
            home=RuntimePaths.resolve(migrate=False).home.parent,
            direct_url=_read_direct_url(),
            is_windows=os.name == "nt",
        )
    except Exception:  # noqa: BLE001 — detection must never break the command
        return "pip"


def build_install_plan(
    method: str, *, is_windows: bool | None = None, home: Path | None = None
) -> InstallPlan:
    """The argv/fetch_url table (§5.3); unknown methods degrade to pip."""
    windows = (os.name == "nt") if is_windows is None else bool(is_windows)
    if method == "installer":
        if windows:
            # Prefer PowerShell 7 (pwsh) when present, else Windows PowerShell
            # 5.1 — the installer is 5.1-compatible, but pwsh is often the only
            # shell on modern/slim images.
            shell = shutil.which("pwsh") or "powershell"
            return InstallPlan(
                method="installer",
                argv=(
                    shell, "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", "{script}", "-SkipSetup",
                ),
                fetch_url=RAW_INSTALL_PS1,
            )
        return InstallPlan(
            method="installer",
            argv=("bash", "{script}", "--skip-setup"),
            fetch_url=RAW_INSTALL_SH,
        )
    if method == "pipx":
        return InstallPlan(method="pipx", argv=("pipx", "upgrade", "hunteros-harness"))
    return InstallPlan(
        method="pip",
        argv=(sys.executable, "-m", "pip", "install", "--upgrade", "hunteros-harness"),
    )


def default_fetch_script(url: str) -> str:
    """Download the raw installer script (15s timeout, raise_for_status)."""
    response = httpx.get(url, timeout=FETCH_SCRIPT_TIMEOUT)
    response.raise_for_status()
    return response.text


def default_runner(argv: Sequence[str]) -> int:
    """Run the upgrade command with output inherited by the console.
    OSError (e.g. ``bash`` missing on a bare Windows box) -> 127."""
    try:
        return subprocess.run(list(argv), check=False).returncode
    except OSError:
        return 127


def execute_plan(
    plan: InstallPlan,
    *,
    script_fetcher: Callable[[str], str] | None = None,
    runner_fn: Callable[[Sequence[str]], int] | None = None,
    is_windows: bool | None = None,
) -> int:
    """Execute an InstallPlan. NEVER raises — any internal failure (fetch,
    temp write, OSError from the runner) maps to exit 127."""
    runner = runner_fn if runner_fn is not None else default_runner
    try:
        if plan.method == "installer" and plan.fetch_url:
            fetch = script_fetcher if script_fetcher is not None else default_fetch_script
            text = fetch(plan.fetch_url)
            windows = (os.name == "nt") if is_windows is None else bool(is_windows)
            script_path = ""
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", suffix=".ps1" if windows else ".sh", delete=False
                ) as handle:
                    handle.write(text)
                    script_path = handle.name
                argv = [script_path if part == "{script}" else part for part in plan.argv]
                return int(runner(argv))
            finally:
                if script_path:
                    with contextlib.suppress(OSError):  # best-effort cleanup
                        os.unlink(script_path)
        return int(runner(list(plan.argv)))
    except Exception:  # noqa: BLE001 — internal failures map to 127, never raise
        return 127


# ------------------------------------------------------------ migration stub --


def example_schema() -> dict:
    """The example config as a dict — the current-schema reference for the
    migration diff. {} on ANY failure. Never raises."""
    try:
        from hunter.llm.config import config_example_yaml

        loaded = yaml.safe_load(config_example_yaml())
    except Exception:  # noqa: BLE001 — the schema is advisory, never load-bearing
        return {}
    return loaded if isinstance(loaded, dict) else {}


def migration_notes(raw: dict | None, schema: dict | None = None) -> list[str]:
    """Read-only schema diff stub (v0.5+ replaces it with real migrations).

    Walks one level deep: unknown top-level keys, unknown subkeys inside
    dict sections, and (absent) optional schema sections become notes. Works
    on the RAW YAML precisely because the loader would reject unknown keys —
    this warns BEFORE the next command's load_config fails against a newer
    schema. Pure; NEVER raises; capped at 5 notes.
    """
    try:
        return _migration_notes_impl(raw, example_schema() if schema is None else schema)
    except Exception:  # noqa: BLE001 — notes are advisory, never load-bearing
        return []


def _migration_notes_impl(raw: dict | None, schema: dict | None) -> list[str]:
    if not isinstance(raw, dict) or not raw:
        return []  # {} / None = no config anywhere -> nothing to migrate
    if not isinstance(schema, dict) or not schema:
        return []
    notes: list[str] = []
    for key, block in raw.items():
        if len(notes) >= 5:
            return notes
        if key not in schema:
            notes.append(
                f"config key '{key}' is not in the current schema — run 'hunter config example'"
            )
            continue
        if isinstance(block, dict) and isinstance(schema[key], dict):
            _diff_block(key, block, schema[key], notes)
    for key, block in schema.items():
        if len(notes) >= 5:
            break
        if key not in raw and isinstance(block, dict):
            notes.append(
                f"optional config section '{key}' is available — see 'hunter config example'"
            )
    return notes


def _diff_block(top_key: str, raw_block: dict, schema_block: dict, notes: list[str]) -> None:
    """Subkeys of the user's block absent from the schema block — matched dict
    subkeys are walked deeper, but every unknown leaf is reported under its
    top-level section ('<top>.<leaf>')."""
    for sub, value in raw_block.items():
        if len(notes) >= 5:
            return
        if sub not in schema_block:
            notes.append(
                f"config key '{top_key}.{sub}' is not in the current schema — "
                "run 'hunter config example'"
            )
        elif isinstance(value, dict) and isinstance(schema_block[sub], dict):
            _diff_block(top_key, value, schema_block[sub], notes)


# -------------------------------------------------------------- run_update --


def _read_raw_config() -> dict:
    """The RAW config mapping (read-only, best-effort) for the migration
    diff — unreadable/missing/outside-home config -> {} (no notes)."""
    try:
        from hunter.llm.writing import resolve_config_target

        text = resolve_config_target().read_text(encoding="utf-8")
        loaded = yaml.safe_load(text)
    except Exception:  # noqa: BLE001 — no config, bad YAML, refused env path
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _default_ask(console: Console, prompt: str, default: str) -> str:
    """The default confirm prompt: console.input with EOFError -> default."""
    try:
        reply = console.input(f"{prompt} [y/N] ", markup=False)
    except EOFError:
        return default
    return reply.strip() or default


def run_update(
    *,
    console: Console,
    err_console: Console,
    yes: bool = False,
    ask: Callable[[str, str], str] | None = None,
    is_windows: bool | None = None,
    runner_fn: Callable[[Sequence[str]], int] | None = None,
    script_fetcher: Callable[[str], str] | None = None,
) -> int:
    """The `hunter update` flow (§5.1). Returns the exit code; every seam
    defaults to a module-level function so tests can monkeypatch or pass
    explicit callables. Never raises for classified paths."""
    windows = (os.name == "nt") if is_windows is None else bool(is_windows)
    one_liner = _MANUAL_WINDOWS if windows else _MANUAL_POSIX
    current = _current_version()

    method = detect_install_method()
    if method == "dev":
        # Nothing executed — a checkout is updated by git, not by pip magic.
        # `&&` is a POSIX/PS7-ism: Windows PowerShell 5.1 rejects it, so the
        # command is split into two lines that work in every supported shell.
        if windows:
            console.print("dev/checkout install detected — update with:")
            console.print("  git pull")
            console.print(f'  & "{sys.executable}" -m pip install -e .')
        else:
            console.print("dev/checkout install detected — update with: git pull && pip install -e .")
        return 0

    result = check_for_newer_version(force=True)
    if not result.latest:
        console.print(
            "could not check for the latest version (offline or rate-limited) — install manually:"
        )
        console.print(one_liner)
        return 1
    # Keep the check result's running-version field authoritative when a caller
    # injects a check seam (the update protocol and its historical tests do
    # this); production checks populate it from the installed package metadata.
    current = result.current or current
    latest = result.latest
    if not result.update_available:
        console.print(f"hunter {current} is up to date (latest release: {latest})")
        return 0

    def declined() -> int:
        console.print("update declined — manual install any time:")
        console.print(one_liner)
        return 0

    if not yes:
        if not _stdin_isatty():
            # Never block on a dead stdin — mirrors init's declined-clobber exit 0.
            return declined()
        prompt = f"update hunter {current} → {latest} now?"
        answer = ask(prompt, "n") if ask is not None else _default_ask(console, prompt, "n")
        if answer.strip().lower() not in ("y", "yes"):
            return declined()

    plan = build_install_plan(method, is_windows=windows)
    code = execute_plan(plan, script_fetcher=script_fetcher, runner_fn=runner_fn, is_windows=windows)
    if code != 0:
        console.print(f"update failed (exit {code}) — install manually:")
        console.print(one_liner)
        return 1

    console.print(f"updated: hunter {current} → {latest}")
    console.print("note: config migrations run on next command")
    for note in migration_notes(_read_raw_config(), example_schema()):
        console.print(f"note: {note}")
    return 0
