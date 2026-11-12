"""Split source into 600-1000 token windows for each lane turn.

A 16 K-char prompt crashes Cloudflare with HTTP 524 (>100 s on the origin).
This module cuts the inlined source into windows that keep the turn small
enough to finish in one shot while still preserving usable context.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Target window size in characters (not tokens — rough 1 token ≈ 4 chars).
DEFAULT_WINDOW_CHARS = int(os.environ.get("HUNTEROS_WINDOW_CHARS", "3000") or 3000)
#: Minimum window size: never send a window so small it carries zero context.
MIN_WINDOW_CHARS = 800
#: Extensions we read.
_CODE_EXTS = {
    ".sol", ".vy", ".cairo", ".move", ".rs",
    ".py", ".pyi", ".js", ".mjs", ".ts", ".tsx",
    ".go", ".java", ".kt", ".cs", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".hh", ".hpp",
    ".swift", ".scala", ".sh", ".bash",
    ".yaml", ".yml", ".toml", ".json", ".sql",
    ".html", ".vue", ".svelte", ".xml",
}
_SKIP_DIRS = {
    ".git", "test", "tests", "script", "scripts",
    "mock", "mocks", "vendor", "build", "out", "cache", "artifacts",
    "dependencies", ".deps", "coverage", "typechain", "typechain-types",
    "node_modules", ".venv", "venv", "__pycache__", "lib",
}
_OWN_HINTS = ("src/", "contracts/", "sources/", "programs/", "core/", "app/")


def target_files(root: Path) -> list[tuple[Path, str]]:
    """Ranked ``(path, relpath)`` for the target's own source files."""
    try:
        if root.is_file():
            return [(root, root.name)]
        if not root.is_dir():
            return []
    except Exception:
        return []
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if Path(fn).suffix.lower() in _CODE_EXTS:
                fp = Path(dirpath) / fn
                try:
                    rel = str(fp.relative_to(root))
                except ValueError:
                    rel = fn
                candidates.append((fp, rel))
    own = [(p, r) for p, r in candidates
           if any(h in r.replace("\\", "/") for h in _OWN_HINTS)]
    rest = [(p, r) for p, r in candidates
            if not any(h in r.replace("\\", "/") for h in _OWN_HINTS)]
    return own + rest


def number_lines(text: str, offset: int = 0) -> str:
    """Prefix every line with its real (1-based) line number."""
    out = []
    for i, line in enumerate(text.splitlines()):
        n = offset + i + 1
        out.append(f"{n:5d} | {line.strip()}")
    return "\n".join(out)


def split_into_windows(text: str, window: int | None = None,
                       min_window: int | None = None) -> list[tuple[int, str]]:
    """Cut source into windows, each ≤ *window* chars.

    Returns ``[(start_line_0_based, code), ...]`` so the caller can number
    each window independently.
    """
    w = window or DEFAULT_WINDOW_CHARS
    mw = min_window or MIN_WINDOW_CHARS
    lines = text.splitlines(keepends=True)
    if not lines:
        return []
    windows: list[tuple[int, str]] = []
    buf: list[str] = []
    buf_start: int = 0
    consumed: int = 0
    for i, line in enumerate(lines):
        cost = len(line)
        if consumed + cost > w and buf:
            windows.append((buf_start, "".join(buf)))
            buf, buf_start, consumed = [], i, 0
        buf.append(line)
        if not buf:
            buf_start = i
        consumed += cost
    if buf:
        # Don't leave a tiny orphan — merge it into the previous window if
        # there is one and the result still fits roughly.
        if len(windows) > 0 and consumed < mw:
            prev_start, prev_text = windows[-1]
            merged = prev_text + "".join(buf)
            if len(merged) <= w + 500:
                windows[-1] = (prev_start, merged)
                return windows
        windows.append((buf_start, "".join(buf)))
    return windows


def read_target_with_windows(target: str, workdir: Path,
                             window: int | None = None) -> list[dict]:
    """Return ``[{label, code, file, start_line}, ...]`` for every window.

    The result is ready to feed into *one lane per window*: a lane is called
    once per entry, so 10 windows = 10 lane turns, each with a manageable
    prompt.
    """
    w = window or DEFAULT_WINDOW_CHARS
    root = Path(target).expanduser() if target else workdir
    if not root.exists():
        return []
    files = target_files(root)
    windows_out: list[dict] = []
    for fp, rel in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        chunks = split_into_windows(text, window=w)
        for ci, (start, chunk) in enumerate(chunks):
            # Keep the `rel` path as the stable file label; add a part
            # suffix only when there is more than one window for this file.
            label = rel if len(chunks) == 1 else f"{rel}#p{ci+1}"
            windows_out.append({
                "label": label,
                "code": number_lines(chunk, start),
                "file": rel,
                "start_line": start,
            })
    return windows_out