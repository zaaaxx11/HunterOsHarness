"""Brand-zero — no case-insensitive legacy brand token may remain.

Walks the repo (excluding .git/__pycache__/.venv cruft and this guard file
itself, which necessarily constructs the target) and asserts zero hits in
file contents AND filenames. The token is built by concatenation so this
file never contains the literal; split-token construction lines are allowed,
never a literal occurrence.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
TARGET = "her" + "mes"  # split construction only; never the literal token

EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    ".venv-ci",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".kilo",
    ".hunter",
    ".hunter-cli-smoke",
}


def _excluded(path: Path) -> bool:
    if path.resolve() == SELF:
        return True
    return any(part in EXCLUDE_DIRS for part in path.parts)


def test_brand_zero():
    content_hits: list[str] = []
    name_hits: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if _excluded(path) or _excluded(rel):
            continue
        if TARGET in path.name.lower():
            name_hits.append(str(rel))
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
            except (UnicodeDecodeError, OSError):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if TARGET in line.lower():
                    if (
                        '"her" + "mes"' in line
                        or "'her' + 'mes'" in line
                        or '"her"+"mes"' in line
                    ):
                        continue
                    content_hits.append(f"{rel}:{i}: {line.strip()[:200]}")
                    if len(content_hits) >= 120:
                        break
    hits = [f"filename: {h}" for h in sorted(name_hits)]
    hits += sorted(content_hits)
    assert not hits, f"brand-zero violated with {len(hits)} hit(s):\n" + "\n".join(hits[:120])
    old = ROOT / "tests" / f"test_fix_{TARGET}_zero.py"
    assert not old.exists(), f"old literal guard still present: {old}"
    assert ".kilo" in (ROOT / ".gitignore").read_text(encoding="utf-8")
