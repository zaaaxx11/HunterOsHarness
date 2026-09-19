"""Planner B T1 — local readonly audit tools (search_files / read_file + skill linter).

No network, no approval. All paths are jailed via the state-dir resolver and
emit exactly one engine_event (even blocked/error paths). Secret shapes are
redacted before reaching the model.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from hunter.kernel.redaction import redact_text

__all__ = [
    "ARCHIVE_READ_SPEC",
    "OUTCOME_TABLE",
    "READ_FILE_SPEC",
    "SEARCH_FILES_SPEC",
    "SEARCH_GLOB_SPEC",
    "SPEC_NAMES",
    "SPECS",
    "archive_read",
    "lint_skill_card",
    "read_file",
    "register_local_tools",
    "search_files",
    "search_glob",
]

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

OUTCOME_TABLE: dict[str, tuple[str, ...]] = {
    "search_files": FIVE,
    "read_file": FIVE,
    "search_glob": FIVE,
    "archive_read": FIVE,
}

_MAX_FILE_BYTES = 1_048_576  # 1MB read cap
_MAX_PATTERN_CHARS = 1000
_DEFAULT_MAX_HITS = 20

SEARCH_FILES_SPEC: dict[str, Any] = {
    "name": "search_files",
    "description": (
        "Fixed-string file search inside the run jail (regex opt-in). "
        "Results are jail-relative, bounded, redacted."
    ),
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string"},
            "root": {"type": "string"},
            "regex": {"type": "boolean"},
            "max_hits": {"type": "integer"},
        },
        "required": ["pattern"],
        "additionalProperties": False,
    },
}

READ_FILE_SPEC: dict[str, Any] = {
    "name": "read_file",
    "description": "Read one jailed file with offset/limit paging, 1MB cap, redacted.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer"},
            "limit": {"type": "integer"},
        },
        "required": ["path"],
        "additionalProperties": False,
    },
}

SPECS = (SEARCH_FILES_SPEC, READ_FILE_SPEC)
SPEC_NAMES = tuple(s["name"] for s in SPECS)

# R2-B B5 Web2 expansion: glob search (basic) + archive read (advanced-only).
SEARCH_GLOB_SPEC: dict[str, Any] = {
    "name": "search_glob",
    "description": "Jail-relative glob file search (fixed-string pattern). Escape attempts BLOCKED.",
    "danger": "none",
    "min_tier": "basic",
    "parameters": {
        "type": "object",
        "properties": {
            "glob": {"type": "string"},
            "pattern": {"type": "string"},
            "max_hits": {"type": "integer"},
        },
        "required": ["glob", "pattern"],
        "additionalProperties": False,
    },
}

ARCHIVE_READ_SPEC: dict[str, Any] = {
    "name": "archive_read",
    "description": "Read one archived file inside the jail (bounded, redacted). Advanced tier only.",
    "danger": "none",
    "min_tier": "advanced",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "archive": {"type": "string"},
        },
        "required": ["path", "archive"],
        "additionalProperties": False,
    },
}

WEB2_SPECS = (SEARCH_GLOB_SPEC, ARCHIVE_READ_SPEC)
WEB2_SPEC_NAMES = tuple(s["name"] for s in WEB2_SPECS)


def _tier(ctx: Any) -> str:
    try:
        return str((getattr(ctx, "config", {}) or {}).get("tier", "basic"))
    except Exception:
        return "basic"


def _resolve_jailed(ctx: Any, raw_path: str) -> tuple[Path | None, Path | None, str | None]:
    """Resolve ``raw_path`` strictly inside the jail. Returns (jail, resolved, error_code)."""
    jail = _jail_dir(ctx)
    if jail is None:
        return None, None, "search.jail_violation"
    if raw_path.startswith("/") or raw_path.startswith("\\"):
        return jail, None, "blocked"
    norm = _norm_seps(raw_path).lstrip("/")
    if not norm or re.match(r"^[a-zA-Z]:/", norm) or ".." in norm.split("/"):
        return jail, None, "blocked"
    candidate = Path(str(jail) + "/" + norm)
    try:
        resolved = candidate.resolve()
    except OSError:
        return jail, None, "blocked"
    if resolved != jail and jail not in resolved.parents:
        return jail, None, "blocked"
    return jail, resolved, None


def search_glob(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Glob opt-in search: jail-relative glob, fixed-string match, redacted hits."""
    raw_glob = str(args.get("glob", "") or "")
    pattern = str(args.get("pattern", "") or "")
    max_hits = _clamp_hits(args.get("max_hits", _DEFAULT_MAX_HITS))

    def _blocked(code: str, msg: str) -> dict[str, Any]:
        _emit(ctx, "search_glob", {"code": code})
        return {"ok": False, "blocked": True, "code": code, "hits": [],
                "result_for_model": msg}

    jail = _jail_dir(ctx)
    if jail is None:
        return _blocked("search.jail_violation", "BLOCKED [search.jail_violation] no jail configured")
    if not pattern:
        _emit(ctx, "search_glob", {"code": "search.pattern_required"})
        return {"ok": False, "blocked": False, "code": "search.pattern_required",
                "hits": [], "result_for_model": "search requires non-empty 'pattern'"}
    norm = _norm_seps(raw_glob).lstrip("/")
    parts = norm.split("/") if norm else []
    if (not norm or re.match(r"^[a-zA-Z]:/", norm) or raw_glob.startswith("/")
            or raw_glob.startswith("\\") or ".." in parts):
        return _blocked("search.jail_violation",
                        f"BLOCKED [search.jail_violation] glob escapes jail: {raw_glob!r}")
    hits: list[dict[str, Any]] = []
    try:
        paths = sorted(p for p in jail.glob(norm) if p.is_file())
    except (OSError, ValueError):
        _emit(ctx, "search_glob", {"code": "search.io_error"})
        return {"ok": False, "blocked": False, "code": "search.io_error",
                "hits": [], "result_for_model": "glob walk failed"}
    for path in paths:
        if len(hits) >= max_hits:
            break
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            try:
                rel = path.relative_to(jail).as_posix()
            except ValueError:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(hits) >= max_hits:
                break
            if pattern in line:
                hits.append({"path": rel, "line": lineno, "text": redact_text(line.strip())[:300]})
    _emit(ctx, "search_glob", {"code": "ok", "hits": len(hits)})
    return {"ok": True, "blocked": False, "code": "ok", "hits": hits,
            "truncated": len(hits) >= max_hits,
            "result_for_model": f"{len(hits)} hit(s) for {pattern!r} in {raw_glob!r}"}


def archive_read(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Advanced-only archived read: jail-contained, bounded at 8k, redacted."""
    if _tier(ctx) != "advanced":
        _emit(ctx, "archive_read", {"code": "tier.capability_locked"})
        return {"ok": False, "blocked": True, "code": "tier.capability_locked",
                "text": "",
                "result_for_model": "BLOCKED [tier.capability_locked] archive_read needs advanced tier."}
    raw_path = str(args.get("path", "") or "")
    archive = str(args.get("archive", "") or "")
    jail, resolved, err = _resolve_jailed(ctx, raw_path)
    if err is not None or resolved is None:
        _emit(ctx, "archive_read", {"code": "archive.jail_violation"})
        return {"ok": False, "blocked": True, "code": "archive.jail_violation",
                "text": "",
                "result_for_model": f"BLOCKED [archive.jail_violation] path escapes jail: {raw_path!r}"}
    if jail is None:
        _emit(ctx, "archive_read", {"code": "archive.jail_violation"})
        return {"ok": False, "blocked": True, "code": "archive.jail_violation",
                "text": "", "result_for_model": "BLOCKED [archive.jail_violation] no jail configured"}
    archive_name = _norm_seps(archive).lstrip("/")
    if not archive_name or ".." in archive_name.split("/"):
        _emit(ctx, "archive_read", {"code": "archive.jail_violation"})
        return {"ok": False, "blocked": True, "code": "archive.jail_violation",
                "text": "",
                "result_for_model": f"BLOCKED [archive.jail_violation] archive escapes jail: {archive!r}"}
    # No extraction engine in v1: read the archived member when the archive
    # path itself resolves inside the jail; a missing bundle is not_found.
    archive_path = Path(str(jail) + "/" + archive_name)
    try:
        archive_resolved = archive_path.resolve()
    except OSError:
        archive_resolved = None
    if archive_resolved is None or (archive_resolved != jail and jail not in archive_resolved.parents):
        _emit(ctx, "archive_read", {"code": "archive.jail_violation"})
        return {"ok": False, "blocked": True, "code": "archive.jail_violation",
                "text": "",
                "result_for_model": f"BLOCKED [archive.jail_violation] archive escapes jail: {archive!r}"}
    if not archive_resolved.is_file():
        _emit(ctx, "archive_read", {"code": "archive.not_found"})
        return {"ok": False, "blocked": False, "code": "archive.not_found",
                "text": "",
                "result_for_model": f"archive not found: {archive!r} (bundle ships separately)"}
    try:
        if resolved.stat().st_size > _MAX_FILE_BYTES:
            _emit(ctx, "archive_read", {"code": "archive.bad_envelope"})
            return {"ok": False, "blocked": False, "code": "archive.bad_envelope",
                    "text": "", "result_for_model": "archived member oversized"}
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _emit(ctx, "archive_read", {"code": "archive.not_found"})
        return {"ok": False, "blocked": False, "code": "archive.not_found",
                "text": "", "result_for_model": f"archived member not found: {raw_path!r}"}
    safe = redact_text(text)
    truncated = len(safe) > 8000
    if truncated:
        safe = safe[:8000] + "\n...[truncated]"
    _emit(ctx, "archive_read", {"code": "ok", "truncated": truncated})
    return {"ok": True, "blocked": False, "code": "ok", "text": safe, "truncated": truncated,
            "result_for_model": f"read {raw_path} from {archive} ({len(safe)} chars)"}


def _jail_dir(ctx: Any) -> Path | None:
    raw = None
    try:
        cfg = getattr(ctx, "config", {}) or {}
        raw = cfg.get("jail", cfg.get("state_dir"))
    except Exception:
        raw = None
    if not raw:
        return None
    try:
        return Path(str(raw)).resolve()
    except OSError:
        return None


def _emit(ctx: Any, tool: str, extra: dict[str, Any] | None = None) -> None:
    try:
        payload = {"tool": tool}
        if extra:
            payload.update(extra)
        ctx.emit("engine_event", payload)
    except Exception:
        pass


def _norm_seps(value: str) -> str:
    # Catch Windows backtrack on any OS: treat "\" as a separator for jail checks.
    return str(value or "").replace("\\", "/")


def _clamp_hits(raw: Any) -> int:
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_MAX_HITS
    return max(1, min(50, n))


def search_files(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    pattern = str(args.get("pattern", "") or "")
    use_regex = bool(args.get("regex", False))
    max_hits = _clamp_hits(args.get("max_hits", _DEFAULT_MAX_HITS))
    code = "ok"
    ok = True
    blocked = False
    hits: list[dict[str, Any]] = []
    result_for_model = ""

    def _finish() -> dict[str, Any]:
        _emit(ctx, "search_files", {"code": code, "hits": len(hits)})
        if blocked:
            return {
                "ok": False,
                "blocked": True,
                "code": code,
                "hits": [],
                "result_for_model": result_for_model,
            }
        return {
            "ok": ok,
            "blocked": False,
            "code": code,
            "hits": hits,
            "truncated": len(hits) >= max_hits,
            "result_for_model": result_for_model or f"{len(hits)} hit(s)",
        }

    jail = _jail_dir(ctx)
    if jail is None:
        code = "search.jail_violation"
        blocked = True
        ok = False
        result_for_model = f"BLOCKED [{code}] no jail configured"
        return _finish()
    root_raw = str(args.get("root", str(jail)) or str(jail))
    # Normalise Windows separators before resolution so "..\\.." cannot slip through.
    candidate = Path(_norm_seps(root_raw))
    if not candidate.is_absolute():
        candidate = Path(str(jail) + "/" + _norm_seps(root_raw))
    try:
        resolved = candidate.resolve()
    except OSError:
        code = "search.jail_violation"
        blocked = True
        ok = False
        result_for_model = f"BLOCKED [{code}] root outside jail"
        return _finish()
    if resolved != jail and jail not in resolved.parents:
        code = "search.jail_violation"
        blocked = True
        ok = False
        result_for_model = f"BLOCKED [{code}] root is outside the jail"
        return _finish()
    if not pattern:
        code = "search.pattern_required"
        ok = False
        result_for_model = "search requires non-empty 'pattern'"
        return _finish()
    if use_regex and len(pattern) > _MAX_PATTERN_CHARS:
        code = "search.pattern_too_large"
        ok = False
        result_for_model = f"pattern too large (>{_MAX_PATTERN_CHARS} chars)"
        return _finish()
    rx = None
    if use_regex:
        try:
            # Guard ReDoS-shaped input with a wall-clock budget around the whole walk.
            rx = re.compile(pattern)
        except re.error as exc:
            code = "search.regex_invalid"
            ok = False
            result_for_model = f"invalid regex: {exc}"
            return _finish()
    started = time.monotonic()
    budget_s = 5.0
    try:
        search_root = resolved if resolved.is_dir() else resolved.parent
        files = (
            [resolved]
            if resolved.is_file()
            else sorted(p for p in search_root.rglob("*") if p.is_file())
        )
        for path in files:
            if time.monotonic() - started > budget_s:
                code = "search.regex_timeout"
                ok = False
                result_for_model = "search timed out (regex budget exceeded)"
                return _finish()
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            try:
                rel = path.relative_to(jail).as_posix()
            except ValueError:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Keep per-file work bounded.
            if len(text) > 512_000:
                text = text[:512_000]
            for lineno, line in enumerate(text.splitlines(), start=1):
                if len(hits) >= max_hits:
                    break
                if time.monotonic() - started > budget_s:
                    code = "search.regex_timeout"
                    ok = False
                    result_for_model = "search timed out (regex budget exceeded)"
                    return _finish()
                if use_regex:
                    assert rx is not None
                    try:
                        matched = rx.search(line) is not None
                    except re.error:
                        code = "search.regex_invalid"
                        ok = False
                        result_for_model = "invalid regex during search"
                        return _finish()
                else:
                    matched = pattern in line
                if matched:
                    snippet = redact_text(line.strip())[:300]
                    hits.append({"path": rel, "line": lineno, "text": snippet})
            if len(hits) >= max_hits:
                break
    except Exception as exc:
        code = "search.io_error"
        ok = False
        result_for_model = f"search failed: {type(exc).__name__}"
        return _finish()
    result_for_model = f"{len(hits)} hit(s) for {pattern!r}"
    return _finish()


def read_file(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    raw_path = str(args.get("path", "") or "")
    try:
        offset = max(1, int(args.get("offset", 1)))
    except (TypeError, ValueError):
        offset = 1
    try:
        limit = max(1, min(500, int(args.get("limit", 200))))
    except (TypeError, ValueError):
        limit = 200
    code = "ok"

    def _blocked(c: str, msg: str) -> dict[str, Any]:
        _emit(ctx, "read_file", {"code": c})
        return {"ok": False, "blocked": True, "code": c, "text": "", "result_for_model": msg}

    jail = _jail_dir(ctx)
    if jail is None:
        return _blocked("scope.outside_jail", "BLOCKED [scope.outside_jail] no jail configured")
    if not raw_path:
        return _blocked("scope.outside_jail", "BLOCKED [scope.outside_jail] path required")
    norm = _norm_seps(raw_path).lstrip("/")
    # Absolute Windows paths (C:/..., C:...) or absolute POSIX are escapes.
    if re.match(r"^[a-zA-Z]:/", norm) or raw_path.startswith("/") or raw_path.startswith("\\"):
        return _blocked("scope.outside_jail", f"BLOCKED [scope.outside_jail] path escapes jail: {raw_path!r}")
    candidate = Path(str(jail) + "/" + norm)
    try:
        resolved = candidate.resolve()
    except OSError:
        return _blocked("scope.outside_jail", f"BLOCKED [scope.outside_jail] path escapes jail: {raw_path!r}")
    if resolved != jail and jail not in resolved.parents:
        return _blocked("scope.outside_jail", f"BLOCKED [scope.outside_jail] path escapes jail: {raw_path!r}")
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        _emit(ctx, "read_file", {"code": "read.not_found"})
        return {
            "ok": False,
            "blocked": False,
            "code": "read.not_found",
            "text": "",
            "result_for_model": f"no such file: {raw_path!r} ({exc})",
        }
    truncated = size > _MAX_FILE_BYTES
    try:
        with open(resolved, "rb") as fh:
            raw = fh.read(_MAX_FILE_BYTES + 1)
    except OSError as exc:
        _emit(ctx, "read_file", {"code": "read.io_error"})
        return {
            "ok": False,
            "blocked": False,
            "code": "read.io_error",
            "text": "",
            "result_for_model": f"read failed: {exc}",
        }
    if len(raw) > _MAX_FILE_BYTES:
        raw = raw[:_MAX_FILE_BYTES]
        truncated = True
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    page = "\n".join(lines[offset - 1 : offset - 1 + limit])
    safe = redact_text(page)
    if len(safe) > _MAX_FILE_BYTES + 256:
        safe = safe[: _MAX_FILE_BYTES + 256]
        truncated = True
    _emit(ctx, "read_file", {"code": code, "truncated": truncated})
    marker = "\n...[truncated]" if truncated else ""
    return {
        "ok": True,
        "blocked": False,
        "code": code,
        "text": safe + marker if truncated and not safe.endswith("[truncated]") else safe,
        "truncated": truncated,
        "result_for_model": f"read {raw_path} ({len(safe)} chars)",
    }


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str] | None:
    m = _FRONTMATTER_RE.match(str(text or ""))
    if not m:
        return None
    raw_head, body = m.group(1), m.group(2)
    fields: dict[str, str] = {}
    try:
        import yaml  # noqa: PLC0415

        loaded = yaml.safe_load(raw_head)
        if isinstance(loaded, dict):
            for k, v in loaded.items():
                fields[str(k).strip()] = str(v) if not isinstance(v, str) else v
            return fields, body
    except Exception:
        pass
    for line in raw_head.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields[k.strip()] = v.strip()
    return fields, body


def lint_skill_card(text: str, *, is_new: bool, known_tools: set[str] | None = None) -> dict[str, Any]:
    parsed = _parse_frontmatter(text)
    if parsed is None:
        return {"ok": False, "error": "missing frontmatter (--- name/description ---)"}
    fields, body = parsed
    description = str(fields.get("description", "")).strip()
    name = str(fields.get("name", "")).strip()
    if not name or not description:
        return {"ok": False, "error": "frontmatter requires name and description"}
    limit = 60 if is_new else 200
    if len(description) > limit:
        return {
            "ok": False,
            "error": f"description is {len(description)} chars; limit is {limit} (60 for new cards)",
        }
    if is_new:
        linked: list[str] = re.findall(r"`([^`]+)`", body or "")
        if known_tools is not None:
            if not any(item.strip() in known_tools for item in linked):
                return {
                    "ok": False,
                    "error": "body must backtick-link at least one registered tool (e.g. `http_request`)",
                }
        elif not linked:
            return {
                "ok": False,
                "error": "body must backtick-link at least one registered tool (e.g. `http_request`)",
            }
    return {"ok": True, "error": ""}


def register_local_tools(registry: Any) -> Any:
    """Register search_files/read_file on a ToolRegistry (danger=none, basic tier)."""
    from hunter.agent.tools_base import ToolContext, ToolOutcome  # noqa: PLC0415

    def _wrap(fn):  # type: ignore[no-untyped-def]
        def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
            out = fn(args, ctx)
            if out.get("blocked"):
                return ToolOutcome(
                    ok=False,
                    blocked=True,
                    code=str(out.get("code", "blocked")),
                    result_for_model=str(out.get("result_for_model", "blocked")),
                )
            if not out.get("ok"):
                return ToolOutcome(
                    ok=False,
                    code=str(out.get("code", "error")),
                    result_for_model=str(out.get("result_for_model", "error")),
                )
            return ToolOutcome(
                result_for_model=str(out.get("result_for_model", "ok")),
                evidence={
                    "kind": "local_read",
                    "data": {"hits": out.get("hits", []), "text": out.get("text", "")[:4000]},
                },
            )

        return handler

    from hunter.agent.tools_base import ToolSpec  # noqa: PLC0415

    for spec_dict, fn in (
        (SEARCH_FILES_SPEC, search_files),
        (READ_FILE_SPEC, read_file),
        (SEARCH_GLOB_SPEC, search_glob),
        (ARCHIVE_READ_SPEC, archive_read),
    ):
        registry.register(
            ToolSpec(
                name=str(spec_dict["name"]),
                description=str(spec_dict["description"]),
                parameters=dict(spec_dict["parameters"]),
                handler=_wrap(fn),
                min_tier=str(spec_dict.get("min_tier", "basic")),
                danger="none",
            )
        )
    return registry
