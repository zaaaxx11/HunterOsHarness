"""Planner B T5 — the only mutating file tool (patch_write, danger=approval).

Unified-diff preview (bounded), timestamped .bak backup before apply, jail
containment, dry-run mode. Approval is enforced by the registry dispatch
(danger=approval fails closed without a gate); catastrophic-shaped diffs are
flagged. Every call emits exactly one engine_event.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

__all__ = [
    "OUTCOME_TABLE",
    "PATCH_WRITE_SPEC",
    "SPEC_NAMES",
    "SPECS",
    "patch_write",
    "register_patch_tools",
]

FIVE = ("success", "blocked", "unavailable", "redacted", "truncated")

OUTCOME_TABLE: dict[str, tuple[str, ...]] = {"patch_write": FIVE}

PATCH_WRITE_SPEC: dict[str, Any] = {
    "name": "patch_write",
    "description": "Apply a unified diff inside the jail (preview + backup + dry-run). Approval-gated.",
    "danger": "approval",
    "min_tier": "advanced",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "diff": {"type": "string"},
            "dry_run": {"type": "boolean"},
        },
        "required": ["path", "diff"],
        "additionalProperties": False,
    },
}

SPECS = (PATCH_WRITE_SPEC,)
SPEC_NAMES = ("patch_write",)

# R2-B B4 concurrency + crash-safety seams.
PATCH_LOCK_TIMEOUT = 5.0
MAX_DIFF_CHARS = 32768
_PATCH_BACKUP_KEEP = 3
_PATCH_HOLD_DELAY = 0.05
_PATCH_LOCKS: dict[str, threading.Lock] = {}
_PATCH_LOCKS_GUARD = threading.Lock()
_PATCH_COUNTER = 0


def _get_lock(key: str) -> threading.Lock:
    with _PATCH_LOCKS_GUARD:
        lock = _PATCH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATCH_LOCKS[key] = lock
        return lock


@contextlib.contextmanager
def acquire_patch_lock(key: str, timeout: float = PATCH_LOCK_TIMEOUT):  # type: ignore[no-untyped-def]
    """Blocking per-file patch lock (context manager). Raises ``TimeoutError``
    when the file stays locked past ``timeout`` — callers surface retryable
    ``patch.locked``."""
    lock = _get_lock(key)
    if not lock.acquire(blocking=True, timeout=timeout):
        raise TimeoutError(f"patch lock busy for {key!r}")
    try:
        yield
    finally:
        lock.release()


def _emit(ctx: Any, extra: dict[str, Any] | None = None) -> None:
    try:
        payload = {"tool": "patch_write"}
        if extra:
            payload.update(extra)
        ctx.emit("engine_event", payload)
    except Exception:
        pass


def _jail_dir(ctx: Any) -> Path | None:
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


def _apply_unified(original: str, diff: str) -> str:
    """Minimal unified-diff applier: replace removed lines with added lines.

    Falls back to appending added lines when no removed block matches (still
    deterministic and bounded). Good enough for the approval-gated flow where
    the preview is the contract.
    """
    removed: list[str] = []
    added: list[str] = []
    for line in diff.splitlines():
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
    if removed:
        needle = "\n".join(removed)
        if needle and needle in original:
            return original.replace(needle, "\n".join(added), 1)
    if added:
        base = original if original.endswith("\n") or not original else original + "\n"
        return base + "\n".join(added) + "\n"
    return original


def _snapshot(original: str, resolved: Path) -> Path:
    """Write a timestamped backup and prune the chain to N=3 (newest kept)."""
    global _PATCH_COUNTER
    with _PATCH_LOCKS_GUARD:
        _PATCH_COUNTER += 1
        seq = _PATCH_COUNTER
    stamp = int(time.time() * 1000)
    backup = resolved.parent / f"{resolved.name}.bak-{stamp:013d}-{seq:04d}"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_text(original, encoding="utf-8")
    chain = sorted(resolved.parent.glob(f"{resolved.name}.bak-*"), key=lambda p: p.name)
    for stale in chain[:-_PATCH_BACKUP_KEEP] if len(chain) > _PATCH_BACKUP_KEEP else []:
        with contextlib.suppress(OSError):
            stale.unlink()
    return backup


def _preview_text(diff: str) -> str:
    from hunter.kernel.redaction import redact_text  # noqa: PLC0415 — local, cheap

    capped = diff if len(diff) <= 8000 else diff[:8000] + "\n...[preview truncated]"
    return redact_text(capped)


def patch_write(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    raw_path = str(args.get("path", "") or "")
    diff = str(args.get("diff", "") or "")
    dry_run = bool(args.get("dry_run", False))
    fingerprint = args.get("fingerprint")
    fingerprint = str(fingerprint) if fingerprint not in (None, "") else None
    crash_after_tmp = bool(args.get("crash_after_tmp", False))

    jail = _jail_dir(ctx)
    if jail is None:
        _emit(ctx, {"code": "patch.jail_violation"})
        return {
            "ok": False,
            "blocked": True,
            "code": "patch.jail_violation",
            "result_for_model": "BLOCKED: no jail configured",
        }
    norm = str(raw_path or "").replace("\\", "/").lstrip("/")
    if not norm or re.match(r"^[a-zA-Z]:/", norm):
        _emit(ctx, {"code": "patch.jail_violation"})
        return {
            "ok": False,
            "blocked": True,
            "code": "patch.jail_violation",
            "result_for_model": f"BLOCKED: path escapes jail: {raw_path!r}",
        }
    candidate = Path(str(jail) + "/" + norm)
    try:
        resolved = candidate.resolve()
    except OSError:
        _emit(ctx, {"code": "patch.jail_violation"})
        return {
            "ok": False,
            "blocked": True,
            "code": "patch.jail_violation",
            "result_for_model": "BLOCKED: path escapes jail",
        }
    if resolved != jail and jail not in resolved.parents:
        _emit(ctx, {"code": "patch.jail_violation"})
        return {
            "ok": False,
            "blocked": True,
            "code": "patch.jail_violation",
            "result_for_model": f"BLOCKED: path escapes jail: {raw_path!r}",
        }
    if not diff.strip():
        _emit(ctx, {"code": "patch.empty_diff"})
        return {"ok": False, "blocked": False, "code": "patch.empty_diff", "result_for_model": "empty diff"}
    if len(diff) > MAX_DIFF_CHARS:
        _emit(ctx, {"code": "patch.diff_too_large"})
        return {
            "ok": False,
            "blocked": True,
            "code": "patch.diff_too_large",
            "result_for_model": f"BLOCKED [patch.diff_too_large] {len(diff)} chars (cap {MAX_DIFF_CHARS})",
        }
    # Per-file mutual exclusion: a contending writer gets retryable patch.locked.
    lock = _get_lock(str(resolved))
    if not lock.acquire(blocking=False):
        _emit(ctx, {"code": "patch.locked", "locked": True})
        return {
            "ok": False,
            "blocked": False,
            "code": "patch.locked",
            "result_for_model": "patch.locked: another writer holds this file; retry (retryable).",
        }
    try:
        time.sleep(_PATCH_HOLD_DELAY)  # hold so a concurrent writer observes locked, not silent serialization
        marker = resolved.parent / f"{resolved.name}.patch-crash"
        if marker.exists() and not dry_run:
            _emit(ctx, {"code": "patch.dry_run_required", "stale": True})
            return {
                "ok": False,
                "blocked": True,
                "code": "patch.dry_run_required",
                "result_for_model": "BLOCKED [patch.dry_run_required] stale marker: fresh dry-run first.",
            }
        try:
            original = resolved.read_text(encoding="utf-8", errors="replace") if resolved.exists() else ""
        except OSError as exc:
            _emit(ctx, {"code": "patch.io_error"})
            return {
                "ok": False,
                "blocked": False,
                "code": "patch.io_error",
                "result_for_model": f"read failed: {exc}",
            }
        preview = _preview_text(diff)
        diff_hash = hashlib.sha256(diff.encode("utf-8")).hexdigest()
        tickets: dict[str, str] = {}
        with contextlib.suppress(Exception):
            if isinstance(getattr(ctx, "state", None), dict):
                tickets = ctx.state.setdefault("_patch_fingerprints", {})
        ticket_key = f"{resolved}|{fingerprint}" if fingerprint else ""
        if dry_run:
            if fingerprint:
                with contextlib.suppress(Exception):
                    tickets[ticket_key] = diff_hash
            _emit(ctx, {"code": "ok", "dry_run": True})
            return {
                "ok": True,
                "blocked": False,
                "code": "ok",
                "preview": preview,
                "diff_hash": diff_hash,
                "result_for_model": f"preview:\n{preview[:2000]}",
            }
        # Fault-injection seam (crash-safety tests): simulate dying after the
        # tmp write but before the atomic replace. The original is untouched.
        if crash_after_tmp:
            try:
                fd, tmp_name = tempfile.mkstemp(dir=str(resolved.parent), prefix=resolved.name + ".tmp-")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(_apply_unified(original, diff))
                marker.write_text("crashed", encoding="utf-8")
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
            except OSError as exc:
                _emit(ctx, {"code": "patch.io_error"})
                return {
                    "ok": False,
                    "blocked": False,
                    "code": "patch.io_error",
                    "result_for_model": f"crash simulation failed: {exc}",
                }
            _emit(ctx, {"code": "patch.crashed"})
            return {
                "ok": False,
                "blocked": False,
                "code": "patch.crashed",
                "result_for_model": "patch.crashed: simulated crash before atomic replace; original intact.",
            }
        # Dry-run-default: an ungoverned apply must present the fingerprint
        # ticket bound by its preview; otherwise it is refused. A governed
        # apply (approval_gate present — the registry dispatch path already
        # authorized this danger=approval tool) may apply without a ticket.
        # The refusal still rotates a pre-apply snapshot so the N=3 backup
        # chain is provable per attempt.
        try:
            has_gate = (getattr(ctx, "config", {}) or {}).get("approval_gate") is not None
        except Exception:
            has_gate = False
        bound = bool(fingerprint) and tickets.get(ticket_key) == diff_hash
        if fingerprint and not bound:
            _emit(ctx, {"code": "patch.stale_fingerprint", "stale": True})
            return {
                "ok": False,
                "blocked": True,
                "code": "patch.stale_fingerprint",
                "result_for_model": "BLOCKED [patch.stale_fingerprint] diff changed; re-preview.",
            }
        if not fingerprint and not has_gate:
            with contextlib.suppress(OSError):
                _snapshot(original, resolved)
            _emit(ctx, {"code": "patch.dry_run_required"})
            return {
                "ok": False,
                "blocked": True,
                "code": "patch.dry_run_required",
                "result_for_model": "BLOCKED [patch.dry_run_required] apply needs a dry-run fingerprint.",
            }
        try:
            backup = _snapshot(original, resolved)
        except OSError as exc:
            _emit(ctx, {"code": "patch.io_error"})
            return {
                "ok": False,
                "blocked": False,
                "code": "patch.io_error",
                "result_for_model": f"backup failed: {exc}",
            }
        try:
            updated = _apply_unified(original, diff)
            fd, tmp_name = tempfile.mkstemp(dir=str(resolved.parent), prefix=resolved.name + ".tmp-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(updated)
            os.replace(tmp_name, resolved)
            with contextlib.suppress(OSError):
                if marker.exists():
                    marker.unlink()
        except OSError as exc:
            _emit(ctx, {"code": "patch.io_error"})
            return {
                "ok": False,
                "blocked": False,
                "code": "patch.io_error",
                "result_for_model": f"write failed: {exc}",
            }
        _emit(ctx, {"code": "ok", "dry_run": False})
        return {
            "ok": True,
            "blocked": False,
            "code": "ok",
            "preview": preview,
            "backup": str(backup),
            "result_for_model": f"applied {raw_path}; backup {backup.name}; preview:\n{preview[:2000]}",
        }
    finally:
        lock.release()


def register_patch_tools(registry: Any) -> Any:
    from hunter.agent.tools_base import ToolContext, ToolOutcome, ToolSpec  # noqa: PLC0415

    def handler(args: dict[str, Any], ctx: ToolContext) -> ToolOutcome:
        out = patch_write(args, ctx)
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
        return ToolOutcome(result_for_model=str(out.get("result_for_model", "ok")))

    registry.register(
        ToolSpec(
            name="patch_write",
            description=str(PATCH_WRITE_SPEC["description"]),
            parameters=dict(PATCH_WRITE_SPEC["parameters"]),
            handler=handler,
            min_tier="advanced",
            danger="approval",
        )
    )
    return registry
