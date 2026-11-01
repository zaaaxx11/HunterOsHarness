"""ReviewEngine — static source review behind the EngineDriver seam.

Reads files under a local root and emits ``code_location`` evidence for
suspicious patterns. Never promotes findings to ``verified``: a code reading
is evidence that a span exists, not proof of exploitability.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from ..kernel.findings import Severity
from .base import CandidateFinding, EngineContext, EngineResult, Evidence, ScanPlan, TargetSpec


class ReviewEngine:
    name = "review"

    _SUSPECT_PATTERNS = (
        ("delegatecall", "unchecked delegatecall", "CWE-829"),
        ("tx.origin", "tx.origin used for authorization", "CWE-477"),
        ("selfdestruct", "selfdestruct reachable", "CWE-672"),
    )

    def plan(self, target: TargetSpec) -> ScanPlan:
        return ScanPlan(engine=self.name, phases=["scan-files"], notes={"strategy": "static-review"})

    def _local_root(self, ctx: EngineContext, target: TargetSpec) -> Path | None:
        root = ctx.config.get("local_root") or target.notes.get("local_root")
        if not root:
            return None
        try:
            resolved = Path(str(root)).resolve()
        except (OSError, RuntimeError, ValueError):
            return None
        # Fail-closed filesystem gate: the root must be inside one of the
        # scope's local_roots (absent local_roots keeps the permissive
        # localhost behaviour, mirroring daemon.hunt_worker).
        if not target.scope.allows_local_root(resolved):
            return None
        return resolved

    def run(self, target: TargetSpec, ctx: EngineContext) -> EngineResult:
        root = self._local_root(ctx, target)
        if root is None or not root.is_dir():
            ctx.emit("engine_event", {"stage": "review.no_root", "root": str(root)})
            empty = {"files_scanned": 0, "requests": 0, "blocked": 0, "errors": 0}
            return EngineResult(candidates=[], stats=empty)

        candidates: list[CandidateFinding] = []
        files_scanned = 0
        for dirpath, _dirs, files in os.walk(root):
            # Real containment guard: os.walk starting at `root` stays inside
            # it for real subdirectories, but a link-named dirpath must not
            # escape; resolve and refuse anything outside the root.
            try:
                Path(dirpath).resolve().relative_to(root)
            except ValueError:
                continue
            for fname in files:
                path = Path(dirpath) / fname
                # File symlinks are NOT followed: a link placed in the scanned
                # tree must not point the reader at ~/.ssh/id_rsa etc.
                if path.is_symlink():
                    continue
                _CODE_SUFFIXES = {
                    ".sol", ".py", ".js", ".ts", ".go",
                    ".rs", ".java", ".c", ".cpp", ".h",
                }
                if path.suffix.lower() not in _CODE_SUFFIXES:
                    continue
                try:
                    if path.stat().st_size > 1_000_000:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                files_scanned += 1
                lines = text.splitlines()
                for idx, line in enumerate(lines, start=1):
                    for needle, title, cwe in self._SUSPECT_PATTERNS:
                        if needle in line:
                            span = line
                            digest = hashlib.sha256(span.encode("utf-8")).hexdigest()
                            candidates.append(
                                CandidateFinding(
                                    key=f"review-{needle}|{path}|{idx}",
                                    title=title,
                                    severity=Severity.MEDIUM,
                                    cwe=cwe,
                                    endpoint=str(path),
                                    method="READ",
                                    description=f"Suspicious pattern {needle!r} at {path}:{idx}",
                                    impact="Potential vulnerability; requires manual review.",
                                    remediation="Review and validate the flagged code.",
                                    klass="unknown",
                                    evidence=(
                                        Evidence(
                                            kind="code_location",
                                            data={
                                                "path": str(path),
                                                "line_start": idx,
                                                "line_end": idx,
                                                "sha256": digest,
                                            },
                                        ),
                                    ),
                                )
                            )
        ctx.emit(
            "engine_event",
            {"stage": "review.done", "files_scanned": files_scanned, "candidates": len(candidates)},
        )
        stats = {"files_scanned": files_scanned, "requests": 0, "blocked": 0, "errors": 0}
        return EngineResult(candidates=candidates, stats=stats)

    def replay(self, target: TargetSpec, ctx: EngineContext, candidate: CandidateFinding) -> bool:
        # Code findings are never auto-verified.
        return False
