"""Cross-process smoke test: two LLM hunts in two terminals, one provider.

Spawns two processes that each drive NativeProvider through the real gate and
logs when they are INSIDE a dial. We then assert no two processes were inside
a dial at the same wall-clock instant — proof the cross-process gate serializes
them even though they share one provider key.

Run: python3 tests/smoke/cross_process_llm_smoke.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[2]  # repo root
SRC = str(HARNESS / "src")
WORKER = str(HARNESS / "tests" / "smoke" / "_smoke_worker.py")


def main() -> int:
    state = tempfile.mkdtemp(prefix="hoh-smoke-")
    log = Path(state) / "dials.jsonl"
    log.write_text("")
    env = {**os.environ, "HUNTEROS_STATE_DIR": state, "SMOKE_LOG": str(log),
           "PYTHONPATH": SRC, "DEVORA_API_KEY": "fake-smoke-key"}
    procs = [
        subprocess.Popen([sys.executable, WORKER], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(2)
    ]
    for p in procs:
        out, _ = p.communicate(timeout=60)
        if out.strip():
            print("WORKER OUTPUT:", out[:800])

    windows: list[tuple[float, float, int]] = []
    for line in log.read_text().splitlines():
        rec = json.loads(line)
        windows.append((rec["in"], rec["out"], rec["pid"], rec.get("dt", 0.0)))
    windows.sort()

    overlaps = 0
    for i, a in enumerate(windows):
        for b in windows[i + 1:]:
            if b[0] < a[1]:  # b started before a finished
                overlaps += 1

    print(f"dial windows: {len(windows)} (expect ~10 across 2 procs)")
    print(f"overlapping dial windows: {overlaps} (expect 0)")
    for w in windows:
        print(f"  pid={w[2]} in={w[0]:.3f} out={w[1]:.3f} dt={w[3]:.3f}")
    if overlaps == 0 and len(windows) >= 6:
        print("SMOKE PASS: cross-process gate serialized the shared provider")
        return 0
    print("SMOKE FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
