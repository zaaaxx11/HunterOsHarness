"""Cross-process gate: two hunts in two terminals must not dial together."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from hunter.llm.rate_control import FileGate

_SCRIPT = '''
import os, sys, time
from hunter.llm.rate_control import FileGate
gate = FileGate()
mid = sys.argv[1]
print("ENTER", mid, time.time(), flush=True)
with gate.slot("shared-provider", float(sys.argv[2])):
    print("IN", mid, time.time(), flush=True)
    time.sleep(0.25)
    print("OUT", mid, time.time(), flush=True)
'''


@pytest.mark.skipif(not hasattr(__import__("fcntl"), "flock"), reason="POSIX only")
def test_file_gate_mutual_exclusion_across_processes(tmp_path):
    script = tmp_path / "worker.py"
    script.write_text(_SCRIPT, encoding="utf-8")
    env = {**__import__("os").environ, "HUNTEROS_STATE_DIR": str(tmp_path), "PYTHONPATH": _src()}
    procs = [
        subprocess.Popen(
            [sys.executable, str(script), f"w{i}", "0"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for i in range(2)
    ]
    lines = []
    for p in procs:
        lines += p.communicate(timeout=20)[0].splitlines()

    entries = [l for l in lines if l.startswith("IN ")]
    exits = [l for l in lines if l.startswith("OUT ")]
    assert len(entries) == 2 and len(exits) == 2, lines

    def ts(line):
        return float(line.rsplit(" ", 1)[1])

    # No process entered while the other was still inside its slot.
    first_in, second_in = sorted(ts(l) for l in entries)
    first_out = sorted(ts(l) for l in exits)[0]
    assert second_in >= first_out, f"overlap: entered at {second_in}, first exit {first_out}"


@pytest.mark.skipif(not hasattr(__import__("fcntl"), "flock"), reason="POSIX only")
def test_file_gate_paces_across_processes(tmp_path):
    script = tmp_path / "worker.py"
    script.write_text(_SCRIPT, encoding="utf-8")
    env = {**__import__("os").environ, "HUNTEROS_STATE_DIR": str(tmp_path), "PYTHONPATH": _src()}
    procs = [
        subprocess.Popen(
            [sys.executable, str(script), f"p{i}", "0.4"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for i in range(2)
    ]
    lines = []
    for p in procs:
        lines += p.communicate(timeout=20)[0].splitlines()
    entries = sorted(float(l.rsplit(" ", 1)[1]) for l in lines if l.startswith("IN "))
    assert len(entries) == 2, lines
    assert entries[1] - entries[0] >= 0.4 - 0.05, f"gap {entries[1] - entries[0]}"


def test_file_gate_disabled_without_fcntl(tmp_path, monkeypatch):
    gate = FileGate(state_dir=tmp_path)
    monkeypatch.setattr("hunter.llm.rate_control.fcntl", None)
    with gate.slot("p", 1.0):
        pass  # no-op path must still work as a context manager


def _src() -> str:
    return str(Path(__file__).resolve().parents[1] / "src")
