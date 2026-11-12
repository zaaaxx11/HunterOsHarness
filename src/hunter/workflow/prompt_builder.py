"""PromptBuilder — assembles 4-element agent prompts under 1000 tokens.

One builder, two modes:
  sweep     → broad audit, all functions, map boundaries
  deep_dive → zoom into one anchored finding, confirm/refute/variant

Prompt size ceiling: 1000 tokens (~4000 chars). Delivery in Bahasa
Indonesia casual (lo/gue) when the operator is Indonesian.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: Max prompt chars (rough 1 token ≈ 4 chars for mixed ID/EN text).
CEILING = 3800

# ── static soul snippets (kept short — every char counts) ─────────

_SNIPPET = {
    "architect": (
        "Kamu ARCHITECT. Petakan trust graph sebelum menyerang. "
        "Jangan klaim vuln — keluarkan hipotesis, precondition, falsifier."
    ),
    "redteam": (
        "Kamu RED-TEAM. Serang satu hal spesifik. "
        "Violate invariant dgn probe terkecil. Satu probe bersih > 50 payload buta."
    ),
    "fuzzer": (
        "Kamu FUZZER. Mutasi satu variabel, catat perubahan state. "
        "Differential evidence: dua request, satu diff, satu penjelasan."
    ),
    "chainer": (
        "Kamu CHAINER. Output step N = input step N+1. "
        "Sebut handoff eksplisit — value yang berpindah adalah chain."
    ),
    "verifier": (
        "Kamu VERIFIER. Bayar untuk bilang TIDAK. "
        "Baca ulang bukti, daftarkan setiap precondition, tentukan verdict."
    ),
}

_TASKS = {
    "architect": [
        "Petakan aktor (siapa bisa panggil fungsi apa)",
        "Identifikasi SPOF (single owner? threshold=1? no timelock?)",
        "Telusuri data flow (input → transform → storage → output)",
        "Petakan trust boundary (pre-auth vs post-auth)",
    ],
    "redteam": [
        "Temukan auth bypass (cookie polos? delegatecall? proxy?)",
        "Temukan injection point (XSS, SQLi, SSTI, SSRF)",
        "Violate satu invariant per temuan",
        "Setiap temuan: adversarial validation — buktikan ini TIDAK exploitable dulu",
    ],
    "fuzzer": [
        "Edge cases di setiap high-risk sink: 0, -1, null, empty, MAX_UINT",
        "Precision loss, race condition, state update order",
        "Boundary values: tepat di batas validasi",
        "Satu mutasi, satu observasi, satu penjelasan",
    ],
    "chainer": [
        "Cari handoff: output step N = input step N+1",
        "Bangun [Trigger]→[Effect]→[Boundary]→[Impact]",
        "Nilai handoff eksplisit — jangan narasi, sebut value-nya",
        "Return JSON: {chains:[{title,steps,severity,impact}]}",
    ],
    "verifier": [
        "Baca ulang bukti — jangan percaya ringkasan hunter",
        "List setiap precondition: apa yg HARUS true agar exploitable?",
        "Tentukan verdict: VERIFIED atau REFUTED",
        "Akhiri reply dengan VERDICT: VERIFIED atau VERDICT: REFUTED",
    ],
}

_GOALS = {
    "architect": "≥5 trust-graph entries per cycle. Status: in_code.",
    "redteam": "≥1 critical/high finding per cycle. Status: in_code.",
    "fuzzer": "≥1 edge-case finding per cycle. Status: in_code.",
    "chainer": "≥1 multi-step chain per cycle. Status: in_code (auto-anchored).",
    "verifier": "Verdict jelas: VERIFIED atau REFUTED, disertai alasan.",
}


def _count_tokens(text: str) -> int:
    """Rough ID/EN token counter: ~4 chars ≈ 1 token."""
    return len(text) // 4


# ── public builder ─────────────────────────────────────────────────

class PromptBuilder:
    """One builder per hunt session — caches static parts, injects dynamic."""

    def __init__(self, target: str, files: list[str] | None = None,
                 findings: list[dict] | None = None):
        self.target = target
        self.files = files or []
        self.findings = findings or []

    def build(self, agent: str, *, mode: str = "sweep",
              focus: dict | None = None) -> tuple[str, list[dict]]:
        """Return (prompt, tools) for one agent turn under the ceiling."""
        if mode == "deep_dive" and focus:
            prompt = self._build_deep_dive(agent, focus)
        else:
            prompt = self._build_sweep(agent)

        tools = self._tools_for(agent)

        # Safety: if prompt exceeds ceiling, trim the file list and
        # previously-recorded section (they are the most elastic).
        while _count_tokens(prompt) > 1000:
            prompt = self._trim(prompt)

        return prompt, tools

    # ── sweep mode ──────────────────────────────────────────────

    def _build_sweep(self, agent: str) -> str:
        role = _SNIPPET.get(agent, f"Kamu {agent.upper()}.")
        tasks = "\n".join(f"  {i+1}. {t}" for i, t in enumerate(_TASKS.get(agent, [])))
        goals = _GOALS.get(agent, "≥1 finding per cycle.")
        files = "\n".join(f"  {f}" for f in self.files[:20])
        known = self._known_section(agent)

        return (
            f"ROLE: {role}\n\n"
            f"TARGET: {self.target}\n\n"
            f"TASKS:\n{tasks}\n\n"
            f"FILES (read with read_file tool):\n{files}\n\n"
            f"ALREADY RECORDED:\n{known}\n\n"
            f"GOALS: {goals}\n"
            f"Output: gunakan tool yang tersedia. Jangan narasi — langsung tool call."
        )

    # ── deep-dive mode ───────────────────────────────────────────

    def _build_deep_dive(self, agent: str, focus: dict) -> str:
        role = _SNIPPET.get(agent, f"Kamu {agent.upper()}.")
        title = focus.get("title", "?")
        desc = focus.get("description", "")[:300]
        anchor = focus.get("file_line") or f"{focus.get('file','')}:{focus.get('line','')}"
        tasks = "\n".join(f"  {i+1}. {t}" for i, t in enumerate(_TASKS.get(agent, [])[:2]))
        goals = _GOALS.get(agent, "verdict jelas — VERIFIED atau REFUTED.")

        return (
            f"ROLE: {role}\n"
            f"MODE: DEEP DIVE — fokus pada SATU finding di bawah.\n\n"
            f"FINDING: {title}\n"
            f"  anchor: {anchor}\n"
            f"  description: {desc}\n\n"
            f"TASKS:\n{tasks}\n\n"
            f"GOALS: {goals}\n"
            f"Output: gunakan tool. Akhiri dengan VERDICT: VERIFIED atau VERDICT: REFUTED."
        )

    # ── helpers ──────────────────────────────────────────────────

    def _known_section(self, agent: str) -> str:
        relevant = [
            f for f in self.findings[-30:]
            if isinstance(f, dict) and f.get("source_lane", "")[:3].lower() == agent[:3]
        ]
        if not relevant:
            return "(belum ada — siklus pertama)"
        lines = []
        for i, f in enumerate(relevant[-15:], 1):
            title = str(f.get("title", ""))[:60]
            st = f.get("status", "?")
            lines.append(f"  {i}. [{st}] {title}")
        return "\n".join(lines)

    def _tools_for(self, agent: str) -> list[dict]:
        if agent == "architect":
            return [{
                "type": "function",
                "function": {
                    "name": "report_mapping",
                    "description": "Report a trust-graph mapping entry.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "findings": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "type": {"type": "string",
                                                 "enum": ["actor", "asset", "invariant", "spof", "boundary", "data_flow"]},
                                        "description": {"type": "string"},
                                        "file": {"type": "string"},
                                        "line": {"type": "integer"},
                                        "code": {"type": "string"},
                                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                                    },
                                    "required": ["title", "type", "description"],
                                },
                            }
                        },
                        "required": ["findings"],
                    },
                },
            }]
        return [{
            "type": "function",
            "function": {
                "name": "report_finding",
                "description": "Report a vulnerability finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "severity": {"type": "string",
                                                 "enum": ["critical", "high", "medium", "low", "info"]},
                                    "description": {"type": "string"},
                                    "file": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "code": {"type": "string"},
                                    "vuln_type": {"type": "string"},
                                },
                                "required": ["title", "severity", "description"],
                            },
                        }
                    },
                    "required": ["findings"],
                },
            },
        }]

    def _trim(self, prompt: str) -> str:
        """Trim the most elastic section: ALREADY RECORDED or FILES."""
        # halve the known section
        marker = "ALREADY RECORDED:"
        if marker in prompt:
            parts = prompt.split(marker, 1)
            known_lines = parts[1].split("\n")
            if len(known_lines) > 5:
                kept = known_lines[:1] + known_lines[2::2]  # keep every other
                return parts[0] + marker + "\n".join(kept)
        # halve the files section
        marker2 = "FILES (read with read_file tool):"
        if marker2 in prompt:
            parts = prompt.split(marker2, 1)
            file_lines = parts[1].split("\n")
            if len(file_lines) > 15:
                kept = file_lines[:10]
                return parts[0] + marker2 + "\n".join(kept)
        # desperate: strip to 1000 tokens raw
        return prompt[:_count_tokens(prompt) * 4]