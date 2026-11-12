# SUB-AGENT PROMPT ARCHITECTURE — 1000 tokens max

## Rule: 1 agent = 1 prompt = max 1000 tokens

Setiap sub-agent dapat 1 prompt kecil. Prompt harus mengandung 4 elemen:
- **ROLE & OBJECTIVES** — siapa dia, apa misinya
- **TASKS** — apa yg harus dikerjakan di cycle ini
- **METHODS** — gimana cara kerjanya (pendekatan, tool yg dipakai)
- **GOALS** — output apa yg diharapkan

---

## Prompt Template per Agent

```
╔══════════════════════════════════════════════════════════════╗
║ ROLE & OBJECTIVES                                           ║
║   You are the [ARCHITECT]. Your job: map trust boundaries.  ║
║                                                             ║
║ TASKS                                                       ║
║   1. List every actor (who can call what)                   ║
║   2. Identify SPOFs (single owner? threshold=1?)            ║
║   3. Trace data flow (input → transform → output)           ║
║   4. Map trust boundaries (pre-auth vs post-auth)           ║
║                                                             ║
║ METHODS                                                     ║
║   Read the source files named in FILE LIST below.           ║
║   For each function, ask: who can call this? what guards?   ║
║   Use report_mapping tool — one call per finding.           ║
║                                                             ║
║ GOALS                                                       ║
║   Output: ≥5 trust-graph entries per cycle.                 ║
║   Status: theoretical → in_code when anchored.              ║
║                                                             ║
║ FILE LIST (paths only — read with read_file tool)           ║
║   server.py     (350 lines, 12 functions)                   ║
║                                                             ║
║ ALREADY RECORDED                                            ║
║   (empty / list of previous titles)                         ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Prompt Size Budget

| Element | Tokens (approx) | Agent |
|---------|-----------------|-------|
| Role & objectives | ~150 | all |
| Tasks | ~200 | all |
| Methods | ~200 | all |
| Goals | ~100 | all |
| File list (target) | ~50 | all |
| Already recorded | ~150 | varies |
| **TOTAL** | **~850** | **semua di bawah 1000** |

---

## Alur per Cycle

```
┌──────────────────────────────────────────────────────────────────┐
│ CYCLE N                                                         │
│                                                                  │
│  builder = PromptBuilder(target, previous_findings)              │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ PHASE 1: ARCHITECT (1 prompt, ~850 tokens)                 │ │
│  │                                                             │ │
│  │  prompt = builder.build("architect")                       │ │
│  │  ┌──────────────────────────────────────────┐              │ │
│  │  │ ROLE: Map trust graph & attack surface  │              │ │
│  │  │ TASKS:                                   │              │ │
│  │  │   • List actors, assets, invariants      │              │ │
│  │  │   • Find SPOFs & trust boundaries        │              │ │
│  │  │   • Trace data flow paths               │              │ │
│  │  │ METHODS:                                 │              │ │
│  │  │   • read_file tool for source access     │              │ │
│  │  │   • report_mapping tool for output       │              │ │
│  │  │ GOALS:                                   │              │ │
│  │  │   • ≥5 trust-graph entries               │              │ │
│  │  └──────────────────────────────────────────┘              │ │
│  │  → LLM call → 3-5s reasoning → tool calls → findings      │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ PHASE 2: RED-TEAMER (1 prompt, ~850 tokens)                │ │
│  │                                                             │ │
│  │  prompt = builder.build("redteam")                         │ │
│  │  ┌──────────────────────────────────────────┐              │ │
│  │  │ ROLE: Break the system                   │              │ │
│  │  │ TASKS:                                   │              │ │
│  │  │   • Auth bypass vectors                  │              │ │
│  │  │   • Injection points (XSS, SQLi, SSTI)   │              │ │
│  │  │   • Access control violations            │              │ │
│  │  │ METHODS:                                 │              │ │
│  │  │   • read_file for code, probe endpoints  │              │ │
│  │  │   • report_finding tool                  │              │ │
│  │  │ GOALS:                                   │              │ │
│  │  │   • ≥1 critical/high finding             │              │ │
│  │  └──────────────────────────────────────────┘              │ │
│  │  → LLM call → 3-5s → tool calls → findings                │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ PHASE 3: FUZZ-ENGINEER (1 prompt, ~850 tokens)             │ │
│  │   ROLE: Find edge cases                                    │ │
│  │   TASKS: boundary values, precision, race, state order     │ │
│  │   METHODS: systematic input mutation, read_file            │ │
│  │   GOALS: ≥1 edge-case finding                              │ │
│  │  → LLM call → 3-5s → tool calls → findings                │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ PHASE 4: CHAINER (1 prompt, ~500 tokens)                   │ │
│  │   ROLE: Build exploit chains                               │ │
│  │   TASKS: [trigger]→[effect]→[boundary]→[impact]            │ │
│  │   METHODS: match output of N to input of N+1               │ │
│  │   GOALS: ≥1 multi-step chain                               │ │
│  │  → LLM call → 3s → JSON chains                             │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  4 LLM calls total (was 16+), each < 5s, 0 timeout              │
│  Findings accumulated from all 4 agents                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## Sebelum vs Sesudah

```
SEBELUM (source code inlined)        SESUDAH (structured prompt 1000 tokens)
──────────────────────────────       ────────────────────────────────────────

1 prompt = soul + code + tools        1 prompt = ROLE + TASKS + METHODS
           = 16,000+ chars                      + GOALS + file_list
                                               = ~850 tokens
                                                                           
LLM reasoning: 60-80 detik             LLM reasoning: 3-5 detik
Tool call:      40% sampai             Tool call:      100% sampai
Timeout 524:    50%                    Timeout 524:    0%

Finding count:  ~26                    Finding count:  ~30 (lebih fokus)
Calls per cycle: 16-20                 Calls per cycle: 4
Waktu per cycle: 5-8 menit             Waktu per cycle: 30-45 detik
```

---

## Yang berubah di loop.py

```python
# SEBELUM:
source = self._source_for_lane("architect")  # 16,000 char inlined
user = f"LANE: {lane}\nTARGET SOURCE:\n{source}"
findings = self._run_lane(lane, state, user, tools)

# SESUDAH:
prompt = build_agent_prompt(lane, state)     # 850 tokens structured
findings = self._run_lane(lane, state, prompt, tools)
```