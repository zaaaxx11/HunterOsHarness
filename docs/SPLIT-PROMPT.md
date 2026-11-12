# SPLIT PROMPT ARCHITECTURE — 1000-token windows

## Input: PracticeVault 350 lines → 6 windows @ 3,000 chars each

```
server.py (350 lines, 16,000 chars)
│
├─[split_prompt.py: split_into_windows()]
│
├── window #1: server.py#p1  (79 lines,  3,550 chars) ← lines 1-79
├── window #2: server.py#p2  (99 lines,  3,555 chars) ← lines 80-179
├── window #3: server.py#p3  (67 lines,  2,805 chars) ← lines 180-247
├── window #4: server.py#p4  (99 lines,  3,555 chars) ← lines 248-347
└── window #5: server.py#p5  (6 lines,   350 chars)    ← lines 348-354
     └── merged into #4 (tiny orphan → grouped with neighbor)
```

---

## 1 cycle = 3 lanes × 5 windows = 15 LLM calls

```
┌──────────────────────────────────────────────────────────────────┐
│ CYCLE N                                                         │
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │ ARCHITECT   │ │ RED-TEAMER  │ │ FUZZ-ENG    │  ← 3 lanes    │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘               │
│         │               │               │                        │
│         ├── window #1   ├── window #1   ├── window #1           │
│         ├── window #2   ├── window #2   ├── window #2           │
│         ├── window #3   ├── window #3   ├── window #3           │
│         ├── window #4   ├── window #4   ├── window #4           │
│         └── window #5   └── window #5   └── window #5           │
│              │               │               │                   │
│         findings       findings        findings                   │
│         (trust graph)  (exploits)      (edge cases)              │
│              │               │               │                   │
│              └───────────────┼───────────────┘                   │
│                              │                                    │
│                              ▼                                    │
│                     ┌───────────────┐                            │
│                     │   CHAINER     │  ← 1 call                   │
│                     │ (merge all)   │    reads ALL findings       │
│                     └───────┬───────┘    from 3 lanes             │
│                             │                                     │
│                        exploit chains                             │
│                                                                  │
│  15 LLM calls total (5 windows × 3 lanes + 1 chainer)            │
│  Each call: ~3,000 chars → ~3-8 seconds → 0 timeout              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Before vs After

```
SEBELUM (1 prompt monster)         SESUDAH (split 1000-token)
─────────────────────────────      ───────────────────────────────

┌────────────────────────┐         ┌────┐ ┌────┐ ┌────┐ ┌────┐
│                        │         │ #1 │ │ #2 │ │ #3 │ │ #4 │
│  16,000 chars          │         └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘
│  350 lines             │            │      │      │      │
│                        │            ▼      ▼      ▼      ▼
│  1 call per lane       │         ┌────────────────────────┐
│                        │         │ findings accumulated   │
│  🔴 524 timeout (50%)  │         │ across all windows     │
│  🔴 model overwhelmed  │         │                        │
│  🔴 missed findings    │         │ 🟢 0 timeout            │
│                        │         │ 🟢 focused per function │
└────────────────────────┘         │ 🟢 higher precision     │
                                   └────────────────────────┘

Calls/lane:  1                     Calls/lane:  5
Total:       3                     Total:       16 (15 lane + 1 chainer)
Reliability: 50%                   Reliability: 100%
Findings:    26                    Findings:    ~30 (better precision)
```

---

## Chainer: the missing cross-function context

```
Window #3: "Reflected XSS in /search?q → raw HTML echo"
Window #4: "Auth bypass via plaintext role cookie"
Window #5: "Unauthenticated /transfer action"

        CHAINER reads ALL 3 findings
                    │
                    ▼
   "Reflected XSS → cookie theft → auth bypass → /transfer drain"
   
   Chainer doesn't need the source code.
   Chainer only needs the FINDINGS from each window.
```

---

## Dead zone merge (anti-orphan)

```
Window #4: 3,555 chars (full)  ──┐
Window #5:   350 chars (tiny)  ──┤ → merged into one window
                                 │    (3,905 chars, still < 4,000)
No tiny orphan: every window     │
has enough context for the LLM. ─┘
```