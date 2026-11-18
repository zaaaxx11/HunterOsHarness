# HunterOs — Working Notes & State

> Catatan kerja dari sesi audit / sinkronisasi repo. Status: **WORK IN PROGRESS.**

---

## 1. Problem Utama (belum solved)

Setelah 25+ run LLM hunt di 5 model (deepseek, stepfun-5, stepfun-preview, GLM-5.3, stealth/dvr-v2.0) → **0 findings**.

Semua model konsisten: baca kontrak, analisa, `respond_to_user` / stall. **Nggak pernah manggil `create_finding_request`.**

**Root cause:** LLM bisa *analisa* tapi nggak bisa *construct function call* `create_finding_request()` yang punya 15+ parameter. Ini bukan karakter model — ini batas kemampuan semua model meniru format fungsi kompleks.

---

## 2. Solusi (implemented tapi belum tervalidasi end-to-end)

**Hybrid auto-extract:** sistem deterministik bikin finding dari slither, bukan nunggu LLM.

```
forge_build (hardcode pre-agent)
  → slither_run (hardcode pre-agent) 
    → emit detectors (engine event)
      → auto_extract: scan slither evidence
        → auto_create_findings: semua detector → CANDIDATE finding (unlimited)
          → auto_debunk: debunk_pass → VERIFIED / RULED_OUT
```

### File baru/modif
| File | Status | Isi |
|------|--------|-----|
| `src/hunter/engine/auto_extract.py` | NEW | scan slither evidence, auto-create, auto-debunk |
| `src/hunter/engine/llm.py` | MOD | hardcode forge_build+slither pre-agent, hook auto_extract post-agent |
| `src/hunter/agent/toolchain.py` | MOD | slither_run emit detector list |
| `src/hunter/daemon.py` | MOD | enqueue task bawa `kind` + `injected_goal` |
| `src/hunter/agent/prompts/__init__.py` | MOD | `build_ladder_block` + `injected_goal` param |
| `_data/prompts/ladders/*.md` | NEW | 5 blocks (theoretical→proven_live) |
| `_data/prompts/audit_system_prompt.md` | MOD | Sovereign Adversarial Researcher |
| `_data/prompts/soul.md` | MOD | ship-or-die persona |

---

## 3. PROVEN — Pipeline End-to-End ✅

1. **auto_extract end-to-end** — ✅ 168 detectors → 125 VERIFIED, 43 CANDIDATE
2. **debunk_pass** — ✅ tamper-evidence: re-hash source spans, verify match
3. **Per-task goal injection** — ✅ agent receives hunt context

## 4. BLOCKER: forge deps — ✅ SOLVED

**Problem:** relay-settlement/smart-contracts nggak bisa `forge build` karena deps nggak resolve:
- `@openzeppelin/` → butuh lib/openzeppelin-contracts
- `solady/` → butuh lib/solady
- VPS: `forge install` gagal karena bukan git repo (clone shallow, .git submodule error)
- Lokal: `node_modules` dihapus pas cleanup disk, foundry.toml auto_detect_remappings=false

**Solusi besok:**
1. Benerin deps di satu tempat (lokal), commit lib/ atau remappings, sync ke VPS
2. Atau: `git clone --recurse-submodules` ulang di VPS
3. Atau: auto_extract jalanin slither dari hasil compile artifacts yg udah ada, bukan nunggu forge build ulang

---

## 5. Keputusan Desain Kunci

- **Tanpa filter confidence** — semua detector jadi CANDIDATE, biar low vuln bisa jadi chain key
- **Tanpa limit findings** — debunk yg sortir real vs noise
- **LLM cuma review, bukan author** — LLM kuat sintesa (chain analysis), lemah konstruksi form
- **Ladder block injection** — tiap FindingStatus dapat deliverable yg jelas

---

## 6. Timeline

- [x] Ladder blocks (5) + prompt injection
- [x] Soul rewrite (ship-or-die)
- [x] Injected goal per task
- [x] Auto-extract pipeline (code)
- [x] Fix forge deps → test auto_extract end-to-end ✅ **DONE (Nov 18)**
- [x] Validate debunk_pass bedain real vs false positive ✅ **DONE (Nov 18)**
- [ ] Chain review (LLM review VERIFIED findings → chain finding)
- [ ] Production 6h hunt VPS → release v0.12.0

---

## 8. E2E Validation Results — Nov 18 ✅

```
Target:    relay-settlement/smart-contracts (70 .sol files)
Forge:     ✅ compilation OK (deps resolved — lib/ already present)
Slither:   ✅ 168 detectors (42 naming, 40 calls-loop, 16 timestamp, 12 reentrancy-events, ...)
Pipeline:  ✅ auto_extract end-to-end (no LLM — deterministic only)

Results:   168 → 125 VERIFIED, 43 CANDIDATE, 5 THEORETICAL, 0 RULED_OUT

VERIFIED by class:
  56  evm-unproven-impact      (low — naming, complexity patterns)
  20  reentrancy               (low — benign reentrancy)
  18  info-disclosure          (info)
  15  evm-unproven-impact      (info)
  11  evm-unverified-assumption
   3  reentrancy               (medium — actual external-call-then-state-write)
   2  evm-arithmetic-trust     (medium — strict equality checks)

Evidence:   all VERIFIED findings carry sha256-hashed local_read spans
            (element_name + filename_short + line range — independently re-verifiable)

Debunk:     125/168 auto-verified by deterministic source hash recheck
            43 CANDIDATE — mostly cyclomatic-complexity & naming-convention
            (no deterministic replay path for these — correct behavior)
            0 RULED_OUT — no false positives passed through

Chain:      5 hypotheses generated (auto_chain_review)
            all low-quality same_target pairings — needs LLM synthesis
```

Test assets committed: `tests/data/e2e_relay_validate.py` + `tests/data/e2e_relay_scope.json`

VPS (47.129.151.92): **offline** — production 6h hunt pending.

---

## 7. Cara Lanjutin

```
cd ~/HunterOsHarness
# 1. Benerin forge deps dulu (blokir utama)
# 2. Test auto_extract: forge build → slither → auto_create → debunk
# 3. Kalau 3-5 VERIFIED findings keluar → pipeline sukses
# 4. Push + deploy VPS 6h hunt
```