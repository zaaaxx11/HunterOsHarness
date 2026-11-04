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
- [ ] Fix forge deps → test auto_extract end-to-end
- [ ] Validate debunk_pass bedain real vs false positive
- [ ] Chain review (LLM review VERIFIED findings → chain finding)

---

## 7. Cara Lanjutin

```
cd ~/HunterOsHarness
# 1. Benerin forge deps dulu (blokir utama)
# 2. Test auto_extract: forge build → slither → auto_create → debunk
# 3. Kalau 3-5 VERIFIED findings keluar → pipeline sukses
# 4. Push + deploy VPS 6h hunt
```