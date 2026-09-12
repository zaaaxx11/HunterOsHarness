# Business — HunterOs Harness

*Positioning, pricing, and roadmap. Concise by design; the product is the
argument.*

## Positioning

**Evidence-first security auditing: trustless, pay-per-verified-vuln.**

Traditional pentests sell hours and produce PDFs whose claims cannot be
checked. Bug bounties sell attention and drown in noise. HunterOs sells
**proof**: every finding carries a hash-chained evidence pack that an
independent party can replay and re-verify — including against a Merkle
commitment published at engagement time. If it cannot be replayed, it is a
`candidate`, not a `verified`, and it does not bill. The customer's trust is
placed in the chain, not in the vendor's reputation.

## Tiers

| Tier | Price | What it is |
| ---- | ----- | ---------- |
| **OSS core** | MIT, free | This repo: kernel, deterministic engine, scope gate, TUI, reporting. The trust anchor — anyone can verify the machinery. |
| **Cloud seats** | **$49 / seat / mo** | Hosted dashboards, team workflows, scheduled regression scans, evidence storage, integrations. |
| **Pay-per-verified-vuln** | critical **$400** · high **$150** · medium **$50** | Continuous hunting on your attack surface. Only **replay-verified** findings bill — ever. Engagement floor **$500**. |
| **One-time pentest** | **$1.5k – $8k** | Fixed-scope engagement with a human-in-the-loop, delivered as a verifiable evidence pack, not a PDF. |
| **Enterprise** | **$3k – $6k / mo** | Dedicated continuous coverage, custom scope governance, SLA-backed adjudication, on-prem ledger option. |

## Unit economics (v0.2+, LLM engine era)

- A deep scan costs roughly **$30 – $45** in LLM + infrastructure
  (tokens + compute + the deterministic pre-pass).
- At the price points above, a single verified high finding covers ~3–5 full
  scans; the deterministic core (free) pre-filters most noise before the
  expensive brain runs.
- The debunk/challenger agent exists for economic reasons, not just quality
  ones: an overturned candidate costs minutes; a false-positive bill costs
  the positioning.

## Differentiators

1. **Verifiable evidence pack** — hash-chained, Merkle-ready; third parties
   can audit what was found *and what was checked* without trusting us.
2. **False-positive adjudication with SLA** — disputes are answered by
   replay, not rhetoric; the ledger settles the argument.
3. **Scope/consent gating as product** — fail-closed, structural, auditable;
   the compliance story enterprises actually need from an autonomous hunter.
4. **Regression bonds** — verified findings are re-scanned on schedule; a
   regression is detected and evidenced automatically, turning "pentest
   once" into "continuously proven".
5. **Bug-bounty export bridge** — evidence packs map onto bounty-platform
   submissions (HackerOne/Bugcrowd reports with attached proof).

## Competitor note

- **Strix** — agent-based pentesting; per-seat plus per-test pricing. Strong
  automation, but its output claims are not independently verifiable.
- **XBOW** — autonomous bounty hunter; priced per engagement. Closes the
  loop on exploitation but sells outcomes, not auditable evidence.
- **CodeAnt** — closest analog in the "verifiable findings" direction; our
  wedge is the ledger-native evidence chain (proof is the primitive, not a
  report attachment) and the pay-per-verified-vuln commercial model that
  only a ledger makes enforceable.
