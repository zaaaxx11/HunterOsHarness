# PRE-REPORT checklist

One failed item blocks the report. Every item below must pass before a
report is filed. There are no partial reports.

## Evidence

- [ ] `poc_path` exists per finding.
- [ ] `proven-live` findings carry an `evidence_ref`.
- [ ] Theoretical findings are labeled theoretical.
- [ ] No finding marked "submitted" is unverified.

## Adversary

- [ ] Every concrete finding has been blind-adversary reviewed.
- [ ] Overturns are recorded.

## Waves

- [ ] Re-audit of the previous wave is recorded before a new wave starts.
- [ ] Verdict per wave is recorded with a reason.

## Report

- [ ] Impact chain is complete: trigger -> effect -> boundary.
- [ ] A falsifier is recorded per finding.
- [ ] No em-dash anywhere in the report.
- [ ] No AI-slop.
- [ ] Human tone throughout.
- [ ] PoC is embedded in the report.
- [ ] Real tool output only — no synthesized or invented output.

## Retro

- [ ] Lessons are recorded after the report.
- [ ] A pattern candidate covering >=2 targets is proposed for promotion.