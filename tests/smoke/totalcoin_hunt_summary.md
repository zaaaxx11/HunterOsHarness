# Totalcoin Bug Bounty — Hunt Summary (HunterOsHarness)

**Target**: api.totalcoin.io, web.totalcoin.io, totalcoin.io/* (portal utama explicitly out-of-scope, di-skip)
**Engine**: HunterOs `llm` (devora / devora-01/tencent/hy4-flash)
**Duration**: 5000s x2 runs (broad + deep-dive)
**Total findings**: 27 candidates (2 ruled_out) + deep-dive run in progress

## Checker verdict (verified manually via curl from VPS)

### CONFIRMED VALID — Low / Info only
| ID | Title | Severity (program) | Note |
|----|-------|-------------------|------|
| F-0001 | API endpoints accessible without auth (root `/`) | Low | Returns `{"data":null,"errorCode":-1}` — no data leak, just open endpoint |
| F-0002 | `/api` accessible without auth | Low | same empty-response pattern |
| F-0006 | Error response exposes internal error codes | Low | `errorCode:-1` in JSON envelope — info disclosure |
| F-0011 | Generic error without details | Info | by-design error shape |
| F-0012 | Debug endpoint `/api?debug=true` reachable | Medium* | needs confirmation it leaks internals, not just toggles behavior |
| F-0018–F-0023 | Missing security headers (HSTS/CSP/XFO/etc) on portal | Low | program excludes "UX not relating to security"; headers usually Low |

### FALSE POSITIVES (ruled out by manual check)
| ID | Claimed | Reality |
|----|---------|---------|
| F-0004/0005/0007 | "auth bypass / 200 with error body" on `/v1/accounts` | Returns `data:null` — no account data exposed |
| F-0008 | Balances leak without auth | `data:null` — no balance exposed |
| F-0024 | Unauthenticated account verification | `data:null` |
| F-0025 | Account ID enumeration | `/v1/accounts/1..1000` all return identical empty error — no per-ID data |
| F-0026/0027 | Auth bypass on `/accounts/me` | Returns empty error, NOT user data — no bypass |
| F-0009/0010 | Cookie flags | DDoS-Guard sets these, not the app — ruled_out |

## Bottom line for submission

- **No Critical / High confirmed.** Every "auth bypass / account / balance" candidate was verified to return `{"data":null,"errorCode":-1}` — the API is open but leaks NOTHING sensitive.
- Best realistic submission: **F-0006 (internal error code leakage)** + **F-0012 (debug endpoint)** as Low-severity info disclosures. Max payout Low = $200 each, and program may reject as "by design".
- Program Totalcoin excludes "not reproducible" & "business logic errors" — all findings here are reproducible but low-impact.

## Remaining work
- Deep-dive run (proc_13dab1615901) still hunting `/v1/accounts`, `/v1/balances`, `/v1/orders`, debug endpoint.
- If deep-dive finds an endpoint that returns REAL data (non-null) without auth → that is the actual Critical/High. So far: none.
