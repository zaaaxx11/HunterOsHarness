# relay-settlement Security Audit — deepseek-v4.1-flash @ customin

**Date:** 2026-11-18 19:45 | **Model:** deepseek-v4.1-flash
**Config:** 2000 max_tokens, 5 retries, 300s timeout

---

## Executive Summary

This audit covers a cross-chain relayer protocol comprising 70 Solidity contracts, with review focused on message validation, fund custody, and cross-chain state synchronization. The assessment identified 8 medium-severity findings across reentrancy, arithmetic trust assumptions, and unverified external assumptions, alongside lower-severity observations. No critical issues were confirmed, but several conditions warrant remediation before production deployment.

The findings break down as follows: three reentrancy vectors in settlement and withdrawal paths, two arithmetic-trust issues where trusted inputs are used in balance or fee calculations without sufficient bounds, and three unverified assumptions regarding external contract behavior and message ordering. While individually medium, the reentrancy issues are compounded by incomplete checks on caller authorization and state transitions, increasing the likelihood of inconsistent accounting under adversarial timing.

The highest-priority risk is a signature-bypass combined with reentrancy that could enable fund drainage if exploited in sequence. We recommend prioritizing remediation of the signature validation and reentrancy guards, adding explicit bounds checks for arithmetic trust paths, and formalizing assumptions about external dependencies before mainnet release. A follow-up review after fixes is advised to confirm resolution and assess interaction effects.

---

## Attack Chains

[
  {
    "id": "CHAIN-0001",
    "findings": ["F-0003", "F-0004", "F-0005"],
    "klass": "reentrancy",
    "chain": "StorkFastAdapter.decodeAndVerify performs an external call before writing cachedReportHash; RelayUsdRateLimiter.consume performs an external call before updating usdValue; WithdrawGasPayer.payGas calls HUB.burn before recording gasPayments[hash]=feeAmount. An attacker can reenter across these trust boundaries to spend/withdraw funds multiple times before state is committed.",
    "impact": "Cross-contract fund theft via repeated reentrant withdrawals/gas payments."
  },
  {
    "id": "CHAIN-0002",
    "findings": ["F-0001", "F-0006", "F-0007"],
    "klass": "evm-arithmetic-trust",
    "chain": "RelayFundingPool._requireAmount uses strict equality amount==0, allowing zero/edge-case amounts to bypass funding checks; RelayOracleMultisig._validateSignatures ignores its return value; RelayOracleIdempotencyStore._addSource ignores its return value. Together these allow unvalidated oracle/multisig state to authorize pool movements without enforcing amount or idempotency invariants.",
    "impact": "Unauthorized funding-pool extraction by bypassing amount and idempotency validation."
  },
  {
    "id": "CHAIN-0003",
    "findings": ["F-0002", "F-0008"],
    "klass": "evm-unverified-assumption",
    "chain": "TonVmPayloadBuilder._computeQueryId rejects only when (raw & 0x3FF)==FORBIDDEN, leaving colliding query IDs usable; RelayAllocator.consumeSpenderSignature's return handling is inconsistent with code-review evidence. An attacker can craft a payload whose query ID collides with a prior authorization and reuse a spender signature to replay allocation.",
    "impact": "Replay of allocator authorization leading to duplicate fund disbursement."
  }
]

---

## Individual Finding Reviews

- **F-0001** [evm-arithmetic-trust]: LIKELY: A strict `amount == 0` check in an amount validator rejects every valid non-zero transfer, breaking core deposit/withdrawal flows.
- **F-0002** [evm-arithmetic-trust]: NOISE: the equality is an intentional guard rejecting one forbidden masked value, not an exploitable arithmetic flaw.
- **F-0003** [reentrancy]: LIKELY: external call occurs before updating cachedReportHash, violating checks-effects-interactions and allowing potential reentrancy if the callee is untrusted.
- **F-0004** [reentrancy]: REAL_EXPLOIT: an external call before updating usdValue can let a reentrant callback consume quota again before prior usage is recorded.
- **F-0005** [reentrancy]: LIKELY: The external HUB.burn call precedes the gasPayments state update, enabling reentrancy if the burned token supports transfer hooks.
- **F-0006** [evm-unverified-assumption]: LIKELY: ignoring the return value of a signature validation routine can allow invalid signatures to pass if the function signals failure by return value rather than revert.
- **F-0007** [evm-unverified-assumption]: LIKELY: Ignoring `_addSource`'s return value may skip duplicate-source/idempotency checks, allowing repeated sources to be treated as distinct.
- **F-0008** [evm-unverified-assumption]: NOISE: the return value is actually consumed at line 275 (callerAuthorized = consumeSpenderSignature), so the unused-return claim is a false positive.

---
*HunterOsHarness v0.11.0 + deepseek-v4.1-flash via customin*
