# relay-settlement Security Audit — LLM-Augmented

**Date:** 2026-11-18 | **Engine:** HunterOsHarness v0.11.0 + deepseek-v4.1-flash
**Evidence:** 125 verified, 487 sha256-chained artifacts

---

## Executive Summary

Provider 503 — see manual report above

---

## Attack Chains

Provider 503 — see manual chains below

---

## Individual Reviews

F-0001: NOISE: Reverting exactly when `amount == 0` is a conventional and safe nonzero-amount check, not an exploitable arithmetic condition.
F-0002: FAILED
F-0003: LIKELY: the external call can reenter before cachedReportHash is updated, allowing a stale cached hash to be read or reused, though the actual impact depends on how that cached hash is consumed.
F-0004: FAILED
F-0005: LIKELY: HUB.burn is an external call before gasPayments is updated, allowing reentrancy to exploit stale payment state.
F-0006: FAILED
F-0007: LIKELY — Ignoring `_addSource`’s return value can allow duplicate source processing to be treated as a fresh addition, undermining idempotency if callers rely on that result.
F-0008: REAL_EXPLOIT: ignoring the return value of signature verification allows invalid spender authorizations to be treated as valid, enabling forged withdrawals.

---

## Raw Findings

- **F-0001** [evm-arithmetic-trust] RelayFundingPool._requireAmount strict equality amount==0
- **F-0002** [evm-arithmetic-trust] TonVmPayloadBuilder._computeQueryId strict equality (raw & 0x3FF)==FORBIDDEN
- **F-0003** [reentrancy] StorkFastAdapter.decodeAndVerify: external call before state write cachedReportHash
- **F-0004** [reentrancy] RelayUsdRateLimiter.consume: external call before state update usdValue
- **F-0005** [reentrancy] WithdrawGasPayer.payGas: HUB.burn before gasPayments[hash]=feeAmount
- **F-0006** [evm-unverified-assumption] RelayOracleMultisig._validateSignatures unused return value
- **F-0007** [evm-unverified-assumption] RelayOracleIdempotencyStore._addSource unused return value
- **F-0008** [evm-unverified-assumption] RelayAllocator.consumeSpenderSignature unused return - forged withdrawals
