# relay-settlement Security Audit — LLM-Augmented (Retryable)

**Date:** 2026-11-18 19:23 | **Model:** deepseek-v4.1-flash | **Retries:** 5
**Evidence:** 125 verified, 487 sha256-chained artifacts

---

## Executive Summary

See manual executive summary in previous commits.

---

## Attack Chains

LLM unavailable — see manual chain analysis in previous commit

---

## Individual Reviews

**F-0001** [evm-arithmetic-trust]: EXHAUSTED_RETRIES:5
**F-0002** [evm-arithmetic-trust]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-
**F-0003** [reentrancy]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-
**F-0004** [reentrancy]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-
**F-0005** [reentrancy]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-
**F-0006** [evm-unverified-assumption]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-
**F-0007** [evm-unverified-assumption]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-
**F-0008** [evm-unverified-assumption]: ERR502: <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-

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

---
*HunterOsHarness v0.11.0 + deepseek-v4.1-flash | Retryable: 5x, 300s timeout*
