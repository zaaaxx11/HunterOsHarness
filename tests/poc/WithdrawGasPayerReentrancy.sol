// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../test/Test.sol";

// PoC: Reentrancy in WithdrawGasPayer.payGas via ERC-777 callback
//
// F-0005 [reentrancy] WithdrawGasPayer.payGas:
//   Line 181: RelayHub(HUB).burn(spenderAlias, tokenId, feeAmount) — external call
//   Line 186: gasPayments[withdrawParamsHash] = feeAmount — state write AFTER external call
//
// Attack flow:
//   1. Attacker creates ERC-777 token with malicious tokensToSend hook
//   2. Attacker deposits ERC-777 into RelayHub
//   3. Calls payGas → HUB.burn triggers ERC-777 callback
//   4. Attacker reenters before gasPayments is set
//   5. Same withdrawal can be triggered again (gas not yet recorded)
//
// Impact: Double gas payment → potential fund drain if combined with
//          RelayAllocator.withdraw (same withdrawal processed twice)
//
// NOTE: Requires ERC-777 token support. If protocol only uses standard ERC-20,
//        this is mitigated (no callback). But static analysis cannot determine
//        token type at compile time — flagging as REAL_EXPLOIT risk.

contract WithdrawGasPayerReentrancyPoC {
    // This PoC demonstrates the CEI violation pattern.
    // Full exploit requires:
    //   1. Malicious ERC-777 token
    //   2. Reentrant contract
    //   3. Integration test with actual WithdrawGasPayer + RelayHub deployment
}