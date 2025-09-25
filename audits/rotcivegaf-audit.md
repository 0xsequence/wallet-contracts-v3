# Sequence V3 Wallet Contracts Security Review

- Security researcher: [@Rotcivegaf](https://github.com/rotcivegaf)
- Date From: 21/08/2025
- Date To: 15/09/2025
- Repository: [0xsequence/wallet-contracts-v3](https://github.com/0xsequence/wallet-contracts-v3)
- Commit Hash: [`2401d7631e636d9a45f17d2ae80b43513a0b68ed`](https://github.com/0xsequence/wallet-contracts-v3/tree/2401d7631e636d9a45f17d2ae80b43513a0b68ed)

# Content

- [Disclaimer](#disclaimer)
- [Scope](#scope)
- [Executive Summary and Observations](#executive-summary-and-observations)
- [Risk Classification](#risk-Classification)
    - [Impact](#impact)
    - [Likelihood](#likelihood)
- [Findings](#findings)
    - [Medium](#medium)
        - [[M-01] Unsorted implicitBlacklist enables bypass the blacklist](#m-01-unsorted-implicitBlacklist-enables-bypass-the-blacklist)
    - [Low](#Low)
        - [[L-01] Shadow functions selector on Hooks contract](#l-01-shadow-functions-selector-on-hooks-contract)
    - [Non-Critical](#non-critical)
        - [[NC-01] Unused `using`s](#nc-01-unused-usings)
        - [[NC-02] Unused `error`s](#nc-02-unused-errors)
        - [[NC-03] Unused imports](#nc-03-unused-imports)
        - [[NC-04] Unused functions and unused constant](#nc-04-unused-functions-and-unused-constant)
        - [[NC-05] The deploy can be frontrunned](#nc-05-the-deploy-can-be-frontrunned)

## Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. 

This is a time, resource and expertise bound effort where we try to ﬁnd as many vulnerabilities as possible. 

I can not guarantee 100% security after the review or even if the review will ﬁnd any problems with your smart contracts. 

Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

## Scope

All files in [`src/`](https://github.com/0xsequence/wallet-contracts-v3/tree/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src) folder with the exception of the following files:

- [`./src/Estimator.sol`](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/Estimator.sol)
- [`./src/Guest.sol`](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/Guest.sol)
- [`./src/Simulator.sol`](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/Simulator.sol)
- [`./src/utils/Base64.sol`](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/utils/Base64.sol) [(copy of solady lib)](https://github.com/Vectorized/solady/blob/main/src/utils/Base64.sol)
- [`./src/utils/WebAuthn.sol`](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/utils/WebAuthn.sol) [(copy of solady lib)](https://github.com/Vectorized/solady/blob/main/src/utils/WebAuthn.sol)
- [`./src/utils/P256.sol`](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/utils/P256.sol) [(copy of solady lib)](https://github.com/Vectorized/solady/blob/main/src/utils/P256.sol) *

> Note *: The functions `hasPrecompileOrVerifier` and `hasPrecompile` was removed and the `verifySignature` and `verifySignatureAllowMalleability` was modified

## Executive Summary and Observations

The security review was focused on key aspects including signature validation, session management, replay protection, delegatecall/update flows, privilege boundary design, and extensibility patterns.

The analysis traced the logic and data flows across critical components, especially examining how permissions and call routing operate between Stage1 and Stage2 modules, session verifiers, and the Hooks fallback structure.

The codebase is modular and highly extensible, which introduces significant escalation and persistence vectors if privilege boundaries are weakened.

Given its versatility, users can configure almost their entire wallet. However, this versatility can lead to security risks, such as enabling a malicious hook.

The coverage of the test suite covers all code as well as complex cases.

## Risk Classification

| Likelihood \ Impact | High     | Medium | Low    |
|---------------------|----------|--------|--------|
| High                | Critical | High   | Medium |
| Medium              | High     | Medium | Low    |
| Low                 | Medium   | Low    | Low    |

### Impact

- High: Leads to a significant material loss of assets in the protocol or significantly
harms a group of users.
- Medium: Only a small amount of funds can be lost (such as leakage of value) or a
core functionality of the protocol is affected.
- Low: Can lead to any kind of unexpected behavior with some of the protocol's
functionalities that's not so critical.

### Likelihood

- High: Attack path is possible with reasonable assumptions that mimic on-chain
conditions, and the cost of the attack is relatively low compared to the amount of
funds that can be stolen or lost.
- Medium: Only a conditionally incentivized attack vector, but still relatively
likely.
- Low: Has too many or too unlikely assumptions or requires a significant stake by
the attacker with little or no incentive.

## Findings

| Severity     | Amount |
|--------------|--------|
| High         |   0    |
| Medium       |   1    |
| Low          |   1    |
| Non-Critical |   5    |

## Medium

### [M-01] Unsorted implicitBlacklist enables bypass the blacklist

- Impact: High
- Likelihood: Low

#### Code Snippets

- [./src/extensions/sessions/implicit/ImplicitSessionManager.sol#L59-L81](https://github.com/0xsequence/wallet-contracts-v3/blob/2401d7631e636d9a45f17d2ae80b43513a0b68ed/src/extensions/sessions/implicit/ImplicitSessionManager.sol#L59-L81)

#### Description

In the `_isAddressBlacklisted` function, it is assumed that the blacklist received is sorted `/// @param blacklist The sorted array of blacklisted addresses`.
This causes false positives in the binary search within the `_isAddressBlacklisted` function.

An attacker could supply a unsorted blacklist where the target (`sessionSigner` or `call.to`) has been revoked, but when performing the binary search, we would obtain a false negative, causing this blacklisted target to be authorized.

#### PoC

```solidity
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import { ImplicitSessionManager } from "src/extensions/sessions/implicit/ImplicitSessionManager.sol";

contract PoCTest is Test, ImplicitSessionManager {
  address[] blacklist;
  address blacklistedAddress = address(3);

  function testSortedBlacklist() public {
    blacklist.push(address(1));
    blacklist.push(address(2));
    blacklist.push(blacklistedAddress);

    assertTrue(_isAddressBlacklisted(
        blacklistedAddress,
        blacklist
    ));
  }

  function testUnsortedBlacklist() public {
    blacklist.push(blacklistedAddress);
    blacklist.push(address(1));
    blacklist.push(address(2));

    assertTrue(_isAddressBlacklisted(
        blacklistedAddress,
        blacklist
    ));
  }
}
```

#### Fix

[Verify sorted blacklist](https://github.com/0xsequence/wallet-contracts-v3/commit/6ead0f1e611b15f9e008bbbc0b1b7ba186e0eddc)

## Low

### [L-01] Shadow functions selector on Hooks contract

- Impact: Low
- Likelihood: Low 

#### Code Snippets

- [./src/modules/Hooks.sol#L27-L122](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/modules/Hooks.sol#L27-L122)

#### Description

The Hooks contract works as a proxy, however the following selectors cannot be used as they are defined within the Hooks:

- readHook(bytes4)
- addHook(bytes4,address)
- removeHook(bytes4)
- onERC1155Received(address,address,uint256,uint256,bytes)
- onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)
- tokensReceived(address,address,address,uint256,bytes,bytes)
- onERC721Received(address,address,uint256,bytes)
- tokenReceived(address,uint256,bytes)
- receive()

In addition to the selectors for the functions implemented by the module

The most critical selectors are `onERC1155Received`, `onERC1155BatchReceived`, `tokensReceived`, `onERC721Received`, `tokenReceived`, and `receive`, as the user may want to modify these functions by assigning them a behavior.

#### PoC

A user might want to deposit their ethers in Aave upon receiving them, and with the current implementation, this would not be possible.

#### Fix

One could choose to define the selectors in another contract and leave the Hooks contract only with the fallback behavior and everything related to hook management. However, the contract tends to consume more gas, and the average user would not use this functionality. If they did, it would be in isolated cases.

## Non-Critical

### [NC-01] Unused `using`s

The follow `using`s are not used:

- [`using LibBytes for bytes;`, Guest.sol#L15](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/Guest.sol#L15)
- [`using LibBytes for bytes;`, SessionManager.sol#L19](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/extensions/sessions/SessionManager.sol#L19)
- [`using LibBytes for bytes;`, ExplicitSessionManager.sol#L14](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/extensions/sessions/explicit/ExplicitSessionManager.sol#L14)

Proposal Fix: [PR #77](https://github.com/0xsequence/wallet-contracts-v3/pull/77)

### [NC-02] Unused `error`s

- [Stage1Auth.sol#L16-L17:](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/modules/auth/Stage1Auth.sol#L16-L17)
```solidity
  /// @notice Error thrown when the signature type is invalid
  error InvalidSignatureType(bytes1 _type);
```

- [P256.sol#L9-L16:](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/utils/P256.sol#L9-L16)
```solidity

  /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
  /*                        CUSTOM ERRORS                       */
  /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/


  /// @dev Unable to verify the P256 signature, due to missing
  /// RIP-7212 P256 verifier precompile and missing Solidity P256 verifier.
  error P256VerificationFailed();
```

Proposal Fix: [PR #78](https://github.com/0xsequence/wallet-contracts-v3/pull/78)

### [NC-03] Unused imports

The follow imports are not used:

- [`Permission`, SessionManager.sol#L16](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/extensions/sessions/SessionManager.sol#L16)

- [`import { Payload } from "../Payload.sol";`, ICheckpointer.sol#L4](https://github.com/0xsequence/wallet-contracts-v3/blob/a61c891ce773cde95c4f062764f38d458416c56f/src/modules/interfaces/ICheckpointer.sol#L4)

Proposal Fix: [PR #79](https://github.com/0xsequence/wallet-contracts-v3/pull/79)

### [NC-04] Unused functions and unused constant

Although the following functions are not used by the protocol, since they are inside a library, they do not affect gas consumption, only the number of lines of code.

From `./src/utils/P256.sol`:
- `verifySignatureAllowMalleability`
- `normalized`
- `tryDecodePoint`
- `tryDecodePointCalldata`

Also the constant `N` is unused

Proposal Fix: [PR #80](https://github.com/0xsequence/wallet-contracts-v3/pull/80)

### [NC-05] The deploy can be frontrunned

In the Factory contract, the `deploy` function performs a `create2`, creating a new contract. 

A malicious actor could frontrun this transaction, causing the first transaction to be revert. The only thing the malicious actor could change is the value, but since the modules do not receive value, this has no effect.

Although the malicious actor would not gain any benefit, and would even help the original sender, I want to leave this as a known issue.