# Code4rena - Sequence Audit Response

This document is a response to the [Code4rena Audit](./code4rena-audit.pdf). This report is also available on the [Code4rena website](https://code4rena.com/reports/2025-10-sequence).

We also include responses to issues we have addressed that were found during the audit, but not included in the final report.

## High Findings

### H-01: Chained signature with checkpoint usage disabled can bypass all checkpointer validation

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/F-292](https://code4rena.com/audits/2025-10-sequence/submissions/F-292).

This finding has been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/95](https://github.com/0xsequence/wallet-contracts-v3/pull/95).

The use of nested chained signatures is blocked.

### H-02: Partial signature replay/frontrunning attack on session calls

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/F-395](https://code4rena.com/audits/2025-10-sequence/submissions/F-395).

This finding has been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/89](https://github.com/0xsequence/wallet-contracts-v3/pull/89).

The hashing strategy now hashing the entire payload, wallet address and call index.

This change also fixes M-01.

## Medium Findings

### M-01: Session signatures replay across wallets due to missing wallet binding

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/F-124](https://code4rena.com/audits/2025-10-sequence/submissions/F-124).

See H-02 above.

### M-02: Static signatures bound to caller revert under ERC-4337, causing DoS

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/F-326](https://code4rena.com/audits/2025-10-sequence/submissions/F-326).

This finding has been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/92](https://github.com/0xsequence/wallet-contracts-v3/pull/92).

`isValidSignature` is called internally.

### M-03: `BaseAuth.recoverSapientSignature` returns a constant instead of signer image hash, breaking sapient signer flows

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/F-358](https://code4rena.com/audits/2025-10-sequence/submissions/F-358).

This finding is acknowledged.

Returning a static image hash allows the child wallet to act as a flexible sapient signer, supporting evolving ownership.

A child wallet with a fixed image hash can instead embed their configuration tree within the parent wallet's configuration as a nested tree.

### M-04: Factory `deploy` reverts instead of returning address when account already exists

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/F-374](https://code4rena.com/audits/2025-10-sequence/submissions/F-374).

This finding has been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/93](https://github.com/0xsequence/wallet-contracts-v3/pull/93).

A factory wrapper has been added that detects existing deployments and returns early.

## Low Findings

Submission for all low findings: [https://code4rena.com/audits/2025-10-sequence/submissions/S-426](https://code4rena.com/audits/2025-10-sequence/submissions/S-426).

### L-01: Incorrect intermediate validation of cumulative parameter rules

This finding is intended behaviour.

Each call must pass validation independently.

### L-02: Value usage is incremented for fallback and aborted calls

This finding is intended behaviour.

Cumulative permissions are exhausted regardless of call success.

### L-03: Nonce consumption reverts on execution failure enabling signature replay attacks

This finding is intended behaviour.

The nonce is only intended to be consumed on successful execution.

### L-04: Unnecessary bitmasking in `LibBytes::readUnitX`

This finding is acknowledged and as it is not a security exploit, will be addressed in a future release.

### L-05: Inefficient usage limit increment call

This finding is acknowledged and as it is not a security exploit, will be addressed in a future release.

### L-06: Duplicated delegate call validations

This finding is acknowledged and as it is not a security exploit, will be addressed in a future release.

## Unreported Findings

### S-436: Protocol is not `EIP712` compliant: incorrect typehash in `Payload.toDIP712` function

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/S-436](https://code4rena.com/audits/2025-10-sequence/submissions/S-436).

This finding is invalid. However it references some invalid comments which have been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/94](https://github.com/0xsequence/wallet-contracts-v3/pull/94).

### S-368: Execution of registered static signatures with no chain ID reverts

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/S-368](https://code4rena.com/audits/2025-10-sequence/submissions/S-368).

This finding has been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/91](https://github.com/0xsequence/wallet-contracts-v3/pull/91).

This finding represents a missing feature rather than an exploit.

### S-308 / S-512: Signature Canonicalisation Missing - Contract Accepts Different Encodings - Packed ABI-Tuple and Trailing Bytes as the Same Valid Signature

Submissions: [https://code4rena.com/audits/2025-10-sequence/submissions/S-308](https://code4rena.com/audits/2025-10-sequence/submissions/S-308) and [https://code4rena.com/audits/2025-10-sequence/submissions/S-512](https://code4rena.com/audits/2025-10-sequence/submissions/S-512).

These findings have been fixed here: [https://github.com/0xsequence/wallet-contracts-v3/pull/88](https://github.com/0xsequence/wallet-contracts-v3/pull/88).

These findings are not exploits. However we agree that the suggested encoding lengths should be verified.

### S-619: Protocol Failures on Certain Supported Chains Due to Lack of Support RIP-7212 precompile and Hardcoded P256 Verifier Address

Submission: [https://code4rena.com/audits/2025-10-sequence/submissions/S-619](https://code4rena.com/audits/2025-10-sequence/submissions/S-619).

This finding has been fixed here: [https://github.com/0xsequence/live-contracts/pull/81](https://github.com/0xsequence/live-contracts/pull/81).

The deployment of the P256 verifier fallback has been added to our deployment flow.
