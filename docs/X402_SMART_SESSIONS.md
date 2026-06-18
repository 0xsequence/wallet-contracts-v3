# x402 Sapient Signer Documentation

This document describes the `X402SessionSapientSigner` contract used to validate x402 Permit2 payments through Sequence wallet ERC-1271 signatures.

The signer has two validation paths that both return `hashPolicy(policy)`:

- x402 payment digests
- Permit2 approval setup transactions for `policy.token`

The wallet configuration commits to the policy root once. That policy can authorize both x402 payments and the setup transaction needed to approve Permit2 for the policy token.

---

## 1. Overview

x402 Permit2 payments require a per-payment Permit2 witness transfer authorization. For a Sequence wallet, Permit2 verifies that authorization through the wallet's ERC-1271 path:

```
wallet.isValidSignature(permit2Digest, sequenceSignature)
```

The Sequence wallet wraps the external digest as `Payload.KIND_DIGEST` and validates the provided Sequence signature. If the signature includes an x402 sapient signer leaf, the wallet calls:

```
X402SessionSapientSigner.recoverSapientSignature(payload, sapientSignature)
```

For a payment digest, the x402 sapient signer:

1. Requires `payload.kind == Payload.KIND_DIGEST`.
2. Decodes the x402 session policy and payment metadata.
3. Recomputes the canonical x402 Permit2 digest.
4. Requires the recomputed digest to equal `payload.digest`.
5. Checks the stateless policy limits.
6. Verifies the session key signature over the wallet, policy root, and external digest.
7. Returns the policy root as the sapient image hash.

The returned policy root must match the sapient signer leaf committed in the wallet image hash. If it does not match, the wallet rejects the ERC-1271 signature.

For setup, the same signer can validate this transaction shape:

```
policy.token.approve(PERMIT2, type(uint256).max)
```

The setup transaction is policy-bound and requires session-key intent over the exact wallet transaction payload. To prevent the same rule from being used to reduce or revoke allowance, the amount must be exactly `type(uint256).max`.

---

## 2. Contract Scope

The implementation lives at:

```
src/extensions/x402/X402SessionSapientSigner.sol
```

It targets one payment method:

- x402 `exact`
- Permit2 witness transfer
- configured Permit2 verifying contract
- configured x402 Permit2 proxy as the Permit2 spender

It targets one setup transaction:

- a single call to `policy.token`
- nonce space no greater than `type(uint80).max - 1`
- calldata selector `approve(address,uint256)`
- spender equal to the configured Permit2 contract
- amount equal to `type(uint256).max`

It does not implement:

- EIP-3009 validation
- ERC-7710 delegation validation
- batch-settlement vouchers
- stateful total spend accounting
- recipient allowlists
- resource or origin allowlists
- arbitrary spender approvals

Those features require additional contracts or a broader policy format.

---

## 3. Constructor Parameters

The signer is deployed with two immutable addresses:

```
constructor(address permit2, address x402Permit2Proxy)
```

### `permit2`

The Permit2 contract used as the EIP-712 verifying contract when reconstructing the payment digest.

The setup path also requires ERC-20 approval calls to set this address as the spender.

### `x402Permit2Proxy`

The x402 Permit2 proxy used as the Permit2 `spender` in the signed payment digest.

These values are immutable so they do not need to be carried inside every policy or payment signature.

---

## 4. Payment Policy

The payment policy is the sapient image hash preimage for `Payload.KIND_DIGEST`. The wallet configuration commits to:

```
hashPolicy(policy)
```

### Encoding

```
struct Policy {
  address sessionKey;
  uint256 chainId;
  address token;
  uint256 maxAmountPerPayment;
  uint16 maxPayments;
  uint256 validBefore;
}
```

### Fields

#### `sessionKey`

The key authorized to sign x402 payments for this policy.

The sapient signer recovers this address from the session authorization signature. A zero session key is invalid.

#### `chainId`

The chain where the policy is valid.

If `chainId == 0`, the policy is chain-agnostic. Otherwise, it must equal `block.chainid`.

Permit2's EIP-712 domain already binds each payment digest to the current chain. This field exists to make the policy itself explicitly single-chain or multi-chain.

#### `token`

The ERC-20 token allowed by the payment policy.

The payment metadata does not carry a token. The signer reconstructs the Permit2 digest using `policy.token`.

#### `maxAmountPerPayment`

The maximum allowed Permit2 `permitted.amount` for one payment.

For x402 `exact`, this is the exact payment amount being authorized. The signer rejects zero amounts and amounts above this cap.

#### `maxPayments`

The number of allowed Permit2 nonce slots in the policy's deterministic nonce word.

The signer derives a Permit2 unordered nonce word from the wallet and policy root. The low 8 bits of the Permit2 nonce are treated as a slot index. The payment is valid only if:

```
uint8(payment.nonce) < maxPayments
```

`maxPayments` must be greater than zero and at most `256`.

#### `validBefore`

The policy expiry timestamp.

The signer rejects the policy after `validBefore`. Individual Permit2 `deadline` and x402 witness `validAfter` remain part of the payment digest and are enforced by Permit2 and the x402 proxy during settlement.

---

## 5. Payment Metadata

The payment metadata is the minimum data needed to reconstruct the canonical x402 Permit2 digest and enforce the policy.

### Encoding

```
struct Permit2Payment {
  uint256 amount;
  uint256 nonce;
  uint256 deadline;
  address witnessTo;
  uint256 witnessValidAfter;
}
```

### Fields

#### `amount`

The Permit2 permitted token amount.

The signer uses this field in `TokenPermissions(token, amount)` and enforces `amount <= policy.maxAmountPerPayment`.

#### `nonce`

The Permit2 unordered nonce.

The high 248 bits must equal the deterministic nonce word for `(signer, wallet, policyRoot)`. The low 8 bits select the payment slot and must be below `policy.maxPayments`.

#### `deadline`

The Permit2 permit deadline.

The signer includes this field in the reconstructed Permit2 digest. It does not separately enforce the deadline because Permit2 enforces it when settling.

#### `witnessTo`

The x402 recipient encoded in the Permit2 witness.

The signer does not restrict recipients. Any recipient is allowed by this policy shape.

#### `witnessValidAfter`

The x402 witness lower-bound timestamp.

The signer includes this field in the reconstructed Permit2 digest. It does not separately enforce it because the x402 Permit2 proxy enforces the witness timing during settlement.

---

## 6. Sapient Signature

The payment sapient signature passed to the signer for `Payload.KIND_DIGEST` is ABI-encoded as:

```
struct X402Signature {
  Policy policy;
  Permit2Payment payment;
  bytes sessionKeySignature;
}
```

There is no mode byte. The payload kind selects the validation path.

The approval sapient signature passed to the signer for `Payload.KIND_TRANSACTIONS` is ABI-encoded as:

```
struct ApprovalSignature {
  Policy policy;
  bytes sessionKeySignature;
}
```

The session key signs the wallet transaction payload hash, wrapped in the same session authorization type used by payments.

---

## 7. Permit2 Digest Reconstruction

The signer reconstructs the canonical Permit2 digest from:

- `policy.token`
- `payment.amount`
- `X402_PERMIT2_PROXY`
- `payment.nonce`
- `payment.deadline`
- `payment.witnessTo`
- `payment.witnessValidAfter`
- `PERMIT2`
- `block.chainid`

The x402 witness type is:

```
Witness(address to,uint256 validAfter)
```

The Permit2 witness transfer type is:

```
PermitWitnessTransferFrom(
  TokenPermissions permitted,
  address spender,
  uint256 nonce,
  uint256 deadline,
  Witness witness
)
TokenPermissions(address token,uint256 amount)
Witness(address to,uint256 validAfter)
```

If the reconstructed digest does not equal `payload.digest`, validation fails.

---

## 8. Approval Transaction

The approval path exists to let the wallet set Permit2 allowance without requiring a separate manual wallet signing flow.

The transaction payload must contain exactly one call:

```
policy.token.approve(PERMIT2, type(uint256).max)
```

The transaction nonce space must be in the same reserved range used by smart sessions:

```
payload.space <= type(uint80).max - 1
```

The call must satisfy:

- `call.value == 0`
- `call.delegateCall == false`
- `call.onlyFallback == false`
- `call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR`
- calldata length is exactly `68` bytes
- calldata selector is `approve(address,uint256)`
- decoded spender is `PERMIT2`
- decoded amount is exactly `type(uint256).max`

The signer checks `call.to == policy.token`.

This approval does not spend funds by itself. It grants Permit2 allowance for the same token the policy can later spend through x402. The later payment path still requires a valid x402 Permit2 digest, policy root, session key signature, amount cap, nonce slot, and token match.

---

## 9. Session Authorization

The session key does not sign raw external digests directly. It signs a Sequence x402 session authorization:

```
X402SessionAuthorization(
  address wallet,
  bytes32 policyRoot,
  bytes32 payloadDigest
)
```

The EIP-712 domain is:

```
EIP712Domain(
  string name,
  string version,
  uint256 chainId,
  address verifyingContract
)
```

with:

```
name = "Sequence X402 Session"
version = "1"
chainId = block.chainid
verifyingContract = address(this)
```

This binds the session key signature to:

- the wallet currently being validated
- the policy committed in the wallet configuration
- the exact external x402 Permit2 digest or wallet transaction payload hash
- this sapient signer contract and chain

For approval setup, `payloadDigest` is `Payload.hashFor(payload, wallet)`, so the signature covers the target token, calldata, nonce, nonce space, and parent wallets.

---

## 10. Deterministic Permit2 Nonce Word

Permit2 unordered nonces are partitioned into 248-bit words with 8-bit slots. The signer reserves one deterministic nonce word per wallet and policy:

```
permit2NonceWord(wallet, policyRoot) =
  uint256(
    keccak256(
      abi.encode(
        PERMIT2_NONCE_WORD_TYPEHASH,
        address(this),
        wallet,
        policyRoot
      )
    )
  ) >> 8
```

The payment nonce must satisfy:

```
payment.nonce >> 8 == permit2NonceWord(wallet, policyRoot)
uint8(payment.nonce) < policy.maxPayments
```

This gives each `(signer, wallet, policy)` tuple its own Permit2 nonce namespace without adding a nonce word field to the policy.

---

## 11. Validation Rules

During `recoverSapientSignature`, the signer first validates the payload kind.

For `Payload.KIND_DIGEST`, it validates:

1. The policy is structurally valid:
   - `sessionKey != address(0)`
   - `token != address(0)`
   - `chainId == 0 || chainId == block.chainid`
   - `block.timestamp <= validBefore`
   - `0 < maxPayments <= 256`
2. The payment is in policy:
   - `amount > 0`
   - `amount <= maxAmountPerPayment`
   - nonce word equals the deterministic policy nonce word
   - nonce slot is below `maxPayments`
3. The reconstructed Permit2 digest equals `payload.digest`.
4. The session key signature recovers `policy.sessionKey`.

If all checks pass, the signer returns:

```
hashPolicy(policy)
```

For `Payload.KIND_TRANSACTIONS`, it validates:

1. The policy is structurally valid.
2. The nonce space is no greater than `type(uint80).max - 1`.
3. The payload contains exactly one call.
4. The call target is `policy.token`.
5. The call cannot send ETH.
6. The call cannot use delegatecall.
7. The call cannot be fallback-only.
8. The call must revert on error.
9. The calldata must be exactly `approve(PERMIT2, type(uint256).max)`.
10. The session key signature over `hashSessionAuthorization(wallet, policyRoot, Payload.hashFor(payload, wallet))` recovers `policy.sessionKey`.

If all checks pass, the signer returns:

```
hashPolicy(policy)
```

---

## 12. Wallet Configuration

To enable x402 payments for a policy, the wallet configuration must include a sapient signer leaf for:

```
sapient = address(X402SessionSapientSigner)
sapientImageHash = hashPolicy(policy)
```

The same leaf enables both payment validation and Permit2 approval setup for that policy. Revocation is performed by removing that sapient leaf from the wallet configuration.

Changing any payment policy field changes the policy root. A signature for one policy does not validate against another policy root.

---

## 13. Security Properties

The payment path enforces:

- one session key per policy
- one token per policy
- optional chain scoping
- per-payment amount cap
- maximum number of payments
- policy expiry
- deterministic Permit2 nonce namespace
- canonical x402 Permit2 digest reconstruction
- wallet-bound session authorization

The approval path enforces:

- one session key per policy
- one policy token
- the smart-session nonce-space range
- one approval call per transaction
- Permit2 as the only spender
- max allowance as the only allowed amount
- no ETH transfer
- no delegatecall
- no fallback-only execution
- revert-on-error execution

The max-amount approval requirement is intentional. Allowing arbitrary amounts would also allow `approve(PERMIT2, 0)`, which can revoke or reduce Permit2 allowance through the same sapient leaf.

This signer does not enforce:

- cumulative token spend by exact value
- recipient restrictions
- merchant/resource restrictions
- facilitator restrictions
- revocation without a wallet configuration update
- arbitrary spender approvals

The maximum stateless payment exposure for a policy is:

```
maxPayments * maxAmountPerPayment
```

This is an upper bound, not exact cumulative accounting.

---

## 14. Integration Notes

An SDK setting up Permit2 approval should:

1. Build the policy and compute `policyRoot = hashPolicy(policy)`.
2. Ensure the wallet configuration includes the sapient signer leaf for `policyRoot`.
3. If Permit2 allowance is insufficient for `policy.token`, build a transaction payload containing:

   ```
   policy.token.approve(PERMIT2, type(uint256).max)
   ```

4. Set `payload.space <= type(uint80).max - 1`.
5. Have the session key sign `hashSessionAuthorization(wallet, policyRoot, Payload.hashFor(payload, wallet))`.
6. ABI-encode `ApprovalSignature(policy, sessionKeySignature)`.
7. Embed that as the sapient signature in the Sequence transaction signature.
8. Execute the approval transaction.

An SDK creating a payment should:

1. Build the policy and compute `policyRoot = hashPolicy(policy)`.
2. Ensure the wallet configuration includes the sapient signer leaf for `policyRoot`.
3. Derive `nonceWord = permit2NonceWord(wallet, policyRoot)`.
4. Choose an unused slot `slot < policy.maxPayments`.
5. Build `nonce = (nonceWord << 8) | slot`.
6. Construct the x402 Permit2 payment using:
   - token: `policy.token`
   - amount: payment amount
   - spender: configured x402 Permit2 proxy
   - nonce: derived nonce
   - deadline: Permit2 deadline
   - witness: `Witness({to, validAfter})`
7. Compute the canonical Permit2 digest.
8. Have the session key sign `hashSessionAuthorization(wallet, policyRoot, permit2Digest)`.
9. ABI-encode `X402Signature(policy, payment, sessionKeySignature)`.
10. Embed that as the sapient signature in the Sequence signature.

---

## 15. Limitations

Because ERC-1271 validation is `view`, this signer cannot update a spend counter. It uses Permit2 nonce slots to bound payment count, not to sum exact spend.

For exact cumulative accounting, use a state-changing settlement path or a separate accounting mechanism. Examples include a custom settlement helper, an escrow, a delegation manager, or a policy that maps nonce buckets to fixed denominations.

The signer also assumes the x402 Permit2 proxy enforces its own witness semantics during settlement. The signer reconstructs and approves the digest; it does not replace Permit2 or proxy settlement checks.

The approval setup path only approves Permit2 at max allowance for `policy.token`. It does not approve the x402 proxy, facilitators, or arbitrary spenders. It also cannot be used to lower Permit2 allowance.
