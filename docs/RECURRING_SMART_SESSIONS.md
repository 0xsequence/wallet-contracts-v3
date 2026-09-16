# Monthly subscription sessions

`RecurringSessionSapientSigner` authorizes one positive payment per UTC calendar
month, with a variable amount up to a cap. One session key can send a native
token or ERC20 to one fixed recipient. A merchant/backend submits each payment;
the contract does not schedule transactions.

Commit `hashPolicy(policy)` as this signer's sapient image hash in the wallet
configuration. For a 100 USDC monthly subscription, use the desired signer,
chain, USDC address and recipient, with `limit = 100_000_000` and the desired
`start` and `deadline` timestamps.

A payment of 63 against a cap of 100 consumes that month's one payment; the
remaining 37 cannot be charged. The amount can vary the following month.

- Billing resets on the first of each month at 00:00 UTC.
- `start` is inclusive; the first partial calendar month has the full cap,
  with no proration. A payment on September 30 can be followed by another on
  October 1.
- `deadline = 0` means no expiry; otherwise the deadline is inclusive.
- Unused capacity does not carry over, including skipped months. Each month
  has its own usage entry, so no reset transaction is needed.
- Usage is separate per executing wallet, policy and chain, including when
  validation passes through nested wallets. Changing a policy creates a
  new payment authorization; revoking and re-adding the identical policy
  preserves its usage.

Every transaction batch contains exactly two calls:

1. `consumeUsage(hashPolicy(policy), currentPeriod(policy), amount)` on the
   signer, with zero native value.
2. One positive payment: `token.transfer(recipient, amount)`, or an empty-data
   native transfer to `recipient` when `token = address(0)`.

All calls must revert on failure, with no delegate calls or fallback-only calls.
The first call's amount must equal the payment amount. The signer checks that
the amount fits the cap and the month is unused before execution; a reverting
payment rolls back accounting too, allowing a retry. Amounts refer to the requested transfers,
not balance differences; a token returning `false` without reverting still
consumes usage, following the wallet's usual call semantics.

The session key signs `Payload.hashFor(payload, wallet)`. Pass
`abi.encode(Signature(policy, signature))` as the sapient signature inside the
normal wallet signature. This covers the full batch, nonce, wallet, parent
wallets and accounting call. A batch signed for an earlier period must be rebuilt
and signed again. Wallet configuration changes authorize or revoke the session.

This prototype uses its own ABI encoding, not the existing `SessionSig` encoding.
It accepts only the accounting call and payments; arbitrary calls, approvals,
fee-payment calls and message signatures are outside its scope. SDK integration
and deployment are separate from this contract prototype.
