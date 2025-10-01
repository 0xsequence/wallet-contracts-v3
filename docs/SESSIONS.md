# Ecosystem Wallets Smart Sessions Documentation

This document provides an in-depth overview of the smart sessions system in Ecosystem wallets. It explains the encoding of signatures and configurations, details the permissions system, and distinguishes between explicit sessions and implicit sessions.

---

## Overview

Ecosystem wallets smart sessions enable batched call authorization via signed payloads. Two primary session modes are supported:

- **Explicit Sessions:**  
  Explicit sessions are part of the wallet's configuration. Their permissions are granted counter factually - derived from signature calldata. These permissions can be added or removed with a configuration update. As the configuration is tied to the wallet's image hash, any change to the wallet (and thus its image hash) immediately affects which explicit session permissions remain valid.

- **Implicit Sessions:**  
  Implicit sessions are automatically able to sign on behalf of the wallet when they present an attestation that is signed by the wallet's identity signer. This mode leverages off-chain attestations and enforces additional constraints (e.g., blacklisting) to protect against misuse.

---

## Signature Encoding

Signature encoding consists of **three** main parts:

1. **Session Configuration Encoding**
2. **Attestation List Encoding**
3. **Call Signatures Encoding**

Each part uses a specific layout and bit-level structure to efficiently encode the required data.

---

### 1. Session Configuration Encoding

The session configuration is embedded within the signature as follows:

```
┌─────────────────────────────────────────────────────┐
│ uint24 dataSize                                     │
│ ┌───────────────────────────────────────────────┐   │
│ │ Session Configuration Bytes (dataSize bytes)  │   │
│ └───────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

Within these configuration bytes, the data is structured as a series of tagged nodes. Each node begins with a flag byte that indicates the node type and any associated metadata.

#### Flag Byte Structure

```
 ┌───────────────────────────────┐
 │  Bits 7..4: FLAG              │  (Identifies the node type)
 │  Bits 3..0: Additional Data   │  (Depends on the FLAG)
 └───────────────────────────────┘
```

The following flags are defined:

- **0x00: Permissions Node**
- **0x01: Hash Node (Pre-hashed 32-byte value)**
- **0x02: Branch Node (Nested encoding)**
- **0x03: Blacklist Node**
- **0x04: Identity Signer Node**

> [!IMPORTANT]
> During validation there must be **exactly one** Identity Signer and **at most one** Blacklist node. Multiple entries will trigger a validation error. If there are any implicit sessions (attestations), a blacklist is mandatory.

> [!TIP]
> Unused nodes may be hashed into hash nodes to recover the correct image hash with reduced processing. A complete configuration may have multiple Identity Signers but must only include one unhashed Identity Signer node for validation.

#### Permissions Node (FLAG 0x00)

This node encodes session permissions for a specific signer:

```
Permissions Node Layout:
 ┌─────────────────────────────────────────────┐
 │ Flag Byte                                   │
 │   ┌────────────────────────┐                │
 │   │ Bits 7..4: FLAG (0x00) │                │
 │   │ Bits 3..0: Unused      │                │
 │   └────────────────────────┘                │
 │ Signer (address)                            │
 │ Value Limit (uint256)                       │
 │ Deadline (uint256)                          │
 │ Permissions Array (encoded permissions)     │
 └─────────────────────────────────────────────┘
```

##### Permission Object Encoding

Each permission object is structured as follows:

```
Permission Encoding:
 ┌─────────────────────────────┐
 │ Target Address              │
 │ Rules Count (uint8)         │
 │ ┌─────────────────────────┐ │
 │ │ Parameter Rule 1        │ │
 │ │ Parameter Rule 2        │ │  ... (if any)
 │ └─────────────────────────┘ │
 └─────────────────────────────┘
```

If the **Rules Count** is zero, the permission is considered _open_, allowing any call that targets the specified address without additional parameter restrictions.

##### Parameter Rule Encoding

Each parameter rule enforces conditions on the call data:

```
Parameter Rule Encoding:
 ┌──────────────────────────────────────────────────────────────┐
 │ Operation & Cumulative Flag (1 byte)                         │
 │   ┌────────────────────────────────────────────────────────┐ │
 │   │ Bits 7..1  (0xFE): Operation (e.g., 0 = EQUAL, etc.)   │ │
 │   │ Bit 0 (0x01): Cumulative flag (1 = cumulative)         │ │
 │   └────────────────────────────────────────────────────────┘ │
 │ Value (bytes32)                                              │
 │ Offset (uint256)                                             │
 │ Mask (bytes32)                                               │
 └──────────────────────────────────────────────────────────────┘
```

> [!TIP]
> A permission with an empty rules array is treated as _open_, granting unrestricted access to the target, subject only to other constraints such as value limits and deadlines.

#### Hash Node (FLAG 0x01)

This node includes a 32-byte pre-hashed value:

```
Node Layout:
 ┌──────────────────────────────┐
 │ Flag Byte                    │
 │   ┌────────────────────────┐ │
 │   │ Bits 7..4: FLAG (0x01) │ │
 │   │ Bits 3..0: Unused      │ │
 │   └────────────────────────┘ │
 │ Node Hash (bytes32)          │
 └──────────────────────────────┘
```

This node is an optimization to reduce the size of the configuration tree in calldata. By using this node, unused permissions or configuration segments can be hidden, while still allowing the complete image hash to be derived.

#### Branch (FLAG 0x02)

Branches allow for the recursive grouping of nested configuration nodes into a single unit. They are used to bundle together multiple nodes - such as several permissions nodes or even other branch nodes - so that the entire collection can be processed as one entity. This design minimizes redundancy and optimizes the calldata size by avoiding repeated encoding of common structures.

```
Branch Node Layout:
 ┌──────────────────────────────────────────────┐
 │ Flag Byte                                    │
 │   ┌────────────────────────────────────────┐ │
 │   │ Bits 7..4: FLAG (0x02)                 │ │
 │   │ Bits 3..0: Size of size field in bytes │ │
 │   └────────────────────────────────────────┘ │
 │ Size (uintX, where X is determined above)    │
 │ Branch Data (nested configuration bytes)     │
 └──────────────────────────────────────────────┘
```

The **Size** field specifies the total number of bytes that the branch occupies. The size of this field is determined by the additional data portion of the flag byte (bits 3..0), which indicates how many bytes are used to encode the size. The branch data that follows can include a mix of permissions nodes, pre-hashed nodes, blacklists, and even other branches. When processing a branch:

- The branch data is parsed recursively, with each nested node being processed according to its own flag.
- The leaf hashes of all nested nodes are computed.
- These individual hashes are then combined (e.g., using `LibOptim.fkeccak256`) to produce a single cumulative hash representing the entire branch.
- This branch hash is then integrated into the parent configuration's image hash, ensuring that all the nested information contributes to the final cryptographic fingerprint.

> [!TIP]
> Branch nodes are especially useful for modularizing the configuration structure. They allow logically related nodes to be grouped together, which not only improves organization but also potentially reduces the overall size of the calldata by allowing unused leaves to be rolled up into a single node.

#### Blacklist (FLAG 0x03)

The blacklist node specifies addresses that are disallowed for implicit sessions. This includes both target addresses that cannot be called and session signers that are not allowed to make implicit calls.

```
Blacklist Node Layout:
 ┌──────────────────────────────────────────────┐
 │ Flag Byte                                    │
 │   ┌────────────────────────────────────────┐ │
 │   │ Bits 7..4: FLAG (0x03)                 │ │
 │   │ Bits 3..0: Blacklist count or 0x0F     │ │
 │   └────────────────────────────────────────┘ │
 │ [Optional] Extended Count (uint16)           │
 │ Blacklisted Addresses (sorted array)         │
 └──────────────────────────────────────────────┘
```

The blacklist count is encoded in the additional data portion of the flag byte (bits 3..0):

- If the count is 14 or less, it is stored directly in these bits
- If the count is 15 or more, these bits are set to 0x0F and the actual count is stored in the next 2 bytes as a uint16

The blacklist serves two security purposes:

1. Prevents implicit sessions from calling specific target addresses
2. Blocks specific session signers from making any implicit calls

When an implicit session call is made, both the session signer and the target address are checked against the blacklist. If either appears in the blacklist, the call will be rejected with a `BlacklistedAddress` error.

> [!IMPORTANT]
> For implicit sessions, the blacklist is mandatory. The blacklist addresses must be sorted or validation will fail. This is to allow a binary search during validation.

> [!WARNING]
> The blacklist doesn't not prevent explicit sessions from calling blacklisted addresses or prevent explicit signers. To block an explicit session or it's permissions, update the wallet configuration to remove the explicit session.

#### Identity Signer (FLAG 0x04)

Specifies the identity signer used for attestation verification:

```
Identity Signer Layout:
 ┌──────────────────────────────┐
 │ Flag Byte                    │
 │   ┌────────────────────────┐ │
 │   │ Bits 7..4: FLAG (0x04) │ │
 │   │ Bits 3..0: Unused      │ │
 │   └────────────────────────┘ │
 │ Identity Signer (address)    │
 └──────────────────────────────┘
```

> [!IMPORTANT]
> The configuration must include exactly one identity signer during validation. Duplicate or missing entries trigger an error.

> [!NOTE]
> An Identity Signer can be any address capable or authorizing an implicit session. This should not be confused with other uses of the term Identity outside the sessions extension.

---

### 2. Attestation List Encoding

After reading the session configuration, a single byte `attestationCount` indicates how many attestations follow:

```
┌─────────────────────────────────────────────────────┐
│ uint8 attestationCount                              │
│ ┌────────────────────────────────────────────────┐  │
│ │ Attestation + identity signature               │  │
│ │ ... repeated attestationCount times ...        │  │
│ └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

Each attestation is encoded as described in [Attestation (Implicit Sessions)](#attestation-implicit-sessions) below, then followed by a single identity signature from the configured identity signer (in EIP-2098 compact form).

If `attestationCount > 0` but no blacklist node was present in the configuration, validation fails.

---

### 3. Call Signatures Encoding

Each call in the payload is accompanied by a call signature. The encoding differs slightly for explicit sessions and implicit sessions.

#### Call Signature Structure

```
Call Signature Layout:
 ┌─────────────────────────────────────────────────────────────┐
 │ Flag Byte                                                   │
 │   ┌────────────────────────────────────────────────────────┐│
 │   │ Bit 7 (0x80): isImplicit flag                          ││
 │   │ Bits 6..0 (0x7F): If implicit, this is the attestation ││
 │   │               index; if explicit, this is the          ││
 │   │               session permission index                 ││
 │   └────────────────────────────────────────────────────────┘│
 │ Session Signature (EIP-2098 compact: see below)             │
 └─────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> The flag byte is critical for distinguishing call types. For implicit sessions, the most significant bit (Bit 7) must be set. For explicit sessions, the lower 7 bits represent the permission index.

The session signature is an ECDSA signature of the call and replay protection information in the payload (nonce, space and chainId).

No attestation data is embedded here for implicit calls; instead, each implicit call references an attestation by index from the Attestation List.

#### EIP-2098 Compact Signature Encoding

Compact signatures follows the [EIP-2098](https://eip.tools/eip/2098) compact signature format. In this format, the signature is encoded as follows:

```
EIP-2098 Compact Encoding:
 ┌─────────────────────────────────────────────────────────────┐
 │ 256-bit r value                                             │
 │ 1-bit yParity (encoded into s)                              │
 │ 255-bit s value                                             │
 └─────────────────────────────────────────────────────────────┘
```

This encoding merges the `v` value into the `s` value, reducing the overall signature size while maintaining full signature recovery capability.

---

## Permissions System

The permissions system governs what actions a session signer is allowed to execute within explicit sessions. It is designed to be flexible, allowing validations on any field within the call data through the use of **value**, **offset**, and **mask** parameters.

### Session Permissions (Explicit Sessions)

Defined in the `SessionPermissions` struct, these include:

- **Signer:** Authorized session signer.
- **Value Limit:** Maximum native token value allowed.
- **Deadline:** Expiration timestamp (0 indicates no deadline).
- **Permissions Array:** List of permission objects.

> [!WARNING]
> If a session's deadline is set and the current block timestamp exceeds it, the session is considered expired and all calls will be rejected.

### Permission Object and Parameter Rules

Each permission object specifies a target contract and a set of rules that define acceptable call parameters.

#### Permission Object Recap

```
Permission Object:
 ┌────────────────────────────────┐
 │ Target Address                 │
 │ Rules Count (uint8)            │
 │ Rules (array of ParameterRule) │
 └────────────────────────────────┘
```

#### Parameter Rule Recap

```
Parameter Rule:
 ┌────────────────────────────────────────────────────────────┐
 │ Operation & Cumulative Flag (1 byte)                       │
 │   ┌──────────────────────────────────────────────────────┐ │
 │   │ Bits 7..1  (0xFE): Operation (e.g., 0 = EQUAL, etc.) │ │
 │   │ Bit 0 (0x01): Cumulative flag (1 = cumulative)       │ │
 │   └──────────────────────────────────────────────────────┘ │
 │ Value (bytes32)                                            │
 │ Offset (uint256)                                           │
 │ Mask (bytes32)                                             │
 └────────────────────────────────────────────────────────────┘
```

> [!TIP]
> A permission with an empty rules array is treated as _open_, granting unrestricted access to the target, subject only to other constraints such as value limits and deadlines.

---

## Detailed Permission Rules and Validation

The permission rules mechanism provides a powerful and flexible method to validate any field within the call data. Here's a detailed look at how the rules work:

### Components of a Permission Rule

- **Value:**  
  The expected value (stored as a `bytes32`) used for comparison.

- **Offset:**  
  The byte offset in the call data from which the 32-byte parameter is extracted.

- **Mask:**  
  A bitmask applied to the extracted data. This isolates the relevant bits, allowing validation even when the field is embedded within a larger data structure.

### Validation Process

For each rule, the validation function performs the following steps:

1. **Extraction:**  
   Read 32 bytes from the call data starting at the specified offset:

   ```solidity
   bytes32 extracted_value = call.data.readBytes32(rule.offset);
   ```

2. **Masking:**  
   Apply the mask to isolate the target bits:

   ```solidity
   bytes32 masked_value = extracted_value & rule.mask;
   ```

3. **Comparison:**  
   Compare the masked value with the expected value using the defined operation:
   - **EQUAL:** The masked value must exactly equal the expected value.
   - **LESS_THAN_OR_EQUAL:** The masked value must be less than or equal to the expected value.
   - **GREATER_THAN_OR_EQUAL:** The masked value must be greater than or equal to the expected value.
   - **NOT_EQUAL:** The masked value must not equal the expected value.

> [!TIP]
> This approach allows validation on any field within the call data regardless of its format or position.

### The Cumulative Flag

When the **cumulative** flag is set on a permission rule:

1. **Cumulative Calculation:**  
   The value extracted from the current call is added to a previously recorded usage amount (stored in the payload's usage limits or persistent storage).

2. **Threshold Comparison:**  
   The cumulative total (current value plus previous usage) is compared against the threshold defined by the rule.

3. **Preceding Update:**  
   Because cumulative values persist across multiple calls, a preceding call to `incrementUsageLimit` is required. This call updates the on-chain storage with the new cumulative total, ensuring that future validations reflect the updated usage.

> [!WARNING]
> Cumulative usage is tracked using hashes: `keccak256(abi.encode(signer, permission, ruleIdx))` for rules and `keccak256(abi.encode(signer, VALUE_TRACKING_ADDRESS))` for native tokens. Modifying a permission creates a new hash, so the old usage state must be considered when modifying a permission.

### Example: ERC20.transfer

Consider an ERC20 token `transfer` function:

```solidity
function transfer(address to, uint256 amount) returns (bool);
```

**Call Data Layout:**

- **4 bytes:** Function selector.
- **32 bytes:** Encoded `to` address.
- **32 bytes:** Encoded `amount`.

**Permission Rule Setup:**

- **Target:**  
  The ERC20 token contract address.

- **Offset:**  
  `36` bytes (4 bytes for the function selector + 32 bytes for the `to` address) - this is where the `amount` parameter begins.

- **Mask:**  
  A full mask (`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`) to extract the entire 32-byte value.

- **Value:**  
  `100 * 10^18` (expressed as a `bytes32` value) to represent a maximum transfer amount of 100 tokens (assuming 18 decimals).

- **Operation:**  
  `LESS_THAN_OR_EQUAL` - ensuring the transfer amount does not exceed the threshold.

- **Cumulative Flag (optional):**  
  If you want to enforce a cumulative limit (e.g., a daily cap), set the cumulative flag. Each transfer's amount is then added to a cumulative total that must not exceed the threshold, with an `incrementUsageLimit` call required to update the stored value.

> [!NOTE]
> ERC20.transfer Example Recap: The permission rule extracts the `amount` parameter from call data at offset 36, applies a mask to isolate the full value, and verifies that the value is less than or equal to 100 \* 10^18. Optionally, if the cumulative flag is set, it enforces a cumulative limit across multiple calls. In practice, the permission would also include a rule to check the function selector, ensuring that the call is to the `transfer` function.

---

## Attestation (Implicit Sessions)

Implicit sessions use an attestation to verify that the session signer is approved. The attestation is encoded and then validated by the target contract.

### Attestation Encoding

```
Attestation Encoding:
 ┌──────────────────────────────────────────────┐
 │ Approved Signer (address)                    │
 │ Identity Type (bytes4)                       │
 │ Issuer Hash (bytes32)                        │
 │ Audience Hash (bytes32)                      │
 │ Application Data Length (uint24)             │
 │ Application Data (variable bytes)            │
 │ Redirect URL Length (uint24)                 │
 │ Redirect URL (variable string)               │
 │ Issued At (uint64)                           │
 └──────────────────────────────────────────────┘
```

The Attestation data obtained during authentication. The `Identity Type` is the type of identity that was used to authenticate the user. The `Issuer Hash` is the hash of the issuer. The `Audience Hash` is the hash of the audience. The `Application Data` can be provided by the dapp. The `Auth Data` contains the redirect URL (string) and issuance timestamp (uint64).

> [!WARNING]
> The `Application Data` length is encoded using a `uint24`. Ensure that data lengths are within these limits.

> [!NOTE]
> The `Redirect URL` length is encoded using a `uint24`, and the `Issued At` field is a `uint64` timestamp representing when the attestation was issued. The encoding order is: `redirectUrlLength` (uint24), `redirectUrl` (string), `issuedAt` (uint64).

### Attestation Validation

- The attestation's **approved signer** must match the session signer.
- A magic value is generated using a combination of a prefix, the wallet address, the attestation's audience hash, and issuer hash.
- The attestation signature is validated against the identity signer from the configuration.
- The target contract's `acceptImplicitRequest` function must return the expected magic value; otherwise, the call is rejected.

> [!WARNING]
> Implicit sessions require a properly encoded blacklist in the configuration. Calls to a blacklisted address will be rejected, and missing blacklist data will cause validation errors.

---

## Future Improvements

Several improvements can be made

> [!NOTE]
> Configuration Flexibility: Introduce versioning or additional flags in the configuration encoding to support new features while preserving backward compatibility. Allow dynamic adjustments without breaking the merkle tree-based image hash structure.

> [!NOTE]
> Gas Optimization: Optimize the recursive encoding/decoding logic for configurations with a large number of permissions or deep branch nesting to reduce gas costs.

> [!NOTE]
> Call Signature Optimization: Optimize the call signature encoding to reduce the size of the calldata. A potential target for optimization is to remove repeated encodings of the same attestation data.

> [!NOTE]
> Advanced Permission Rules: Extend the permission system to support more complex conditional checks or dynamic rule adjustments. Provide improved error messages and diagnostic tools for failed validations.

---

## Conclusion

The smart sessions system in Ecosystem wallets offers a flexible framework for authorizing batched operations via signed payloads. By leveraging detailed encoding schemes for configuration, permissions, and attestations - and by deriving an image hash that cryptographically fingerprints the configuration tree (even when sparse) - the system supports both explicit sessions and implicit sessions while ensuring robust validation. The detailed permission rules, including the use of **value**, **offset**, and **mask**, provide granular control over call data validation, and the cumulative flag facilitates persistent limits across calls. The outlined future improvements aim to enhance security, efficiency, and usability as the system evolves.

This documentation serves as a technical guide for developers integrating and extending the smart sessions framework, providing both detailed encoding breakdowns and practical considerations for deployment and further development.
