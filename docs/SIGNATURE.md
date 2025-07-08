# **Technical Document: Sequence Signature Encoding**

This document describes, in detail, how the Sequence signature encoding is structured, how each part is packed into bytes, and how chained signatures and top-level signatures work. It is purely technical, explaining the bit layouts, flags, and usage with examples.

---

## **1. Overview**

Sequence uses a specialized signature format that:

1. Has a **top-level signature** that includes:

   - A single "signature flag" byte that encodes multiple fields (checkpointer usage, signature type, checkpoint size, threshold size, etc.).
   - (Optionally) data related to an on-chain checkpointer contract.
   - A notion of _chained signatures_ vs. _normal signatures_ vs. _“no chain id”_ signatures.
   - A final threshold and checkpoint value that tie into the overall wallet or contract logic.

2. Contains a **merkle-like structure** for the signers at the “branch” level, where each “leaf” or “node” is encoded using a separate mini-flag nibble. This is parsed with a loop in the `recoverBranch` function.

3. Supports multiple sub-signature types, such as ECDSA (`FLAG_SIGNATURE_HASH` or `FLAG_SIGNATURE_ETH_SIGN`), ERC-1271 contract-based checks, nested “multi-sig inside multi-sig,” and special “sapient” signatures. Each sub-signature or branch piece is prefixed by one byte: the top nibble is the “flag type” and the bottom nibble contains per-flag configuration bits (like weight, sizes, or additional bits for `v`).

---

## **2. Top-level Signature Format**

When `recover` is first invoked, it reads the **first byte** of the signature as `signatureFlag`. That byte is bit-packed as follows (with bit `0` as the least-significant bit):

```
 ┌─────────────── Bit 7 (0x80) : Static signature
 │ ┌───────────── Bit 6 (0x40) : Checkpointer usage flag
 │ │ ┌─────────── Bit 5 (0x20) : Threshold size indicator (0 => 1 byte, 1 => 2 bytes)
 │ │ │  ┌──────── Bits 4..2 (0x1C) : Checkpoint size (encoded as an integer 0..7)
 │ │ │  │  ┌───── Bit 1 (0x02) : "no chain id" signature type
 │ │ │  │  │ ┌─── Bit 0 (0x01) : "chained" signature type
[7 6 5 432 1 0]
```

We can break this down more concretely:

1. **Bit 7** set (`0x80`) indicates a static signature:
   - When set, the signature has been pre-stored in contract storage and bypasses normal validation
   - Validation only checks:
     - That the stored expiry timestamp has not passed
     - That the stored signer matches the transaction sender (or is unset with `address(0)`)
1. **Bit 6** set (`0x40`) means the signature includes an external **imageHash checkpointer**:
   - If set, the signature will contain:
     - The checkpointer contract `address`
     - A 3-byte length for the “checkpointer data”
     - That data, passed to `ICheckpointer(checkpointer).snapshotFor(...)`
1. **Bits 4..2** (the field `((signatureFlag & 0x1c) >> 2)`) define the **checkpoint size** in bytes. Possible values are `0..7`. If this value is `N`, then the next `N` bytes of the signature after reading the flag (and optional checkpointer data) represent the **checkpoint**.
1. **Bit 5** (`0x20`) sets how many bytes are used to read the threshold. If it is `0`, the threshold is read as 1 byte; if it is `1`, the threshold is read as 2 bytes. (Hence `( (signatureFlag & 0x20) >> 5 ) + 1`.)
1. **Bit 1** (`0x02`) indicates the “no chain id” signature. If set, `_payload.noChainId` is true. This affects how `_payload.hash()` is computed.
1. **Bit 0** (`0x01`) indicates the signature is **chained**. In that case, the code calls `recoverChained`, which processes multiple sub-signatures in sequence.

Putting it together:

- If bit `0` is set, we do a **chained** approach: The signature is composed of chunks, each chunk specifying a length and then a nested signature.
- Otherwise, we do a “regular” top-level parse: we read the checkpoint size, threshold size, then parse the “branch” for signers.

### **Example of a Top-level Signature Byte**

Suppose the top-level `signatureFlag` is `0x6A` in hex. Converting `0x6A` to binary:

```
0x6A = 01101010 in binary
        ^ ^ ^ ^
bit 7:  0 (reserved)
bit 6:  1 => checkpointer usage
bit 5:  1 => threshold uses 2 bytes
bits 4..2: 0b101 => checkpoint size = 5 bytes
bit 1:  0 => normal (not "no chain id")
bit 0:  0 => not chained
```

From this:

- We first read an `address` for the checkpointer, then read 3 bytes for the checkpointer data length, etc.
- We know we must parse **5 bytes** for the checkpoint value.
- Then parse **2 bytes** for the threshold.
- Then parse the remainder as the merkle-branch structure for signers.

---

## **3. Chained Signatures**

When **bit 0** is set (the least-significant bit), the signature is **chained**. Instead of the usual approach (parsing threshold, checkpoint, etc. from that same byte), the code calls:

```solidity
recoverChained(_payload, snapshot, _signature);
```

A chained signature is a series of **signature chunks**, each chunk defined like this:

```
[3-byte length] [chunk of that length]
[3-byte length] [chunk of that length]
...
```

Each chunk can itself be a top-level signature in the sense that it calls `recover(...)` again—except it ignores checkpointer details after the first chunk. The code enforces:

- Each chunk recovers `(threshold, weight, imageHash, checkpoint)`.
- If `weight < threshold`, it reverts with `LowWeightChainedSignature`.
- The `checkpoint` must be **strictly less** than the previous chunk’s `checkpoint`, ensuring correct ordering (`WrongChainedCheckpointOrder`).
- All but the first chunk are interpreted as a “configuration update” with a special “linkedPayload.”

This allows multiple signature instructions to be “chained” in a single byte array.

```
   0           1           2           3
   |----- byte indices: 0..2 => 3-byte length L1
   |----- next L1 bytes => chunk #1
            ...
   |----- next 3 bytes => length L2
   |----- next L2 bytes => chunk #2
            ...
   |----- next 3 bytes => length L3
   |----- next L3 bytes => chunk #3
            ...
   <end of signature>
```

Each chunk is itself a “top-level style signature” minus the repeated checkpointer usage. The final `(threshold, weight, imageHash, checkpoint)` from the last chunk can be used to validate the overall signature.

---

## **4. Branch-Level Parsing**

Regardless of whether it is a chained signature or a direct one, eventually the code calls:

```solidity
recoverBranch(_payload, opHash, _signature)
```

This function loops over the remainder of the signature, reading one byte at a time as the “header” for a sub-signature or branch item. We’ll call that one byte `firstByte`. The code extracts:

- `flag = (firstByte & 0xf0) >> 4;` (the top nibble)
- The lower nibble is used as “free bits.”

### **4.1 Flag Values**

The contract defines constants:

| Constant Name                          | Value (Decimal) | Purpose                                                                                               |
| -------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------- |
| `FLAG_SIGNATURE_HASH`                  | 0               | ECDSA signature with `r,yParityAndS` (ERC-2098 compact) directly against `_opHash`.                   |
| `FLAG_ADDRESS`                         | 1               | Just an address “leaf” (with no actual ECDSA check)                                                   |
| `FLAG_SIGNATURE_ERC1271`               | 2               | A contract-based signature check using `isValidSignature(opHash, signature)`                          |
| `FLAG_NODE`                            | 3               | Includes a raw 32-byte node hash in the merkle root. No weight added.                                 |
| `FLAG_BRANCH`                          | 4               | Nested branch. The next bytes specify length, then recursion into `recoverBranch`.                    |
| `FLAG_SUBDIGEST`                       | 5               | Hard-coded “accepted subdigest.” If `_opHash` matches the stored 32 bytes, infinite weight.           |
| `FLAG_NESTED`                          | 6               | A nested multi-sig node with an internal threshold plus an external weight.                           |
| `FLAG_SIGNATURE_ETH_SIGN`              | 7               | ECDSA signature in “Eth_sign” format (`"\x19Ethereum Signed Message:\n32" + opHash`), using ERC-2098. |
| `FLAG_SIGNATURE_ANY_ADDRESS_SUBDIGEST` | 8               | `FLAG_SUBDIGEST` but with counter factual support.                                                    |
| `FLAG_SIGNATURE_SAPIENT`               | 9               | A specialized “sapient” signature with an `ISapient` contract check.                                  |
| `FLAG_SIGNATURE_SAPIENT_COMPACT`       | 10              | A specialized “sapient” signature with `ISapientCompact` and `_opHash` only.                          |

When the parser sees `flag == someValue`, it dispatches to the corresponding block. Each block interprets the lower nibble differently.

---

## **5. Detailed Flag-by-Flag Format**

Below are the internal mini-formats for each **flag**. Recall that in code, `firstByte` is the single byte at the start of each item, and we do:

```
flag = (firstByte & 0xf0) >> 4;      // top nibble
// "free nibble" = (firstByte & 0x0f)
```

Each bullet will show how the bits in the “free nibble” are used.

---

### 5.1 **Signature Hash** (`flag = 0`)

- Uses **ERC-2098** to parse the signature in 64 bytes (`r` + `yParityAndS`).
- The free nibble bits [3..0] define the signer's weight (0 => we read the weight from the next byte, else 1..15).
- After reading `r` (32 bytes) and `yParityAndS` (32 bytes), the top bit of `yParityAndS` (bit 255) is `yParity` (0 or 1), which is added to 27 to form `v`. The remaining 255 bits are `s`.
- We then perform `ecrecover(_opHash, v, r, s)`.

**Example**  
If the sub-signature byte is `0x05` (`0000 0101` in binary), then top nibble=0 => `FLAG_SIGNATURE_HASH`, free nibble=5 => weight=5. We do **not** read an extra byte for the weight. Next, we read 64 bytes as the compact signature: 32 bytes for `r`, 32 bytes for `yParityAndS`. If the top bit of `yParityAndS` is 0 => `v=27`; if it is 1 => `v=28`. The rest is `s`. Then we do `ecrecover`.

---

### 5.2 **Address** (`flag = 1`)

- Takes an address leaf (no ECDSA).
- The free nibble bits 3..0 define the weight in the same scheme:
  - If those bits are zero, read an extra byte for weight.
  - Else use that 1..15 as the weight.
- Then reads 20 bytes for the address.
- Merges `_leafForAddressAndWeight(addr, weight)`.

---

### 5.3 **Signature ERC-1271** (`flag = 2`)

- The free nibble bits are used as:
  - The bottom two bits are the weight (with the same “0 => dynamic read, else 1..3” logic).
  - The next two bits define the size of the “signature size” field: 0..3 means we read 0..3 bytes to get the dynamic length of the next part.
- Then we read 20 bytes for the contract address, read that dynamic-size signature, and call `IERC1271(addr).isValidSignature(_opHash, data)`. If it returns the magic value `0x1626ba7e`, it is valid; otherwise revert.
- Weight is added if valid.

**Example**

```
firstByte = 0x2D  ->  0010 1101 in binary
 top nibble = 2 -> FLAG_SIGNATURE_ERC1271
 free nibble = 0xD = 1101 in binary
 bits 3..2 = 11 -> sizeSize=3 => read 3 bytes to get length
 bits 1..0 = 01 -> weight=1
```

Then parse next 3 bytes to discover how big the signature is, read it, do the 1271 check.

---

### 5.4 **Node** (`flag = 3`)

- No free bits used.
- Simply reads a 32-byte “node hash” and merges it.
- No weight is added.

---

### 5.5 **Branch** (`flag = 4`)

- The free nibble bits 3..0 define how many bytes are used to read the upcoming “branch size.”
- Once the branch size is read, we extract that many bytes as a sub-branch, and recursively call `recoverBranch` on that sub-slice.
- We get `(nweight, nodeHash)` from that sub-branch, add `nweight` to the total, and merge the nodeHash into the root.

---

### 5.6 **Subdigest** (`flag = 5`)

- The code reads a 32-byte “hardcoded subdigest.” If it matches the `_opHash`, sets `weight = type(uint256).max`.
- Merges `_leafForHardcodedSubdigest(hardcoded)`.

This effectively means “if the 32 bytes match the current operation hash, we grant infinite weight.”

---

### 5.7 **Nested** (`flag = 6`)

- The free nibble is split:
  - The bottom two bits define the “external weight.” Again, `0 => read from next byte, else 1..3`.
  - The next two bits define the “internal threshold” size. If `0`, read 2 bytes from the next portion for that threshold, else 1..3 is just 1..3?
  - Then read 3 bytes to get the length of the nested sub-branch, parse it. That yields `(internalWeight, internalRoot)`.
  - If `internalWeight >= internalThreshold`, we add the external weight to the total. Finally, we merge `_leafForNested(internalRoot, internalThreshold, externalWeight)` into the root.

**Example**

```
firstByte = 0x64  ->  0110 0100 in binary
 top nibble = 6 -> FLAG_NESTED
 free nibble = 0x4 = 0100 in binary
   bits 3..2 = 01 -> internalThreshold=1
   bits 1..0 = 00 -> externalWeight => read from next byte
```

Then read next byte for externalWeight, read next 2 bytes for threshold if needed, etc.

---

### 5.8 **Signature ETH Sign** (`flag = 7`)

- Similar to `FLAG_SIGNATURE_HASH`, but recovers via:

```
ecrecover( keccak256("\x19Ethereum Signed Message:\n32" + _opHash), v, r, s )
```

- Uses **ERC-2098**: we read 64 bytes (32 for `r`, 32 for `yParityAndS`), retrieve `yParity` from the top bit, add 27 to form `v`, and use the remainder as `s`.
- The free nibble bits [3..0] define the weight (0 => dynamic read, else 1..15).

---

### 5.9 **Signature Any Address Subgiest** (`flag = 8`)

- The code reads a 32-byte "hardcoded subdigest." If it matches `_payload.hashFor(address(0))`, sets `weight = type(uint256).max`.
- Merges `_leafForAnyAddressSubdigest(anyAddressOpHash)`.

This effectively means "if the 32 bytes match the operation hash computed for address(0), we grant infinite weight." This allows for counter-factual payloads.

---

### 5.10 **Signature Sapient** (`flag = 9`)

- The free nibble is structured like `ERC1271`: some bits define how many bytes to read for the signature, some bits define the weight.
- Then it calls `ISapient(addr).recoverSapientSignature(_payload, data)`, which must return a “sapientImageHash” used in `_leafForSapient`.
- Weight is added if valid.

---

### 5.11 **Signature Sapient Compact** (`flag = 10`)

- Same approach as `FLAG_SIGNATURE_SAPIENT`, except the contract uses `ISapientCompact.recoverSapientSignatureCompact(_opHash, data)` instead, passing only `_opHash`.

---

## **6. Merkle Root Construction**

The branch parser accumulates a “root” by repeatedly combining leaves with the function:

```solidity
root = LibOptim.fkeccak256(root, leaf)
```

In each sub-flag block, a leaf is computed, for example:

- `_leafForAddressAndWeight(address, weight)`
- `_leafForNested(internalRoot, threshold, externalWeight)`
- `_leafForHardcodedSubdigest(someDigest)`
- etc.

The final `root` is combined with the threshold and checkpoint (and checkpointer address, if present) to yield the final “imageHash.” That is used to tie the signatures to a specific configuration or permission set.

---

## **7. Example Putting it All Together**

Below is a hypothetical top-level signature that is **not** chained, uses a checkpointer, has a 2-byte threshold, a 1-byte checkpoint, and then includes a single ECDSA leaf:

1. **signatureFlag** = `0x6C` => in binary `0110 1100`
   - Bit 6 => `1`, so we have a checkpointer
   - Bit 5 => `1`, threshold uses 2 bytes
   - Bits 4..2 => `110` => checkpoint size = 6 bytes
   - Bit 1 => `0`, normal chain id usage
   - Bit 0 => `0`, not chained
2. We read:
   - `checkpointer` address (20 bytes)
   - 3-byte checkpointer data size => parse that data
   - 6 bytes => the “checkpoint” number
   - 2 bytes => the threshold
3. We jump into `recoverBranch`, and the next 1-byte might be `0x02` in hex => top nibble=0 => `FLAG_SIGNATURE_HASH` with free nibble=2 => weight=2. Then parse 64 bytes for ERC-2098. We derive `v` from the top bit of the second 32 bytes, do ecrecover, and merge the address in the merkle root.

Finally, the code compares the final computed image hash, checks if we pass threshold vs. weight, checks snapshot logic, and returns `(threshold, weight, imageHash, checkpoint)`.

---

## **8. Snapshot and Checkpointer Logic**

If the top-level byte indicates we have a checkpointer (`bit 6` set), we read:

- The checkpointer’s address
- The next 3 bytes => `checkpointerDataSize`
- That many bytes => `checkpointerData`

We call:

```solidity
snapshot = ICheckpointer(checkpointer).snapshotFor(address(this), checkpointerData);
```

This yields a `Snapshot { imageHash, checkpoint }`. If the final signature’s computed `imageHash` and `checkpoint` do not properly exceed or match the snapshot, the code can revert with `UnusedSnapshot`.

---

## **9. Summary**

1. **Top-level “signatureFlag”** byte sets the “checkpointer usage,” “signature type,” “checkpoint size,” “threshold size,” etc.
2. If the signature is **chained**, parse a series of sub-signatures, each of which in turn calls the normal `recover`.
3. Eventually, a **branch** parse is done with `recoverBranch`, which looks at many items. Each item is marked by a single byte whose **top nibble** identifies the flag (ECDSA, ERC1271, sub-branch, nested multi-sig, etc.), and whose **bottom nibble** has special bits (like the signers’ weight, or signature-size format).
4. The final output is `(threshold, weight, imageHash, checkpoint)` plus snapshot checks if any.

This structure allows advanced multi-signature logic, nested multi-sigs, infinite weight if a known subdigest matches `_opHash`, and optional checkpointer extension.
