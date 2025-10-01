# Sequence Wallet Configuration Documentation

This document provides a description on how the Sequence wallet contracts define and handle sets of signers, checkpoints, extensions and other parameters that fall within the scope of its "configuration".

## **1. Overview**

All Sequence wallets have a defined "configuration", this is the set of parameters that governs the wallet's behavior.

The configuration includes:

- The threshold needed to authorize a transaction.
- The set of signers, and their corresponding weights.
- The current "checkpoint", which determines the order of configuration updates.
- Any "extensions" that are enabled, with their corresponding parameters.
- The "checkpointer" contract, which acts as a connector for a keystore rollup.
- Any pre-authorized transactions or messages, that are considered signed by the wallet.

All these parameters are encoded into leaves of a merkle tree, of which the root is stored either as counter-factual information during wallet creation (as the salt of the `CREATE2` opcode), or directly within the contract storage; this "merkle root" is internally referred as the `imageHash` of the wallet.

Since the wallet contract does not have direct access to the configuration, every time a signature is provided, the signature must provide both the "signature parts" that may be needed for the individual signers, as well as the "merkle proof" that allows the wallet contract to reconstruct the `imageHash` and thus validate the signature.

## **2. Tree structure**

The tree is a **sparse binary merkle tree**, this allows for more frequently accessed parameters to be stored closer to the root, making merkle proofs more efficient. Some elements like the `checkpointer`, `checkpoint` and `threshold` have fixed positions at the top of the tree, afterwards the other leaves can be arranged in any order.

The top of the tree looks like:

```
imageHash = keccak256(
    keccak256(
        keccak256(
          ...leaves,
          threshold
        ),
        checkpoint
    ),
    checkpointer || address(0)
)
```

The `checkpointer` is optional, if it is not provided it still has to be included in the merkle tree, it will be automatically set to `address(0)` if the signature flags do not set the `CHECKPOINTER` bit.

```
             ┌────────────────┐
             │                │
             │   Image hash   │
             │                │
             └───▲────────▲───┘
                 │        │
             ┌───┘        └────┐
             │      ┌──────────┼───────────┐
        ╭────┴───╮  │  ┌───────┴────────┐  │
        │        │  │  │                │  ├────▶ This section is
        │        │  │  │  Checkpointer  │  │      always in the tree.
        │        │  │  │                │  │
        ╰─▲────▲─╯  │  └────────────────┘  │      It won't be shown
          │    │    │                      │      in the other diagrams.
          │    └────┼──────────┐           │
          │         │          │           │
        ╭─┴──────╮  │  ┌───────┴────────┐  │
        │        │  │  │                │  │
        │        │  │  │   Checkpoint   │  │
        │        │  │  │                │  │
        ╰─▲────▲─╯  │  └────────────────┘  │
          │    │    │                      │
          │    └────┼──────────┐           │
          │         │          │           │
╔═════════╧══════╗  │  ┌───────┴────────┐  │
║    ... rest    ║  │  │                │  │
║  of the tree   ║  │  │   Threshold    │  │
║                ║  │  │                │  │
╚════════════════╝  │  └────────────────┘  │
                    └──────────────────────┘
```

## **3. Leaf types**

### 3.1 Signer leaf

Signer leaves are used to specify signer addresses, meaning that when a valid signature is provided, the wallet will count their weight towards the threshold. Signer leaves do not specify if they are ERC1271 signers or not, instead this is determined when the signature is encoded.

```
                     ┌────────────────┐
                     │                │
                     │   Image hash   │
                     │                │
                     └───▲────────▲───┘
                         │        │
                     ┌───┘        └──────┐
                     │                   │
                ╭────┴───╮     ╔═════════╧═════════╗
                │        │     ║Checkpointer: 0x   ║
                │        │     ║Checkpoint: 0      ║
                │        │     ║Threshold: 1       ║
                ╰─▲────▲─╯     ╚═══════════════════╝
                  │    │
          ┌───────┘    └──────┐
          │                   │
          │                   │
┌────────────────┐     ┌────────────────┐
│  Signer 0xaaa  │     │  Signer 0xbbb  │
│   Weight: 1    │     │   Weight: 1    │
│                │     │                │
└────────────────┘     └────────────────┘
```

The hash of a signer leaf is computed as:

```
leaf = keccak256(
  "Sequence signer:\n",
  address,
  weight
)
```

> Notice that any address that is registered **more than once** will be counted **multiple times** in the threshold.

### 3.2 Hardcoded signature leaf

Hardcoded signature leaves allow for the configuration to automatically sign a specific payload, this is useful for pre-approving transactions, for example pre-approving an approval for an ERC20 at the same time as the wallet is created.

If a payload hash matches the hardcoded hash (subdigest), the weight counted towards the threshold will automatically be bumped to `type(uint256).max`, ensuring the signature to be valid.

```
            ┌────────────────┐
            │                │
            │   Image hash   │
            │                │
            └───▲────────▲───┘
                │        │
        ┌───────┘        └────────┐
        │                         │
┌───────┴────────┐      ╔═════════╧═════════╗
│   Subdigest:   │      ║Checkpointer: 0x   ║
│   0x11223344   │      ║Checkpoint: 0      ║
│                │      ║Threshold: 1       ║
└────────────────┘      ╚═══════════════════╝
```

The hash of a hardcoded signature leaf is computed as:

```
leaf = keccak256(
  "Sequence static digest:\n",
  subdigest
)
```

### 3.3 Any address hardcoded signature leaf

This works very similarly to the hardcoded signature leaf, but the hash of the payload is computed setting its ERC712 domain separator to `address(0)` instead of the wallet's address.

This allows for pre-approving transactions before the wallet has counterfactually been defined, otherwise attempting to compute the hash would require the wallet's address to be known beforehand, and determining the address would require the hash to be known beforehand, causing a recursive dependency.

After a wallet is created, it is recommended to use the hardcoded signature leaf instead, as it is more efficient.

The hash of an any address hardcoded signature leaf is computed as:

```
leaf = keccak256(
  "Sequence any address subdigest:\n",
  subdigest
)
```

### 3.4 Nested configuration leaf

Nested configuration leaves are used to specify nested configuration trees, this allows for certain sets of signers to be grouped in such a way that their signing power is limited by a threshold. It can also allow to augment the signing power of a set of signers, by making them have no signing power individually but still be able to sign as a group.

They have their own internal thresholds, internally they work exactly as the parent "main" tree, but externally they can only contribute their own weight.

```
                     ┌────────────────┐
                     │                │
                     │   Image hash   │
                     │                │
                     └───▲────────▲───┘
                         │        │
                     ┌───┘        └──────┐
                     │                   │
                ╭────┴───╮     ╔═════════╧═════════╗
                │        │     ║ Checkpointer: 0x  ║
                │        │     ║   Checkpoint: 0   ║
                │        │     ║   Threshold: 2    ║
                ╰─▲────▲─╯     ╚═══════════════════╝
                  │    │
           ┌──────┘    └──────┐
           │                  │                    ────┐
┌──────────┴─────┐      ┌─────┴──────────┐             │
│  Signer 0xaaa  │      │  Threshold: 1  │             ├─▶ The maximum weight
│   Weight: 1    │      │   Weight: 1    │             │   of 0xbbb and 0xccc
│                │      │                │             │   can't exceed 1
└────────────────┘      └─────▲────▲─────┘             │
                              │    │                   │   Forced either of
                       ┌──────┘    └──────┐            │   them to be combined
                       │                  │            │   with 0xaaa
            ┌──────────┴─────┐      ┌─────┴──────────┐ │
            │ Signer: 0xbbb  │      │  Signer 0xccc  │ │
            │   Weight: 1    │      │   Weight: 2    │ │
            │                │      │                │ │
            └────────────────┘      └────────────────┘ │
                                                   ────┘
```

The hash of a nested tree is computed as:

```
leaf = keccak256(
  "Sequence nested config:\n",
  node,
  threshold,
  weight
)
```

### 3.5 Sapient Signer Leaf

Sapient signer leaves work similarly to Signer leaves, but have 3 key distinctions:

1. Sapient signers **must** always be smart contracts, EOA signers are not allowed
2. Sapient signers **do not** use the ERC1271 interface, instead they get passed a fully decoded `Payload` to sign
3. Sapient signatures are not validated, they are **recovered** into a hash

When a sapient signer leaf is added to a configuration, it must define its `address`, `weight` and `imageHash`. The `imageHash` represents the expected value that the sapient signer **must recover** for the signature to be valid.

This allows sapient signers to act as **extensions** of the configuration tree, they can define their own leaf types and overall structures, alongside arbitrary logic. This allows for extensions to be configured per wallet without having to rely on the contract storage of the extension, as the definition of the configuration resides in the same `imageHash`.

```
                           ┌────────────────┐
                           │                │
                           │   Image hash   │
                           │                │
                           └───▲────────▲───┘
                               │        │
                           ┌───┘        └──────┐
                           │                   │
                      ╭────┴───╮     ╔═════════╧═════════╗
                      │        │     ║ Checkpointer: 0x  ║
                      │        │     ║   Checkpoint: 0   ║
                      │        │     ║   Threshold: 2    ║
                      ╰─▲────▲─╯     ╚═══════════════════╝
                        │    │
                 ┌──────┘    └──────┐
                 │                  │                                      ────┐
      ┌──────────┴─────┐      ┌─────┴──────────┐                               ├─▶ The passkey sapient
      │  Signer 0xaaa  │      │    Passkey     │                               │   signer uses its tree
      │   Weight: 1    │      │   weight: 1    │                               │   to define public
      │                │      │imageHash: 0xabc│                               │   keys and
      └────────────────┘      └─────▲────▲─────┘                               │   configuration
                                    │    │                                     │   parameters.
                    ┌───────────────┘    └───────────────┐                     │
                    │                                    │                     │   Signatures must be
              ╭─────┴──╮                              ╭──┴─────╮               │   able to recover the
              │        │                              │        │               │   inner root of the
              │        │                              │        │               │   tree to be
              │        │                              │        │               │   considered valid.
              ╰─▲────▲─╯                              ╰─▲────▲─╯               │
                │    │                                  │    │                 │
         ┌──────┘    └──────┐                    ┌──────┘    └──────┐          │
         │                  │                    │                  │          │
┌────────┴───────┐  ┌───────┴────────┐  ┌────────┴───────┐  ┌───────┴────────┐ │
│                │  │                │  │  Require user  │  │                │ │
│    Pubkey X    │  │    Pubkey Y    │  │  verification  │  │    Metadata    │ │
│                │  │                │  │   true/false   │  │                │ │
└────────────────┘  └────────────────┘  └────────────────┘  └────────────────┘ │
                                                                           ────┘
```

The hash of a sapient signer leaf is:

```
leaf = keccak256(
  "Sequence sapient config:\n",
  address,
  weight,
  imageHash
)
```
