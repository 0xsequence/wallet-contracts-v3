// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SequenceHelpers } from "./SequenceHelpers.sol";

/// @notice Implementation of the Sequence SDK to encode payload branches, signatures and configurations
///         directly in solidity (primarily for testing). This mirrors the expectations of BaseSig.recoverBranch.
///
///         This version supports *all* known branch FLAGs:
///         - 0  FLAG_SIGNATURE_HASH              (ECDSA over opHash, ERC-2098 compact)
///         - 1  FLAG_ADDRESS                     (address + weight placeholder)
///         - 2  FLAG_SIGNATURE_ERC1271           (IERC1271(addr).isValidSignature(opHash, data))
///         - 3  FLAG_NODE                        (pre-hashed node root)
///         - 4  FLAG_BRANCH                      (nested sub-branch: size + bytes)
///         - 5  FLAG_SUBDIGEST                   (hardcoded digest == opHash)
///         - 6  FLAG_NESTED                      (nested multisig: internalRoot/threshold gated -> external weight)
///         - 7  FLAG_SIGNATURE_ETH_SIGN          (ECDSA over eth_sign(opHash), ERC-2098 compact)
///         - 8  FLAG_SIGNATURE_ANY_ADDRESS_SUBDIGEST (hardcoded digest == payload.hashFor(address(0)))
///         - 9  FLAG_SIGNATURE_SAPIENT           (ISapient(addr).recoverSapientSignature(payload, data))
///         - 10 FLAG_SIGNATURE_SAPIENT_COMPACT    (ISapientCompact(addr).recoverSapientSignatureCompact(opHash, data))
///
///         NOTE on hashing:
///         - Leaves are hashed with domain-separated encodings to mirror BaseSig's internal leaves.
///           For address-based signers (ECDSA / ERC1271 / ETH_SIGN), the leaf hashing is identical:
///             keccak256("Sequence signer:\n", addr, weight)
///         - For the special leaves we use the following domain separators:
///             "Sequence subdigest:\n"
///             "Sequence any-address subdigest:\n"
///             "Sequence nested:\n"
///             "Sequence sapient:\n"
///             "Sequence sapient-compact:\n"
///         - Internal nodes are folded as f(leftRoot, rightRoot) where f(a,b)=keccak256(abi.encodePacked(a,b)).
///
library SequenceConfigLib {

  // -------------------------------------------------------------------------
  // Errors
  // -------------------------------------------------------------------------

  error InvalidSignatureLength(uint256 length);
  error InvalidKind(uint256 kind);
  error InvalidFlag(uint256 flag);
  error WeightTooLarge(uint256 weight); // > 255 where a single byte is expected
  error ThresholdTooLarge(uint256 threshold); // > 4 bytes for nested-encoding (testing helper guard)
  error LengthSizeTooLarge(uint256 lenLen); // > 3 for signature-size fields (erc1271/sapient)
  error UnexpectedNodeKind(uint256 expected, uint256 got);

  // -------------------------------------------------------------------------
  // Branch FLAGs (top nibble of each branch item)
  // -------------------------------------------------------------------------

  uint256 internal constant FLAG_SIGNATURE_HASH = 0;
  uint256 internal constant FLAG_ADDRESS = 1;
  uint256 internal constant FLAG_SIGNATURE_ERC1271 = 2;
  uint256 internal constant FLAG_NODE = 3;
  uint256 internal constant FLAG_BRANCH = 4;
  uint256 internal constant FLAG_SUBDIGEST = 5;
  uint256 internal constant FLAG_NESTED = 6;
  uint256 internal constant FLAG_SIGNATURE_ETH_SIGN = 7;
  uint256 internal constant FLAG_SIGNATURE_ANY_ADDRESS_SUBDIGEST = 8;
  uint256 internal constant FLAG_SIGNATURE_SAPIENT = 9;
  uint256 internal constant FLAG_SIGNATURE_SAPIENT_COMPACT = 10;

  // -------------------------------------------------------------------------
  // Encoded "node" kinds for building the expected configuration tree
  // -------------------------------------------------------------------------

  uint256 constant KIND_ADDRESS = 0; // (address addr, uint256 weight)
  uint256 constant KIND_NODE = 1; // (EncodedNode left, EncodedNode right)
  uint256 constant KIND_SUBDIGEST = 2; // (bytes32 digest)
  uint256 constant KIND_ANYADDR_SUBDIGEST = 3; // (bytes32 digest)
  uint256 constant KIND_NESTED = 4; // (EncodedNode internalTree, uint256 internalThreshold, uint256 externalWeight)
  uint256 constant KIND_SAPIENT = 5; // (address sapient, uint256 weight, bytes32 sapientImageHash)
  uint256 constant KIND_SAPIENT_COMPACT = 6; // (address sapientCompact, uint256 weight, bytes32 sapientImageHash)

  // -------------------------------------------------------------------------
  // Types
  // -------------------------------------------------------------------------

  struct EncodedNode {
    uint256 kind;
    bytes data;
  }

  struct Node {
    EncodedNode left;
    EncodedNode right;
  }

  /// @notice Signature descriptor for leaves. The `flag` selects which FLAG_SIGNATURE_* is used.
  ///         - For address leaves (KIND_ADDRESS) allowed flags: 0, 2, 7
  ///         - For sapient leaves (KIND_SAPIENT): 9
  ///         - For sapient-compact leaves (KIND_SAPIENT_COMPACT): 10
  ///         - For subdigest kinds, no signature entry is required (data lives in the node)
  struct SignatureForNode {
    EncodedNode node;
    bytes signature;
    uint8 flag; // one of FLAG_SIGNATURE_* matching the node
  }

  // -------------------------------------------------------------------------
  // Internal helpers (local fkeccak semantics)
  // -------------------------------------------------------------------------

  function _f(bytes32 a, bytes32 b) private pure returns (bytes32) {
    return keccak256(abi.encodePacked(a, b));
  }

  // -- leaf hash helpers (domain-separated) --

  function _leafForAddressAndWeight(address _addr, uint256 _weight) private pure returns (bytes32) {
    // must exactly match BaseSig._leafForAddressAndWeight
    return keccak256(abi.encodePacked("Sequence signer:\n", _addr, _weight));
  }

  function _leafForSubdigest(
    bytes32 _digest
  ) private pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence static digest:\n", _digest));
  }

  function _leafForAnyAddrSubdigest(
    bytes32 _digest
  ) private pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence any-address subdigest:\n", _digest));
  }

  function _leafForNested(
    bytes32 _internalRoot,
    uint256 _internalThreshold,
    uint256 _externalWeight
  ) private pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence nested:\n", _internalRoot, _internalThreshold, _externalWeight));
  }

  function _leafForSapient(bytes32 _sapientImageHash, uint256 _weight) private pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence sapient:\n", _sapientImageHash, _weight));
  }

  function _leafForSapientCompact(bytes32 _sapientImageHash, uint256 _weight) private pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence sapient-compact:\n", _sapientImageHash, _weight));
  }

  // -------------------------------------------------------------------------
  // Node constructors
  // -------------------------------------------------------------------------

  function addressLeaf(address _addr, uint256 _weight) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_ADDRESS, data: abi.encode(_addr, _weight) });
  }

  function node(EncodedNode memory _left, EncodedNode memory _right) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_NODE, data: abi.encode(_left, _right) });
  }

  /// @notice Hardcoded digest (must equal opHash) => infinite weight
  function subdigestLeaf(
    bytes32 _digest
  ) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_SUBDIGEST, data: abi.encode(_digest) });
  }

  /// @notice Hardcoded digest (must equal payload.hashFor(address(0))) => infinite weight
  function anyAddressSubdigestLeaf(
    bytes32 _digest
  ) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_ANYADDR_SUBDIGEST, data: abi.encode(_digest) });
  }

  /// @notice Nested signer (internal branch + internal threshold gated) provides an external weight
  function nestedLeaf(
    EncodedNode memory _internalTree,
    uint256 _internalThreshold,
    uint256 _externalWeight
  ) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_NESTED, data: abi.encode(_internalTree, _internalThreshold, _externalWeight) });
  }

  /// @notice Sapient signer leaf (contract-driven imageHash) with external weight
  /// @param _sapient Address of the ISapient contract (used at encoding time)
  /// @param _weight  External weight contributed if sapient verification succeeds
  /// @param _sapientImageHash Image hash returned by the sapient verifier (used for hashing the configuration)
  function sapientLeaf(
    address _sapient,
    uint256 _weight,
    bytes32 _sapientImageHash
  ) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_SAPIENT, data: abi.encode(_sapient, _weight, _sapientImageHash) });
  }

  /// @notice Sapient-compact signer leaf (contract-driven imageHash) with external weight
  function sapientCompactLeaf(
    address _sapientCompact,
    uint256 _weight,
    bytes32 _sapientImageHash
  ) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_SAPIENT_COMPACT, data: abi.encode(_sapientCompact, _weight, _sapientImageHash) });
  }

  // -------------------------------------------------------------------------
  // Hashing that mirrors BaseSig.recoverBranch folding
  // -------------------------------------------------------------------------

  function hash(
    Node memory _node
  ) internal pure returns (bytes32) {
    return hashEncodedNode(node(_node.left, _node.right));
  }

  function hashEncodedNode(
    EncodedNode memory _node
  ) internal pure returns (bytes32) {
    if (_node.kind == KIND_ADDRESS) {
      (address addr, uint256 weight) = abi.decode(_node.data, (address, uint256));
      return _leafForAddressAndWeight(addr, weight);
    } else if (_node.kind == KIND_NODE) {
      (EncodedNode memory left, EncodedNode memory right) = abi.decode(_node.data, (EncodedNode, EncodedNode));
      bytes32 leftRoot = hashEncodedNode(left);
      bytes32 rightRoot = hashEncodedNode(right);
      return _f(leftRoot, rightRoot);
    } else if (_node.kind == KIND_SUBDIGEST) {
      (bytes32 digest) = abi.decode(_node.data, (bytes32));
      return _leafForSubdigest(digest);
    } else if (_node.kind == KIND_ANYADDR_SUBDIGEST) {
      (bytes32 digest) = abi.decode(_node.data, (bytes32));
      return _leafForAnyAddrSubdigest(digest);
    } else if (_node.kind == KIND_NESTED) {
      (EncodedNode memory inner, uint256 threshold, uint256 externalWeight) =
        abi.decode(_node.data, (EncodedNode, uint256, uint256));
      bytes32 innerRoot = hashEncodedNode(inner);
      return _leafForNested(innerRoot, threshold, externalWeight);
    } else if (_node.kind == KIND_SAPIENT) {
      (, uint256 weight, bytes32 img) = abi.decode(_node.data, (address, uint256, bytes32));
      return _leafForSapient(img, weight);
    } else if (_node.kind == KIND_SAPIENT_COMPACT) {
      (, uint256 weight, bytes32 img) = abi.decode(_node.data, (address, uint256, bytes32));
      return _leafForSapientCompact(img, weight);
    } else {
      revert InvalidKind(_node.kind);
    }
  }

  // -------------------------------------------------------------------------
  // Signature branch encoding (full-featured)
  // -------------------------------------------------------------------------

  /// @dev Internal: write 4-bit weight into low nibble for flags that use 1..15 inline, 0 => dynamic uint8 follows.
  function _appendWeightNibble4(bytes memory _prefix, uint256 _weight) private pure returns (bytes memory out) {
    bytes1 b0 = _prefix[0];
    if (_weight <= 15 && _weight != 0) {
      b0 = b0 | bytes1(uint8(_weight));
      out = _prefix;
      out[0] = b0;
    } else {
      if (_weight > 255) {
        revert WeightTooLarge(_weight);
      }
      out = abi.encodePacked(b0, uint8(_weight));
    }
  }

  /// @dev Internal: write 2-bit weight into low 2 bits (1..3 inline), 0 => dynamic uint8 follows.
  function _appendWeightBits2(bytes memory _prefix, uint256 _weight) private pure returns (bytes memory out) {
    uint8 low2;
    if (_weight >= 1 && _weight <= 3) {
      low2 = uint8(_weight);
      out = _prefix;
      out[0] = _prefix[0] | bytes1(low2);
    } else {
      if (_weight > 255) {
        revert WeightTooLarge(_weight);
      }
      out = abi.encodePacked(_prefix, uint8(_weight));
    }
  }

  /// @dev Encode nested threshold size into bits 3..2 using 1..4 bytes (encoded as len-1).
  function _encodeThresholdLenNibble(
    uint256 _threshold
  ) private pure returns (uint8 lenCode, bytes memory be) {
    uint256 n = SequenceHelpers._byteLen(_threshold);
    if (n == 0) {
      n = 1;
    } // represent zero with 1 byte 0x00
    if (n > 4) {
      revert ThresholdTooLarge(_threshold);
    }
    lenCode = uint8(n - 1); // 0->1 byte, 1->2, 2->3, 3->4
    be = SequenceHelpers._uN(_threshold, n);
  }

  /// @dev Helper to choose signature length-of-length (0..3 bytes) for ERC1271/Sapient-like flags.
  function _sigLenLen(
    uint256 _len
  ) private pure returns (uint256) {
    uint256 n = SequenceHelpers._byteLen(_len); // 0..32
    if (n > 3) {
      revert LengthSizeTooLarge(n);
    }
    return n;
  }

  /// @notice Full-featured encoder that supports all branch flags.
  function encodeSignature(
    EncodedNode memory _node,
    SignatureForNode[] memory _signatures,
    bool _trim
  ) internal pure returns (bool hasSig, bytes memory out) {
    // --- Address leaf (can encode: HASH (0), ETH_SIGN(7), ERC1271(2), or placeholders/NODE) ---
    if (_node.kind == KIND_ADDRESS) {
      (address addr, uint256 weight) = abi.decode(_node.data, (address, uint256));
      (bool found, bytes memory sig, uint8 chosenFlag) = findSignature(_signatures, _node);

      if (found) {
        // Normalize 65-byte {r,s,v} to EIP-2098 when using HASH/ETH_SIGN flags.
        if (chosenFlag == FLAG_SIGNATURE_HASH || chosenFlag == FLAG_SIGNATURE_ETH_SIGN) {
          if (sig.length == 65) {
            sig = SequenceHelpers.pack65to64(sig);
          } else if (sig.length != 64) {
            revert InvalidSignatureLength(sig.length);
          }
        }

        if (chosenFlag == FLAG_SIGNATURE_HASH) {
          bytes memory encoded = new bytes(1);
          encoded[0] = bytes1(uint8(FLAG_SIGNATURE_HASH) << 4);
          encoded = _appendWeightNibble4(encoded, weight);
          encoded = bytes.concat(encoded, sig);
          return (true, encoded);
        } else if (chosenFlag == FLAG_SIGNATURE_ETH_SIGN) {
          bytes memory encoded = new bytes(1);
          encoded[0] = bytes1(uint8(FLAG_SIGNATURE_ETH_SIGN) << 4);
          encoded = _appendWeightNibble4(encoded, weight);
          encoded = bytes.concat(encoded, sig);
          return (true, encoded);
        } else if (chosenFlag == FLAG_SIGNATURE_ERC1271) {
          // ERC1271(addr) + len(lenSig in 0..3 bytes) + sig
          uint256 lenSig = sig.length;
          uint256 lenLen = _sigLenLen(lenSig); // 0..3
          bytes1 b0 = bytes1(uint8(FLAG_SIGNATURE_ERC1271) << 4);
          // bits 3..2 = sizeSize (0..3)
          b0 = b0 | bytes1(uint8(lenLen) << 2);
          bytes memory encoded = abi.encodePacked(b0);
          // bottom 2 bits: external weight (1..3 inline; 0 => next byte)
          encoded = _appendWeightBits2(encoded, weight);
          encoded = bytes.concat(encoded, abi.encodePacked(addr));
          if (lenLen > 0) {
            encoded = bytes.concat(encoded, SequenceHelpers._uN(lenSig, lenLen));
          }
          encoded = bytes.concat(encoded, sig);
          return (true, encoded);
        } else {
          revert InvalidFlag(chosenFlag);
        }
      } else if (_trim) {
        // collapse to a pre-hashed node (FLAG_NODE + 32-bytes)
        bytes32 nodeHash = hashEncodedNode(_node);
        return (false, bytes.concat(bytes1(uint8(FLAG_NODE) << 4), bytes32(nodeHash)));
      } else {
        // encode as FLAG_ADDRESS placeholder (address + weight)
        bytes memory encoded = new bytes(1);
        encoded[0] = bytes1(uint8(FLAG_ADDRESS) << 4);
        encoded = _appendWeightNibble4(encoded, weight);
        encoded = abi.encodePacked(encoded, addr);
        return (false, encoded);
      }
    }

    // --- Internal binary node: emit left, then BRANCH(right) ---
    if (_node.kind == KIND_NODE) {
      (EncodedNode memory left, EncodedNode memory right) = abi.decode(_node.data, (EncodedNode, EncodedNode));
      (bool hasL, bytes memory encL) = encodeSignature(left, _signatures, _trim);
      (bool hasR, bytes memory encR) = encodeSignature(right, _signatures, _trim);

      if (!hasL && !hasR && _trim) {
        // collapse subtree to FLAG_NODE
        bytes32 subtree = hashEncodedNode(_node);
        return (false, bytes.concat(bytes1(uint8(FLAG_NODE) << 4), bytes32(subtree)));
      }

      // emit left in-place; wrap right as FLAG_BRANCH(len|encR)
      bytes memory encoded = encL;
      uint256 lenR = encR.length;
      uint256 lenLen = SequenceHelpers._byteLen(lenR); // 0 for zero, else 1..32
      encoded = bytes.concat(
        encoded, bytes1(uint8((FLAG_BRANCH << 4) | uint8(lenLen))), SequenceHelpers._uN(lenR, lenLen), encR
      );
      return (hasL || hasR, encoded);
    }

    // --- SUBDIGEST (hardcoded opHash) ---
    if (_node.kind == KIND_SUBDIGEST) {
      (bytes32 digest) = abi.decode(_node.data, (bytes32));
      bytes memory enc = bytes.concat(bytes1(uint8(FLAG_SUBDIGEST) << 4), digest);

      // Search for a signature
      // it is a signal that the subdigest
      // should be considered signed
      (bool found,,) = findSignature(_signatures, _node);
      return (found, enc);
    }

    // --- ANY-ADDRESS SUBDIGEST (hardcoded payload.hashFor(address(0))) ---
    if (_node.kind == KIND_ANYADDR_SUBDIGEST) {
      (bytes32 digest) = abi.decode(_node.data, (bytes32));
      bytes memory enc = bytes.concat(bytes1(uint8(FLAG_SIGNATURE_ANY_ADDRESS_SUBDIGEST) << 4), digest);
      return (true, enc);
    }

    // --- NESTED multisig ---
    if (_node.kind == KIND_NESTED) {
      (EncodedNode memory inner, uint256 internalThreshold, uint256 externalWeight) =
        abi.decode(_node.data, (EncodedNode, uint256, uint256));

      (bool hasInner, bytes memory encInner) = encodeSignature(inner, _signatures, _trim);

      // first byte:
      //   top nibble = 6 (FLAG_NESTED)
      //   bits 3..2   = threshold-size code (0=>1 byte, 1=>2, 2=>3, 3=>4)
      //   bits 1..0   = externalWeight (1..3 inline; 0 => next byte)
      (uint8 thLenCode, bytes memory thBE) = _encodeThresholdLenNibble(internalThreshold);
      bytes1 b0 = bytes1(uint8(FLAG_NESTED) << 4);
      b0 = b0 | bytes1(uint8(thLenCode) << 2);
      bytes memory encoded = abi.encodePacked(b0);
      encoded = _appendWeightBits2(encoded, externalWeight);
      encoded = bytes.concat(
        encoded,
        thBE,
        SequenceHelpers._uN(encInner.length, 3), // nested sub-branch length (3-byte big-endian)
        encInner
      );
      return (hasInner, encoded);
    }

    // --- SAPIENT ---
    if (_node.kind == KIND_SAPIENT) {
      (address sapient, uint256 weight, bytes32 imageHash) = abi.decode(_node.data, (address, uint256, bytes32));
      // Find a sapient signature explicitly flagged with FLAG_SIGNATURE_SAPIENT
      (bool found, bytes memory sig, uint8 selected) = findSignature(_signatures, _node);
      if (found) {
        if (selected != FLAG_SIGNATURE_SAPIENT) {
          revert InvalidFlag(selected);
        }
        uint256 lenSig = sig.length;
        uint256 lenLen = _sigLenLen(lenSig);
        bytes1 b0 = bytes1(uint8(FLAG_SIGNATURE_SAPIENT) << 4);
        // bits 3..2 = sizeSize
        b0 = b0 | bytes1(uint8(lenLen) << 2);
        bytes memory encoded = abi.encodePacked(b0);
        encoded = _appendWeightBits2(encoded, weight);
        encoded = bytes.concat(encoded, abi.encodePacked(sapient));
        if (lenLen > 0) {
          encoded = bytes.concat(encoded, SequenceHelpers._uN(lenSig, lenLen));
        }
        encoded = bytes.concat(encoded, sig);
        return (true, encoded);
      } else {
        // no sapient sig present; collapse to pre-hashed node
        bytes32 nodeHash = _leafForSapient(imageHash, weight);
        return (false, bytes.concat(bytes1(uint8(FLAG_NODE) << 4), nodeHash));
      }
    }

    // --- SAPIENT COMPACT ---
    if (_node.kind == KIND_SAPIENT_COMPACT) {
      (address sapientCompact, uint256 weight, bytes32 imageHash) = abi.decode(_node.data, (address, uint256, bytes32));
      (bool found, bytes memory sig, uint8 selected) = findSignature(_signatures, _node);
      if (found) {
        if (selected != FLAG_SIGNATURE_SAPIENT_COMPACT) {
          revert InvalidFlag(selected);
        }
        uint256 lenSig = sig.length;
        uint256 lenLen = _sigLenLen(lenSig);
        bytes1 b0 = bytes1(uint8(FLAG_SIGNATURE_SAPIENT_COMPACT) << 4);
        b0 = b0 | bytes1(uint8(lenLen) << 2);
        bytes memory encoded = abi.encodePacked(b0);
        encoded = _appendWeightBits2(encoded, weight);
        encoded = bytes.concat(encoded, abi.encodePacked(sapientCompact));
        if (lenLen > 0) {
          encoded = bytes.concat(encoded, SequenceHelpers._uN(lenSig, lenLen));
        }
        encoded = bytes.concat(encoded, sig);
        return (true, encoded);
      } else {
        bytes32 nodeHash = _leafForSapientCompact(imageHash, weight);
        return (false, bytes.concat(bytes1(uint8(FLAG_NODE) << 4), nodeHash));
      }
    }

    revert InvalidKind(_node.kind);
  }

  // -------------------------------------------------------------------------
  // Lookups
  // -------------------------------------------------------------------------

  /// @dev Lookup that must also match the intended FLAG for the node.
  function findSignature(
    SignatureForNode[] memory _signatures,
    EncodedNode memory _node
  ) internal pure returns (bool, bytes memory, uint8) {
    for (uint256 i = 0; i < _signatures.length; i++) {
      if (_signatures[i].node.kind == _node.kind && keccak256(_signatures[i].node.data) == keccak256(_node.data)) {
        return (true, _signatures[i].signature, _signatures[i].flag);
      }
    }
    return (false, "", 0);
  }

}
