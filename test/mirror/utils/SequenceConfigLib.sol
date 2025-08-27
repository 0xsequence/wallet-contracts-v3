// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SequenceHelpers } from "./SequenceHelpers.sol";

// Implementation of the Sequence SDK to encode payloads, signatures and configurations directly in solidity
// meant mostly for testing purposes
library SequenceConfigLib {

  error InvalidSignatureLength(uint256 length);
  error InvalidKind(uint256 kind);

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

  uint256 constant KIND_ADDRESS = 0;
  uint256 constant KIND_NODE = 1;

  struct AddressNode {
    address addr;
    uint256 weight;
  }

  struct EncodedNode {
    uint256 kind;
    bytes data;
  }

  struct Node {
    EncodedNode left;
    EncodedNode right;
  }

  struct SignatureForNode {
    EncodedNode node;
    bytes signature; // EIP-2098 (64 bytes) or {r,s,v} (65 bytes); 65 will be packed
  }

  // --- internal helpers (local fkeccak == LibOptim.fkeccak256 semantics) ---
  function _f(bytes32 a, bytes32 b) private pure returns (bytes32) {
    return keccak256(abi.encodePacked(a, b));
  }

  function _leafForAddressAndWeight(address _addr, uint256 _weight) private pure returns (bytes32) {
    // must exactly match BaseSig._leafForAddressAndWeight
    return keccak256(abi.encodePacked("Sequence signer:\n", _addr, _weight));
  }

  // --- node constructors ---
  function addressLeaf(address _addr, uint256 _weight) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_ADDRESS, data: abi.encode(_addr, _weight) });
  }

  function node(EncodedNode memory _left, EncodedNode memory _right) internal pure returns (EncodedNode memory) {
    return EncodedNode({ kind: KIND_NODE, data: abi.encode(_left, _right) });
  }

  // --- hashing that mirrors BaseSig.recoverBranch exactly ---
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
      // fold like BaseSig: root = fkeccak(leftRoot, rightRoot)
      bytes32 leftRoot = hashEncodedNode(left);
      bytes32 rightRoot = hashEncodedNode(right);
      return _f(leftRoot, rightRoot);
    } else {
      revert InvalidKind(_node.kind);
    }
  }

  // --- encoding the signature branch (what BaseSig.recoverBranch expects) ---
  /// @dev Encodes the branch for `_node`. If `_trim` is true, nodes without a provided signature are
  ///      collapsed into `FLAG_NODE` (their subtree root hash). Otherwise, they encode as `FLAG_ADDRESS`.
  function encodeSignature(
    EncodedNode memory _node,
    SignatureForNode[] memory _signatures,
    bool _trim
  ) internal pure returns (bool hasSig, bytes memory out) {
    if (_node.kind == KIND_ADDRESS) {
      (address addr, uint256 weight) = abi.decode(_node.data, (address, uint256));
      (bool found, bytes memory sig) = findSignature(_signatures, _node);

      if (found) {
        // Normalize 65-byte {r,s,v} to EIP-2098 64 bytes if needed.
        if (sig.length == 65) {
          sig = SequenceHelpers.pack65to64(sig);
        } else if (sig.length != 64) {
          revert InvalidSignatureLength(sig.length);
        }

        bytes memory encoded = new bytes(1);
        // top nibble = FLAG_SIGNATURE_HASH
        encoded[0] = bytes1(uint8(FLAG_SIGNATURE_HASH) << 4);

        // low nibble = weight (1..15); 0 => dynamic (uint8 follows)
        if (weight <= 15 && weight != 0) {
          encoded[0] = encoded[0] | bytes1(uint8(weight));
        } else {
          require(weight <= 255, "weight>255 not encodable");
          encoded = abi.encodePacked(encoded, uint8(weight));
        }

        encoded = bytes.concat(encoded, sig);
        return (true, encoded);
      } else if (_trim) {
        // collapse to a pre-hashed node
        bytes32 nodeHash = hashEncodedNode(_node);
        return (false, bytes.concat(bytes1(uint8(FLAG_NODE) << 4), bytes32(nodeHash)));
      } else {
        // encode as FLAG_ADDRESS (address + weight)
        bytes memory encoded = new bytes(1);
        encoded[0] = bytes1(uint8(FLAG_ADDRESS) << 4);
        if (weight <= 15 && weight != 0) {
          encoded[0] = encoded[0] | bytes1(uint8(weight));
        } else {
          require(weight <= 255, "weight>255 not encodable");
          encoded = abi.encodePacked(encoded, uint8(weight));
        }
        encoded = abi.encodePacked(encoded, addr);
        return (false, encoded);
      }
    }

    if (_node.kind == KIND_NODE) {
      (EncodedNode memory left, EncodedNode memory right) = abi.decode(_node.data, (EncodedNode, EncodedNode));

      (bool hasL, bytes memory encL) = encodeSignature(left, _signatures, _trim);
      (bool hasR, bytes memory encR) = encodeSignature(right, _signatures, _trim);

      // if both sides have no signatures and trimming is allowed, collapse whole subtree
      if (!hasL && !hasR && _trim) {
        bytes32 subtree = hashEncodedNode(_node);
        return (false, bytes.concat(bytes1(uint8(FLAG_NODE) << 4), bytes32(subtree)));
      }

      // emit left as-is, then wrap right as FLAG_BRANCH(size|encR)
      bytes memory encoded = encL;

      uint256 lenR = encR.length;
      uint256 lenLen = SequenceHelpers._byteLen(lenR); // 0 for zero-size (unlikely), else 1..32
      encoded = bytes.concat(
        encoded, bytes1(uint8((FLAG_BRANCH << 4) | uint8(lenLen))), SequenceHelpers._uN(lenR, lenLen), encR
      );

      return (hasL || hasR, encoded);
    }

    revert InvalidKind(_node.kind);
  }

  function findSignature(
    SignatureForNode[] memory _signatures,
    EncodedNode memory _node
  ) internal pure returns (bool, bytes memory) {
    for (uint256 i = 0; i < _signatures.length; i++) {
      if (_signatures[i].node.kind == _node.kind && keccak256(_signatures[i].node.data) == keccak256(_node.data)) {
        return (true, _signatures[i].signature);
      }
    }
    return (false, "");
  }

}
