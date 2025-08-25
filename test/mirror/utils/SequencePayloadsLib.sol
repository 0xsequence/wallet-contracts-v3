// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "src/modules/Payload.sol";

// Implementation of the Sequence SDK to encode payloads, signatures and configurations directly in solidity
// meant mostly for testing purposes
library SequencePayloadsLib {
  /// @notice Error thrown when the kind is invalid
  error InvalidKind(uint8 _kind);

  /// @notice Error when nonce does not fit in 7 bytes (56 bits)
  error NonceTooLarge(uint256 nonce);

  /// @notice Error when space does not fit in 20 bytes (uint160)
  error SpaceTooLarge(uint256 space);

  /// @notice Error when number of calls does not fit in 16 bits
  error TooManyCalls(uint256 calls);

  /// @notice Error when call.data length exceeds 24-bit length field
  error DataTooLong(uint256 idx, uint256 length);

  /// @notice Error when behaviorOnError does not fit in 2 bits
  error InvalidBehaviorOnError(uint256 behavior);

  /// @notice Encodes the payload into a packed calls format
  ///         This mirrors `Payload.fromPackedCalls` (reverse operation).
  ///         Simplicity/correctness over gas-efficiency (testing helper).
  /// @param _decoded The decoded payload (must have kind = KIND_TRANSACTIONS)
  /// @param _self The address of the self (wallet)
  /// @return The packed calls
  function toPackedCalls(Payload.Decoded memory _decoded, address _self) internal pure returns (bytes memory) {
    if (_decoded.kind != Payload.KIND_TRANSACTIONS) {
      revert InvalidKind(_decoded.kind);
    }

    // --- Global flag --------------------------------------------------------
    // bit 0: 1 => space omitted (implied zero), 0 => space present (uint160)
    // bits 1..3: nonce byte-length (0..7). If 0 => nonce omitted (implied zero)
    // bit 4: 1 => exactly one call (numCalls omitted), 0 => numCalls present
    // bit 5: 1 => numCalls is uint16, 0 => numCalls is uint8
    uint8 globalFlag = 0;

    // Space
    bool omitSpace = (_decoded.space == 0);
    if (!omitSpace && _decoded.space > type(uint160).max) {
      revert SpaceTooLarge(_decoded.space);
    }
    if (omitSpace) {
      globalFlag |= 0x01; // bit 0
    }

    // Nonce
    uint256 nonce = _decoded.nonce;
    uint256 nonceSize = _byteLen(nonce); // 0..32
    if (nonceSize > 7) revert NonceTooLarge(nonce);
    // place into bits [3:1]
    globalFlag |= uint8(nonceSize << 1);

    // Calls / numCalls
    uint256 nCalls = _decoded.calls.length;
    bool single = (nCalls == 1);
    if (single) {
      globalFlag |= 0x10; // bit 4
    }

    bool callsUse16 = false;
    if (!single) {
      if (nCalls <= type(uint8).max) {
        // bit 5 remains 0 (uint8)
        callsUse16 = false;
      } else if (nCalls <= type(uint16).max) {
        globalFlag |= 0x20; // bit 5 -> uint16
        callsUse16 = true;
      } else {
        revert TooManyCalls(nCalls);
      }
    }

    // --- Build the packed bytes --------------------------------------------
    bytes memory out = abi.encodePacked(bytes1(globalFlag));

    // Optional: space (uint160, 20 bytes)
    if (!omitSpace) {
      out = bytes.concat(out, abi.encodePacked(bytes20(uint160(_decoded.space))));
    }

    // Optional: nonce (nonceSize bytes, big-endian)
    if (nonceSize > 0) {
      out = bytes.concat(out, _uN(nonce, nonceSize));
    }

    // Optional: number of calls
    if (!single) {
      if (callsUse16) {
        out = bytes.concat(out, abi.encodePacked(uint16(nCalls))); // big-endian
      } else {
        out = bytes.concat(out, abi.encodePacked(uint8(nCalls)));
      }
    }

    // --- Per-call encoding --------------------------------------------------
    // flags:
    // bit 0: 1 => "call to self" (address omitted), 0 => address present
    // bit 1: value present (uint256)
    // bit 2: data present (uint24 length + bytes)
    // bit 3: gasLimit present (uint256)
    // bit 4: delegateCall (bool)
    // bit 5: onlyFallback (bool)
    // bits 6..7: behaviorOnError (2 bits)
    for (uint256 i = 0; i < nCalls; i++) {
      Payload.Call memory c = _decoded.calls[i];

      // We cannot infer the caller's "self" (wallet) address here,
      // so we always encode the destination address explicitly.
      // => bit0 remains 0 and we append c.to as 20 bytes.
      uint8 flags = 0;

      if (c.to == _self) {
        flags |= 0x01;
      }

      // value
      if (c.value > 0) flags |= 0x02;

      // data
      uint256 dlen = c.data.length;
      if (dlen > 0) {
        if (dlen > type(uint24).max) revert DataTooLong(i, dlen);
        flags |= 0x04;
      }

      // gasLimit
      if (c.gasLimit > 0) flags |= 0x08;

      // delegateCall / onlyFallback
      if (c.delegateCall) flags |= 0x10;
      if (c.onlyFallback) flags |= 0x20;

      // behaviorOnError
      if (c.behaviorOnError > 3) revert InvalidBehaviorOnError(c.behaviorOnError);
      flags |= uint8((c.behaviorOnError & 0x03) << 6);

      // Write flags first
      out = bytes.concat(out, abi.encodePacked(bytes1(flags)));

      // Address (since we never set "call to self")
      if (c.to != _self) {
        out = bytes.concat(out, abi.encodePacked(c.to));
      }

      // value (uint256)
      if ((flags & 0x02) != 0) {
        out = bytes.concat(out, abi.encodePacked(bytes32(c.value)));
      }

      // data: uint24 length (big-endian) + bytes
      if ((flags & 0x04) != 0) {
        out = bytes.concat(out, _uN(dlen, 3), c.data);
      }

      // gasLimit (uint256)
      if ((flags & 0x08) != 0) {
        out = bytes.concat(out, abi.encodePacked(bytes32(c.gasLimit)));
      }
    }

    return out;
  }

  // -------------------------------------------------------------------------
  // Helpers (simple & explicit for correctness in tests)
  // -------------------------------------------------------------------------

  /// @dev Returns the minimal number of bytes to represent `x` (big-endian).
  function _byteLen(uint256 x) private pure returns (uint256 n) {
    while (x != 0) { n++; x >>= 8; }
  }

  /// @dev Encodes `value` as exactly `len` big-endian bytes.
  function _uN(uint256 value, uint256 len) private pure returns (bytes memory out) {
    out = new bytes(len);
    for (uint256 i = 0; i < len; i++) {
      out[len - 1 - i] = bytes1(uint8(value & 0xFF));
      value >>= 8;
    }
    // If value != 0 here, it did not fit; callers guard lengths.
  }
}