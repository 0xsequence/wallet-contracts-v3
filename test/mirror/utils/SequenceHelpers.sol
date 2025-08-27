pragma solidity ^0.8.27;

library SequenceHelpers {

  error ValueDidNotFit(uint256 value, uint256 len);

  // -------------------------------------------------------------------------
  // Helpers (simple & explicit for correctness in tests)
  // -------------------------------------------------------------------------

  /// @dev Returns the minimal number of bytes to represent `x` (big-endian).
  function _byteLen(
    uint256 x
  ) internal pure returns (uint256 n) {
    while (x != 0) {
      n++;
      x >>= 8;
    }
  }

  /// @dev Encodes `value` as exactly `len` big-endian bytes.
  function _uN(uint256 value, uint256 len) internal pure returns (bytes memory out) {
    out = new bytes(len);
    for (uint256 i = 0; i < len; i++) {
      out[len - 1 - i] = bytes1(uint8(value & 0xFF));
      value >>= 8;
    }
    if (value != 0) {
      revert ValueDidNotFit(value, len);
    }
  }

  /// @dev Pack 65-byte {r,s,v} into EIP-2098 64-byte form.
  function pack65to64(
    bytes memory sig65
  ) internal pure returns (bytes memory sig64) {
    require(sig65.length == 65, "sig65 length");
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := mload(add(sig65, 0x20))
      s := mload(add(sig65, 0x40))
      v := byte(0, mload(add(sig65, 0x60)))
    }
    return toEIP2098(r, s, v);
  }

  /// @dev EIP-2098 encoding from (r,s,v). Reverts if s is not low.
  function toEIP2098(bytes32 r, bytes32 s, uint8 v) internal pure returns (bytes memory sig64) {
    // enforce low-s to mirror typical wallet signing
    uint256 sInt = uint256(s);
    require(sInt < 0x8000000000000000000000000000000000000000000000000000000000000000, "s not low");
    uint256 yParity = v - 27;
    bytes32 yParityAndS = bytes32((yParity << 255) | sInt);
    sig64 = abi.encodePacked(r, yParityAndS);
  }

}
