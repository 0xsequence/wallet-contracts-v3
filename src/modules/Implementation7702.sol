// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title Implementation7702
/// @author Agustin Aguilar
/// @notice Reads the delegated implementation of an EIP-7702 authority account
abstract contract Implementation7702 {

  /// @notice Get the current delegated implementation
  /// @return implementation The delegated implementation address
  function getImplementation() external view virtual returns (address) {
    return _getImplementation();
  }

  function _getImplementation() internal view virtual returns (address implementation) {
    address authority = address(this);

    assembly {
      // EIP-7702 delegation code is 0xef0100 || implementation.
      // When the wallet is called through delegation, address(this) is the authority account,
      // so its runtime code is the canonical source of the current delegated target.
      if eq(extcodesize(authority), 23) {
        extcodecopy(authority, 0, 0, 23)

        let word := mload(0)
        if eq(shr(232, word), 0xef0100) {
          implementation := and(shr(72, word), 0xffffffffffffffffffffffffffffffffffffffff)
        }
      }
    }
  }

}
