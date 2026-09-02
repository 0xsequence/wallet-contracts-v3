// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title SelfAuth
/// @author Agustin Aguilar, Michael Standen
/// @notice Modifier for checking if the caller is the same as the contract
abstract contract SelfAuth {

  /// @notice Error thrown when the caller is not the same as the contract
  error OnlySelf(address _sender);

  /// @notice Restricts a function to calls where the caller is the contract itself
  /// @dev Under EIP-7702 the authority EOA also satisfies this check: a plain transaction from the EOA to its
  /// own address runs the delegated code with `msg.sender == address(this)`. For an EIP-7702 wallet this
  /// modifier therefore gates on "the wallet or its authority key", and the authority key reaches it without a
  /// Sequence signature, a nonce or a checkpointer. Rotating the configuration does not revoke that access.
  /// See `docs/EIP7702.md` for the full trust model.
  modifier onlySelf() {
    if (msg.sender != address(this)) {
      revert OnlySelf(msg.sender);
    }
    _;
  }

}
