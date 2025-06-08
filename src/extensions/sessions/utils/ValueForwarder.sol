// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title ValueForwarder
/// @author Michael Standen
/// @notice Forwarder for value transfers
contract ValueForwarder {

  /// @notice Error thrown when a value transfer fails
  error TransferFailed();

  /// @notice Forward value to a recipient
  /// @param to The recipient of the value
  function forwardValue(
    address to
  ) external payable {
    (bool success,) = to.call{ value: msg.value }("");
    if (!success) {
      revert TransferFailed();
    }
  }

}
