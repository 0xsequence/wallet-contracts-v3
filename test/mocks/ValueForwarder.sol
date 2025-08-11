// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title ValueForwarder
/// @author Michael Standen
/// @notice Forwarder for value
contract ValueForwarder {

  function forwardValue(address to, uint256 value) external payable {
    (bool success,) = to.call{ value: value }("");
    require(success, "ValueForwarder: Failed to forward value");
  }

}
