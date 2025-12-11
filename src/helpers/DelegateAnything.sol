// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { IDelegatedExtension } from "../modules/interfaces/IDelegatedExtension.sol";
import { LibBytes } from "../utils/LibBytes.sol";
import { LibOptim } from "../utils/LibOptim.sol";

/// @title DelegateAnything
/// @author Michael Standen
/// @notice Helper for delegating calls to any contract
contract DelegateAnything is IDelegatedExtension {

  address internal immutable _SELF = address(this);

  /// @notice Error thrown when not called via delegatecall
  error NotDelegateCall();

  /// @notice Error thrown when a delegate call fails
  error DelegateCallFailed(bytes returnData);

  /// @inheritdoc IDelegatedExtension
  function handleSequenceDelegateCall(
    bytes32,
    uint256,
    uint256,
    uint256,
    uint256,
    bytes calldata data
  ) external {
    if (address(this) == _SELF) {
      revert NotDelegateCall();
    }

    (address to, uint256 pointer) = LibBytes.readAddress(data, 0);

    bool success;
    (success) = LibOptim.delegatecall(to, gasleft(), data[pointer:]);
    if (!success) {
      revert DelegateCallFailed(LibOptim.returnData());
    }
  }

}
