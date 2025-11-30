// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SelfAuth } from "../modules/auth/SelfAuth.sol";

/// @title CreateHook
/// @author Michael Standen
/// @notice A hook that allows the creation of a contract using the wallet.
contract CreateHook is SelfAuth {

  /// @notice Emitted when a contract is created
  event CreatedContract(address addr);

  /// @notice Error thrown when the creation of a contract fails
  error CreateFailed(bytes initCode);

  /// @notice Error thrown when the creation of a contract with a salt fails
  error Create2Failed(bytes initCode, bytes32 salt);

  /// @notice Create a new contract
  /// @param initCode The init code of the contract
  /// @return addr The address of the created contract
  function createContract(
    bytes memory initCode
  ) public payable onlySelf returns (address addr) {
    assembly {
      addr := create(callvalue(), add(initCode, 32), mload(initCode))
    }
    if (addr == address(0)) {
      revert CreateFailed(initCode);
    }
    emit CreatedContract(addr);
  }

  /// @notice Create a new contract with a salt
  /// @param initCode The init code of the contract
  /// @param salt The salt used to create the contract
  /// @return addr The address of the created contract
  function createContractWithSalt(
    bytes memory initCode,
    bytes32 salt
  ) public payable onlySelf returns (address addr) {
    assembly {
      addr := create2(callvalue(), add(initCode, 32), mload(initCode), salt)
    }
    if (addr == address(0)) {
      revert Create2Failed(initCode, salt);
    }
    emit CreatedContract(addr);
  }

}
