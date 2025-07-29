// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SelfAuth } from "./auth/SelfAuth.sol";

abstract contract Creator is SelfAuth {

  /// @notice Emitted when a contract is created
  event CreatedContract(address _contract);

  /// @notice Error thrown when contract creation failed
  error CreateFailed(bytes _code);
  /// @notice Error thrown when contract creation failed
  error Create2Failed(bytes _code, bytes32 _salt);

  /**
   * @notice Creates a contract forwarding eth value
   * @param _code Creation code of the contract
   * @return addr The address of the created contract
   */
  function createContract(
    bytes memory _code
  ) public payable virtual onlySelf returns (address addr) {
    assembly {
      addr := create(callvalue(), add(_code, 32), mload(_code))
    }
    if (addr == address(0)) {
      revert CreateFailed(_code);
    }
    emit CreatedContract(addr);
  }

  /**
   * @notice Creates a contract forwarding eth value via CREATE2
   * @param _code Creation code of the contract
   * @param _salt Salt for deterministic address derivation
   * @return addr The address of the created contract
   */
  function create2Contract(bytes memory _code, bytes32 _salt) public payable virtual onlySelf returns (address addr) {
    assembly {
      addr := create2(callvalue(), add(_code, 32), mload(_code), _salt)
    }
    if (addr == address(0)) {
      revert Create2Failed(_code, _salt);
    }
    emit CreatedContract(addr);
  }

}
