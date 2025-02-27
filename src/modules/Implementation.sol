// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SelfAuth } from "./auth/SelfAuth.sol";

contract Implementation is SelfAuth {

  event ImplementationUpdated(address newImplementation);

  function updateImplementation(
    address _implementation
  ) external payable virtual onlySelf {
    _updateImplementation(_implementation);
  }

  function getImplementation() external view virtual returns (address) {
    return _getImplementation();
  }

  function _updateImplementation(
    address _implementation
  ) internal virtual {
    _setImplementation(_implementation);
    emit ImplementationUpdated(_implementation);
  }

  function _setImplementation(
    address _imp
  ) internal {
    assembly {
      sstore(address(), _imp)
    }
  }

  function _getImplementation() internal view returns (address _imp) {
    assembly {
      _imp := sload(address())
    }
  }

}
