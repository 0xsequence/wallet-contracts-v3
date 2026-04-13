// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Calls } from "./modules/Calls.sol";

import { ERC4337v07 } from "./modules/ERC4337v07.sol";
import { Hooks } from "./modules/Hooks.sol";
import { Stage7702Auth } from "./modules/auth/Stage7702Auth.sol";
import { IAuth } from "./modules/interfaces/IAuth.sol";

/// @title Stage7702Module
/// @author Agustin Aguilar
/// @notice The only stage of an EIP-7702 wallet
contract Stage7702Module is Calls, Stage7702Auth, Hooks, ERC4337v07 {

  constructor(
    address _entryPoint,
    address _defaultCheckpointer
  ) ERC4337v07(_entryPoint) Stage7702Auth(_defaultCheckpointer) { }

  /// @inheritdoc IAuth
  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(IAuth, Stage7702Auth) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
