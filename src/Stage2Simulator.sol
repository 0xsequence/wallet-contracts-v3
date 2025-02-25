// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage2Module } from "./Stage2Module.sol";
import { Simulator } from "./modules/Simulator.sol";

contract Stage2Simulator is Simulator, Stage2Module {

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(Simulator, Stage2Module) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
