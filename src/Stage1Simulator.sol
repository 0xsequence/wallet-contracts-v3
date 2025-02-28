// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage1Module } from "./Stage1Module.sol";
import { Simulator } from "./modules/Simulator.sol";

contract Stage1Simulator is Simulator, Stage1Module {

  constructor(
    address _factory
  ) Stage1Module(_factory) { }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(Simulator, Stage1Module) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
