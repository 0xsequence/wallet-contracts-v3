// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SingletonDeployer, console } from "erc2470-libs/script/SingletonDeployer.s.sol";
import { Factory } from "src/Factory.sol";
import { Guest } from "src/Guest.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";

contract Deploy is SingletonDeployer {

  function run() external {
    uint256 pk = vm.envUint("PRIVATE_KEY");

    bytes32 salt = bytes32(0);

    bytes memory initCode = abi.encodePacked(type(Factory).creationCode);
    address factory = _deployIfNotAlready("Factory", initCode, salt, pk);

    initCode = abi.encodePacked(type(Stage1Module).creationCode, abi.encode(factory));
    address stage1Module = _deployIfNotAlready("Stage1Module", initCode, salt, pk);

    console.log("Stage2Module for Stage1Module is", Stage1Module(payable(stage1Module)).STAGE_2_IMPLEMENTATION());

    initCode = abi.encodePacked(type(Guest).creationCode);
    _deployIfNotAlready("Guest", initCode, salt, pk);

    initCode = abi.encodePacked(type(SessionManager).creationCode);
    _deployIfNotAlready("SessionManager", initCode, salt, pk);
  }

}
