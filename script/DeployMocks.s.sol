// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SingletonDeployer, console } from "lib/erc2470-libs/script/SingletonDeployer.s.sol";

import { Emitter } from "test/mocks/Emitter.sol";
import { MockSapient } from "test/mocks/MockSapient.sol";

contract DeployMocks is SingletonDeployer {

  function run() external {
    uint256 pk = vm.envUint("PRIVATE_KEY");

    bytes32 salt = bytes32(0);

    bytes memory initCode = abi.encodePacked(type(Emitter).creationCode);
    _deployIfNotAlready("Emitter", initCode, salt, pk);

    initCode = abi.encodePacked(type(MockSapient).creationCode);
    _deployIfNotAlready("MockSapient", initCode, salt, pk);
  }

}
