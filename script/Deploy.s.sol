// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SingletonDeployer } from "erc2470-libs/script/SingletonDeployer.s.sol";
import { Factory } from "src/Factory.sol";
import { Guest } from "src/Guest.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { Stage2Module } from "src/Stage2Module.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";

contract Deploy is SingletonDeployer {

  Factory public factory;
  Stage1Module public stage1Module;
  Stage2Module public stage2Module;
  Guest public guest;
  SessionManager public sessionManager;

  address public factoryAddress = 0x4B755c6A321C86bD35bBbb5CD56321FE48b51d1e;
  address public stage1ModuleAddress = 0x486300225986f854a03815B5C9f11d0abd83f6F9;
  address public stage2ModuleAddress = 0x50184E6a3c237Cfd1cCf359A8f9F2D0Fdc262f0B;
  address public guestModuleAddress = 0x2F2FED5893257F470308a64e041cbAd46501f68a;
  address public utilsAddress = 0x486300225986f854a03815B5C9f11d0abd83f6F9;
  address public sessionManagerAddress = 0x486300225986f854a03815B5C9f11d0abd83f6F9;

  function run() external {
    uint256 pk = vm.envUint("PRIVATE_KEY");
    address deployer = vm.envAddress("ADDRESS");

    vm.deal(deployer, 1000000 ether);

    bytes32 salt = bytes32(0);

    bytes memory initCode = abi.encodePacked(type(Factory).creationCode);
    address factoryDeploymentAddress = _deployIfNotAlready("Factory", initCode, salt, pk);
    vm.etch(factoryAddress, address(factoryDeploymentAddress).code);
    factory = Factory(payable(factoryAddress));

    initCode = abi.encodePacked(type(Stage1Module).creationCode, abi.encode(factory));
    address stage1ModuleDeploymentAddress = _deployIfNotAlready("Stage1Module", initCode, salt, pk);
    vm.etch(stage1ModuleAddress, address(stage1ModuleDeploymentAddress).code);
    stage1Module = Stage1Module(payable(stage1ModuleAddress));

    initCode = abi.encodePacked(type(Stage2Module).creationCode, abi.encode(factory));
    address stage2ModuleDeploymentAddress = _deployIfNotAlready("Stage2Module", initCode, salt, pk);
    vm.etch(stage2ModuleAddress, address(stage2ModuleDeploymentAddress).code);
    stage2Module = Stage2Module(payable(stage2ModuleAddress));

    initCode = abi.encodePacked(type(Guest).creationCode);
    address guestDeploymentAddress = _deployIfNotAlready("Guest", initCode, salt, pk);
    vm.etch(guestModuleAddress, address(guestDeploymentAddress).code);
    guest = Guest(payable(guestModuleAddress));

    initCode = abi.encodePacked(type(SessionManager).creationCode);
    address sessionManagerDeploymentAddress = _deployIfNotAlready("SessionManager", initCode, salt, pk);
    vm.etch(sessionManagerAddress, address(sessionManagerDeploymentAddress).code);
    sessionManager = SessionManager(payable(sessionManagerAddress));
  }

}
