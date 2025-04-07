// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../src/Factory.sol";
import { AdvTest } from "./utils/TestUtils.sol";

contract FactoryTest is AdvTest {

  Factory factory;

  function setUp() external {
    factory = new Factory();
  }

  function test_deploy(address _mainModule, bytes32 _salt) external {
    address result = factory.deploy(_mainModule, _salt);
    assertNotEq(result.code.length, 0);
  }

  function test_deployTwice(address _mainModule, bytes32 _salt) external {
    factory.deploy(_mainModule, _salt);
    vm.expectRevert(abi.encodeWithSelector(Factory.DeployFailed.selector, _mainModule, _salt));
    factory.deploy(_mainModule, _salt);
  }

  function test_deployForwardValue(address _mainModule, bytes32 _salt, uint256 _value) external {
    vm.deal(address(this), _value);
    address result = factory.deploy{ value: _value }(_mainModule, _salt);
    assertEq(result.balance, _value);
  }

}
