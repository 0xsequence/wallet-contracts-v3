// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ERC4337FactoryWrapper } from "../src/ERC4337FactoryWrapper.sol";
import { Factory } from "../src/Factory.sol";
import { AdvTest } from "./utils/TestUtils.sol";

contract ERC4337FactoryWrapperTest is AdvTest {

  ERC4337FactoryWrapper factoryWrapper;
  Factory factory;
  address senderCreator;

  function setUp() external {
    factory = new Factory();
    senderCreator = makeAddr("senderCreator");
    factoryWrapper = new ERC4337FactoryWrapper(address(factory), senderCreator);
  }

  function test_deploy(address _mainModule, bytes32 _salt) external {
    vm.startPrank(senderCreator);
    address result = factoryWrapper.deploy(_mainModule, _salt);
    assertNotEq(result.code.length, 0);
  }

  function test_deployMatchesFactory(address _mainModule, bytes32 _salt) external {
    address factoryResult = factory.deploy(_mainModule, _salt);
    vm.startPrank(senderCreator);
    address result = factoryWrapper.deploy(_mainModule, _salt);
    assertEq(result, factoryResult);
  }

  function test_deployNotSenderCreator(address _mainModule, bytes32 _salt) external {
    vm.expectRevert(abi.encodeWithSelector(ERC4337FactoryWrapper.NotSenderCreator.selector));
    factoryWrapper.deploy(_mainModule, _salt);
  }

  function test_deployTwice(address _mainModule, bytes32 _salt) external {
    vm.startPrank(senderCreator);
    address result1 = factoryWrapper.deploy(_mainModule, _salt);
    address result2 = factoryWrapper.deploy(_mainModule, _salt);
    assertEq(result1, result2);
  }

  /// @notice The senderCreator will never send value.
  function test_deployForwardValue(address _mainModule, bytes32 _salt, uint256 _value) external {
    vm.deal(address(senderCreator), _value);
    vm.startPrank(senderCreator);
    address result = factoryWrapper.deploy{ value: _value }(_mainModule, _salt);
    assertEq(result.balance, _value);
  }

}
