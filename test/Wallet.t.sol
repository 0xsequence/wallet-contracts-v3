// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../src/Factory.sol";
import { AdvTest } from "./utils/TestUtils.sol";

contract VariableDataStore {

  bytes public data;

  constructor(
    bytes memory _data
  ) {
    data = _data;
  }

}

contract ModuleImp {

  VariableDataStore public immutable expectedDataPointer;
  VariableDataStore public immutable willReturnPointer;
  uint256 public immutable expectedValue;
  bool public immutable alwaysReverts;

  constructor(bytes memory _expectedData, bytes memory _willReturn, uint256 _expectedValue, bool _alwaysReverts) {
    expectedDataPointer = new VariableDataStore(_expectedData);
    willReturnPointer = new VariableDataStore(_willReturn);
    expectedValue = _expectedValue;
    alwaysReverts = _alwaysReverts;
  }

  receive() external payable {
    _verifyAndReturn();
  }

  fallback() external payable {
    _verifyAndReturn();
  }

  function _verifyAndReturn() internal {
    if (alwaysReverts) {
      revert("Always reverts");
    }

    bytes memory expectedData = expectedDataPointer.data();
    bytes memory willReturn = willReturnPointer.data();

    if (keccak256(expectedData) != keccak256(msg.data)) {
      revert("Invalid data");
    }

    if (msg.value != expectedValue) {
      revert("Invalid value");
    }

    assembly {
      return(add(willReturn, 32), mload(willReturn))
    }
  }

}

contract WalletTest is AdvTest {

  Factory public factory;

  function setUp() public {
    factory = new Factory();
  }

  function test_forward(bytes32 _salt, bytes calldata _data, bytes calldata _return) external {
    ModuleImp module = new ModuleImp(_data, _return, 0, false);
    address wallet = factory.deploy(address(module), _salt);

    (bool success, bytes memory returnData) = wallet.call(_data);
    assertEq(success, true);
    assertEq(returnData, _return);
  }

  function test_doNotForwardWithValue(bytes32 _salt, uint256 _value) external {
    vm.assume(_value > 0);

    vm.deal(address(this), _value);
    ModuleImp module = new ModuleImp(bytes(""), bytes(""), 0, true);
    address wallet = factory.deploy(address(module), _salt);

    (bool success, bytes memory returnData) = wallet.call{ value: _value }(bytes(""));
    assertEq(success, true);
    assertEq(returnData, bytes(""));
  }

  function test_forwardValueWithData(
    bytes32 _salt,
    bytes calldata _data,
    bytes calldata _return,
    uint256 _value
  ) external {
    vm.assume(_data.length > 0);

    vm.deal(address(this), _value);
    ModuleImp module = new ModuleImp(_data, _return, _value, false);
    address wallet = factory.deploy(address(module), _salt);

    (bool success, bytes memory returnData) = wallet.call{ value: _value }(_data);
    assertEq(success, true);
    assertEq(returnData, _return);
  }

}
