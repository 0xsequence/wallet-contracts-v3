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

  constructor(bytes memory _expectedData, bytes memory _willReturn) {
    expectedDataPointer = new VariableDataStore(_expectedData);
    willReturnPointer = new VariableDataStore(_willReturn);
  }

  fallback() external {
    bytes memory expectedData = expectedDataPointer.data();
    bytes memory willReturn = willReturnPointer.data();

    if (keccak256(expectedData) != keccak256(msg.data)) {
      revert("Invalid data");
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
    address to = address(0x1234);
    vm.mockCall(to, _data, _return);

    ModuleImp module = new ModuleImp(_data, _return);
    address wallet = factory.deploy(address(module), _salt);

    (bool success, bytes memory returnData) = wallet.call(_data);
    assertEq(success, true);
    assertEq(returnData, _return);
  }

}
