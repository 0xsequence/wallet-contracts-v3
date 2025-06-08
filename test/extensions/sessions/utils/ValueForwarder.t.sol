// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

import { ValueForwarder } from "src/extensions/sessions/utils/ValueForwarder.sol";

import { AdvTest } from "test/utils/TestUtils.sol";

contract ValueForwarderTest is AdvTest {

  ValueForwarder public valueForwarder;

  function setUp() public {
    valueForwarder = new ValueForwarder();
  }

  function test_forwardValue(address from, address to, uint256 value) public {
    assumeNotPrecompile2(to);
    vm.assume(from != to);
    vm.assume(from.balance == 0);
    vm.deal(from, value);
    vm.prank(from);
    valueForwarder.forwardValue{ value: value }(to);
    assertEq(address(valueForwarder).balance, 0);
    assertEq(to.balance, value);
    assertEq(from.balance, 0);
  }

}
