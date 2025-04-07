// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Implementation } from "../../src/modules/Implementation.sol";
import { SelfAuth } from "../../src/modules/auth/SelfAuth.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";

contract ImplementationTest is AdvTest {

  Implementation public implementation;

  function setUp() public {
    implementation = new Implementation();
  }

  function test_updateImplementation(
    address _implementation
  ) public {
    vm.prank(address(implementation));
    implementation.updateImplementation(_implementation);
    assertEq(implementation.getImplementation(), _implementation);
  }

  function test_updateImplementation_revertWhenNotSelf() public {
    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, address(this)));
    implementation.updateImplementation(address(this));
  }

}
