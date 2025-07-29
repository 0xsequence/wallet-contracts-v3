// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Creator } from "../../src/modules/Creator.sol";

import { AdvTest } from "../utils/TestUtils.sol";

contract CreatorImp is Creator { }

contract CreatorTest is AdvTest {

  CreatorImp public creator = new CreatorImp();

  function test_createContract_success(
    uint256 _value
  ) external {
    _value = bound(_value, 0, 100 ether);

    bytes memory code = type(Dummy).creationCode;

    // fund Creator so it can forward ETH
    vm.deal(address(creator), _value);

    // We only care that the event is emitted – we do not validate the data
    vm.expectEmit(false, false, false, false, address(creator));
    emit Creator.CreatedContract(address(0));

    vm.prank(address(creator));
    address newAddr = creator.createContract{ value: _value }(code);

    assertTrue(newAddr != address(0), "new address is zero");
    assertGt(newAddr.code.length, 0, "no runtime code"); // contract really exists
    assertEq(newAddr.balance, _value, "forwarded value mismatch");
  }

  function test_create2Contract_success(uint256 _value, bytes32 _salt) external {
    _value = bound(_value, 0, 100 ether);
    bytes memory code = type(Dummy).creationCode;

    vm.deal(address(creator), _value);

    vm.expectEmit(false, false, false, false, address(creator));
    emit Creator.CreatedContract(address(0));

    vm.prank(address(creator));
    address deployed = creator.create2Contract{ value: _value }(code, _salt);

    bytes32 data = keccak256(abi.encodePacked(bytes1(0xff), address(creator), _salt, keccak256(code)));
    address expected = address(uint160(uint256(data)));
    assertEq(deployed, expected, "unexpected CREATE2 address");

    assertGt(deployed.code.length, 0, "no runtime code");
    assertEq(deployed.balance, _value, "forwarded value mismatch");
  }

  function test_create2Contract_duplicate(
    bytes32 _salt
  ) external {
    bytes memory code = type(Dummy).creationCode;

    vm.prank(address(creator));
    creator.create2Contract(code, _salt); // first deployment succeeds

    // second deployment with same salt & code must revert
    vm.expectRevert(abi.encodeWithSelector(Creator.Create2Failed.selector, code, _salt));

    vm.prank(address(creator));
    creator.create2Contract(code, _salt);
  }

}

contract Dummy {

  // A tiny contract whose runtime code is non‑empty
  uint256 public constant MAGIC = 42;

  constructor() payable { }

}
