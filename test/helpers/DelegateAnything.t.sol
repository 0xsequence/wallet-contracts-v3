// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { DelegateAnything } from "../../src/helpers/DelegateAnything.sol";
import { AdvTest } from "../utils/TestUtils.sol";

contract Target {

  function setStorageSlot(
    bytes32 slot,
    uint256 value
  ) external {
    assembly {
      sstore(slot, value)
    }
  }

  function revertCall() external pure {
    revert("Revert message");
  }

}

contract DelegateCallWrapper {

  DelegateAnything public delegateAnything;

  constructor(
    DelegateAnything _delegateAnything
  ) {
    delegateAnything = _delegateAnything;
  }

  function delegateCall(
    bytes32 opHash,
    uint256 startingGas,
    uint256 index,
    uint256 numCalls,
    uint256 space,
    bytes calldata data
  ) external {
    (bool success, bytes memory returnData) = address(delegateAnything)
      .delegatecall(
        abi.encodeWithSelector(
          DelegateAnything.handleSequenceDelegateCall.selector, opHash, startingGas, index, numCalls, space, data
        )
      );
    if (!success) {
      assembly {
        revert(add(returnData, 0x20), mload(returnData))
      }
    }
  }

}

contract DelegateAnythingTest is AdvTest {

  DelegateAnything public delegateAnything;
  DelegateCallWrapper public wrapper;
  Target public target;

  // Known random hash for storage slot
  bytes32 constant STORAGE_SLOT = keccak256("DelegateAnything.test.storage.slot");

  function setUp() public {
    delegateAnything = new DelegateAnything();
    wrapper = new DelegateCallWrapper(delegateAnything);
    target = new Target();
  }

  function test_directCallReverts() external {
    bytes memory inner = abi.encodeWithSelector(Target.setStorageSlot.selector, STORAGE_SLOT, 42);
    bytes memory data = abi.encodePacked(address(target), inner);

    vm.expectRevert(DelegateAnything.NotDelegateCall.selector);
    delegateAnything.handleSequenceDelegateCall(bytes32(0), 0, 0, 0, 0, data);
  }

  function test_successfulDelegateCall() external {
    uint256 expectedValue = 42;
    bytes32 slot = STORAGE_SLOT;
    bytes memory inner = abi.encodeWithSelector(Target.setStorageSlot.selector, slot, expectedValue);
    bytes memory data = abi.encodePacked(address(target), inner);

    // Call via delegatecall through wrapper
    wrapper.delegateCall(bytes32(0), 0, 0, 0, 0, data);

    // Validate storage slot on wrapper contract (since delegatecall executes in wrapper's context)
    uint256 storedValue = uint256(vm.load(address(wrapper), slot));
    assertEq(storedValue, expectedValue);
  }

  function test_failedDelegateCall() external {
    bytes memory inner = abi.encodeWithSelector(Target.revertCall.selector);
    bytes memory data = abi.encodePacked(address(target), inner);

    vm.expectRevert(
      abi.encodeWithSelector(
        DelegateAnything.DelegateCallFailed.selector, abi.encodeWithSignature("Error(string)", "Revert message")
      )
    );
    wrapper.delegateCall(bytes32(0), 0, 0, 0, 0, data);
  }

}
