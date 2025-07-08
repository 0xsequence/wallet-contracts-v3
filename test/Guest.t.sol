// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Guest } from "../src/Guest.sol";

import { Calls } from "../src/modules/Calls.sol";
import { Payload } from "../src/modules/Payload.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";

struct GuestPayload {
  bool noChainId;
  Payload.Call[] calls;
  uint160 space;
  uint56 nonce;
}

function toDecodedGuestPayload(
  GuestPayload memory p
) pure returns (Payload.Decoded memory d) {
  d.kind = Payload.KIND_TRANSACTIONS;
  d.calls = p.calls;
  d.space = p.space;
  d.nonce = p.nonce;
}

contract GuestTest is AdvTest {

  Guest public guest;

  event CallSucceeded(bytes32 _opHash, uint256 _index);
  event CallFailed(bytes32 _opHash, uint256 _index, bytes _returnData);
  event CallAborted(bytes32 _opHash, uint256 _index, bytes _returnData);
  event CallSkipped(bytes32 _opHash, uint256 _index);

  function setUp() external {
    guest = new Guest();
  }

  function test_fallback(
    GuestPayload memory p
  ) external {
    vm.assume(p.calls.length < 5 && p.calls.length > 0);
    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0; // No ETH transfers allowed
      decoded.calls[i].delegateCall = false; // No delegate calls allowed
      decoded.calls[i].behaviorOnError = bound(decoded.calls[i].behaviorOnError, 0, 2);
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    bytes32 opHash = Payload.hashFor(decoded, address(guest));
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (decoded.calls[i].onlyFallback) {
        vm.expectEmit(true, true, true, true);
        emit CallSkipped(opHash, i);
      } else {
        vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        // vm.expectEmit(true, true, true, true);
        // emit CallSucceeded(opHash, i);
      }
    }
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_notEnoughGas(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;

      if (i == callIndex) {
        // Only set high gas limit for the specified call
        uint256 gasLimit = bound(decoded.calls[i].gasLimit, gasleft() + 1, type(uint256).max);
        decoded.calls[i].gasLimit = gasLimit;
        decoded.calls[i].onlyFallback = false;
      } else {
        // Set normal gas limits for other calls
        decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    vm.expectRevert();
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_delegateCallNotAllowed(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (i == callIndex) {
        // Set delegateCall to true for the specified call
        decoded.calls[i].delegateCall = true;
        decoded.calls[i].onlyFallback = false;
      } else {
        decoded.calls[i].delegateCall = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    vm.expectRevert(abi.encodeWithSelector(Guest.DelegateCallNotAllowed.selector, callIndex));
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_callFailsWithIgnoreBehavior(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (i == callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
        decoded.calls[i].onlyFallback = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    bytes32 opHash = Payload.hashFor(decoded, address(guest));

    // Mock the call to fail with some revert data
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "Test error");
    vm.mockCallRevert(decoded.calls[callIndex].to, decoded.calls[callIndex].data, revertData);

    // Expect the failure event
    vm.expectEmit(true, true, true, true);
    emit CallFailed(opHash, callIndex, revertData);

    // Expect success or skipped events for remaining calls
    for (uint256 i = callIndex + 1; i < decoded.calls.length; i++) {
      vm.expectEmit(true, true, true, true);
      if (i == callIndex + 1 || !decoded.calls[i].onlyFallback) {
        vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        emit CallSucceeded(opHash, i);
      } else {
        emit CallSkipped(opHash, i);
      }
    }

    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_callFailsWithRevertBehavior(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (i == callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
        decoded.calls[i].onlyFallback = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    // Mock the call to fail with some revert data
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "Test error");
    vm.mockCallRevert(decoded.calls[callIndex].to, decoded.calls[callIndex].data, revertData);

    // Expect the revert
    vm.expectRevert(abi.encodeWithSelector(Calls.Reverted.selector, decoded, callIndex, revertData));

    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_callFailsWithAbortBehavior(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (i == callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_ABORT_ON_ERROR;
        decoded.calls[i].onlyFallback = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    bytes32 opHash = Payload.hashFor(decoded, address(guest));

    // Mock the call to fail with some revert data
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "Test error");
    vm.mockCallRevert(decoded.calls[callIndex].to, decoded.calls[callIndex].data, revertData);

    // Expect the abort event
    vm.expectEmit(true, true, true, true);
    emit CallAborted(opHash, callIndex, revertData);

    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_forwardPayment(uint256 _value1, uint256 _value2) external {
    address to1 = address(0x100001);
    address to2 = address(0x100002);

    _value1 = bound(_value1, 0, type(uint128).max);
    _value2 = bound(_value2, 0, type(uint128).max);

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](2);
    payload.calls[0].to = to1;
    payload.calls[0].value = _value1;
    payload.calls[1].to = to2;
    payload.calls[1].value = _value2;

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, payload);

    uint256 total = _value1 + _value2;
    vm.deal(address(this), total);
    (bool ok,) = address(guest).call{value: total}(packed);
    assertTrue(ok);

    assertEq(address(this).balance, 0);

    assertEq(address(to1).balance, _value1);
    assertEq(address(to2).balance, _value2);
  }
}
