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

  event Success(bytes32 _opHash, uint256 _index);
  event Failed(bytes32 _opHash, uint256 _index);
  event Aborted(bytes32 _opHash, uint256 _index);
  event Skipped(bytes32 _opHash, uint256 _index);

  function setUp() external {
    guest = new Guest();
  }

  function test_fallbackZeroPrefix(
    GuestPayload memory p
  ) external {
    vm.assume(p.calls.length < 5 && p.calls.length > 0);
    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0; // No ETH transfers allowed
      decoded.calls[i].delegateCall = false; // No delegate calls allowed
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    bytes memory finalData = abi.encodePacked(bytes1(0x00), packed);

    bytes32 opHash = Payload.hashFor(decoded, address(guest));
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (decoded.calls[i].onlyFallback) {
        vm.expectEmit(true, true, true, true);
        emit Skipped(opHash, i);
      } else {
        vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        vm.expectEmit(true, true, true, true);
        emit Success(opHash, i);
      }
    }
    (bool ok,) = address(guest).call(finalData);
    assertTrue(ok);
  }

  function test_callInterface(GuestPayload memory p, bytes memory signature) external {
    vm.assume(p.calls.length < 5 && p.calls.length > 0);
    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0; // No ETH transfers allowed
      decoded.calls[i].delegateCall = false; // No delegate calls allowed
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    bytes32 opHash = Payload.hashFor(decoded, address(guest));

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (decoded.calls[i].onlyFallback) {
        vm.expectEmit(true, true, true, true);
        emit Skipped(opHash, i);
      } else {
        vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        vm.expectEmit(true, true, true, true);
        emit Success(opHash, i);
      }
    }

    Calls(address(guest)).execute(packed, signature);
  }

}
