// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../src/modules/Payload.sol";
import { BaseSig } from "../../../src/modules/auth/BaseSig.sol";
import { BaseSigImp } from "../../modules/BaseSig.t.sol";
import { PrimitivesRPC } from "../../utils/PrimitivesRPC.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract IntentConfigFuzzTest is AdvTest {

  BaseSigImp public baseSigImp;

  function setUp() public {
    baseSigImp = new BaseSigImp();
  }

  struct FuzzParams {
    uint256 mainSignerPk;
    address callTarget;
    uint256 callValue;
    bytes callData;
  }

  function testFuzz_IntentConfig_Subdigest(
    FuzzParams memory params
  ) public {
    params.mainSignerPk = boundPk(params.mainSignerPk);
    params.callTarget = boundAddress(params.callTarget);
    if (params.callData.length > 1024) {
      bytes memory shortData = new bytes(1024);
      for (uint256 i = 0; i < 1024; i++) {
        shortData[i] = params.callData[i];
      }
      params.callData = shortData;
    }
    params.callValue = bound(params.callValue, 0, 10 ether);

    address mainSigner = vm.addr(params.mainSignerPk);

    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: params.callTarget,
      value: params.callValue,
      data: params.callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: 0
    });

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = calls;
    payload.space = 0;
    payload.nonce = 0;

    bytes32 anyAddressSubdigest = Payload.hashFor(payload, address(0));
    bytes32 opHash = Payload.hashFor(payload, address(baseSigImp));

    string memory configElements = string.concat(
      "signer:", vm.toString(mainSigner), ":1 ", "any-address-subdigest:", vm.toString(anyAddressSubdigest)
    );

    uint16 expectedThreshold = 1;
    uint64 expectedCheckpoint = 0;

    string memory configJson = PrimitivesRPC.newConfig(vm, expectedThreshold, expectedCheckpoint, configElements);

    bytes memory encodedSig = PrimitivesRPC.toEncodedSignature(vm, configJson, "", false);

    bytes32 expectedImageHash = PrimitivesRPC.getImageHash(vm, configJson);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 recoveredOpHash) =
      baseSigImp.recoverPub(payload, encodedSig, true, address(0));

    assertEq(threshold, expectedThreshold, "Threshold mismatch");
    assertEq(checkpoint, expectedCheckpoint, "Checkpoint mismatch");
    assertEq(weight, type(uint256).max, "Weight mismatch (should be max due to subdigest)");
    assertEq(recoveredOpHash, opHash, "OpHash mismatch");
    assertEq(imageHash, expectedImageHash, "ImageHash mismatch");
  }

}
