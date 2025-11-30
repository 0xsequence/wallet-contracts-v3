// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase } from "./ExtendedSessionTestBase.sol";
import { Vm, console } from "forge-std/Test.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { SessionErrors, SessionManager, SessionSig } from "src/extensions/sessions/SessionManager.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation,
  ParameterRule,
  Permission,
  UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Calls } from "src/modules/Calls.sol";
import { Payload } from "src/modules/Payload.sol";

/// @notice Session signature abuse tests.
contract IntegrationSessionSignatureAbuseTest is ExtendedSessionTestBase {

  function test_SessionSigner_ZeroAddress_reverts_InvalidSessionSigner(
    uint8 v,
    bytes32 s
  ) public {
    // Create a topology with the session signer
    string memory topology = _createDefaultTopology();

    // Create a wallet with the topology
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Build the payload
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0].to = address(mockTarget);

    // Build the signature
    string[] memory callSignatures = new string[](1);
    bytes32 payloadHash = SessionSig.hashPayloadCallIdx(address(wallet), payload, 0);
    bytes32 r = bytes32(0); // Force the signature to return address(0)
    assertEq(ecrecover(payloadHash, v, r, s), address(0));
    callSignatures[0] = _explicitCallSignatureToJSON(
      0, string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)))
    );
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    bytes memory encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, false);

    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    // Execute
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSessionSigner.selector, address(0)));
    wallet.execute(packedPayload, encodedSignature);
  }

  function test_PermissionIndex_OutOfRange_reverts_MissingPermission(
    FuzzPermission[] memory fuzzPermissions,
    uint8 permissionIndex
  ) public {
    // Create permissions for test
    Permission[] memory permissions = _fuzzToPermissions(fuzzPermissions, 3, 3);

    permissionIndex = uint8(bound(permissionIndex, permissions.length, 2 ** 7 - 1));
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: block.chainid,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: permissions
    });

    // Create a topology with the session signer
    string memory topology = _createTopology(sessionPerms);

    // Create a wallet with the topology
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Build the payload
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0].to = address(mockTarget);

    // Build the signature
    uint8[] memory permissionIdxs = new uint8[](1);
    permissionIdxs[0] = permissionIndex;
    bytes memory signature =
      _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, permissionIdxs);

    // Execute
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.MissingPermission.selector, permissionIndex));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);
  }

  function test_CrossChain_ReplayProtection_RepeatableCall() public {
    // Create default wallet
    string memory topology = _createDefaultTopology();
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Build cross chain supported payload
    Payload.Decoded memory payload1 = _buildPayload(1);
    payload1.noChainId = true;
    payload1.calls[0].to = address(mockTarget);

    // Sign
    string[] memory callSignatures1 = new string[](1);
    bytes32 callHash = SessionSig.hashPayloadCallIdx(address(wallet), payload1, 0);
    string memory sessionSignature = _signAndEncodeRSV(callHash, sessionWallet);
    callSignatures1[0] = _explicitCallSignatureToJSON(0, sessionSignature);

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);

    // Assume the signature is submitted on chain 1. Attacker reads signature and crafts replay attack, duplicating call for chain 2.
    Payload.Decoded memory payload2 = _buildPayload(2);
    payload2.noChainId = true;
    payload2.calls[0] = payload1.calls[0];
    payload2.calls[1] = payload1.calls[0];

    // Sign
    string[] memory callSignatures2 = new string[](2);
    callSignatures2[0] = callSignatures1[0];
    callSignatures2[1] = callSignatures1[0];

    // Construct signature
    bytes memory sessionSignatures2 =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures2, explicitSigners, implicitSigners);
    string memory signatures2 =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures2)));
    bytes memory signature2 = PrimitivesRPC.toEncodedSignature(vm, config, signatures2, !payload2.noChainId);

    // Execute
    try wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload2), signature2) {
      revert("Execution should fail");
    } catch (bytes memory reason) {
      // We don't validate the address in the error
      bytes4 errorSelector = bytes4(reason);
      assertEq(errorSelector, SessionErrors.InvalidSessionSigner.selector);
    }
  }

}
