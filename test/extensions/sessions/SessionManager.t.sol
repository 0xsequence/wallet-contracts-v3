// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { MockImplicitContract } from "test/mocks/MockImplicitContract.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";
import { ISapient } from "src/modules/interfaces/ISapient.sol";

contract SessionManagerTest is SessionTestBase {

  SessionManager public sessionManager;
  address public explicitTarget;
  address public implicitTarget;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public globalWallet;
  MockImplicitContract public mockImplicit;

  function setUp() public {
    sessionManager = new SessionManager();
    sessionWallet = vm.createWallet("session");
    globalWallet = vm.createWallet("global");
    explicitTarget = address(0xBEEF);
    // Deploy a mock implicit contract so that implicit calls do not revert.
    mockImplicit = new MockImplicitContract();
    implicitTarget = address(mockImplicit);
  }

  function testSupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
  }

  /// @notice Valid explicit session test.
  function testValidExplicitSessionSignature(
    bytes memory callData
  ) public {
    // Build a payload with two calls:
    //   Call 0: an explicit call to an external target (explicitTarget)
    //   Call 1: the required incrementUsageLimit call (self–call)
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // --- Explicit Call (Call 0) ---
    // Encode call with selector 0x12345678 and parameter amount.
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Self Call (Call 1) ---
    // This call is to incrementUsageLimit (which is allowed) in the valid case.
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0, // valid case: zero value
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Session Permissions ---
    // Create a SessionPermissions struct granting permission for calls to explicitTarget.
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    // Permission with an empty rules set allows all calls to the target.
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    // Build the session topology using PrimitiveRPC.
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // --- Call Signatures ---
    string[] memory callSignatures = new string[](2);
    // Sign the explicit call (call 0) using the session key.
    string memory sessionSignature = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
    callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);
    // Sign the self call (call 1) using the session key.
    sessionSignature = _signAndEncodeRSV(Payload.hashCall(payload.calls[1]), sessionWallet);
    callSignatures[1] = _explicitCallSignatureToJSON(0, sessionSignature);

    // Encode the full signature.
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // --- Validate the Payload Signature ---
    bytes32 imageHash = sessionManager.isValidSapientSignature(payload, encodedSig);
    bytes32 expectedImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    assertEq(imageHash, expectedImageHash);
  }

  /// @notice Test that a call using delegateCall reverts.
  function testInvalidDelegateCallReverts(
    bytes memory data
  ) public {
    // Build a payload with one call that erroneously uses delegateCall.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: true, // invalid
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    Attestation memory attestation = Attestation({
      approvedSigner: sessionWallet.addr,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: new bytes(0),
      applicationData: new bytes(0)
    });

    // Build topology (even though it won’t be used because the delegateCall check runs first).
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    string[] memory callSignatures = new string[](1);
    callSignatures[0] = _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation);
    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    vm.expectRevert(SessionErrors.InvalidDelegateCall.selector);
    sessionManager.isValidSapientSignature(payload, encodedSig);
  }

  /// @notice Test that a self–call with nonzero value reverts with InvalidSelfCall.
  function testInvalidSelfCallReverts() public {
    // Build a payload with two calls:
    //   Call 0: valid explicit call.
    //   Call 1: self–call (incrementUsageLimit) with nonzero value (invalid).
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // --- Explicit Call (Call 0) ---
    bytes memory explicitCallData = abi.encodeWithSelector(0x12345678, uint256(42));
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: explicitCallData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Self Call (Call 1) ---
    // Intentionally set nonzero value.
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 1, // nonzero -> should revert
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions for call 0.
    SessionPermissions memory sessionPerms;
    sessionPerms.signer = sessionWallet.addr;
    sessionPerms.valueLimit = 0;
    sessionPerms.deadline = block.timestamp + 1 days;
    sessionPerms.permissions = new Permission[](1);
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](1) });
    sessionPerms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(0x12345678)) << 224),
      offset: 0,
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });

    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // --- Call Signatures ---
    // For call 0:
    string memory sessionSignature0 = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
    string memory callSig0 = _explicitCallSignatureToJSON(0, sessionSignature0);
    // For call 1 (self–call), we now sign it as well.
    string memory sessionSignature1 = _signAndEncodeRSV(Payload.hashCall(payload.calls[1]), sessionWallet);
    string memory callSig1 = _explicitCallSignatureToJSON(0, sessionSignature1);
    string[] memory callSignatures = new string[](2);
    callSignatures[0] = callSig0;
    callSignatures[1] = callSig1;

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    vm.expectRevert(SessionErrors.InvalidSelfCall.selector);
    sessionManager.isValidSapientSignature(payload, encodedSig);
  }

  /// @notice Valid implicit session test.
  function testValidImplicitSessionSignature(bytes memory authData, bytes memory applicationData) public {
    // Build a payload with one call for implicit session.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: implicitTarget,
      value: 0,
      data: "test", // arbitrary data
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Create an Attestation for the Implicit Session ---
    Attestation memory attestation = Attestation({
      approvedSigner: sessionWallet.addr,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    // Create the implicit call signature.
    string memory callSignature =
      _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation);

    // Build the session topology for implicit sessions.
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    string[] memory callSignatures = new string[](1);
    callSignatures[0] = callSignature;

    // Encode the full signature with the implicit flag set to true.
    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // Validate the signature.
    bytes32 imageHash = sessionManager.isValidSapientSignature(payload, encodedSig);
    bytes32 expectedImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    assertEq(imageHash, expectedImageHash);
  }

}
