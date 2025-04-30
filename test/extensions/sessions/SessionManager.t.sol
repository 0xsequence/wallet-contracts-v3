// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { MockImplicitContract } from "test/mocks/MockImplicitContract.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
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
  Vm.Wallet public identityWallet;
  MockImplicitContract public mockImplicit;

  function setUp() public {
    sessionManager = new SessionManager();
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
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
    bytes4 selector,
    uint256 param,
    uint256 value,
    address explicitTarget2
  ) public {
    vm.assume(explicitTarget != explicitTarget2);
    vm.assume(value > 0);
    vm.assume(param > 0);
    bytes memory callData = abi.encodeWithSelector(selector, param);

    // --- Session Permissions ---
    // Create a SessionPermissions struct granting permission for calls to explicitTarget.
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      allowMessages: false,
      valueLimit: value,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](2)
    });
    // Permission with an empty rules set allows all calls to the target.
    ParameterRule[] memory rules = new ParameterRule[](2);
    // Rules for explicitTarget in call 0.
    rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(selector)) << 224),
      offset: 0,
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });
    rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(param),
      offset: 4, // offset the param (selector is 4 bytes)
      mask: bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: rules });
    sessionPerms.permissions[1] = Permission({ target: explicitTarget2, rules: new ParameterRule[](0) }); // Unlimited access

    // Build the session topology using PrimitiveRPC.
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // Build a payload with two calls:
    //   Call 0: call not requiring incrementUsageLimit
    //   Call 1: call requiring incrementUsageLimit
    //   Call 2: the required incrementUsageLimit call (self–call)
    Payload.Decoded memory payload = _buildPayload(3);

    // --- Explicit Call 1 ---
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: value,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Explicit Call 2 ---
    payload.calls[1] = Payload.Call({
      to: explicitTarget2,
      value: 0,
      data: callData, // Reuse this because permission for this target is open
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Increment Usage Limit ---
    {
      UsageLimit[] memory limits = new UsageLimit[](2);
      limits[0] = UsageLimit({
        usageHash: keccak256(abi.encode(sessionWallet.addr, sessionPerms.permissions[0], uint256(1))),
        usageAmount: param
      });
      limits[1] =
        UsageLimit({ usageHash: keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS)), usageAmount: value });
      payload.calls[2] = Payload.Call({
        to: address(sessionManager),
        value: 0,
        data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // --- Call Signatures ---
    string[] memory callSignatures = new string[](3);
    {
      // Sign the explicit call (call 0) using the session key.
      string memory sessionSignature =
        _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[0], payload), sessionWallet);
      callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);
      // Sign the explicit call (call 1) using the session key.
      sessionSignature =
        _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[1], payload), sessionWallet);
      callSignatures[1] = _explicitCallSignatureToJSON(1, sessionSignature);
      // Sign the self call (call 2) using the session key.
      sessionSignature =
        _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[2], payload), sessionWallet);
      callSignatures[2] = _explicitCallSignatureToJSON(0, sessionSignature);
    }

    // Encode the full signature.
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // --- Validate the Payload Signature ---
    vm.prank(sessionWallet.addr);
    bytes32 imageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    bytes32 expectedImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    assertEq(imageHash, expectedImageHash);
  }

  function testInvalidPayloadKindReverts() public {
    Payload.Decoded memory payload;
    bytes memory encodedSig;

    payload.kind = Payload.KIND_CONFIG_UPDATE;
    vm.expectRevert(SessionManager.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);

    payload.kind = Payload.KIND_DIGEST;
    vm.expectRevert(SessionManager.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  function testInvalidCallsLengthReverts() public {
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    bytes memory encodedSig;

    vm.expectRevert(SessionManager.InvalidCallsLength.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that a call using delegateCall reverts.
  function testInvalidDelegateCallReverts(Attestation memory attestation, bytes memory data) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify

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

    // Build topology (even though it won’t be used because the delegateCall check runs first).
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string[] memory callSignatures = new string[](1);
    callSignatures[0] = _createImplicitCallSignature(payload, 0, sessionWallet, identityWallet, attestation);
    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    vm.expectRevert(SessionErrors.InvalidDelegateCall.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
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

    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // --- Call Signatures ---
    // For call 0:
    string memory sessionSignature0 =
      _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[0], payload), sessionWallet);
    string memory callSig0 = _explicitCallSignatureToJSON(0, sessionSignature0);
    // For call 1 (self–call), we now sign it as well.
    string memory sessionSignature1 =
      _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[1], payload), sessionWallet);
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
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Valid implicit session test.
  function testValidImplicitSessionSignature(Attestation memory attestation, bytes memory data) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify

    // Build a payload with one call for implicit session.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: implicitTarget,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create the implicit call signature.
    string memory callSignature = _createImplicitCallSignature(payload, 0, sessionWallet, identityWallet, attestation);

    // Build the session topology for implicit sessions.
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string[] memory callSignatures = new string[](1);
    callSignatures[0] = callSignature;

    // Encode the full signature with the implicit flag set to true.
    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // Validate the signature.
    bytes32 imageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    bytes32 expectedImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    assertEq(imageHash, expectedImageHash);
  }

  function testValidMessageSignature(
    bytes memory message
  ) public {
    // Create a message payload
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_MESSAGE;
    payload.message = message;

    // Create session permissions that allow messages
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      allowMessages: true, // Allow messages
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](0)
    });

    // Build the session topology using PrimitiveRPC
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // Create the call signature for the message
    string[] memory callSignatures = new string[](1);
    bytes32 messageHash = Payload.hash(payload);
    string memory sessionSignature = _signAndEncodeRSV(messageHash, sessionWallet);
    callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);

    // Encode the full signature
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // Validate the signature
    bytes32 imageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    bytes32 expectedImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    assertEq(imageHash, expectedImageHash);
  }

  function testInvalidMessageSignature_MissingPermissions(
    bytes memory message
  ) public {
    // Create a message payload
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_MESSAGE;
    payload.message = message;

    // Create session permissions that allow messages
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      allowMessages: false, // Do not allow messages
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](0)
    });

    // Build the session topology using PrimitiveRPC
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // Create the call signature for the message
    string[] memory callSignatures = new string[](1);
    bytes32 messageHash = Payload.hash(payload);
    string memory sessionSignature = _signAndEncodeRSV(messageHash, sessionWallet);
    callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);

    // Encode the full signature
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // Validate the signature
    vm.expectRevert(SessionErrors.MissingPermission.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

}
