// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { Emitter } from "test/mocks/Emitter.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
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

import { CanReenter } from "test/mocks/CanReenter.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";

contract SessionManagerTest is SessionTestBase {

  SessionManager public sessionManager;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public identityWallet;
  Emitter public emitter;

  function setUp() public {
    sessionManager = new SessionManager();
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
    emitter = new Emitter();
  }

  /// @notice Valid explicit session test.
  function testValidExplicitSessionSignature(
    bytes4 selector,
    uint256 param,
    uint256 value,
    address explicitTarget,
    address explicitTarget2,
    bool useChainId
  ) public {
    vm.assume(explicitTarget != explicitTarget2);
    vm.assume(value > 0);
    vm.assume(param > 0);
    vm.assume(explicitTarget != address(sessionManager));
    vm.assume(explicitTarget2 != address(sessionManager));
    vm.assume(explicitTarget != address(sessionWallet.addr));
    vm.assume(explicitTarget2 != address(sessionWallet.addr));

    bytes memory callData = abi.encodeWithSelector(selector, param);

    // --- Session Permissions ---
    // Create a SessionPermissions struct granting permission for calls to explicitTarget.
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: useChainId ? block.chainid : 0,
      valueLimit: value,
      deadline: uint64(block.timestamp + 1 days),
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

    // Build a payload with two calls:
    //   Call 0: call not requiring incrementUsageLimit
    //   Call 1: call requiring incrementUsageLimit
    //   Call 2: the required incrementUsageLimit call (self–call)
    Payload.Decoded memory payload = _buildPayload(3);

    // --- Explicit Call 1 ---
    payload.calls[1] = Payload.Call({
      to: explicitTarget,
      value: value,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Explicit Call 2 ---
    payload.calls[2] = Payload.Call({
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
      payload.calls[0] = Payload.Call({
        to: address(sessionManager),
        value: 0,
        data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    uint8[] memory permissionIdxs = new uint8[](3);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1
    permissionIdxs[2] = 1; // Call 2

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  function testIncrementReentrancy() external {
    MockERC20 token = new MockERC20();
    CanReenter canReenter = new CanReenter();
    Factory factory = new Factory();
    Stage1Module stage1Module = new Stage1Module(address(factory), address(0));
    Vm.Wallet memory badGuy = vm.createWallet("badGuy");

    // --- Session Permissions ---
    // Create a SessionPermissions struct granting permission for calls to explicitTarget.
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](2)
    });
    // Permission with an empty rules set allows all calls to the target.
    ParameterRule[] memory rules = new ParameterRule[](2);
    rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(MockERC20.transfer.selector)) << 224),
      offset: 0,
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });
    rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(uint256(1 ether)),
      offset: 4 + 32, // offset the param (selector is 4 bytes)
      mask: bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    });
    sessionPerms.permissions[0] = Permission({ target: address(token), rules: rules });
    sessionPerms.permissions[1] = Permission({ target: address(canReenter), rules: new ParameterRule[](0) }); // Unlimited access

    // Build the session topology using PrimitiveRPC.
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // Topology hash
    bytes32 topologyHash = PrimitivesRPC.sessionImageHash(vm, topology);

    // Create wallet for this topology
    string memory config = PrimitivesRPC.newConfig(
      vm,
      1,
      0,
      string(
        abi.encodePacked(
          "sapient:", vm.toString(topologyHash), ":", vm.toString(address(sessionManager)), ":", vm.toString(uint256(1))
        )
      )
    );
    bytes32 configHash = PrimitivesRPC.getImageHash(vm, config);
    address payable wallet = payable(factory.deploy(address(stage1Module), configHash));

    // Transfer tokens to the wallet (2 ether)
    token.transfer(wallet, 2 ether);

    // Build the reentrant payload
    // Call 0: update the usage limit
    // Call 1: transfer 0.5 ether to the bad guy
    Payload.Decoded memory reentrantPayload = _buildPayload(2);
    reentrantPayload.nonce = 1;

    UsageLimit[] memory reentrantLimits = new UsageLimit[](1);
    reentrantLimits[0] = UsageLimit({
      usageHash: keccak256(abi.encode(sessionWallet.addr, sessionPerms.permissions[0], uint256(1))),
      usageAmount: 1 ether
    });

    // Call 0: update the usage limit
    reentrantPayload.calls[0] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, reentrantLimits),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    reentrantPayload.calls[1] = Payload.Call({
      to: address(token),
      value: 0,
      data: abi.encodeWithSelector(token.transfer.selector, badGuy.addr, 1 ether),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Encode the call signatures for the reentrant payload
    string[] memory reentrantCallSignatures = new string[](2);
    string memory sessionSignature =
      _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(reentrantPayload, 0), sessionWallet);
    reentrantCallSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);
    sessionSignature = _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(reentrantPayload, 1), sessionWallet);
    reentrantCallSignatures[1] = _explicitCallSignatureToJSON(0, sessionSignature);
    address[] memory reentrantExplicitSigners = new address[](1);
    reentrantExplicitSigners[0] = sessionWallet.addr;
    address[] memory reentrantImplicitSigners = new address[](0);
    bytes memory reentrantEncodedSig = PrimitivesRPC.sessionEncodeCallSignatures(
      vm, topology, reentrantCallSignatures, reentrantExplicitSigners, reentrantImplicitSigners
    );

    // Encode the main signature for the reentrant payload
    bytes memory reentrantMainSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(reentrantEncodedSig))),
      false
    );

    // Pack reentrant payload
    bytes memory reentrantPackedPayload = PrimitivesRPC.toPackedPayload(vm, reentrantPayload);

    // Encode the execute function call
    bytes memory reentrantExecuteData = abi.encodeWithSelector(
      canReenter.doAnotherCall.selector,
      address(wallet),
      abi.encodeWithSelector(Stage1Module(wallet).execute.selector, reentrantPackedPayload, reentrantMainSignature)
    );

    // Build a payload with two calls:
    //   Call 1: transfer tokens to the bad guy
    //   Call 2: re-enter and transfer more tokens to the bad guy
    //   Call 3: the required incrementUsageLimit call (self–call)
    Payload.Decoded memory payload = _buildPayload(3);

    // --- Explicit Call 0 ---
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0] = UsageLimit({
      usageHash: keccak256(abi.encode(sessionWallet.addr, sessionPerms.permissions[0], uint256(0.5 ether))),
      usageAmount: 0.5 ether
    });

    payload.calls[0] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Explicit Call 1 ---
    payload.calls[1] = Payload.Call({
      to: address(token),
      value: 0,
      data: abi.encodeWithSelector(token.transfer.selector, badGuy.addr, 1 ether),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Explicit Call 2 ---
    payload.calls[2] = Payload.Call({
      to: address(canReenter),
      value: 0,
      data: reentrantExecuteData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Call Signatures ---
    string[] memory callSignatures = new string[](3);
    {
      // Sign the explicit call (call 0) using the session key.
      sessionSignature = _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload, 0), sessionWallet);
      callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);
      // Sign the explicit call (call 1) using the session key.
      sessionSignature = _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload, 1), sessionWallet);
      callSignatures[1] = _explicitCallSignatureToJSON(0, sessionSignature);
      // Sign the self call (call 2) using the session key.
      sessionSignature = _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload, 2), sessionWallet);
      callSignatures[2] = _explicitCallSignatureToJSON(1, sessionSignature);
    }

    // Encode the full signature.
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    // Encode the main signature
    bytes memory mainSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(encodedSig))),
      false
    );

    // Execute the payload
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);
    vm.expectRevert();
    Stage1Module(wallet).execute(packedPayload, mainSignature);

    // Bad guy should have 0 funds
    assertEq(token.balanceOf(badGuy.addr), 0);
  }

  function _prepareIncrementOverMultipleCalls(
    address wallet,
    address target,
    uint256 startIncrement,
    uint256 value1,
    uint256 value2,
    uint256 ruleValue
  ) internal returns (Payload.Decoded memory payload, bytes32 imageHash, bytes memory encodedSig) {
    vm.assume(target.code.length == 0);

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](1) });
    sessionPerms.permissions[0].rules[0] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(uint256(ruleValue)),
      offset: 0,
      mask: bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    });

    // Set the initial limit usage
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0] = UsageLimit({
      usageHash: keccak256(abi.encode(sessionWallet.addr, sessionPerms.permissions[0], uint256(0))),
      usageAmount: startIncrement
    });
    vm.prank(wallet);
    sessionManager.incrementUsageLimit(limits);
    assertEq(sessionManager.getLimitUsage(wallet, limits[0].usageHash), startIncrement);

    // Call 0: increment the usage limit
    payload = _buildPayload(3);
    limits[0].usageAmount = startIncrement + value1 + value2;
    payload.calls[0] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Use limit
    payload.calls[1] = Payload.Call({
      to: target,
      value: 0,
      data: abi.encodePacked(uint256(value1)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.calls[2] = Payload.Call({
      to: target,
      value: 0,
      data: abi.encodePacked(uint256(value2)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    uint8[] memory permissionIdxs = new uint8[](3);

    (imageHash, encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    return (payload, imageHash, encodedSig);
  }

  function testIncrementOverMultipleCalls_Invalid(
    address wallet,
    address target,
    uint256 startIncrement,
    uint256 value1,
    uint256 value2,
    uint256 ruleValue
  ) public {
    startIncrement = bound(startIncrement, 0, 1 ether);
    value1 = bound(value1, 1, 1 ether);
    value2 = bound(value2, 1, 1 ether);

    ruleValue = bound(ruleValue, 0, startIncrement + value1 + value2 - 1);

    Payload.Decoded memory payload;
    bytes memory encodedSig;
    (payload,, encodedSig) =
      _prepareIncrementOverMultipleCalls(wallet, target, startIncrement, value1, value2, ruleValue);

    vm.prank(wallet);
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  function testIncrementOverMultipleCalls_Valid(
    address wallet,
    address target,
    uint256 startIncrement,
    uint256 value1,
    uint256 value2,
    uint256 ruleValue
  ) public {
    vm.assume(target != wallet);
    startIncrement = bound(startIncrement, 0, 1 ether);
    value1 = bound(value1, 1, 1 ether);
    value2 = bound(value2, 1, 1 ether);

    ruleValue = bound(ruleValue, startIncrement + value1 + value2, 100 ether);

    (Payload.Decoded memory payload, bytes32 imageHash, bytes memory encodedSig) =
      _prepareIncrementOverMultipleCalls(wallet, target, startIncrement, value1, value2, ruleValue);

    vm.prank(wallet);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  function testInvalidPayloadKindReverts() public {
    Payload.Decoded memory payload;
    bytes memory encodedSig;

    payload.kind = Payload.KIND_MESSAGE;
    vm.expectRevert(SessionErrors.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);

    payload.kind = Payload.KIND_CONFIG_UPDATE;
    vm.expectRevert(SessionErrors.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);

    payload.kind = Payload.KIND_DIGEST;
    vm.expectRevert(SessionErrors.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  function testInvalidCallsLengthReverts(
    bytes memory sig
  ) public {
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;

    vm.expectRevert(SessionErrors.InvalidCallsLength.selector);
    sessionManager.recoverSapientSignature(payload, sig);
  }

  function testInvalidSpaceReverts(uint160 space, bytes memory sig) public {
    space = uint160(bound(space, sessionManager.MAX_SPACE() + 1, type(uint160).max));

    Payload.Decoded memory payload;

    vm.expectRevert(SessionErrors.InvalidCallsLength.selector);
    sessionManager.recoverSapientSignature(payload, sig);
  }

  /// @notice Test that a call using delegateCall reverts.
  function testInvalidDelegateCallReverts(Attestation memory attestation, bytes memory data, address target) public {
    vm.assume(target != address(sessionManager));
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    // Build a payload with one call that erroneously uses delegateCall.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: true, // invalid
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.expectRevert(SessionErrors.InvalidDelegateCall.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Valid implicit session test.
  function testValidImplicitSessionSignature(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    // Build a payload with one call for implicit session.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(Emitter.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (bytes32 imageHash, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with onlyFallback = true are allowed
  function testOnlyFallbackCallsAllowed() public {
    // Build a payload with one call that has onlyFallback = true
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(emitter), // Use emitter instead of explicitTarget for implicit sessions
      value: 0,
      data: abi.encodeWithSelector(Emitter.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (bytes32 imageHash, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with BEHAVIOR_ABORT_ON_ERROR will revert with InvalidBehavior
  function testBehaviorAbortOnErrorCallsRevert(address target, bytes memory data) public {
    vm.assume(target != address(sessionManager));
    vm.assume(target != address(sessionWallet.addr));

    // Build a payload with one call that has BEHAVIOR_ABORT_ON_ERROR
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_ABORT_ON_ERROR // This should revert
     });

    (, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.expectRevert(SessionErrors.InvalidBehavior.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that calls with onlyFallback = true in explicit sessions are allowed
  function testExplicitSessionOnlyFallbackAllowed(address target, bytes memory data) public {
    vm.assume(target != address(sessionManager));
    vm.assume(target != address(sessionWallet.addr));

    // Build a payload with one call: explicit call
    Payload.Decoded memory payload = _buildPayload(1);

    // First call with onlyFallback = true (should be allowed)
    // increment call is not allowed since there is no consumption of the usage limit
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](1);
    permissionIdxs[0] = 0; // Call 0

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that the increment call cannot have onlyFallback = true
  function testIncrementCallOnlyFallbackReverts(address target, bytes memory data) public {
    vm.assume(target != address(sessionManager));
    vm.assume(target != address(sessionWallet.addr));

    // Build a payload with two calls: explicit call + increment call with onlyFallback
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // First call (valid explicit call that will use usage limits)
    payload.calls[0] = Payload.Call({
      to: target,
      value: 1, // Use some value to trigger usage tracking
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Second call (increment call with onlyFallback = true - should revert)
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](1)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true, // This should cause the increment call to be skipped
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions with value limit to trigger usage tracking
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 1, // Set value limit to trigger usage tracking
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that calls with BEHAVIOR_IGNORE_ERROR in explicit sessions are allowed
  function testExplicitSessionBehaviorIgnoreErrorAllowed(address target, bytes memory data) public {
    vm.assume(target != address(sessionManager));
    vm.assume(target != address(sessionWallet.addr));

    Payload.Decoded memory payload = _buildPayload(1);

    // First call with BEHAVIOR_IGNORE_ERROR (should be allowed)
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](0) });

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, new uint8[](1));

    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with BEHAVIOR_ABORT_ON_ERROR in explicit sessions revert
  function testExplicitSessionBehaviorAbortOnErrorReverts(address target, bytes memory data) public {
    vm.assume(target != address(sessionManager));
    vm.assume(target != address(sessionWallet.addr));

    Payload.Decoded memory payload = _buildPayload(1);

    // First call with BEHAVIOR_ABORT_ON_ERROR (should revert)
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_ABORT_ON_ERROR // This should revert
     });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](0) });

    (, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, new uint8[](1));

    vm.expectRevert(SessionErrors.InvalidBehavior.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that valid linear execution still works
  function testValidLinearExecution(address target, bytes memory data) public {
    vm.assume(target != address(sessionManager));
    vm.assume(target != address(sessionWallet.addr));

    Payload.Decoded memory payload = _buildPayload(1);

    // First call (normal explicit call)
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR // Valid behavior
     });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](0) });

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, new uint8[](1));

    // This should succeed since all flags are valid for linear execution
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  // ============================================================================
  // HELPER FUNCTIONS
  // ============================================================================

  /// @notice Create a valid attestation for testing
  function _createValidAttestation() internal view returns (Attestation memory) {
    Attestation memory attestation;
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com";
    attestation.authData.issuedAt = uint64(block.timestamp);
    return attestation;
  }

  function _validImplicitSessionSignature(
    Payload.Decoded memory payload
  ) internal returns (bytes32 imageHash, bytes memory encodedSig) {
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    imageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    uint256 callCount = payload.calls.length;
    string[] memory callSignatures = new string[](callCount);
    Attestation memory attestation = _createValidAttestation();
    for (uint256 i; i < callCount; i++) {
      callSignatures[i] = _createImplicitCallSignature(payload, i, sessionWallet, identityWallet, attestation);
    }

    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    return (imageHash, encodedSig);
  }

  function _validExplicitSessionSignature(
    Payload.Decoded memory payload,
    SessionPermissions memory sessionPerms,
    uint8[] memory permissionIdxs
  ) internal returns (bytes32 imageHash, bytes memory encodedSig) {
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    imageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    uint256 callCount = payload.calls.length;
    string[] memory callSignatures = new string[](callCount);
    for (uint256 i; i < callCount; i++) {
      string memory sessionSignature =
        _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload, i), sessionWallet);
      callSignatures[i] = _explicitCallSignatureToJSON(permissionIdxs[i], sessionSignature);
    }

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    return (imageHash, encodedSig);
  }

}
