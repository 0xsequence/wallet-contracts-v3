// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Test.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { ExplicitSessionManager } from "src/extensions/sessions/explicit/ExplicitSessionManager.sol";
import { IExplicitSessionManager } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { SessionPermissions, SessionUsageLimits } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Payload } from "src/modules/Payload.sol";

contract ExplicitSessionManagerTest is SessionTestBase {

  ExplicitSessionManagerHarness harness;
  address wallet;
  Vm.Wallet sessionWallet;
  bytes32 constant SELECTOR_MASK = bytes32(bytes4(0xffffffff));

  modifier supportChainId(
    uint64 chainId
  ) {
    if (chainId != 0) {
      vm.chainId(chainId);
    }
    _;
  }

  function setUp() public {
    harness = new ExplicitSessionManagerHarness();
    wallet = vm.createWallet("wallet").addr;
    sessionWallet = vm.createWallet("session");
  }

  function test_validateExplicitCall(
    uint64 chainId,
    address target,
    bytes4 selector,
    bytes memory callData
  ) public supportChainId(chainId) {
    vm.assume(target != address(harness));
    // Build a payload with one call.
    Payload.Decoded memory payload = _buildPayload(1);
    // Prepend the selector to the call data.
    callData = abi.encodePacked(selector, callData);
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions with one Permission.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: 0, // no native token usage for this test
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    // Allow calls to the target if the selector matches..
    perms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(selector),
      offset: 0,
      mask: SELECTOR_MASK
    });

    // Prepare initial session usage limits.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    // Convert our single SessionPermissions into an array.
    SessionPermissions[] memory permsArr = _toArray(perms);

    // Call the internal explicit call validator.
    SessionUsageLimits memory newUsage = harness.validateExplicitCall(
      payload,
      0, // call index
      wallet,
      sessionWallet.addr,
      permsArr,
      0, // permission index
      usage
    );

    // Since the call value is 0, expect totalValueUsed to remain 0.
    assertEq(newUsage.totalValueUsed, 0, "totalValueUsed should be 0");
  }

  function test_validateExplicitCall_invalidChainId(
    uint64 chainId,
    uint256 invalidChainId,
    address target,
    bytes4 selector,
    bytes memory callData
  ) public supportChainId(chainId) {
    invalidChainId = bound(invalidChainId, 1, type(uint256).max);
    vm.assume(invalidChainId != chainId);
    vm.assume(target != address(harness));
    // Build a payload with one call.
    Payload.Decoded memory payload = _buildPayload(1);
    // Prepend the selector to the call data.
    callData = abi.encodePacked(selector, callData);
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions with one Permission.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: invalidChainId,
      valueLimit: 0, // no native token usage for this test
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    // Allow calls to the target if the selector matches..
    perms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(selector),
      offset: 0,
      mask: SELECTOR_MASK
    });

    // Prepare initial session usage limits.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    // Convert our single SessionPermissions into an array.
    SessionPermissions[] memory permsArr = _toArray(perms);

    // Call the internal explicit call validator.
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidChainId.selector, invalidChainId));
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_InvalidSessionSigner(
    address invalidSigner,
    uint64 chainId
  ) public supportChainId(chainId) {
    vm.assume(invalidSigner != sessionWallet.addr);
    // Build a payload with one call.
    Payload.Decoded memory payload = _buildPayload(1);
    bytes memory callData = hex"deadbeef";
    payload.calls[0] = Payload.Call({
      to: address(0x1234),
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions with a signer that does NOT match the session signer.
    SessionPermissions memory perms = SessionPermissions({
      signer: invalidSigner, // different signer
      chainId: chainId,
      valueLimit: 100,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: address(0x1234), rules: new ParameterRule[](0) });

    // Create session usage limits.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    // Expect revert with the correct error selector
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSessionSigner.selector, sessionWallet.addr));
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_SessionExpired(
    uint64 chainId,
    uint64 currentTimestamp,
    uint64 expiredTimestamp
  ) public supportChainId(chainId) {
    currentTimestamp = uint64(bound(currentTimestamp, 2, type(uint256).max));
    expiredTimestamp = uint64(bound(expiredTimestamp, 1, currentTimestamp - 1));
    vm.warp(currentTimestamp);

    Payload.Decoded memory payload = _buildPayload(1);
    bytes memory callData = hex"12345678";
    payload.calls[0] = Payload.Call({
      to: address(0x1234),
      value: 0,
      data: abi.encodePacked(bytes4(0x12345678), callData),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions with a deadline in the past.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: 100,
      deadline: expiredTimestamp, // expired
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: address(0x1234), rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(bytes4(0x12345678)),
      offset: 0,
      mask: SELECTOR_MASK
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    // Expect revert due to session expiration with the correct deadline
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.SessionExpired.selector, expiredTimestamp));
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_DelegateCall(
    uint64 chainId
  ) public supportChainId(chainId) {
    Payload.Decoded memory payload = _buildPayload(1);
    bytes memory callData = hex"12345678";
    // Set delegateCall to true which is not allowed.
    payload.calls[0] = Payload.Call({
      to: address(0x1234),
      value: 0,
      data: abi.encodePacked(bytes4(0x12345678), callData),
      gasLimit: 0,
      delegateCall: true,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create valid SessionPermissions (won't reach permission check).
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: 100,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: address(0x1234), rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(bytes4(0x12345678)),
      offset: 0,
      mask: SELECTOR_MASK
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    vm.expectRevert(SessionErrors.InvalidDelegateCall.selector);
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_InvalidSelfCall_Value(
    uint64 chainId
  ) public supportChainId(chainId) {
    // Self-call with nonzero value should revert.
    bytes memory callData = abi.encodeWithSelector(harness.incrementUsageLimit.selector, new UsageLimit[](0));
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(harness), // self-call
      value: 1, // nonzero value
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Need valid session permissions for the test to reach self-call validation
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr, // Match the session signer
      chainId: chainId,
      valueLimit: 100,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: address(harness), rules: new ParameterRule[](0) });

    SessionPermissions[] memory permsArr = _toArray(perms);
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    vm.expectRevert(SessionErrors.InvalidValue.selector);
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_MissingPermission(
    uint64 chainId
  ) public supportChainId(chainId) {
    // Build a valid payload call.
    bytes memory callData = hex"12345678";
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0x1234),
      value: 0,
      data: abi.encodePacked(bytes4(0x12345678), callData),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions with an empty permissions array.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: 100,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](0)
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    vm.expectRevert(SessionErrors.MissingPermission.selector);
    // permissionIdx is 0, but there are no permissions.
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_ValueLimitExceeded(
    uint64 chainId
  ) public supportChainId(chainId) {
    // Build a payload call with a nonzero value.
    bytes memory callData = hex"12345678";
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0x1234),
      value: 20, // call value that will exceed the valueLimit
      data: abi.encodePacked(bytes4(0x12345678), callData),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Set valueLimit lower than the call value.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: 10, // limit too low
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: address(0x1234), rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(bytes4(0x12345678)),
      offset: 0,
      mask: SELECTOR_MASK
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    vm.expectRevert(SessionErrors.InvalidValue.selector);
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateExplicitCall_InvalidPermission(
    uint64 chainId
  ) public supportChainId(chainId) {
    Payload.Decoded memory payload = _buildPayload(1);
    // Use call data that does not match the expected selector.
    bytes memory callData = hex"deadbeef";
    payload.calls[0] = Payload.Call({
      to: address(0xDEAD),
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions expecting selector 0x12345678.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: payload.calls[0].to, rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(bytes4(0x12345678)),
      offset: 0,
      mask: SELECTOR_MASK
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    // Expect a revert with the InvalidPermission error.
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  function test_validateLimitUsageIncrement_rule(
    UsageLimit memory limit
  ) public {
    limit.usageAmount = bound(limit.usageAmount, 1, type(uint256).max);

    // Prepare a call that is intended to be the increment call.
    Payload.Call memory incCall = Payload.Call({
      to: address(harness), // must equal the harness address (the contract itself)
      value: 0,
      data: "", // will be filled with expected encoding
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Prepare session usage limits with a nonzero totalValueUsed.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](1);
    usage.limits[0] = limit;

    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    // Construct the expected usage increment.
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = limit;

    // Encode the expected increment call data.
    bytes memory expectedData = abi.encodeWithSelector(harness.incrementUsageLimit.selector, limitsArr);
    incCall.data = expectedData;

    // This call should pass without revert.
    vm.prank(wallet);
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_validateLimitUsageIncrement_value(
    uint256 value
  ) public view {
    value = bound(value, 1, type(uint256).max);

    // Prepare a call that is intended to be the increment call.
    Payload.Call memory incCall = Payload.Call({
      to: address(harness), // must equal the harness address (the contract itself)
      value: 0,
      data: "", // will be filled with expected encoding
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Prepare session usage limits with a nonzero totalValueUsed.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0); // no extra limits for simplicity
    usage.totalValueUsed = value;

    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    // Construct the expected usage increment.
    UsageLimit memory expectedLimit =
      UsageLimit({ usageHash: keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS)), usageAmount: value });
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = expectedLimit;

    // Encode the expected increment call data.
    bytes memory expectedData = abi.encodeWithSelector(harness.incrementUsageLimit.selector, limitsArr);
    incCall.data = expectedData;

    // This call should pass without revert.
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_validateLimitUsageIncrement_RuleAndValue(UsageLimit memory limit, uint256 value) public view {
    limit.usageAmount = bound(limit.usageAmount, 1, type(uint256).max);
    value = bound(value, 1, type(uint256).max);

    // Prepare a call that is intended to be the increment call.
    Payload.Call memory incCall = Payload.Call({
      to: address(harness),
      value: 0,
      data: "", // will be filled with expected encoding
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Prepare session usage limits with a nonzero totalValueUsed.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](1);
    usage.limits[0] = limit;
    usage.totalValueUsed = value;

    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;
    // Construct the expected usage increment.
    UsageLimit[] memory limitsArr = new UsageLimit[](2);
    limitsArr[0] = limit;
    limitsArr[1] =
      UsageLimit({ usageHash: keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS)), usageAmount: value });

    // Encode the expected increment call data.
    bytes memory expectedData = abi.encodeWithSelector(harness.incrementUsageLimit.selector, limitsArr);
    incCall.data = expectedData;

    // This call should pass without revert.
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_validateLimitUsageIncrement_InvalidBehaviorOnError() public {
    // Prepare a call with correct target but incorrect behaviorOnError.
    Payload.Call memory incCall = Payload.Call({
      to: address(harness),
      value: 0,
      data: "invalid", // data is not checked because behaviorOnError is wrong
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: 0 // not the expected Payload.BEHAVIOR_REVERT_ON_ERROR
     });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 100;
    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    vm.prank(wallet);
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_validateLimitUsageIncrement_OnlyFallbackAllowed() public {
    // Prepare a call with correct target and behaviorOnError but onlyFallback = true
    // This should revert because increment calls cannot be skippable
    Payload.Call memory incCall = Payload.Call({
      to: address(harness),
      value: 0,
      data: "invalid", // data is not checked because onlyFallback is wrong
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true, // This should cause the increment call to be skipped
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 100;
    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    // This should revert because increment calls cannot have onlyFallback = true
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    vm.prank(wallet);
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_validateLimitUsageIncrement_InvalidCallData() public {
    // Prepare session usage limits with nonzero totalValueUsed.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 100;
    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    // Create a call with the correct target and behaviorOnError but invalid call data.
    Payload.Call memory incCall = Payload.Call({
      to: address(harness),
      value: 0,
      data: hex"deadbeef", // incorrect encoding
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    vm.prank(wallet);
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_validateLimitUsageIncrement_InvalidCall() public {
    // Prepare a call with an incorrect target.
    Payload.Call memory incCall = Payload.Call({
      to: address(0xDEAD), // wrong target
      value: 0,
      data: "invalid",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 50;

    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    vm.prank(wallet);
    harness.validateLimitUsageIncrement(incCall, usageArr);
  }

  function test_incrementUsageLimit(
    UsageLimit[] memory limits
  ) public {
    vm.assume(limits.length > 0);
    // Limit to 5
    if (limits.length > 5) {
      assembly {
        mstore(limits, 5)
      }
    }

    // Ensure not duplicates
    for (uint256 i = 0; i < limits.length; i++) {
      for (uint256 j = i + 1; j < limits.length; j++) {
        vm.assume(limits[i].usageHash != limits[j].usageHash);
      }
    }

    // Increment the usage limit
    vm.prank(wallet);
    harness.incrementUsageLimit(limits);

    // Check totals
    for (uint256 i = 0; i < limits.length; i++) {
      assertEq(harness.getLimitUsage(wallet, limits[i].usageHash), limits[i].usageAmount);
    }
  }

  function test_incrementUsageLimit_twice(
    UsageLimit[] memory limits
  ) public {
    // Limit to 5
    if (limits.length > 5) {
      assembly {
        mstore(limits, 5)
      }
    }
    // First increment
    test_incrementUsageLimit(limits);
    // Bound amount to be larger than the first increment
    for (uint256 i = 0; i < limits.length; i++) {
      limits[i].usageAmount = bound(limits[i].usageAmount, limits[i].usageAmount, type(uint256).max);
    }
    // Second increment (without checks or tests)
    vm.prank(wallet);
    harness.incrementUsageLimit(limits);

    // Check totals
    for (uint256 i = 0; i < limits.length; i++) {
      assertEq(harness.getLimitUsage(wallet, limits[i].usageHash), limits[i].usageAmount);
    }
  }

  function test_incrementUsageLimit_decrement(
    UsageLimit memory limit
  ) public {
    vm.assume(limit.usageAmount > 0);
    UsageLimit[] memory limits = new UsageLimit[](2);
    limits[0] = limit;
    limits[1] = UsageLimit({ usageHash: limit.usageHash, usageAmount: limit.usageAmount - 1 });

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    vm.prank(wallet);
    harness.incrementUsageLimit(limits);
  }

  function test_validateExplicitCall_MultipleValues(
    uint64 chainId,
    uint256 firstValue,
    uint256 secondValue,
    uint256 thirdValue,
    uint256 valueLimit
  ) public supportChainId(chainId) {
    // Bound values to reasonable ranges
    firstValue = bound(firstValue, 1, type(uint256).max / 3);
    secondValue = bound(secondValue, 1, type(uint256).max / 3);
    thirdValue = bound(thirdValue, 1, type(uint256).max / 3);
    valueLimit = bound(valueLimit, firstValue + secondValue, firstValue + secondValue + thirdValue - 1);

    // Build a payload with three calls
    Payload.Decoded memory payload = _buildPayload(3);

    // First call
    payload.calls[0] = Payload.Call({
      to: address(0x1234),
      value: firstValue,
      data: abi.encodeWithSelector(bytes4(0x12345678)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Second call
    payload.calls[1] = Payload.Call({
      to: address(0x5678),
      value: secondValue,
      data: abi.encodeWithSelector(bytes4(0x12345678)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Third call
    payload.calls[2] = Payload.Call({
      to: address(0x9ABC),
      value: thirdValue,
      data: abi.encodeWithSelector(bytes4(0x12345678)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Set valueLimit to allow first two calls but not the third
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: valueLimit,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](3)
    });

    // Add permissions for all three targets
    for (uint256 i = 0; i < 3; i++) {
      perms.permissions[i] = Permission({ target: payload.calls[i].to, rules: new ParameterRule[](1) });
      perms.permissions[i].rules[0] = ParameterRule({
        cumulative: false,
        operation: ParameterOperation.EQUAL,
        value: bytes32(bytes4(0x12345678)),
        offset: 0,
        mask: SELECTOR_MASK
      });
    }

    SessionPermissions[] memory permsArr = _toArray(perms);
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    // First transaction: Validate first call
    SessionUsageLimits memory newUsage =
      harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
    assertEq(newUsage.totalValueUsed, firstValue, "First call should add firstValue to total value");

    // Increment usage limit after first call
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0] = UsageLimit({
      usageHash: keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS)),
      usageAmount: firstValue
    });
    vm.prank(wallet);
    harness.incrementUsageLimit(limits);

    // Second transaction: Validate second call
    newUsage = harness.validateExplicitCall(payload, 1, wallet, sessionWallet.addr, permsArr, 1, newUsage);
    assertEq(newUsage.totalValueUsed, firstValue + secondValue, "Second call should add secondValue to total value");

    // Increment usage limit after second call
    limits[0].usageAmount = firstValue + secondValue;
    vm.prank(wallet);
    harness.incrementUsageLimit(limits);

    // Third transaction: Try to make third call which should fail
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    harness.validateExplicitCall(payload, 2, wallet, sessionWallet.addr, permsArr, 2, newUsage);
  }

}

contract ExplicitSessionManagerHarness is ExplicitSessionManager {

  /// @notice Exposes the internal _validateExplicitCall function.
  function validateExplicitCall(
    Payload.Decoded calldata payload,
    uint256 callIdx,
    address wallet,
    address sessionWallet,
    SessionPermissions[] memory allSessionPermissions,
    uint8 permissionIdx,
    SessionUsageLimits memory sessionUsageLimits
  ) public view returns (SessionUsageLimits memory) {
    return _validateExplicitCall(
      payload, callIdx, wallet, sessionWallet, allSessionPermissions, permissionIdx, sessionUsageLimits
    );
  }

  /// @notice Exposes the internal _validateLimitUsageIncrement function.
  function validateLimitUsageIncrement(
    Payload.Call calldata call,
    SessionUsageLimits[] memory sessionUsageLimits
  ) public view {
    _validateLimitUsageIncrement(call, sessionUsageLimits);
  }

}
