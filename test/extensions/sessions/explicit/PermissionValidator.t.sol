// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { PermissionValidator } from "src/extensions/sessions/explicit/PermissionValidator.sol";
import { Payload } from "src/modules/Payload.sol";

contract PermissionValidatorHarness is PermissionValidator {

  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external {
    for (uint256 i = 0; i < limits.length; i++) {
      limitUsage[limits[i].usageHash] += limits[i].usageAmount;
    }
  }

}

contract PermissionValidatorTest is Test {

  PermissionValidatorHarness validator;
  address constant TARGET = address(0xDEAD);
  bytes4 constant DUMMY_SELECTOR = bytes4(0x12345678);
  bytes32 constant SELECTOR_MASK = bytes32(bytes4(0xffffffff));
  bytes32 constant TEST_HASH_PREFIX = bytes32(uint256(1)); // Arbitrary test prefix

  function setUp() public {
    validator = new PermissionValidatorHarness();
  }

  function test_validatePermission_Equal(
    bytes4 selector
  ) public view {
    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(selector),
      offset: 0,
      mask: SELECTOR_MASK
    });

    // Create a matching call
    Payload.Call memory call = Payload.Call({
      to: TARGET,
      value: 0,
      data: abi.encodePacked(selector, bytes28(0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    UsageLimit[] memory emptyLimits = new UsageLimit[](0);
    (bool success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);
    assertTrue(success, "Permission validation should succeed with matching selector");

    // Test with non-matching call (flip all bits of selector)
    bytes4 nonMatchingSelector = ~selector;
    call.data = abi.encodePacked(nonMatchingSelector, bytes28(0));
    (success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);
    assertFalse(success, "Permission validation should fail with non-matching selector");
  }

  function test_validatePermission_Cumulative(uint256 value, uint256 limit) public {
    limit = bound(limit, 0, type(uint256).max - 1);
    value = bound(value, 0, limit);

    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(limit),
      offset: 4, // Offset the selector
      mask: bytes32(type(uint256).max)
    });

    Payload.Call memory call = Payload.Call({
      to: TARGET,
      value: 0,
      data: abi.encodeWithSelector(DUMMY_SELECTOR, value),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Initialize usage limits array with space for one limit
    UsageLimit[] memory emptyLimits = new UsageLimit[](1);
    emptyLimits[0].usageHash = bytes32(0);
    emptyLimits[0].usageAmount = 0;

    (bool success, UsageLimit[] memory newLimits) =
      validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);
    assertTrue(success, "First call should succeed");
    assertEq(newLimits.length, 1, "Should have one usage limit");
    assertEq(newLimits[0].usageAmount, value, "Usage amount should be value");

    // Increment the limit
    validator.incrementUsageLimit(newLimits);

    // Create a second call that would exceed the limit
    value = bound(value, limit - value + 1, type(uint256).max - value);
    call.data = abi.encodeWithSelector(DUMMY_SELECTOR, value);
    (success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, newLimits);
    assertFalse(success, "Second call should fail as it would exceed limit");
  }

  function test_validatePermission_GreaterThanOrEqual(uint256 threshold, uint256 testValue) public view {
    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.GREATER_THAN_OR_EQUAL,
      value: bytes32(threshold),
      offset: 0,
      mask: bytes32(type(uint256).max)
    });

    Payload.Call memory call = Payload.Call({
      to: TARGET,
      value: 0,
      data: abi.encode(testValue),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    UsageLimit[] memory emptyLimits = new UsageLimit[](0);
    (bool success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);

    if (testValue >= threshold) {
      assertTrue(success, "Should succeed with value >= threshold");
    } else {
      assertFalse(success, "Should fail with value < threshold");
    }
  }

  function test_validatePermission_NotEqual(uint256 testValue, uint256 compareValue) public view {
    vm.assume(testValue != compareValue);

    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.NOT_EQUAL,
      value: bytes32(compareValue),
      offset: 0,
      mask: bytes32(type(uint256).max)
    });

    Payload.Call memory call = Payload.Call({
      to: TARGET,
      value: 0,
      data: abi.encode(testValue),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    UsageLimit[] memory emptyLimits = new UsageLimit[](0);
    (bool success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);

    assertTrue(success, "Should pass when values are not equal");
  }

  function test_validatePermission_NotEqual_fail(
    uint256 testValue
  ) public view {
    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.NOT_EQUAL,
      value: bytes32(testValue),
      offset: 0,
      mask: bytes32(type(uint256).max)
    });

    Payload.Call memory call = Payload.Call({
      to: TARGET,
      value: 0,
      data: abi.encode(testValue),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    UsageLimit[] memory emptyLimits = new UsageLimit[](0);
    (bool success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);

    assertFalse(success, "Should fail when values are equal");
  }

  function test_validatePermission_WithMaskAndOffset(
    bytes calldata callData,
    bytes32 mask,
    uint256 offset,
    bytes calldata secondCallData
  ) public view {
    vm.assume(callData.length >= 32);
    offset = bound(offset, 0, callData.length - 32);

    // Extract value from calldata at offset
    bytes32 value;
    assembly {
      value := calldataload(add(callData.offset, offset))
    }

    bytes32 maskedValue = value & mask;
    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: maskedValue,
      offset: offset,
      mask: mask
    });

    Payload.Call memory call = Payload.Call({
      to: TARGET,
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    UsageLimit[] memory emptyLimits = new UsageLimit[](0);
    (bool success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);
    assertTrue(success, "Should succeed when masked value matches with offset");

    // Second test
    bytes32 secondValue;
    assembly {
      secondValue := calldataload(add(secondCallData.offset, offset))
    }
    bytes32 maskedSecondValue = secondValue & mask;
    call.data = secondCallData;
    (success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);
    if (maskedValue == maskedSecondValue) {
      // Expect success when values match
      assertTrue(success, "Should succeed when masked value matches with offset");
    } else {
      // Expect failure when values do not match
      assertFalse(success, "Should fail when masked value does not match with offset");
    }
  }

  function test_validatePermission_WrongTarget(
    address wrongTarget
  ) public view {
    Permission memory permission = Permission({ target: TARGET, rules: new ParameterRule[](1) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint160(TARGET))),
      offset: 0,
      mask: bytes32(type(uint256).max)
    });

    Payload.Call memory call = Payload.Call({
      to: wrongTarget,
      value: 0,
      data: abi.encodeWithSelector(DUMMY_SELECTOR, 0),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    UsageLimit[] memory emptyLimits = new UsageLimit[](0);
    (bool success,) = validator.validatePermission(permission, call, TEST_HASH_PREFIX, emptyLimits);
    assertFalse(success, "Should fail when target does not match");
  }

}
