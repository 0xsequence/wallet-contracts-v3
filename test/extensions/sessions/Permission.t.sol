// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

import {
  LibPermission, ParameterOperation, ParameterRule, Permission
} from "src/extensions/sessions/explicit/Permission.sol";

contract LibPermissionHarness {

  function readPermission(bytes calldata encoded, uint256 pointer) public pure returns (Permission memory, uint256) {
    return LibPermission.readPermission(encoded, pointer);
  }

  function toPacked(
    Permission calldata permission
  ) public pure returns (bytes memory) {
    return LibPermission.toPacked(permission);
  }

}

contract PermissionTest is Test {

  LibPermissionHarness harness;

  function setUp() public {
    harness = new LibPermissionHarness();
  }

  // Forge can't handle inputting enums so we declare the structs here
  struct PermissionTestInput {
    address target;
    ParameterRuleTestInput[] rules;
  }

  struct ParameterRuleTestInput {
    bool cumulative;
    uint8 operation;
    bytes32 value;
    uint256 offset;
    bytes32 mask;
  }

  function test_fail_packRulesLengthExceedsMax(
    PermissionTestInput memory input
  ) public {
    vm.assume(input.rules.length > 0);
    Permission memory permission = _toPermission(input);
    uint256 maxRulesLength = type(uint8).max;
    if (permission.rules.length <= maxRulesLength) {
      ParameterRule[] memory rules = new ParameterRule[](maxRulesLength + 1);
      for (uint256 i = 0; i < permission.rules.length; i++) {
        rules[i] = permission.rules[i];
      }
      // Add more rules
      for (uint256 i = permission.rules.length; i < maxRulesLength + 1; i++) {
        rules[i] = permission.rules[i % permission.rules.length];
      }
      permission.rules = rules;
    }
    vm.expectRevert(LibPermission.RulesLengthExceedsMax.selector);
    harness.toPacked(permission);
  }

  function test_packAndRead(
    PermissionTestInput memory input
  ) public view {
    Permission memory permission = _toPermission(input);
    uint256 maxRulesLength = type(uint8).max;
    if (permission.rules.length > maxRulesLength) {
      ParameterRule[] memory rules = permission.rules;
      uint256 rulesLength = bound(rules.length, 0, maxRulesLength); // Re randomize length
      assembly {
        mstore(rules, rulesLength)
      }
      permission.rules = rules;
    }

    bytes memory encoded = harness.toPacked(permission);
    Permission memory decoded;
    uint256 pointer;
    (decoded, pointer) = harness.readPermission(encoded, pointer);
    assertEq(pointer, encoded.length);
    assertEq(decoded.target, permission.target);
    assertEq(decoded.rules.length, permission.rules.length);
    for (uint256 i = 0; i < permission.rules.length; i++) {
      assertEq(decoded.rules[i].cumulative, permission.rules[i].cumulative);
      assertEq(uint8(decoded.rules[i].operation), uint8(permission.rules[i].operation));
      assertEq(decoded.rules[i].value, permission.rules[i].value);
      assertEq(decoded.rules[i].offset, permission.rules[i].offset);
      assertEq(decoded.rules[i].mask, permission.rules[i].mask);
    }
  }

  function test_packAndReadAtPointer(
    PermissionTestInput memory input,
    bytes memory prepend,
    bytes memory append
  ) public view {
    Permission memory permission = _toPermission(input);
    uint256 maxRulesLength = type(uint8).max;
    if (permission.rules.length > maxRulesLength) {
      ParameterRule[] memory rules = permission.rules;
      uint256 rulesLength = bound(rules.length, 0, maxRulesLength); // Re randomize length
      assembly {
        mstore(rules, rulesLength)
      }
      permission.rules = rules;
    }

    bytes memory encoded = harness.toPacked(permission);
    bytes memory encodedSurrounded = abi.encodePacked(prepend, encoded, append);
    Permission memory decoded;
    uint256 pointer = prepend.length;
    (decoded, pointer) = harness.readPermission(encodedSurrounded, pointer);
    assertEq(pointer, prepend.length + encoded.length);
    assertEq(decoded.target, permission.target);
    assertEq(decoded.rules.length, permission.rules.length);
    for (uint256 i = 0; i < permission.rules.length; i++) {
      assertEq(decoded.rules[i].cumulative, permission.rules[i].cumulative);
      assertEq(uint8(decoded.rules[i].operation), uint8(permission.rules[i].operation));
      assertEq(decoded.rules[i].value, permission.rules[i].value);
      assertEq(decoded.rules[i].offset, permission.rules[i].offset);
      assertEq(decoded.rules[i].mask, permission.rules[i].mask);
    }
  }

  function _toPermission(
    PermissionTestInput memory input
  ) internal pure returns (Permission memory) {
    ParameterRule[] memory rules = new ParameterRule[](input.rules.length);
    for (uint256 i = 0; i < input.rules.length; i++) {
      uint256 operation = bound(input.rules[i].operation, 0, 3);
      ParameterOperation parameterOperation;
      if (operation == 0) {
        parameterOperation = ParameterOperation.EQUAL;
      } else if (operation == 1) {
        parameterOperation = ParameterOperation.NOT_EQUAL;
      } else if (operation == 2) {
        parameterOperation = ParameterOperation.GREATER_THAN_OR_EQUAL;
      } else if (operation == 3) {
        parameterOperation = ParameterOperation.LESS_THAN_OR_EQUAL;
      }
      rules[i] = ParameterRule({
        cumulative: input.rules[i].cumulative,
        operation: parameterOperation,
        value: input.rules[i].value,
        offset: input.rules[i].offset,
        mask: input.rules[i].mask
      });
    }
    return Permission({ target: input.target, rules: rules });
  }

}
