// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../../../utils/LibBytesPointer.sol";

struct Permission {
  address target;
  ParameterRule[] rules;
}

enum ParameterOperation {
  EQUAL,
  NOT_EQUAL,
  GREATER_THAN_OR_EQUAL,
  LESS_THAN_OR_EQUAL
}

struct ParameterRule {
  bool cumulative; // If the value should accumulate over multiple calls
  ParameterOperation operation; // Operation to apply to the parameter
  bytes32 value; // Value to compare against
  uint256 offset; // Offset in calldata to read the parameter
  bytes32 mask; // Mask to apply to the parameter
}

struct UsageLimit {
  bytes32 usageHash;
  uint256 usageAmount;
}

using LibBytesPointer for bytes;

library LibPermission {

  error RulesLengthExceedsMax();

  /// @notice Reads a permission from a packed bytes array
  /// @param encoded The packed bytes array
  /// @param pointer The pointer to the start of the permission
  /// @return permission The decoded permission
  /// @return newPointer The new pointer to the end of the permission
  function readPermission(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Permission memory permission, uint256 newPointer) {
    // Target
    (permission.target, pointer) = encoded.readAddress(pointer);
    // Rules
    uint256 rulesLength;
    (rulesLength, pointer) = encoded.readUint8(pointer);
    permission.rules = new ParameterRule[](rulesLength);
    for (uint256 i = 0; i < rulesLength; i++) {
      uint8 operationCumulative;
      (operationCumulative, pointer) = encoded.readUint8(pointer);
      // 000X: cumulative
      permission.rules[i].cumulative = operationCumulative & 1 != 0;
      // XXX0: operation
      permission.rules[i].operation = ParameterOperation(operationCumulative >> 1);

      (permission.rules[i].value, pointer) = encoded.readBytes32(pointer);
      (permission.rules[i].offset, pointer) = encoded.readUint256(pointer);
      (permission.rules[i].mask, pointer) = encoded.readBytes32(pointer);
    }
    return (permission, pointer);
  }

  /// @notice Encodes a permission into a packed bytes array
  /// @param permission The permission to encode
  /// @return packed The packed bytes array
  function toPacked(
    Permission calldata permission
  ) internal pure returns (bytes memory packed) {
    if (permission.rules.length > type(uint8).max) {
      revert RulesLengthExceedsMax();
    }
    packed = abi.encodePacked(permission.target, uint8(permission.rules.length));
    for (uint256 i = 0; i < permission.rules.length; i++) {
      packed = abi.encodePacked(packed, ruleToPacked(permission.rules[i]));
    }
  }

  /// @notice Encodes a rule into a packed bytes array
  /// @param rule The rule to encode
  /// @return packed The packed bytes array
  function ruleToPacked(
    ParameterRule calldata rule
  ) internal pure returns (bytes memory packed) {
    // Combine operation and cumulative flag into a single byte
    // 0x[operationx3][cumulative]
    uint8 operationCumulative = (uint8(rule.operation) << 1) | (rule.cumulative ? 1 : 0);

    return abi.encodePacked(operationCumulative, rule.value, rule.offset, rule.mask);
  }

}
