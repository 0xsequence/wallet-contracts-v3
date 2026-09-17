// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";
import { LibBytes } from "../../../utils/LibBytes.sol";
import { SessionErrors } from "../SessionErrors.sol";
import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "./Permission.sol";

/// @title PermissionValidator
/// @author Michael Standen, Agustin Aguilar
/// @notice Validates permissions for a given call
abstract contract PermissionValidator {

  using LibBytes for bytes;

  /// @notice Emitted when the usage amount for a given wallet and usage hash is updated
  event LimitUsageUpdated(address wallet, bytes32 usageHash, uint256 usageAmount);

  /// @notice Usage amounts; renewable counters pack [period:uint64 | amount:uint192]
  mapping(address => mapping(bytes32 => uint256)) private limitUsage;

  /// @notice Get the usage amount for a given usage hash and wallet
  /// @dev Renewable keys return the packed period and amount; use getLimitUsageForPeriod to decode them
  /// @param wallet The wallet address
  /// @param usageHash The usage hash
  /// @return The usage amount
  function getLimitUsage(address wallet, bytes32 usageHash) public view returns (uint256) {
    return limitUsage[wallet][usageHash];
  }

  /// @notice Set the usage amount for a given usage hash and wallet
  /// @param wallet The wallet address
  /// @param usageHash The usage hash
  /// @param usageAmount The usage amount
  function setLimitUsage(address wallet, bytes32 usageHash, uint256 usageAmount) internal {
    limitUsage[wallet][usageHash] = usageAmount;
    emit LimitUsageUpdated(wallet, usageHash, usageAmount);
  }

  /// @notice Reads current-period usage, treating an expired counter as zero
  /// @param period One-based renewal period (0 = lifetime limit)
  function getLimitUsageForPeriod(
    address wallet,
    bytes32 usageHash,
    uint256 period
  ) public view returns (uint256) {
    uint256 usage = getLimitUsage(wallet, usageHash);
    if (period == 0) {
      return usage;
    }
    return usage >> 192 == period ? usage & type(uint192).max : 0;
  }

  /// @notice Packs renewable usage so the existing monotonic increment also enforces period ordering
  function _packUsageAmount(
    uint256 usageAmount,
    uint256 period
  ) internal pure returns (uint256) {
    if (period == 0) {
      return usageAmount;
    }
    if (period > type(uint64).max || usageAmount > type(uint192).max) {
      revert SessionErrors.InvalidLimitUsageIncrement();
    }
    return (period << 192) | usageAmount;
  }

  /// @notice Keeps lifetime counters unchanged and separates renewable counters by schedule.
  function _getUsageHash(
    bytes32 usageHash,
    bytes32 usageNamespace
  ) internal pure returns (bytes32) {
    return usageNamespace == bytes32(0) ? usageHash : keccak256(abi.encode(usageHash, usageNamespace));
  }

  /// @notice Validates a rules permission
  /// @param permission The rules permission to validate
  /// @param call The call to validate against
  /// @param wallet The wallet address
  /// @param signer The signer address
  /// @param usageLimits Array of current usage limits
  /// @return True if the permission is valid, false otherwise
  /// @return newUsageLimits New array of usage limits
  function validatePermission(
    Permission memory permission,
    Payload.Call calldata call,
    address wallet,
    address signer,
    UsageLimit[] memory usageLimits
  ) public view returns (bool, UsageLimit[] memory newUsageLimits) {
    return _validatePermission(permission, call, wallet, signer, usageLimits, bytes32(0), 0);
  }

  function _validatePermission(
    Permission memory permission,
    Payload.Call calldata call,
    address wallet,
    address signer,
    UsageLimit[] memory usageLimits,
    bytes32 usageNamespace,
    uint256 usagePeriod
  ) internal view returns (bool, UsageLimit[] memory newUsageLimits) {
    if (permission.target != call.to) {
      return (false, usageLimits);
    }

    // Copy usage limits into array with space for new rules
    newUsageLimits = new UsageLimit[](usageLimits.length + permission.rules.length);
    for (uint256 i = 0; i < usageLimits.length; i++) {
      newUsageLimits[i] = usageLimits[i];
    }
    uint256 actualLimitsCount = usageLimits.length;

    // Check each rule
    for (uint256 i = 0; i < permission.rules.length; i++) {
      ParameterRule memory rule = permission.rules[i];

      // Extract value from calldata at offset
      (bytes32 value,) = call.data.readBytes32(rule.offset);

      // Apply mask
      value = value & rule.mask;

      if (rule.cumulative) {
        // Calculate cumulative usage
        uint256 value256 = uint256(value);
        // Find the usage limit for the current rule
        bytes32 usageHash = _getUsageHash(keccak256(abi.encode(signer, permission, i)), usageNamespace);
        uint256 previousUsage;
        UsageLimit memory usageLimit;
        for (uint256 j = 0; j < newUsageLimits.length; j++) {
          if (newUsageLimits[j].usageHash == bytes32(0)) {
            // Initialize new usage limit
            usageLimit = UsageLimit({ usageHash: usageHash, usageAmount: 0 });
            newUsageLimits[j] = usageLimit;
            actualLimitsCount = j + 1;
            break;
          }
          if (newUsageLimits[j].usageHash == usageHash) {
            // Value exists, use it
            usageLimit = newUsageLimits[j];
            previousUsage = usageLimit.usageAmount;
            break;
          }
        }
        if (previousUsage == 0) {
          // Not in current payload, use storage
          previousUsage = getLimitUsageForPeriod(wallet, usageHash, usagePeriod);
        }
        // Cumulate usage
        value256 += previousUsage;
        usageLimit.usageAmount = value256;
        // Use the cumulative value for comparison
        value = bytes32(value256);
      }

      // Compare based on operation
      if (rule.operation == ParameterOperation.EQUAL) {
        if (value != rule.value) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.LESS_THAN_OR_EQUAL) {
        if (uint256(value) > uint256(rule.value)) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.NOT_EQUAL) {
        if (value == rule.value) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.GREATER_THAN_OR_EQUAL) {
        if (uint256(value) < uint256(rule.value)) {
          return (false, usageLimits);
        }
      }
    }

    // Fix array length
    assembly {
      mstore(newUsageLimits, actualLimitsCount)
    }

    return (true, newUsageLimits);
  }

}
