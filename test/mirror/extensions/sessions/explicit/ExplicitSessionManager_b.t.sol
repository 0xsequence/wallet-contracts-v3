// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { AdvTest } from "../../../../utils/TestUtils.sol";

import { Bytes32ToUint256Map } from "../../../utils/Mappings.sol";
import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { ExplicitSessionManager } from "src/extensions/sessions/explicit/ExplicitSessionManager.sol";
import { UsageLimit } from "src/extensions/sessions/explicit/Permission.sol";
import { Payload } from "src/modules/Payload.sol";

contract ExternalExplicitSessionManager is ExplicitSessionManager {
// ExplicitSessionManager is abstract, so we extend it so we can deploy it by itself
}

contract ExplicitSessionManagerTest is AdvTest {

  event LimitUsageUpdated(address wallet, bytes32 usageHash, uint256 usageAmount);

  struct DeltaUsageLimit {
    bytes32 usageHash;
    uint256 usageDelta;
  }

  struct MultipleUsageLimits {
    DeltaUsageLimit[4] limits;
    uint8 length;
  }

  function min(uint256 a, uint256 b) internal pure returns (uint256) {
    return a < b ? a : b;
  }

  function test_incrementUsageLimit(address wallet, MultipleUsageLimits[4] memory multipleUsageLimits) external {
    ExternalExplicitSessionManager explicitSessionManager = new ExternalExplicitSessionManager();

    // Perform the increment multiple times
    for (uint256 i = 0; i < multipleUsageLimits.length; i++) {
      uint8 numLimitsToProcess = uint8(min(multipleUsageLimits[i].limits.length, multipleUsageLimits[i].length));
      UsageLimit[] memory usageLimits = new UsageLimit[](numLimitsToProcess);
      Bytes32ToUint256Map sameCallIncrements = new Bytes32ToUint256Map();

      for (uint256 j = 0; j < numLimitsToProcess; j++) {
        usageLimits[j].usageHash = keccak256(abi.encode(wallet, multipleUsageLimits[i].limits[j].usageHash));

        // If the usage already reached type(uint256).max then it can't keep increasing
        uint256 lastUsage = sameCallIncrements.get(usageLimits[j].usageHash);
        uint256 contractUsage = explicitSessionManager.getLimitUsage(wallet, usageLimits[j].usageHash);
        uint256 usage = lastUsage > contractUsage ? lastUsage : contractUsage;

        if (type(uint256).max - usage < multipleUsageLimits[i].limits[j].usageDelta) {
          usageLimits[j].usageAmount = type(uint256).max;
        } else {
          usageLimits[j].usageAmount = usage + multipleUsageLimits[i].limits[j].usageDelta;
        }

        sameCallIncrements.set(usageLimits[j].usageHash, usageLimits[j].usageAmount);
      }

      for (uint256 j = 0; j < numLimitsToProcess; j++) {
        vm.expectEmit(true, true, true, true, address(explicitSessionManager));
        emit LimitUsageUpdated(wallet, usageLimits[j].usageHash, usageLimits[j].usageAmount);
      }

      vm.prank(wallet);
      explicitSessionManager.incrementUsageLimit(usageLimits);

      // Check the usage limits
      for (uint256 j = 0; j < usageLimits.length; j++) {
        uint256 usage = explicitSessionManager.getLimitUsage(wallet, usageLimits[j].usageHash);
        assertEq(usage, sameCallIncrements.get(usageLimits[j].usageHash));
      }
    }
  }

  function test_fail_decrementUsageLimit_sameCall(
    address wallet,
    bytes32 usageHash,
    uint256 previousUsageAmount,
    uint256 decrementAmount
  ) external {
    previousUsageAmount = bound(previousUsageAmount, 1, type(uint256).max);
    decrementAmount = bound(decrementAmount, 0, previousUsageAmount - 1);

    ExternalExplicitSessionManager explicitSessionManager = new ExternalExplicitSessionManager();

    UsageLimit[] memory usageLimits = new UsageLimit[](2);

    usageLimits[0].usageHash = keccak256(abi.encode(wallet, usageHash));
    usageLimits[0].usageAmount = previousUsageAmount;

    usageLimits[1].usageHash = keccak256(abi.encode(wallet, usageHash));
    usageLimits[1].usageAmount = decrementAmount;

    vm.prank(wallet);
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidLimitUsageIncrement.selector));
    explicitSessionManager.incrementUsageLimit(usageLimits);
  }

  function test_fail_decrementUsageLimit_differentCall(
    address wallet,
    bytes32 usageHash,
    uint256 previousUsageAmount,
    uint256 decrementAmount
  ) external {
    previousUsageAmount = bound(previousUsageAmount, 1, type(uint256).max);
    decrementAmount = bound(decrementAmount, 0, previousUsageAmount - 1);

    ExternalExplicitSessionManager explicitSessionManager = new ExternalExplicitSessionManager();

    UsageLimit[] memory usageLimits = new UsageLimit[](1);

    usageLimits[0].usageHash = keccak256(abi.encode(wallet, usageHash));
    usageLimits[0].usageAmount = previousUsageAmount;

    vm.prank(wallet);
    explicitSessionManager.incrementUsageLimit(usageLimits);

    usageLimits[0].usageHash = keccak256(abi.encode(wallet, usageHash));
    usageLimits[0].usageAmount = decrementAmount;

    vm.prank(wallet);
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidLimitUsageIncrement.selector));
    explicitSessionManager.incrementUsageLimit(usageLimits);
  }

}
